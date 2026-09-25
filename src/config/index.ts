import * as fs from 'node:fs';
import * as path from 'node:path';
import type { Severity } from '../rules/types.ts';

export interface PublisherPolicy {
  requireSignature?: boolean;
  trustedKeys?: string[];
  revokedKeys?: string[];
}

export interface SkillGuardConfig {
  extends?: string | string[];
  profile?: PolicyProfileName;
  ignoreRules?: string[];
  failOn?: Severity;
  minScore?: number;
  allowedDomains?: string[];
  publishers?: PublisherPolicy;
  baseline?: string;
  severityOverrides?: Record<string, Severity>;
  include?: string[];
  exclude?: string[];
}

export type AgentWardenConfig = SkillGuardConfig;

export interface ConfigLoadResult {
  config: SkillGuardConfig;
  source?: string;
  sources: string[];
  explicit: boolean;
}

export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ConfigError';
  }
}

export type PolicyProfileName = 'legacy' | 'balanced' | 'strict';

export interface PolicyProfile {
  failOn: Severity;
  minScore: number;
}

export const POLICY_PROFILES: Readonly<Record<PolicyProfileName, PolicyProfile>> = {
  legacy: { failOn: 'high', minScore: 60 },
  balanced: { failOn: 'high', minScore: 80 },
  strict: { failOn: 'medium', minScore: 90 },
};

export const DEFAULT_CONFIG: Readonly<SkillGuardConfig> = {
  profile: 'legacy',
  ignoreRules: [],
  failOn: 'high',
  minScore: 60,
  allowedDomains: [],
  publishers: {
    requireSignature: false,
    trustedKeys: [],
    revokedKeys: [],
  },
  severityOverrides: {},
  include: [],
  exclude: [],
};

const VALID_FAIL_ON: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
const VALID_PROFILES: PolicyProfileName[] = ['legacy', 'balanced', 'strict'];
export const CONFIG_FILE_NAMES = [
  path.join('.agentwarden', 'policy.json'),
  '.wardenrc.json',
  '.wardenrc',
  'warden.config.json',
  'agentwarden.config.json',
  '.skillguardrc.json',
  '.skillguardrc',
  'skillguard.config.json',
];

function cleanStringList(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return [...new Set(value.map((v) => String(v).trim()).filter(Boolean))];
}

function cleanSeverityOverrides(value: unknown): Record<string, Severity> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return {};

  const overrides: Record<string, Severity> = {};
  for (const [rawRuleId, rawSeverity] of Object.entries(value)) {
    const ruleId = rawRuleId.trim().toUpperCase();
    const severity = String(rawSeverity).trim().toLowerCase() as Severity;
    if (ruleId && VALID_FAIL_ON.includes(severity)) {
      overrides[ruleId] = severity;
    }
  }
  return overrides;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function cleanPublisherFingerprints(value: unknown, field: string): string[] {
  if (value === undefined) return [];
  if (!Array.isArray(value)) {
    throw new ConfigError(`Invalid "publishers.${field}" (expected an array of SHA-256 fingerprints)`);
  }

  return [
    ...new Set(
      value.map((entry) => {
        if (typeof entry !== 'string') {
          throw new ConfigError(
            `Invalid "publishers.${field}" entry (expected a SHA-256 fingerprint)`,
          );
        }
        const normalized = entry.trim().toLowerCase().replace(/^sha256:/, '');
        if (!/^[a-f0-9]{64}$/.test(normalized)) {
          throw new ConfigError(
            `Invalid "publishers.${field}" fingerprint "${entry}" (expected 64 hexadecimal characters)`,
          );
        }
        return normalized;
      }),
    ),
  ];
}

function cleanPublisherPolicy(value: unknown): Required<PublisherPolicy> {
  if (value === undefined) {
    return { requireSignature: false, trustedKeys: [], revokedKeys: [] };
  }
  if (!isPlainObject(value)) {
    throw new ConfigError('Invalid "publishers" (expected an object)');
  }
  if (value.requireSignature !== undefined && typeof value.requireSignature !== 'boolean') {
    throw new ConfigError('Invalid "publishers.requireSignature" (expected boolean)');
  }

  const revokedKeys = cleanPublisherFingerprints(value.revokedKeys, 'revokedKeys');
  const revoked = new Set(revokedKeys);
  const trustedKeys = cleanPublisherFingerprints(value.trustedKeys, 'trustedKeys').filter(
    (fingerprint) => !revoked.has(fingerprint),
  );

  return {
    requireSignature: value.requireSignature ?? false,
    trustedKeys,
    revokedKeys,
  };
}

export function parseConfigContent(filePath: string, raw: string): Partial<SkillGuardConfig> {
  try {
    const parsed = JSON.parse(raw) as unknown;
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error('config root must be a JSON object');
    }
    return parsed as Partial<SkillGuardConfig>;
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    throw new ConfigError(`Invalid config file "${filePath}": ${detail}`);
  }
}

function parseConfigFile(filePath: string): Partial<SkillGuardConfig> {
  return parseConfigContent(filePath, fs.readFileSync(filePath, 'utf8'));
}

function cleanExtends(value: unknown, source: string): string[] {
  if (value === undefined) return [];
  const entries = Array.isArray(value) ? value : [value];
  if (entries.length === 0) return [];
  if (entries.some((entry) => typeof entry !== 'string' || !entry.trim())) {
    throw new ConfigError(`Invalid "extends" in config file "${source}" (expected string or string[])`);
  }
  return entries.map((entry) => String(entry).trim());
}

function mergeStringLists(base: unknown, override: unknown): string[] {
  const baseValues = Array.isArray(base) ? base : [];
  const overrideValues = Array.isArray(override) ? override : [];
  return [...baseValues, ...overrideValues].map((value) => String(value));
}

function mergeRawConfigs(
  base: Partial<SkillGuardConfig>,
  override: Partial<SkillGuardConfig>,
): Partial<SkillGuardConfig> {
  const merged: Partial<SkillGuardConfig> = { ...base, ...override };

  merged.ignoreRules = mergeStringLists(base.ignoreRules, override.ignoreRules);
  merged.allowedDomains = mergeStringLists(base.allowedDomains, override.allowedDomains);
  merged.include = mergeStringLists(base.include, override.include);
  merged.exclude = mergeStringLists(base.exclude, override.exclude);

  if (base.severityOverrides !== undefined || override.severityOverrides !== undefined) {
    const baseOverrides =
      base.severityOverrides && typeof base.severityOverrides === 'object' && !Array.isArray(base.severityOverrides)
        ? base.severityOverrides
        : {};
    const overrideOverrides =
      override.severityOverrides &&
      typeof override.severityOverrides === 'object' &&
      !Array.isArray(override.severityOverrides)
        ? override.severityOverrides
        : {};
    merged.severityOverrides = { ...baseOverrides, ...overrideOverrides };
  }

  if (base.publishers !== undefined || override.publishers !== undefined) {
    const basePublishers =
      base.publishers === undefined
        ? {}
        : isPlainObject(base.publishers)
          ? base.publishers
          : (() => {
              throw new ConfigError('Invalid "publishers" (expected an object)');
            })();
    const overridePublishers =
      override.publishers === undefined
        ? {}
        : isPlainObject(override.publishers)
          ? override.publishers
          : (() => {
              throw new ConfigError('Invalid "publishers" (expected an object)');
            })();
    merged.publishers = {
      ...basePublishers,
      ...overridePublishers,
      trustedKeys: mergeStringLists(
        basePublishers.trustedKeys,
        overridePublishers.trustedKeys,
      ),
      revokedKeys: mergeStringLists(
        basePublishers.revokedKeys,
        overridePublishers.revokedKeys,
      ),
    };
  }

  return merged;
}

export interface RawConfigTree {
  config: Partial<SkillGuardConfig>;
  sources: string[];
}

export interface ConfigTreeReader {
  /** Return raw configuration text, or undefined when the path does not exist. */
  read(filePath: string): string | undefined;
  /** Return a stable identity used to detect circular `extends` chains. */
  identity(filePath: string): string;
}

const filesystemConfigReader: ConfigTreeReader = {
  read(filePath: string): string | undefined {
    if (!fs.existsSync(filePath)) return undefined;
    if (!fs.statSync(filePath).isFile()) {
      throw new ConfigError(`Config path is not a file: ${filePath}`);
    }
    return fs.readFileSync(filePath, 'utf8');
  },
  identity(filePath: string): string {
    return fs.realpathSync(filePath);
  },
};

/**
 * Load a config inheritance tree through an injected reader. The reader makes
 * the same parser usable for files in the working tree and for blobs read from
 * a Git ref.
 */
export function readConfigTreeFrom(
  filePath: string,
  reader: ConfigTreeReader,
  stack: string[] = [],
): RawConfigTree {
  const source = path.resolve(filePath);
  const raw = reader.read(source);
  if (raw === undefined) {
    throw new ConfigError(`Config file not found: ${source}`);
  }

  const identity = reader.identity(source);
  if (stack.includes(identity)) {
    throw new ConfigError(`Circular config extends chain: ${[...stack, identity].join(' -> ')}`);
  }

  const parsed = parseConfigContent(source, raw);
  const parentPaths = cleanExtends(parsed.extends, source);
  const nextStack = [...stack, identity];
  let merged: Partial<SkillGuardConfig> = {};
  const sources: string[] = [];

  for (const parentPath of parentPaths) {
    const parent = readConfigTreeFrom(
      path.resolve(path.dirname(source), parentPath),
      reader,
      nextStack,
    );
    merged = mergeRawConfigs(merged, parent.config);
    sources.push(...parent.sources);
  }

  const { extends: _extends, ...ownConfig } = parsed;
  merged = mergeRawConfigs(merged, ownConfig);
  sources.push(source);

  return {
    config: merged,
    sources: [...new Set(sources)],
  };
}

function readConfigTree(filePath: string, stack: string[] = []): RawConfigTree {
  return readConfigTreeFrom(filePath, filesystemConfigReader, stack);
}

/** Validate and clamp a raw (possibly partial) config into a safe, usable shape. */
export function normalizeConfig(raw?: Partial<SkillGuardConfig>): SkillGuardConfig {
  const source = raw ?? {};
  const requestedProfile = String(source.profile || '').trim().toLowerCase() as PolicyProfileName;
  const profile = VALID_PROFILES.includes(requestedProfile) ? requestedProfile : DEFAULT_CONFIG.profile!;
  const profileDefaults = POLICY_PROFILES[profile];

  const failOnRaw = source.failOn;
  const failOn: Severity =
    failOnRaw && (VALID_FAIL_ON as string[]).includes(failOnRaw) ? failOnRaw : profileDefaults.failOn;

  const minScoreRaw = source.minScore;
  const minScore =
    typeof minScoreRaw === 'number' && Number.isFinite(minScoreRaw)
      ? Math.min(100, Math.max(0, Math.round(minScoreRaw)))
      : profileDefaults.minScore;

  return {
    profile,
    ignoreRules: cleanStringList(source.ignoreRules),
    failOn,
    minScore,
    allowedDomains: [...new Set(cleanStringList(source.allowedDomains).map((d) => d.toLowerCase().replace(/^\./, '')))],
    publishers: cleanPublisherPolicy(source.publishers),
    ...(typeof source.baseline === 'string' && source.baseline.trim()
      ? { baseline: source.baseline.trim() }
      : {}),
    severityOverrides: cleanSeverityOverrides(source.severityOverrides),
    include: cleanStringList(source.include),
    exclude: cleanStringList(source.exclude),
  };
}

/**
 * Load the effective config and retain the source file that produced it.
 * Explicit config paths fail closed; implicit candidate files retain fallback behavior.
 */
export function loadConfigWithMetadata(
  cwd: string = process.cwd(),
  explicitConfigPath?: string,
): ConfigLoadResult {
  if (explicitConfigPath !== undefined) {
    const source = path.resolve(cwd, explicitConfigPath);
    const tree = readConfigTree(source);
    return {
      config: normalizeConfig(tree.config),
      source,
      sources: tree.sources,
      explicit: true,
    };
  }

  for (const name of CONFIG_FILE_NAMES) {
    const source = path.join(cwd, name);
    if (!fs.existsSync(source)) continue;
    try {
      const tree = readConfigTree(source);
      return {
        config: normalizeConfig(tree.config),
        source,
        sources: tree.sources,
        explicit: false,
      };
    } catch {
      // Malformed implicit config falls through to defaults.
    }
  }

  return {
    config: normalizeConfig(),
    sources: [],
    explicit: false,
  };
}

export function loadConfig(cwd: string = process.cwd(), explicitConfigPath?: string): SkillGuardConfig {
  return loadConfigWithMetadata(cwd, explicitConfigPath).config;
}
