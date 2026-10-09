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

/**
 * Read a list-valued config field. A single string is accepted as a
 * one-element list, but any other shape is rejected so that a typo can never
 * silently drop policy input.
 */
function requireStringList(value: unknown, field: string): string[] {
  if (value === undefined) return [];
  const entries = typeof value === 'string' ? [value] : value;
  if (!Array.isArray(entries)) {
    throw new ConfigError(`Invalid "${field}" (expected a string or an array of strings)`);
  }

  const cleaned: string[] = [];
  for (const entry of entries) {
    if (typeof entry !== 'string') {
      throw new ConfigError(`Invalid "${field}" (expected every entry to be a string)`);
    }
    const trimmed = entry.trim();
    if (trimmed && !cleaned.includes(trimmed)) cleaned.push(trimmed);
  }
  return cleaned;
}

function resolveProfile(value: unknown): PolicyProfileName {
  if (value === undefined) return DEFAULT_CONFIG.profile!;
  if (typeof value !== 'string') {
    throw new ConfigError(`Invalid "profile" (expected one of ${VALID_PROFILES.join('|')})`);
  }
  const requested = value.trim().toLowerCase();
  if (!requested) return DEFAULT_CONFIG.profile!;
  if (!VALID_PROFILES.includes(requested as PolicyProfileName)) {
    throw new ConfigError(
      `Invalid "profile" "${value}" (expected one of ${VALID_PROFILES.join('|')})`,
    );
  }
  return requested as PolicyProfileName;
}

function resolveFailOn(value: unknown, fallback: Severity): Severity {
  if (value === undefined) return fallback;
  if (typeof value !== 'string') {
    throw new ConfigError(`Invalid "failOn" (expected one of ${VALID_FAIL_ON.join('|')})`);
  }
  const severity = value.trim().toLowerCase();
  if (!severity) return fallback;
  if (!VALID_FAIL_ON.includes(severity as Severity)) {
    throw new ConfigError(
      `Invalid "failOn" "${value}" (expected one of ${VALID_FAIL_ON.join('|')})`,
    );
  }
  return severity as Severity;
}

function resolveMinScore(value: unknown, fallback: number): number {
  if (value === undefined) return fallback;
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    throw new ConfigError('Invalid "minScore" (expected a number between 0 and 100)');
  }
  return Math.min(100, Math.max(0, Math.round(value)));
}

function resolveBaseline(value: unknown): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== 'string') {
    throw new ConfigError('Invalid "baseline" (expected a file path string)');
  }
  const trimmed = value.trim();
  return trimmed ? trimmed : undefined;
}

function requireSeverityOverrides(value: unknown): Record<string, Severity> {
  if (value === undefined) return {};
  if (!isPlainObject(value)) {
    throw new ConfigError(
      'Invalid "severityOverrides" (expected an object mapping rule IDs to severities)',
    );
  }

  const overrides: Record<string, Severity> = {};
  for (const [rawRuleId, rawSeverity] of Object.entries(value)) {
    const label = `severityOverrides.${rawRuleId}`;
    const ruleId = rawRuleId.trim().toUpperCase();
    if (!ruleId) {
      throw new ConfigError(`Invalid "${label}" (expected a non-empty rule ID)`);
    }
    if (typeof rawSeverity !== 'string') {
      throw new ConfigError(
        `Invalid "${label}" (expected one of ${VALID_FAIL_ON.join('|')})`,
      );
    }
    const severity = rawSeverity.trim().toLowerCase();
    if (!VALID_FAIL_ON.includes(severity as Severity)) {
      throw new ConfigError(
        `Invalid "${label}" "${rawSeverity}" (expected one of ${VALID_FAIL_ON.join('|')})`,
      );
    }
    overrides[ruleId] = severity as Severity;
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

/**
 * Validate and clamp a raw (possibly partial) config into a safe, usable shape.
 *
 * Fails closed: an unrecognised profile, severity, or a wrongly typed field
 * raises a ConfigError instead of silently falling back to a looser default,
 * so a typo can never quietly weaken the security gate.
 */
export function normalizeConfig(raw?: Partial<SkillGuardConfig>): SkillGuardConfig {
  const source = raw ?? {};
  const profile = resolveProfile(source.profile);
  const profileDefaults = POLICY_PROFILES[profile];
  const baseline = resolveBaseline(source.baseline);

  return {
    profile,
    ignoreRules: requireStringList(source.ignoreRules, 'ignoreRules'),
    failOn: resolveFailOn(source.failOn, profileDefaults.failOn),
    minScore: resolveMinScore(source.minScore, profileDefaults.minScore),
    allowedDomains: [
      ...new Set(
        requireStringList(source.allowedDomains, 'allowedDomains').map((domain) =>
          domain.toLowerCase().replace(/^\./, ''),
        ),
      ),
    ],
    publishers: cleanPublisherPolicy(source.publishers),
    ...(baseline ? { baseline } : {}),
    severityOverrides: requireSeverityOverrides(source.severityOverrides),
    include: requireStringList(source.include, 'include'),
    exclude: requireStringList(source.exclude, 'exclude'),
  };
}

/**
 * Load the effective config and retain the source file that produced it.
 * Any discovered config file is authoritative and fails closed when invalid.
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
    const tree = readConfigTree(source);
    return {
      config: normalizeConfig(tree.config),
      source,
      sources: tree.sources,
      explicit: false,
    };
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
