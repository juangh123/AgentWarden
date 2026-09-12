import * as fs from 'node:fs';
import * as path from 'node:path';
import type { Severity } from '../rules/types.ts';

export interface SkillGuardConfig {
  profile?: PolicyProfileName;
  ignoreRules?: string[];
  failOn?: Severity;
  minScore?: number;
  allowedDomains?: string[];
  baseline?: string;
  severityOverrides?: Record<string, Severity>;
  include?: string[];
  exclude?: string[];
}

export type AgentWardenConfig = SkillGuardConfig;

export interface ConfigLoadResult {
  config: SkillGuardConfig;
  source?: string;
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
  severityOverrides: {},
  include: [],
  exclude: [],
};

const VALID_FAIL_ON: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
const VALID_PROFILES: PolicyProfileName[] = ['legacy', 'balanced', 'strict'];
const CONFIG_FILE_NAMES = [
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

function parseConfigFile(filePath: string): Partial<SkillGuardConfig> {
  const raw = fs.readFileSync(filePath, 'utf8');
  const parsed = JSON.parse(raw) as unknown;
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('config root must be a JSON object');
  }
  return parsed as Partial<SkillGuardConfig>;
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
    let stat: fs.Stats;
    try {
      stat = fs.statSync(source);
    } catch {
      throw new ConfigError(`Config file not found: ${source}`);
    }
    if (!stat.isFile()) {
      throw new ConfigError(`Config path is not a file: ${source}`);
    }
    try {
      return {
        config: normalizeConfig(parseConfigFile(source)),
        source,
        explicit: true,
      };
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      throw new ConfigError(`Invalid config file "${source}": ${detail}`);
    }
  }

  for (const name of CONFIG_FILE_NAMES) {
    const source = path.join(cwd, name);
    if (!fs.existsSync(source)) continue;
    try {
      return {
        config: normalizeConfig(parseConfigFile(source)),
        source,
        explicit: false,
      };
    } catch {
      // Malformed implicit config falls through to defaults.
    }
  }

  return {
    config: normalizeConfig(),
    explicit: false,
  };
}

export function loadConfig(cwd: string = process.cwd(), explicitConfigPath?: string): SkillGuardConfig {
  return loadConfigWithMetadata(cwd, explicitConfigPath).config;
}
