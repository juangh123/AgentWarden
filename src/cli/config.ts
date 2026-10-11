
import {
  ConfigError,
  loadConfigWithMetadata,
  normalizeConfig,
  POLICY_PROFILES,
  type PolicyProfileName,
  type SkillGuardConfig,
} from '../config/index.ts';
import type { Severity } from '../rules/types.ts';
import { type ParsedArgs, usageError, VALID_FAIL_ON } from './args.ts';

export interface BuiltConfig {
  config: SkillGuardConfig;
  source?: string | undefined;
  sources: string[];
  explicit: boolean;
}

export interface PolicySide {
  label: string;
  details: BuiltConfig;
}

export function buildConfigDetails(options: ParsedArgs['options'], ignoreBaseline = false): BuiltConfig {
  const configPath = options.config !== undefined ? String(options.config) : undefined;
  let loaded: ReturnType<typeof loadConfigWithMetadata>;
  try {
    loaded = loadConfigWithMetadata(process.cwd(), configPath);
  } catch (error) {
    if (error instanceof ConfigError) usageError(error.message);
    throw error;
  }

  const base = loaded.config;
  const override: Partial<SkillGuardConfig> = {};

  if (options.profile !== undefined) {
    const value = String(options.profile).trim().toLowerCase() as PolicyProfileName;
    if (!Object.hasOwn(POLICY_PROFILES, value)) {
      usageError(`Invalid --profile "${String(options.profile)}" (expected legacy|balanced|strict)`);
    }
    override.profile = value;
    override.failOn = POLICY_PROFILES[value].failOn;
    override.minScore = POLICY_PROFILES[value].minScore;
  }
  if (options['fail-on'] !== undefined) {
    const value = String(options['fail-on']).toLowerCase() as Severity;
    if (!VALID_FAIL_ON.includes(value)) usageError(`Invalid --fail-on "${String(options['fail-on'])}"`);
    override.failOn = value;
  }
  if (options['min-score'] !== undefined) {
    const value = Number(options['min-score']);
    if (!Number.isFinite(value)) usageError(`Invalid --min-score "${String(options['min-score'])}" (expected 0-100)`);
    override.minScore = value;
  }

  const extraIgnores = (options.ignoreRule as string[] | undefined) ?? [];
  const extraIncludes = (options.include as string[] | undefined) ?? [];
  const extraExcludes = (options.exclude as string[] | undefined) ?? [];
  if (options.baseline !== undefined) override.baseline = String(options.baseline);

  const severityOverrides: Record<string, Severity> = { ...(base.severityOverrides ?? {}) };
  for (const specification of (options.severityOverride as string[] | undefined) ?? []) {
    const separator = specification.indexOf('=');
    if (separator <= 0) {
      usageError(`Invalid --severity-override "${specification}" (expected RULE_ID=severity)`);
    }
    const ruleId = specification.slice(0, separator).trim().toUpperCase();
    const severity = specification.slice(separator + 1).trim().toLowerCase() as Severity;
    if (!ruleId || !VALID_FAIL_ON.includes(severity)) {
      usageError(`Invalid --severity-override "${specification}" (expected RULE_ID=critical|high|medium|low|info)`);
    }
    severityOverrides[ruleId] = severity;
  }
  override.severityOverrides = severityOverrides;

  const merged: Partial<SkillGuardConfig> = {
    ...base,
    ...override,
    ignoreRules: [...(base.ignoreRules ?? []), ...extraIgnores],
    include: [...(base.include ?? []), ...extraIncludes],
    exclude: [...(base.exclude ?? []), ...extraExcludes],
  };
  if (ignoreBaseline) delete merged.baseline;

  return {
    config: normalizeConfig(merged),
    source: loaded.source,
    sources: loaded.sources,
    explicit: loaded.explicit,
  };
}

export function buildConfig(options: ParsedArgs['options'], ignoreBaseline = false): SkillGuardConfig {
  return buildConfigDetails(options, ignoreBaseline).config;
}

export function resolvePolicySide(input: string, options: ParsedArgs['options']): PolicySide {
  const normalizedInput = input.trim();
  const profile = normalizedInput.toLowerCase() as PolicyProfileName;
  if (Object.hasOwn(POLICY_PROFILES, profile)) {
    return {
      label: profile,
      details: {
        config: normalizeConfig({ profile }),
        sources: [],
        explicit: false,
      },
    };
  }

  if (normalizedInput.toLowerCase() === 'current') {
    return {
      label: 'current',
      details: buildConfigDetails(options),
    };
  }

  let loaded: ReturnType<typeof loadConfigWithMetadata>;
  try {
    loaded = loadConfigWithMetadata(process.cwd(), normalizedInput);
  } catch (error) {
    if (error instanceof ConfigError) usageError(error.message);
    throw error;
  }

  return {
    label: normalizedInput,
    details: {
      config: loaded.config,
      source: loaded.source,
      sources: loaded.sources,
      explicit: loaded.explicit,
    },
  };
}

