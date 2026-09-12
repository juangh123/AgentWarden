import * as fs from 'node:fs';
import * as path from 'node:path';
import type { Severity } from '../rules/types.ts';

export interface SkillGuardConfig {
  ignoreRules?: string[];
  failOn?: Severity;
  minScore?: number;
  allowedDomains?: string[];
  baseline?: string;
  severityOverrides?: Record<string, Severity>;
}

export type AgentWardenConfig = SkillGuardConfig;

export const DEFAULT_CONFIG: Readonly<SkillGuardConfig> = {
  ignoreRules: [],
  failOn: 'high',
  minScore: 60,
  allowedDomains: [],
  severityOverrides: {},
};

const VALID_FAIL_ON: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

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

/** Validate and clamp a raw (possibly partial) config into a safe, usable shape. */
export function normalizeConfig(raw?: Partial<SkillGuardConfig>): SkillGuardConfig {
  const source = raw ?? {};

  const failOnRaw = source.failOn;
  const failOn: Severity =
    failOnRaw && (VALID_FAIL_ON as string[]).includes(failOnRaw) ? failOnRaw : DEFAULT_CONFIG.failOn!;

  const minScoreRaw = source.minScore;
  const minScore =
    typeof minScoreRaw === 'number' && Number.isFinite(minScoreRaw)
      ? Math.min(100, Math.max(0, Math.round(minScoreRaw)))
      : DEFAULT_CONFIG.minScore!;

  return {
    ignoreRules: cleanStringList(source.ignoreRules),
    failOn,
    minScore,
    allowedDomains: [...new Set(cleanStringList(source.allowedDomains).map((d) => d.toLowerCase().replace(/^\./, '')))],
    ...(typeof source.baseline === 'string' && source.baseline.trim()
      ? { baseline: source.baseline.trim() }
      : {}),
    severityOverrides: cleanSeverityOverrides(source.severityOverrides),
  };
}

export function loadConfig(cwd: string = process.cwd()): SkillGuardConfig {
  const candidates = [
    path.join(cwd, '.wardenrc.json'),
    path.join(cwd, '.wardenrc'),
    path.join(cwd, 'warden.config.json'),
    path.join(cwd, 'agentwarden.config.json'),
    path.join(cwd, '.skillguardrc.json'),
    path.join(cwd, '.skillguardrc'),
    path.join(cwd, 'skillguard.config.json'),
  ];

  for (const file of candidates) {
    if (fs.existsSync(file)) {
      try {
        const raw = fs.readFileSync(file, 'utf8');
        const parsed = JSON.parse(raw) as Partial<SkillGuardConfig>;
        return normalizeConfig({ ...DEFAULT_CONFIG, ...parsed });
      } catch {
        // Malformed config falls back to defaults
      }
    }
  }

  return normalizeConfig();
}
