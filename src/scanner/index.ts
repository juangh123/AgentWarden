import * as fs from 'node:fs';
import * as crypto from 'node:crypto';
import { parseSkillMarkdown } from '../parser/skillParser.ts';
import { allRules } from '../rules/index.ts';
import type { ScanResult, Finding, Severity } from '../rules/types.ts';
import { loadConfig, normalizeConfig, type SkillGuardConfig } from '../config/index.ts';

const SEVERITY_WEIGHTS: Record<Severity, number> = {
  critical: 40,
  high: 25,
  medium: 15,
  low: 5,
  info: 0,
};

const SEVERITY_ORDER: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

function evaluateFindings(
  findings: Finding[],
  config: SkillGuardConfig,
  filePath: string,
  parsed: any,
  sha256: string
): ScanResult {
  let totalDeduction = 0;
  for (const finding of findings) {
    totalDeduction += SEVERITY_WEIGHTS[finding.severity] || 0;
  }

  const score = Math.max(0, 100 - totalDeduction);
  const minScore = config.minScore !== undefined ? config.minScore : 60;
  const failOn = config.failOn || 'high';

  const minSeverity = SEVERITY_ORDER[failOn] ?? SEVERITY_ORDER.high;
  const hasFailingSeverity = findings.some((f) => SEVERITY_ORDER[f.severity] >= minSeverity);
  const passed = !hasFailingSeverity && score >= minScore;

  return {
    filePath,
    parsedSkill: parsed,
    findings,
    score,
    passed,
    sha256,
  };
}

/** Scan a skill or MCP configuration directly from a raw string in memory. */
export function scanSkillContent(content: string, virtualPath: string = 'inline.md', customConfig?: SkillGuardConfig): ScanResult {
  const parsed = parseSkillMarkdown(content, virtualPath);
  const config = normalizeConfig(customConfig || loadConfig());

  const normalizedForHash = content.replace(/\r\n/g, '\n');
  const sha256 = crypto.createHash('sha256').update(normalizedForHash, 'utf8').digest('hex');

  const allFindings: Finding[] = [];
  const ignored = new Set(config.ignoreRules || []);

  for (const rule of allRules) {
    if (ignored.has(rule.id)) continue;
    const findings = rule.check(parsed, { allowedDomains: config.allowedDomains });
    allFindings.push(...findings);
  }

  return evaluateFindings(allFindings, config, virtualPath, parsed, sha256);
}

/** Scan a skill or MCP configuration file on disk. */
export function scanSkillFile(filePath: string, customConfig?: SkillGuardConfig): ScanResult {
  const content = fs.readFileSync(filePath, 'utf8');
  return scanSkillContent(content, filePath, customConfig);
}