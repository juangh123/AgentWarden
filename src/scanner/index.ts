import * as fs from 'node:fs';
import * as crypto from 'node:crypto';
import { parseSkillMarkdown } from '../parser/skillParser.ts';
import { discoverSkillFiles } from './discovery.ts';
import { allRules } from '../rules/index.ts';
import type { ScanResult, Finding } from '../rules/types.ts';
import { loadConfig, normalizeConfig, type SkillGuardConfig } from '../config/index.ts';
import { applyBaseline, readBaseline } from '../baseline/index.ts';
import { calculateScore, passesPolicy } from './scoring.ts';

function evaluateFindings(
  findings: Finding[],
  config: SkillGuardConfig,
  filePath: string,
  parsed: any,
  sha256: string
): ScanResult {
  const score = calculateScore(findings);
  const minScore = config.minScore !== undefined ? config.minScore : 60;
  const failOn = config.failOn || 'high';

  return {
    filePath,
    parsedSkill: parsed,
    findings,
    score,
    passed: passesPolicy(findings, failOn, minScore),
    sha256,
  };
}

/** Scan a skill or MCP configuration directly from a raw string in memory. */
export function scanSkillContent(
  content: string,
  virtualPath: string = 'inline.md',
  customConfig?: SkillGuardConfig,
  cwd: string = process.cwd(),
): ScanResult {
  const parsed = parseSkillMarkdown(content, virtualPath);
  const config = normalizeConfig(customConfig || loadConfig(cwd));

  const normalizedForHash = content.replace(/\r\n/g, '\n');
  const sha256 = crypto.createHash('sha256').update(normalizedForHash, 'utf8').digest('hex');

  const allFindings: Finding[] = [];
  const ignored = new Set(config.ignoreRules || []);

  for (const rule of allRules) {
    if (ignored.has(rule.id)) continue;
    const findings = rule.check(parsed, { allowedDomains: config.allowedDomains });
    allFindings.push(...findings);
  }

  const result = evaluateFindings(allFindings, config, virtualPath, parsed, sha256);
  if (!config.baseline) return result;

  return applyBaseline(result, readBaseline(config.baseline, cwd), {
    baselinePath: config.baseline,
    cwd,
    failOn: config.failOn,
    minScore: config.minScore,
  });
}

/** Scan a skill or MCP configuration file on disk. */
export function scanSkillFile(
  filePath: string,
  customConfig?: SkillGuardConfig,
  cwd: string = process.cwd(),
): ScanResult {
  const content = fs.readFileSync(filePath, 'utf8');
  return scanSkillContent(content, filePath, customConfig, cwd);
}

/** Discover and scan all supported skills and MCP configurations under the provided paths. */
export function scanSkillPaths(
  targetPaths: string | string[],
  customConfig?: SkillGuardConfig,
  cwd: string = process.cwd(),
): ScanResult[] {
  return discoverSkillFiles(targetPaths, cwd).map((filePath) => scanSkillFile(filePath, customConfig, cwd));
}
