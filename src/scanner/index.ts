import * as fs from 'node:fs';
import * as path from 'node:path';
import { sha256 } from '../utils/hash.ts';

import { parseSkillMarkdown } from '../parser/skillParser.ts';
import { discoverSkillFiles } from './discovery.ts';
import { allRules } from '../rules/index.ts';
import type { ScanResult, Finding } from '../rules/types.ts';
import { loadConfig, normalizeConfig, type SkillGuardConfig } from '../config/index.ts';
import {
  applyBaseline,
  readBaseline,
  type BaselineSchema,
} from '../baseline/index.ts';
import { calculateScore, passesPolicy } from './scoring.ts';

interface BaselineCacheEntry {
  mtimeMs: number;
  size: number;
  baseline: BaselineSchema;
}

const baselineCache = new Map<string, BaselineCacheEntry>();

/**
 * Read a baseline at most once per unchanged file.
 *
 * `scanSkillContent` used to re-read and re-parse the baseline for every file
 * in a multi-file scan. The cache is keyed on the resolved path and validated
 * against mtime/size, so an edited baseline is still picked up immediately.
 */
function loadBaselineCached(filePath: string, cwd: string): BaselineSchema {
  const resolved = path.resolve(cwd, filePath);
  const cached = baselineCache.get(resolved);
  if (cached) {
    try {
      const stat = fs.statSync(resolved);
      if (stat.mtimeMs === cached.mtimeMs && stat.size === cached.size) return cached.baseline;
    } catch {
      // Fall through so the real read error is reported below.
    }
  }

  const baseline = readBaseline(filePath, cwd);
  try {
    const stat = fs.statSync(resolved);
    baselineCache.set(resolved, { mtimeMs: stat.mtimeMs, size: stat.size, baseline });
  } catch {
    // Caching is best effort; a failed stat must not hide the loaded baseline.
  }
  return baseline;
}

/**
 * Derive a machine-independent fallback skill name from the scanned path.
 *
 * Using the raw path here used to write absolute paths (e.g.
 * `C:\Users\...\SKILL.md`) into `skills.lock`, which made the lockfile
 * unreproducible across machines. The result is a slug: never absolute, never
 * containing path separators, so it is safe to use as a lockfile key.
 */
function fallbackSkillName(filePath: string, cwd: string): string {
  const absolute = path.resolve(cwd, filePath);
  const relative = path.relative(cwd, absolute);
  const withinCwd =
    Boolean(relative) && !relative.startsWith('..') && !path.isAbsolute(relative);
  const candidate = withinCwd ? relative : path.basename(absolute);
  const withoutExtension = candidate.replace(/\.(?:md|markdown|json)$/i, '');
  const slug = withoutExtension
    .replace(/\\/g, '/')
    .replace(/[^a-zA-Z0-9._-]+/g, '-')
    .replace(/^[._-]+|[._-]+$/g, '')
    .slice(0, 80);
  return slug || 'unnamed-skill';
}

/** Collapse duplicate reports of the same rule at the same location. */
function dedupeFindings(findings: Finding[]): Finding[] {
  const seenKeys = new Set<string>();
  const seenLocations = new Set<string>();
  const deduped: Finding[] = [];

  for (const finding of findings) {
    const normalizedSnippet = (finding.snippet || '').replace(/\s+/g, ' ').trim();
    const key = [finding.ruleId, finding.severity, finding.line ?? '', normalizedSnippet].join('|');
    if (seenKeys.has(key)) continue;
    seenKeys.add(key);

    // Rules report at most one hit per line, so a repeated (rule, line) pair is
    // always an artifact of scanning both a synthesized block and the raw file.
    if (finding.line !== undefined) {
      const location = [finding.ruleId, finding.severity, finding.line].join('|');
      if (seenLocations.has(location)) continue;
      seenLocations.add(location);
    }

    deduped.push(finding);
  }

  return deduped;
}

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
  const parsed = parseSkillMarkdown(content, fallbackSkillName(virtualPath, cwd));
  const config = normalizeConfig(customConfig || loadConfig(cwd));

  const normalizedForHash = content.replace(/\r\n/g, '\n');
  const digest = sha256(normalizedForHash);

  const allFindings: Finding[] = [];
  const ignored = new Set(config.ignoreRules || []);

  for (const rule of allRules) {
    if (ignored.has(rule.id)) continue;
    const findings = rule.check(parsed, { allowedDomains: config.allowedDomains });
    const effectiveSeverity = config.severityOverrides?.[rule.id] ?? rule.severity;
    allFindings.push(
      ...findings.map((finding) =>
        finding.severity === effectiveSeverity
          ? finding
          : { ...finding, severity: effectiveSeverity },
      ),
    );
  }

  const result = evaluateFindings(dedupeFindings(allFindings), config, virtualPath, parsed, digest);
  if (!config.baseline) return result;

  return applyBaseline(result, loadBaselineCached(config.baseline, cwd), {
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
  const config = normalizeConfig(customConfig || loadConfig(cwd));
  return discoverSkillFiles(targetPaths, cwd, {
    include: config.include,
    exclude: config.exclude,
  }).map((filePath) => scanSkillFile(filePath, config, cwd));
}
