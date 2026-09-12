import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import type { BaselineMetadata, Finding, ScanResult, Severity } from '../rules/types.ts';
import { calculateScore, passesPolicy } from '../scanner/scoring.ts';

export const DEFAULT_BASELINE_NAME = '.agentwarden-baseline.json';
const VALID_SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

export interface BaselineEntry {
  fingerprint: string;
  ruleId: string;
  file: string;
  line?: number;
  severity: Severity;
}

export interface BaselineSchema {
  baselineVersion: 1;
  createdAt: string;
  entries: BaselineEntry[];
}

export interface ApplyBaselineOptions {
  baselinePath?: string;
  cwd?: string;
  failOn?: Severity;
  minScore?: number;
}

function toBaselinePath(filePath: string, cwd: string): string {
  const relative = path.isAbsolute(filePath) ? path.relative(cwd, filePath) : filePath;
  return (relative && !relative.startsWith('..') ? relative : filePath).replace(/\\/g, '/');
}

function baseFingerprint(filePath: string, finding: Finding, cwd: string): string {
  const normalizedSnippet = (finding.snippet || '').replace(/\s+/g, ' ').trim();
  return [
    finding.ruleId,
    finding.category,
    finding.severity,
    toBaselinePath(filePath, cwd),
    normalizedSnippet,
  ].join('\n');
}

function fingerprintWithOccurrence(material: string, occurrence: number): string {
  return crypto.createHash('sha256').update(`${material}\n${occurrence}`, 'utf8').digest('hex');
}

function fingerprintsForResult(result: ScanResult, cwd: string): string[] {
  const occurrences = new Map<string, number>();
  return result.findings.map((finding) => {
    const material = baseFingerprint(result.filePath, finding, cwd);
    const occurrence = occurrences.get(material) || 0;
    occurrences.set(material, occurrence + 1);
    return fingerprintWithOccurrence(material, occurrence);
  });
}

export function createBaseline(results: ScanResult[], cwd: string = process.cwd()): BaselineSchema {
  const entries: BaselineEntry[] = [];

  for (const result of results) {
    const fingerprints = fingerprintsForResult(result, cwd);
    result.findings.forEach((finding, index) => {
      entries.push({
        fingerprint: fingerprints[index],
        ruleId: finding.ruleId,
        file: toBaselinePath(result.filePath, cwd),
        line: finding.line,
        severity: finding.severity,
      });
    });
  }

  return {
    baselineVersion: 1,
    createdAt: new Date().toISOString(),
    entries: entries.sort((a, b) => a.fingerprint.localeCompare(b.fingerprint)),
  };
}

function parseBaseline(raw: string, baselinePath: string): BaselineSchema {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new Error(`Invalid baseline JSON at ${baselinePath}: ${err instanceof Error ? err.message : String(err)}`);
  }

  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error(`Invalid baseline at ${baselinePath}: expected a top-level object.`);
  }

  const candidate = parsed as Partial<BaselineSchema>;
  if (candidate.baselineVersion !== 1 || !Array.isArray(candidate.entries) || typeof candidate.createdAt !== 'string') {
    throw new Error(`Invalid baseline at ${baselinePath}: unsupported schema.`);
  }

  for (const [index, entry] of candidate.entries.entries()) {
    if (
      !entry ||
      typeof entry !== 'object' ||
      typeof entry.fingerprint !== 'string' ||
      !/^[a-f0-9]{64}$/i.test(entry.fingerprint) ||
      typeof entry.ruleId !== 'string' ||
      typeof entry.file !== 'string' ||
      typeof entry.severity !== 'string' ||
      !VALID_SEVERITIES.includes(entry.severity)
    ) {
      throw new Error(`Invalid baseline at ${baselinePath}: entry ${index} is malformed.`);
    }
  }

  return candidate as BaselineSchema;
}

export function readBaseline(filePath: string, cwd: string = process.cwd()): BaselineSchema {
  const resolvedPath = path.resolve(cwd, filePath);
  if (!fs.existsSync(resolvedPath)) {
    throw new Error(`Baseline file not found at ${resolvedPath}`);
  }
  return parseBaseline(fs.readFileSync(resolvedPath, 'utf8'), resolvedPath);
}

export function writeBaseline(
  baseline: BaselineSchema,
  filePath: string = DEFAULT_BASELINE_NAME,
  cwd: string = process.cwd(),
): string {
  const resolvedPath = path.resolve(cwd, filePath);
  const sorted: BaselineSchema = {
    baselineVersion: 1,
    createdAt: baseline.createdAt,
    entries: [...baseline.entries].sort((a, b) => a.fingerprint.localeCompare(b.fingerprint)),
  };
  fs.writeFileSync(resolvedPath, JSON.stringify(sorted, null, 2) + '\n', 'utf8');
  return resolvedPath;
}

export function applyBaseline(
  result: ScanResult,
  baseline: BaselineSchema,
  options: ApplyBaselineOptions = {},
): ScanResult {
  const baselinePath = options.baselinePath ?? DEFAULT_BASELINE_NAME;
  const cwd = options.cwd ?? process.cwd();
  const fingerprints = new Set(baseline.entries.map((entry) => entry.fingerprint));
  const currentFingerprints = fingerprintsForResult(result, cwd);
  const suppressedFindings: Finding[] = [];
  const activeFindings: Finding[] = [];
  const matched = new Set<string>();

  result.findings.forEach((finding, index) => {
    const fingerprint = currentFingerprints[index];
    if (fingerprints.has(fingerprint)) {
      suppressedFindings.push(finding);
      matched.add(fingerprint);
    } else {
      activeFindings.push(finding);
    }
  });

  const metadata: BaselineMetadata = {
    path: baselinePath,
    suppressed: suppressedFindings.length,
    unmatched: baseline.entries.length - matched.size,
  };

  return {
    ...result,
    findings: activeFindings,
    suppressedFindings,
    baseline: metadata,
    score: calculateScore(activeFindings),
    passed: passesPolicy(activeFindings, options.failOn, options.minScore),
  };
}
