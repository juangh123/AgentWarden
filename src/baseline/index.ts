import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import type { BaselineMetadata, Finding, ScanResult, Severity } from '../rules/types.ts';
import { calculateScore, passesPolicy } from '../scanner/scoring.ts';

export const DEFAULT_BASELINE_NAME = '.agentwarden-baseline.json';
const VALID_SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
const MAX_REVIEW_NOTE_LENGTH = 500;

export interface BaselineEntry {
  fingerprint: string;
  ruleId: string;
  file: string;
  line?: number;
  severity: Severity;
  acceptedAt?: string;
}

export interface BaselineReview {
  reviewedAt: string;
  owner?: string;
  expiresAt?: string;
  note?: string;
}

export type BaselineVersion = 1 | 2;

export interface BaselineSchema {
  baselineVersion: BaselineVersion;
  createdAt: string;
  review?: BaselineReview;
  entries: BaselineEntry[];
}

export interface CreateBaselineOptions {
  owner?: string;
  expiresAt?: string | Date;
  note?: string;
  reviewedAt?: string | Date;
}

export interface ApplyBaselineOptions {
  baselinePath?: string;
  cwd?: string;
  failOn?: Severity;
  minScore?: number;
  now?: string | Date;
}

export interface InspectBaselineOptions {
  cwd?: string;
  now?: string | Date;
}

export interface BaselineEntryStatus extends BaselineEntry {
  matched: boolean;
  ageDays?: number;
}

export interface BaselineInspection {
  baselineVersion: BaselineVersion;
  reviewedAt?: string;
  owner?: string;
  expiresAt?: string;
  expired: boolean;
  daysUntilExpiry?: number;
  entries: BaselineEntryStatus[];
  summary: {
    total: number;
    matched: number;
    unmatched: number;
  };
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

function normalizeTimestamp(value: string | Date, field: string): string {
  const timestamp = value instanceof Date ? value.getTime() : Date.parse(value);
  if (!Number.isFinite(timestamp)) {
    throw new Error(`Invalid baseline review ${field}: expected an ISO date`);
  }
  return new Date(timestamp).toISOString();
}

function cleanReviewText(value: string | undefined, field: string): string | undefined {
  if (value === undefined) return undefined;
  const cleaned = value.replace(/[\u0000-\u001f\u007f]/g, ' ').trim();
  if (!cleaned) return undefined;
  if (cleaned.length > MAX_REVIEW_NOTE_LENGTH) {
    throw new Error(`Invalid baseline review ${field}: maximum length is ${MAX_REVIEW_NOTE_LENGTH}`);
  }
  return cleaned;
}

function createReview(options: CreateBaselineOptions): BaselineReview {
  const owner = cleanReviewText(options.owner, 'owner');
  const note = cleanReviewText(options.note, 'note');
  return {
    reviewedAt: options.reviewedAt
      ? normalizeTimestamp(options.reviewedAt, 'reviewedAt')
      : new Date().toISOString(),
    ...(owner ? { owner } : {}),
    ...(options.expiresAt
      ? { expiresAt: normalizeTimestamp(options.expiresAt, 'expiresAt') }
      : {}),
    ...(note ? { note } : {}),
  };
}

export function createBaseline(
  results: ScanResult[],
  cwd: string = process.cwd(),
  options: CreateBaselineOptions = {},
): BaselineSchema {
  const entries: BaselineEntry[] = [];
  const createdAt = new Date().toISOString();

  for (const result of results) {
    const fingerprints = fingerprintsForResult(result, cwd);
    result.findings.forEach((finding, index) => {
      entries.push({
        fingerprint: fingerprints[index],
        ruleId: finding.ruleId,
        file: toBaselinePath(result.filePath, cwd),
        line: finding.line,
        severity: finding.severity,
        acceptedAt: createdAt,
      });
    });
  }

  return {
    baselineVersion: 2,
    createdAt,
    review: createReview(options),
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
  if (
    (candidate.baselineVersion !== 1 && candidate.baselineVersion !== 2) ||
    !Array.isArray(candidate.entries) ||
    typeof candidate.createdAt !== 'string'
  ) {
    throw new Error(`Invalid baseline at ${baselinePath}: unsupported schema.`);
  }

  if (candidate.baselineVersion === 2) {
    const review = candidate.review;
    if (!review || typeof review !== 'object' || Array.isArray(review) || typeof review.reviewedAt !== 'string') {
      throw new Error(`Invalid baseline at ${baselinePath}: review metadata is malformed.`);
    }
    try {
      normalizeTimestamp(review.reviewedAt, 'reviewedAt');
      if (review.expiresAt !== undefined) normalizeTimestamp(review.expiresAt, 'expiresAt');
      cleanReviewText(review.owner, 'owner');
      cleanReviewText(review.note, 'note');
    } catch (error) {
      throw new Error(`Invalid baseline at ${baselinePath}: ${error instanceof Error ? error.message : String(error)}`);
    }
    if (
      (review.owner !== undefined && typeof review.owner !== 'string') ||
      (review.note !== undefined && typeof review.note !== 'string')
    ) {
      throw new Error(`Invalid baseline at ${baselinePath}: review metadata is malformed.`);
    }
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
      !VALID_SEVERITIES.includes(entry.severity) ||
      (entry.acceptedAt !== undefined && typeof entry.acceptedAt !== 'string')
    ) {
      throw new Error(`Invalid baseline at ${baselinePath}: entry ${index} is malformed.`);
    }
    if (entry.acceptedAt !== undefined) {
      try {
        normalizeTimestamp(entry.acceptedAt, `entries[${index}].acceptedAt`);
      } catch (error) {
        throw new Error(
          `Invalid baseline at ${baselinePath}: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
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
    baselineVersion: baseline.baselineVersion,
    createdAt: baseline.createdAt,
    ...(baseline.review ? { review: { ...baseline.review } } : {}),
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
  const now = options.now ? normalizeTimestamp(options.now, 'now') : new Date().toISOString();
  const expiresAt = baseline.review?.expiresAt;
  const expired = expiresAt !== undefined && Date.parse(now) >= Date.parse(expiresAt);

  if (expired) {
    const metadata: BaselineMetadata = {
      path: baselinePath,
      suppressed: 0,
      unmatched: baseline.entries.length,
      expired: true,
      expiresAt,
      ...(baseline.review?.owner ? { owner: baseline.review.owner } : {}),
    };
    return {
      ...result,
      findings: result.findings,
      suppressedFindings: [],
      baseline: metadata,
      score: calculateScore(result.findings),
      passed: passesPolicy(result.findings, options.failOn, options.minScore),
    };
  }

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
    expired: false,
    ...(expiresAt ? { expiresAt } : {}),
    ...(baseline.review?.owner ? { owner: baseline.review.owner } : {}),
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

/** Inspect baseline freshness and per-entry matching against one or more scan results. */
export function inspectBaseline(
  results: ScanResult[],
  baseline: BaselineSchema,
  options: InspectBaselineOptions = {},
): BaselineInspection {
  const cwd = options.cwd ?? process.cwd();
  const now = options.now ? normalizeTimestamp(options.now, 'now') : new Date().toISOString();
  const nowMs = Date.parse(now);
  const expiresAt = baseline.review?.expiresAt;
  const expired = expiresAt !== undefined && nowMs >= Date.parse(expiresAt);
  const baselineFingerprints = new Set(baseline.entries.map((entry) => entry.fingerprint));
  const matchedFingerprints = new Set<string>();

  for (const result of results) {
    for (const fingerprint of fingerprintsForResult(result, cwd)) {
      if (baselineFingerprints.has(fingerprint)) {
        matchedFingerprints.add(fingerprint);
      }
    }
  }

  const entries: BaselineEntryStatus[] = baseline.entries
    .map((entry) => {
      const acceptedMs = entry.acceptedAt ? Date.parse(entry.acceptedAt) : undefined;
      return {
        ...entry,
        matched: matchedFingerprints.has(entry.fingerprint),
        ...(acceptedMs !== undefined
          ? { ageDays: Math.max(0, Math.floor((nowMs - acceptedMs) / (24 * 60 * 60 * 1000))) }
          : {}),
      };
    })
    .sort((a, b) => {
      if (a.matched !== b.matched) return a.matched ? 1 : -1;
      return (
        a.file.localeCompare(b.file) ||
        a.ruleId.localeCompare(b.ruleId) ||
        (a.line ?? 0) - (b.line ?? 0) ||
        a.fingerprint.localeCompare(b.fingerprint)
      );
    });

  return {
    baselineVersion: baseline.baselineVersion,
    ...(baseline.review?.reviewedAt ? { reviewedAt: baseline.review.reviewedAt } : {}),
    ...(baseline.review?.owner ? { owner: baseline.review.owner } : {}),
    ...(expiresAt ? { expiresAt } : {}),
    expired,
    ...(expiresAt
      ? { daysUntilExpiry: Math.ceil((Date.parse(expiresAt) - nowMs) / (24 * 60 * 60 * 1000)) }
      : {}),
    entries,
    summary: {
      total: entries.length,
      matched: entries.filter((entry) => entry.matched).length,
      unmatched: entries.filter((entry) => !entry.matched).length,
    },
  };
}
