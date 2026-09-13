import * as crypto from 'node:crypto';
import * as path from 'node:path';
import type { Finding } from './rules/types.ts';

export function normalizeFindingPath(filePath: string, cwd: string = process.cwd()): string {
  const relative = path.isAbsolute(filePath) ? path.relative(cwd, filePath) : filePath;
  return (relative && !relative.startsWith('..') ? relative : filePath).replace(/\\/g, '/');
}

function findingFingerprintMaterial(
  filePath: string,
  finding: Finding,
  cwd: string,
): string {
  const normalizedSnippet = (finding.snippet || '').replace(/\s+/g, ' ').trim();
  return [
    finding.ruleId,
    finding.category,
    finding.severity,
    normalizeFindingPath(filePath, cwd),
    normalizedSnippet,
  ].join('\n');
}

function fingerprintWithOccurrence(material: string, occurrence: number): string {
  return crypto
    .createHash('sha256')
    .update(`${material}\n${occurrence}`, 'utf8')
    .digest('hex');
}

/**
 * Build line-stable, per-file finding fingerprints.
 *
 * Duplicate findings with the same rule, severity, path, and snippet receive
 * deterministic occurrence suffixes so each result remains independently
 * addressable while surviving line-number changes.
 */
export function createFindingFingerprints(
  filePath: string,
  findings: Finding[],
  cwd: string = process.cwd(),
): string[] {
  const occurrences = new Map<string, number>();
  return findings.map((finding) => {
    const material = findingFingerprintMaterial(filePath, finding, cwd);
    const occurrence = occurrences.get(material) || 0;
    occurrences.set(material, occurrence + 1);
    return fingerprintWithOccurrence(material, occurrence);
  });
}
