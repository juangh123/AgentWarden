import type { Finding, Severity } from '../rules/types.ts';

export const SEVERITY_WEIGHTS: Record<Severity, number> = {
  critical: 40,
  high: 25,
  medium: 15,
  low: 5,
  info: 0,
};

export const SEVERITY_ORDER: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export function calculateScore(findings: Finding[]): number {
  const totalDeduction = findings.reduce(
    (total, finding) => total + (SEVERITY_WEIGHTS[finding.severity] || 0),
    0,
  );
  return Math.max(0, 100 - totalDeduction);
}

export function passesPolicy(
  findings: Finding[],
  failOn: Severity = 'high',
  minScore: number = 60,
): boolean {
  const minSeverity = SEVERITY_ORDER[failOn] ?? SEVERITY_ORDER.high;
  const hasFailingSeverity = findings.some((finding) => SEVERITY_ORDER[finding.severity] >= minSeverity);
  return !hasFailingSeverity && calculateScore(findings) >= minScore;
}
