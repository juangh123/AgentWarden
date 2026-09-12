import type { Finding, ScanResult } from '../rules/types.ts';

export interface ReportOptions {
  /** Redact credentials, secret values, and raw file content from reports. Defaults to true. */
  redact?: boolean;
}

const SECRET_VALUE_PATTERNS: RegExp[] = [
  /\bAKIA[0-9A-Z]{16}\b/g,
  /\b(ghp|gho|ghs|github_pat)_[0-9A-Za-z_]{20,}\b/g,
  /\bsk(-proj)?-[0-9A-Za-z_-]{20,}\b/g,
  /\bsk_live_[0-9a-zA-Z]{20,}\b/g,
  /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/g,
  /\bAIza[0-9A-Za-z_-]{35}\b/g,
  /\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\b/g,
  /\b(sqat|sq0csp|sq0idb)_[0-9A-Za-z_-]{20,}\b/g,
];

const PRIVATE_KEY_BLOCK =
  /-{5}BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-{5}[\s\S]*?-{5}END (?:RSA |EC |OPENSSH |DSA |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-{5}/gi;

const SECRET_KEY_NAME =
  /(?:api[_-]?key|access[_-]?key|secret|token|password|passwd|private[_-]?key|authorization|credential)/i;

function isPlaceholder(value: string): boolean {
  const normalized = value.trim();
  return (
    normalized === '' ||
    normalized === '[REDACTED]' ||
    /^(?:\$\{?[\w.]+\}?|process\.env\.|env\.|secrets\.|vars\.|<[^>]+>|\{\{[^}]+\}\})/.test(normalized) ||
    /^(?:example|placeholder|changeme|replace[_-]?me|your[_-]?|xxx+)/i.test(normalized)
  );
}

/** Redact common credential formats and sensitive key/value assignments from report text. */
export function redactText(text: string): string {
  if (!text) return text;
  let redacted = text
    .replace(PRIVATE_KEY_BLOCK, '[REDACTED PRIVATE KEY]')
    .replace(/-{5}BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-{5}/gi, '[REDACTED PRIVATE KEY]');

  for (const pattern of SECRET_VALUE_PATTERNS) {
    redacted = redacted.replace(pattern, '[REDACTED]');
  }

  redacted = redacted
    .replace(
      /\b([A-Z][A-Z0-9_]*(?:API_KEY|ACCESS_KEY|TOKEN|SECRET|PASSWORD|AUTH)[A-Z0-9_]*)(\s*=\s*)(["']?)([^"'\s]+)\3/g,
      (match, name: string, separator: string, quote: string, value: string) =>
        isPlaceholder(value) ? match : `${name}${separator}${quote}[REDACTED]${quote}`,
    )
    .replace(
      /("(?:api[_-]?key|access[_-]?key|secret|token|password|passwd|private[_-]?key|authorization|credential)"\s*:\s*")([^"]+)(")/gi,
      (match, prefix: string, value: string, suffix: string) =>
        isPlaceholder(value) ? match : `${prefix}[REDACTED]${suffix}`,
    )
    .replace(
      /(\bAuthorization\s*:\s*)(?:Bearer|Basic|Token)\s+[^\s]+/gi,
      '$1[REDACTED]',
    )
    .replace(
      /\b((?:api[_-]?key|access[_-]?key|secret|token|password|passwd|private[_-]?key|authorization|credential)\s*:\s*)([^\s#]+)/gi,
      (match, prefix: string, value: string) => (isPlaceholder(value) ? match : `${prefix}[REDACTED]`),
    )
    .replace(
      /(-H\s+["']?Authorization:\s*(?:Bearer|Basic|Token)\s+)([^"'\s]+)/gi,
      '$1[REDACTED]',
    )
    .replace(/\b(Bearer|Basic)\s+[A-Za-z0-9\-._~+/]+=*/gi, '$1 [REDACTED]')
    .replace(/(https?:\/\/[^/\s:@]+:)([^@\s/]+)(@)/gi, '$1[REDACTED]$3');

  return redacted;
}

function redactFinding(finding: Finding): Finding {
  return {
    ...finding,
    description: redactText(finding.description),
    snippet: finding.snippet ? redactText(finding.snippet) : finding.snippet,
    suggestion: finding.suggestion ? redactText(finding.suggestion) : finding.suggestion,
  };
}

function redactValue(value: unknown): unknown {
  if (typeof value === 'string') return redactText(value);
  if (Array.isArray(value)) return value.map(redactValue);
  if (!value || typeof value !== 'object') return value;

  const redacted: Record<string, unknown> = {};
  for (const [key, child] of Object.entries(value)) {
    if (
      SECRET_KEY_NAME.test(key) &&
      typeof child === 'string' &&
      child.trim() &&
      !isPlaceholder(child)
    ) {
      redacted[key] = '[REDACTED]';
    } else {
      redacted[key] = redactValue(child);
    }
  }
  return redacted;
}

/** Convert a scan result into a report-safe projection. */
export function toReportScanResult(result: ScanResult, options: ReportOptions = {}): ScanResult {
  if (options.redact === false) return result;

  const parsedSkill = redactValue({
    ...result.parsedSkill,
    promptText: '[REDACTED]',
    rawContent: '[REDACTED]',
  }) as ScanResult['parsedSkill'];

  return {
    ...result,
    parsedSkill,
    findings: result.findings.map(redactFinding),
    suppressedFindings: result.suppressedFindings?.map(redactFinding),
  };
}

export function toReportScanResults(results: ScanResult[], options: ReportOptions = {}): ScanResult[] {
  return results.map((result) => toReportScanResult(result, options));
}
