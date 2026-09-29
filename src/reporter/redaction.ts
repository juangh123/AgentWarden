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
  /(?:api[_-]?key|access[_-]?key|secret|token|password|passwd|private[_-]?key|authorization|credential|signature|sig|x-amz-signature|x-amz-credential|sharedaccesssignature)/i;

const SAFE_SIGNATURE_METADATA_SUFFIX =
  /(?:sha256|hash|algorithm|verified|source|url|path|count|present)$/i;

const URL_PATTERN = /\bhttps?:\/\/[^\s<>"'`]+/gi;

function isPlaceholder(value: string): boolean {
  const normalized = value.trim();
  return (
    normalized === '' ||
    normalized === '[REDACTED]' ||
    /^(?:\$\{?[\w.]+\}?|process\.env\.|env\.|secrets\.|vars\.|<[^>]+>|\{\{[^}]+\}\})/.test(normalized) ||
    /^(?:example|placeholder|changeme|replace[_-]?me|your[_-]?|xxx+)/i.test(normalized)
  );
}

function redactUrlQuery(match: string): string {
  let candidate = match;
  let suffix = '';
  while (candidate && /[),.;\]}]$/.test(candidate)) {
    suffix = candidate.slice(-1) + suffix;
    candidate = candidate.slice(0, -1);
  }

  try {
    const url = new URL(candidate);
    let changed = false;
    if (url.username || url.password) {
      url.username = '';
      url.password = '';
      changed = true;
    }
    for (const key of [...url.searchParams.keys()]) {
      const values = url.searchParams.getAll(key);
      if (
        SECRET_KEY_NAME.test(key) &&
        values.some((value) => value.trim() && !isPlaceholder(value))
      ) {
        url.searchParams.set(key, '[REDACTED]');
        changed = true;
      }
    }
    return changed ? `${url.toString()}${suffix}` : match;
  } catch {
    return match;
  }
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
    .replace(/(https?:\/\/[^/\s:@]+:)([^@\s/]+)(@)/gi, '$1[REDACTED]$3')
    .replace(URL_PATTERN, redactUrlQuery)
    .replace(
      /(^|[\s?&#;])([^=&#\s<>"']+)=([^&#\s<>"']*)/gm,
      (match, separator: string, key: string, value: string) =>
        SECRET_KEY_NAME.test(key) && value.trim() && !isPlaceholder(value)
          ? `${separator}${key}=[REDACTED]`
          : match,
    );

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

function isSensitiveObjectKey(key: string): boolean {
  if (!SECRET_KEY_NAME.test(key)) return false;
  if (
    /^(?:signature|sig|x-amz-signature|x-amz-credential|sharedaccesssignature)/i.test(
      key,
    ) &&
    SAFE_SIGNATURE_METADATA_SUFFIX.test(key)
  ) {
    return false;
  }
  return true;
}

function redactValue(value: unknown): unknown {
  if (typeof value === 'string') return redactText(value);
  if (Array.isArray(value)) return value.map(redactValue);
  if (!value || typeof value !== 'object') return value;

  const redacted: Record<string, unknown> = {};
  for (const [key, child] of Object.entries(value)) {
    if (
      isSensitiveObjectKey(key) &&
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

/** Redact arbitrary structured report metadata, including nested URL strings. */
export function redactReportValue<T>(value: T): T {
  return redactValue(value) as T;
}
