import type { Finding, FindingCategory, ParsedSkill, Severity } from './types.ts';

/** Split a string into lines, tolerating both LF and CRLF line endings. */
export function splitLines(text: string): string[] {
  return text.split(/\r?\n/);
}

export interface LineMatch {
  index: number;
  line: string;
  pattern: RegExp;
}

/**
 * Return at most one match per line across the given patterns (first pattern wins).
 * Note: every regexp in `patterns` MUST NOT carry the global flag, because `.test()`
 * with /g would advance lastIndex and cause alternating false negatives.
 */
export function matchPatterns(lines: string[], patterns: RegExp[]): LineMatch[] {
  const matches: LineMatch[] = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!line) continue;
    for (const pattern of patterns) {
      if (pattern.test(line)) {
        matches.push({ index: i, line, pattern });
        break;
      }
    }
  }
  return matches;
}

export interface FindingTemplate {
  ruleId: string;
  category: FindingCategory;
  severity: Severity;
  codeTitle: string;
  promptTitle: string;
  suggestion: string;
  description: (line: string, inCode: boolean) => string;
  /** Return true to suppress a finding on this line (e.g. all URLs are allowed). */
  skip?: (line: string) => boolean;
}

/**
 * Scan both code blocks and the remaining prompt text, reporting every hit once
 * with correct 1-based absolute line numbers and code/prompt-specific titles.
 */
export function scanPatterns(parsed: ParsedSkill, patterns: RegExp[], tpl: FindingTemplate): Finding[] {
  const findings: Finding[] = [];
  const seenCodeLines = new Set<number>();

  for (const block of parsed.codeBlocks) {
    const lines = splitLines(block.code);
    for (const m of matchPatterns(lines, patterns)) {
      if (tpl.skip && tpl.skip(m.line)) continue;
      const lineNo = block.startLine + 1 + m.index;
      seenCodeLines.add(lineNo);
      findings.push({
        ruleId: tpl.ruleId,
        title: tpl.codeTitle,
        category: tpl.category,
        severity: tpl.severity,
        description: tpl.description(m.line, true),
        line: lineNo,
        snippet: m.line.trim(),
        suggestion: tpl.suggestion,
      });
    }
  }

  const allLines = splitLines(parsed.rawContent);
  for (const m of matchPatterns(allLines, patterns)) {
    const lineNo = m.index + 1;
    if (seenCodeLines.has(lineNo)) continue;
    if (tpl.skip && tpl.skip(m.line)) continue;
    findings.push({
      ruleId: tpl.ruleId,
      title: tpl.promptTitle,
      category: tpl.category,
      severity: tpl.severity,
      description: tpl.description(m.line, false),
      line: lineNo,
      snippet: m.line.trim(),
      suggestion: tpl.suggestion,
    });
  }

  return findings;
}

/**
 * Return true when every http(s) URL found in `text` belongs to one of the
 * given allowlisted domains (subdomains included). Lines without any URL are
 * never considered "allowed".
 */
export function isAllowedUrl(text: string, allowedDomains: string[]): boolean {
  if (!Array.isArray(allowedDomains) || allowedDomains.length === 0) return false;
  const urls = text.match(/https?:\/\/[^\s"'<>)\]]+/gi);
  if (!urls || urls.length === 0) return false;

  const allowed = allowedDomains.map((d) => d.trim().toLowerCase().replace(/^\./, '')).filter(Boolean);
  if (allowed.length === 0) return false;

  return urls.every((url) => {
    const host = url
      .replace(/^https?:\/\//i, '')
      .split('/')[0]
      .split('@')
      .pop() ?? ''
      .split(':')[0]
      .toLowerCase();
    return allowed.some((domain) => host === domain || host.endsWith('.' + domain));
  });
}
