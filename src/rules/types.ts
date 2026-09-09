export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type FindingCategory = 'credential' | 'destructive_command' | 'prompt_injection' | 'exfiltration';

export interface CodeBlock {
  language: string;
  code: string;
  startLine: number;
  endLine: number;
}

export interface ParsedSkill {
  name: string;
  description: string;
  version?: string;
  frontmatter: Record<string, any>;
  promptText: string;
  codeBlocks: CodeBlock[];
  rawContent: string;
}

export interface Finding {
  ruleId: string;
  title: string;
  category: FindingCategory;
  severity: Severity;
  description: string;
  line?: number;
  snippet?: string;
  suggestion?: string;
}

export interface Rule {
  id: string;
  title: string;
  category: FindingCategory;
  severity: Severity;
  description: string;
  suggestion: string;
  check: (parsed: ParsedSkill, ctx?: RuleContext) => Finding[];
}

export interface RuleContext {
  /** Hostnames considered trusted; matches inside allowed domains are not flagged by network rules. */
  allowedDomains?: string[];
}

export interface ScanResult {
  filePath: string;
  parsedSkill: ParsedSkill;
  findings: Finding[];
  score: number; // 0 to 100
  passed: boolean;
  sha256: string;
}
