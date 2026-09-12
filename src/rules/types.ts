export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type FindingCategory = 'credential' | 'destructive_command' | 'prompt_injection' | 'exfiltration' | 'mcp_misconfig';

export type SkillKind = 'skill' | 'mcp' | 'agent-instruction';

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
  kind?: SkillKind;
  parseError?: string;
  mcpServers?: Array<{
    name: string;
    command?: string;
    args?: string[];
    env?: Record<string, string>;
  }>;
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
  suppressedFindings?: Finding[];
  baseline?: BaselineMetadata;
  score: number; // 0 to 100
  passed: boolean;
  sha256: string;
}

export interface BaselineMetadata {
  path: string;
  suppressed: number;
  unmatched: number;
  expired?: boolean;
  expiresAt?: string;
  owner?: string;
}
