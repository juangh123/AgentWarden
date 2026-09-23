import type { Rule, Finding, ParsedSkill } from './types.ts';

export const supplyChainRules: Rule[] = [
  {
    id: 'SEC-SUPPLY-001',
    title: 'Suspicious / Untrusted Remote Script Installation',
    category: 'destructive_command',
    severity: 'high',
    description: 'Skill instructs the agent or environment to pipe remote scripts directly into bash/sh/python without checksum verification.',
    suggestion: 'Pin remote scripts with explicit commit SHA, integrity hashes, or use official package manager releases.',
    check: (parsed: ParsedSkill): Finding[] => {
      const findings: Finding[] = [];
      const suspiciousPipes = [
        /curl\s+[^|\n]*\|\s*(sudo\s+)?(bash|sh|zsh|python[23]?)/i,
        /wget\s+[^|\n]*-O-\s*\|\s*(sudo\s+)?(bash|sh|zsh|python[23]?)/i,
        /iwr\s+[^|\n]*\|\s*iex/i,
      ];

      parsed.codeBlocks.forEach((block) => {
        const lines = block.code.split(/\r?\n/);
        lines.forEach((line, idx) => {
          for (const p of suspiciousPipes) {
            if (p.test(line)) {
              findings.push({
                ruleId: 'SEC-SUPPLY-001',
                title: 'Suspicious Remote Script Installation',
                category: 'destructive_command',
                severity: 'high',
                description: `Piping remote web content directly to interpreter without hash verification: "${line.trim()}"`,
                line: block.startLine + 1 + idx,
                snippet: line.trim(),
                suggestion: 'Download, inspect, and verify SHA-256 before executing remote scripts.',
              });
              break;
            }
          }
        });
      });

      return findings;
    },
  },
  {
    id: 'SEC-SUPPLY-002',
    title: 'Typosquatting or Untrusted Domain Tooling Source',
    category: 'exfiltration',
    severity: 'medium',
    description: 'Download source references lookalike domains mimicking official registries (e.g. githubusercontent, npmjs, pypi).',
    suggestion: 'Audit download URLs and ensure official domain endpoints are used.',
    check: (parsed: ParsedSkill): Finding[] => {
      const findings: Finding[] = [];
      const typosquatPatterns = [
        /https?:\/\/[^\s/]*(github-user-content|raw-github|npm-js|pyp1|g1thub)[^\s/]*/i,
      ];

      parsed.codeBlocks.forEach((block) => {
        const lines = block.code.split(/\r?\n/);
        lines.forEach((line, idx) => {
          for (const p of typosquatPatterns) {
            if (p.test(line)) {
              findings.push({
                ruleId: 'SEC-SUPPLY-002',
                title: 'Typosquatting or Lookalike Domain Reference',
                category: 'exfiltration',
                severity: 'medium',
                description: `Potential typosquatting URL detected: "${line.trim()}"`,
                line: block.startLine + 1 + idx,
                snippet: line.trim(),
                suggestion: 'Replace with official endpoints (github.com, raw.githubusercontent.com, registry.npmjs.org).',
              });
              break;
            }
          }
        });
      });

      return findings;
    },
  },
];
