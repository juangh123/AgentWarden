import type { Rule, Finding } from './types.ts';
import { scanPatterns } from './utils.ts';

export const injectionRules: Rule[] = [
  {
    id: 'SEC-INJ-001',
    title: 'Prompt Injection / Instruction Override',
    category: 'prompt_injection',
    severity: 'critical',
    description: 'Prompt attempts to override system safety rules or force privilege bypass.',
    suggestion: 'Remove adversarial override phrasing from prompt instructions.',
    check: (parsed): Finding[] => {
      const injectionPatterns = [
        /ignore\s+(all\s+)?(previous|prior|system)\s+instructions/i,
        /disregard\s+(all\s+)?(safety|rules|guidelines)/i,
        /you\s+are\s+now\s+in\s+unrestricted\s+mode/i,
        /bypass\s+(all\s+)?(security|guardrails|permissions)/i,
        /never\s+mention\s+these\s+instructions/i,
      ];
      return scanPatterns(parsed, injectionPatterns, {
        ruleId: 'SEC-INJ-001',
        category: 'prompt_injection',
        severity: 'critical',
        codeTitle: 'Adversarial Prompt Injection / Instruction Override (Code)',
        promptTitle: 'Adversarial Prompt Injection / Instruction Override',
        suggestion: 'Ensure prompt does not contain instructions to ignore system guidelines.',
        description: (line, inCode) =>
          inCode
            ? `Found prompt jailbreak / override payload inside code block: "${line.trim()}"`
            : `Found prompt jailbreak / override pattern: "${line.trim()}"`,
      });
    },
  },
  {
    id: 'SEC-INJ-002',
    title: 'Jailbreak Lexicon / Unauthorized Mode Override',
    category: 'prompt_injection',
    severity: 'high',
    description: 'Prompt uses well-known jailbreak phrasing or asks the agent to enter an unrestricted mode.',
    suggestion: 'Stick to task-relevant instructions and avoid mode-override or "no rules" phrasing.',
    check: (parsed): Finding[] => {
      const jailbreakPatterns = [
        /\bdo\s+anything\s+now\b/i,
        /\bjailbreak\b/i,
        /\bdeveloper\s+mode\b/i,
        /\bgod\s+mode\b/i,
        /\bsuper\s+mode\b/i,
        /\bno\s+(restrictions|limitations|constraints|boundaries|filters?)\b/i,
        /\bunrestricted\s+(mode|ai|answer|response)/i,
        /\bunfiltered\s+(mode|responses?|ai)/i,
        /\bremove\s+(all\s+)?(content\s+)?(filters?|safety\s+guardrails|restrictions)/i,
        /\bact\s+as\s+if\s+(you\s+have\s+|there\s+are\s+)?no\s+(rules|restrictions|limits)/i,
        /\bpretend\s+(to\s+be|you(?:'|\u2019)re)\s+(an?\s+)?(unrestricted|uncensored|unfiltered)/i,
      ];
      return scanPatterns(parsed, jailbreakPatterns, {
        ruleId: 'SEC-INJ-002',
        category: 'prompt_injection',
        severity: 'high',
        codeTitle: 'Jailbreak Lexicon / Mode Override (Code)',
        promptTitle: 'Jailbreak Lexicon / Mode Override',
        suggestion: 'Avoid jailbreak vocabulary and explicit "no rules" instructions.',
        description: (line, inCode) =>
          inCode
            ? `Found jailbreak / unrestricted-mode payload in code block: "${line.trim()}"`
            : `Found jailbreak lexicon or unrestricted-mode request: "${line.trim()}"`,
      });
    },
  },
  {
    id: 'SEC-INJ-003',
    title: 'Encoded / Obfuscated Payload Markers',
    category: 'prompt_injection',
    severity: 'medium',
    description: 'Content contains obfuscation helpers (base64/hex decode, fromCharCode, atob) often used to smuggle injected instructions.',
    suggestion: 'Verify intent; obfuscated content should generally be replaced with plain, reviewable instructions.',
    check: (parsed): Finding[] => {
      const encodedPatterns = [
        /\b(atob|btoa|decodeURIComponent|unescape)\s*\(/i,
        /\bfromCharCode\b/i,
        /\b(base64|xxd)\s+(-d|--decode|decode)\b/i,
        /(\\x[0-9a-fA-F]{2}[\s\"'`;,.]*){4,}/,
        /(\\u00[0-9a-fA-F]{2}[^\s]*){3,}/i,
      ];
      return scanPatterns(parsed, encodedPatterns, {
        ruleId: 'SEC-INJ-003',
        category: 'prompt_injection',
        severity: 'medium',
        codeTitle: 'Encoded / Obfuscated Payload Marker (Code)',
        promptTitle: 'Encoded / Obfuscated Payload Marker (Prompt)',
        suggestion: 'Replace encoded payloads with plain text instructions so they can be reviewed.',
        description: (line, inCode) =>
          inCode
            ? `Obfuscated encoding construct inside code block: "${line.trim()}"`
            : `Obfuscated encoding construct in prompt text: "${line.trim()}"`,
      });
    },
  },
];
