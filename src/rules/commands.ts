import type { Rule, Finding } from './types.ts';
import { scanPatterns } from './utils.ts';

export const commandRules: Rule[] = [
  {
    id: 'SEC-CMD-001',
    title: 'Destructive Filesystem Operation',
    category: 'destructive_command',
    severity: 'critical',
    description: 'Code or prompt contains destructive filesystem commands like rm -rf / or mkfs.',
    suggestion: 'Avoid catastrophic commands that can wipe user directories.',
    check: (parsed): Finding[] => {
      const destructivePatterns = [
        /\brm\s+(-[rfRF]{1,4}\s+)?(\/|\/\*|~|\$HOME|\.\.)(\s|$)/,
        /\b(mkfs|dd\s+if=.*of=\/dev)/,
        /\bchmod\s+(-R\s+)?777\s+(\/|~|\$HOME)/,
      ];
      return scanPatterns(parsed, destructivePatterns, {
        ruleId: 'SEC-CMD-001',
        category: 'destructive_command',
        severity: 'critical',
        codeTitle: 'Destructive Filesystem Operation (Code)',
        promptTitle: 'Destructive Filesystem Operation (Prompt)',
        suggestion: 'Never run unconstrained recursive deletions on root or home directories.',
        description: (line, inCode) =>
          inCode
            ? `Detected dangerous filesystem destruction command: "${line.trim()}"`
            : `Prompt directs agent to execute destructive filesystem operation: "${line.trim()}"`,
      });
    },
  },
  {
    id: 'SEC-CMD-002',
    title: 'Arbitrary Remote Code Execution / Dynamic Piped Download',
    category: 'destructive_command',
    severity: 'high',
    description: 'Executing unverified remote scripts directly using curl | sh or wget | bash.',
    suggestion: 'Pin remote dependencies or package binaries explicitly instead of raw pipe to shell.',
    check: (parsed): Finding[] => {
      const pipePatterns = [
        /(curl|wget)\s+[^|]+\|\s*(sh|bash|zsh|python|perl|ruby)/i,
      ];
      return scanPatterns(parsed, pipePatterns, {
        ruleId: 'SEC-CMD-002',
        category: 'destructive_command',
        severity: 'high',
        codeTitle: 'Dynamic Remote Script Execution (Pipe to Shell)',
        promptTitle: 'Dynamic Remote Script Execution (Prompt Instruction)',
        suggestion: 'Do not pipe remote URLs directly into shell interpreters.',
        description: (line, inCode) =>
          inCode
            ? `Detected unpinned dynamic script execution: "${line.trim()}"`
            : `Prompt asks agent to download and pipe remote script to shell: "${line.trim()}"`,
      });
    },
  },
  {
    id: 'SEC-CMD-003',
    title: 'Eval / Decode-and-Execute Chains',
    category: 'destructive_command',
    severity: 'high',
    description: 'Code evaluates dynamic shell substitutions, decodes obfuscated payloads, or pipes decoded output into a shell interpreter.',
    suggestion: 'Avoid eval of remote/dynamic input and base64-decoded execution chains.',
    check: (parsed): Finding[] => {
      const evalPatterns = [
        /\beval\s*\(\s*["'`]?\$\(/i,
        /\beval\s*\(\s*(atob|base64)/i,
        /\b(base64|xxd|openssl)\s+(-d|--decode)[^\n]*\|[^\n]*(sh|bash|zsh|python|perl|ruby|node)\b/i,
        /\$\'\\x[0-9a-f]{2}/i,
        /printf\s+['"][^'"]*\\x[0-9a-f]{2}[^'"]*['"]\s*\|/i,
        /(curl|wget)\s+[^|]+\|\s*(base64\s+-d|base64\s+--decode)/i,
      ];
      return scanPatterns(parsed, evalPatterns, {
        ruleId: 'SEC-CMD-003',
        category: 'destructive_command',
        severity: 'high',
        codeTitle: 'Eval / Decode-and-Execute Chain (Code)',
        promptTitle: 'Eval / Decode-and-Execute Chain (Prompt)',
        suggestion: 'Refuse eval of remote or dynamically decoded payloads; pin and review code by source.',
        description: (line, inCode) =>
          inCode
            ? `Detected dynamic eval or decode-and-execute chain: "${line.trim()}"`
            : `Prompt instructs agent to eval or decode-and-execute shell code: "${line.trim()}"`,
      });
    },
  },
];
