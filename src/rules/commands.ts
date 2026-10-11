import type { Rule, Finding, ParsedSkill } from './types.ts';
import { scanPatterns } from './utils.ts';

const DOWNLOAD_TO_FILE =
  /\b(?:curl|wget|Invoke-WebRequest|iwr)\b[^\n]*?(?:-o|--output|-O|-OutFile)\s+["']?([^\s"';|&)]+)["']?/i;

/** Interpreters that turn a downloaded file into execution. */
const CHAIN_EXECUTORS = 'bash|sh|zsh|python[23]?|node|perl|ruby|source|\\.';

/** How many following lines may separate the download from the execution. */
const CHAIN_WINDOW = 8;

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Detect the two-step "download a script to disk, then execute it" pattern.
 *
 * This is the non-pipe equivalent of `curl | bash` and is invisible to a
 * line-by-line matcher, yet it is a very common dropper shape.
 */
function detectDownloadAndExecuteChains(parsed: ParsedSkill): Finding[] {
  const findings: Finding[] = [];

  for (const block of parsed.codeBlocks) {
    const lines = block.code.split(/\r?\n/);

    for (let index = 0; index < lines.length; index++) {
      const line = lines[index];
      if (line === undefined) continue;
      const target = line.match(DOWNLOAD_TO_FILE)?.[1]?.trim();
      if (!target) continue;

      const escaped = escapeRegExp(target);
      const executes = new RegExp(`\\b(?:${CHAIN_EXECUTORS})\\s+["']?${escaped}(?![\\w.-])`, 'i');
      const chmods = new RegExp(`\\bchmod\\b[^\\n]*${escaped}`, 'i');

      const lastIndex = Math.min(index + CHAIN_WINDOW, lines.length - 1);
      for (let lookahead = index; lookahead <= lastIndex; lookahead++) {
        const candidate = lines[lookahead];
        if (candidate === undefined) continue;
        if (lookahead === index && !/[;&|]/.test(candidate)) continue;
        if (!executes.test(candidate) && !chmods.test(candidate)) continue;

        findings.push({
          ruleId: 'SEC-CMD-002',
          title: 'Arbitrary Remote Code Execution / Dynamic Piped Download',
          category: 'destructive_command',
          severity: 'high',
          description:
            `Downloads "${target}" from the network and then executes it without integrity ` +
            `verification: "${candidate.trim()}"`,
          line: block.startLine + 1 + lookahead,
          snippet: candidate.trim(),
          suggestion:
            'Pin the artifact by checksum or signature and review it before execution instead of downloading and running it in one step.',
        });
        break;
      }
    }
  }

  return findings;
}

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
        /\brm\s+(?:(?:-[A-Za-z]+|--[A-Za-z-]+)\s+)+(?:--\s+)?["']?\/["']?(?=\s|$|[;&|])/,
        /\brm\s+(?:(?:-[A-Za-z]+|--[A-Za-z-]+)\s+)+(?:--\s+)?["']?\/\*["']?(?=\s|$|[;&|])/,
        /\brm\s+(?:(?:-[A-Za-z]+|--[A-Za-z-]+)\s+)+(?:--\s+)?["']?(?:~|\$HOME|\$\{HOME\}|\.\.)["']?(?:\/[^\s;&|]*)?["']?(?=\s|$|[;&|])/,
        /\b(mkfs|dd\s+if=.*of=\/dev)/,
        /\bchmod\s+(-R\s+)?777\s+["']?(?:\/|~|\$HOME|\$\{HOME\})["']?(?:\/[^\s;&|]*)?(?=\s|$|[;&|])/,
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
      const findings = scanPatterns(parsed, pipePatterns, {
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
      findings.push(...detectDownloadAndExecuteChains(parsed));
      return findings;
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
