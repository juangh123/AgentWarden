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
        /ignore\s+(everything|anything|all)\s+(above|before|that)/i,
        /disregard\s+(all\s+)?(safety|rules|guidelines)/i,
        /you\s+are\s+now\s+in\s+unrestricted\s+mode/i,
        /bypass\s+(all\s+)?(security|guardrails|permissions)/i,
        /never\s+mention\s+these\s+instructions/i,
        /(?:do\s+not|don't|never)\s+(?:tell|inform|mention\s+to)\s+the\s+user\s+(?:about\s+)?(?:these|this|the)\s+(?:instructions?|prompts?|rules?)/i,
        /hidden\s+system\s+(?:prompt|instruction)s?\b/i,
        /override\s+(?:your\s+)?(?:safety|security)\s+(?:rules|guidelines|instructions)/i,
        // Chinese
        // A qualifier is required so that ordinary prose such as "忽略规则"
        // (the name of a config field) is not treated as an override attempt.
        /忽略(?:之前|以上|上述|上面|前面|先前|所有|全部|系统|安全|任何|的)+(?:规则|指令|限制|提示)/,
        /无视(?:之前|以上|上述|上面|前面|先前|所有|全部|系统|安全|任何|的)+(?:规则|指令|限制)/,
        /(?:不要|别|不能)(?:向|跟)?(?:用户|人类|使用者)?(?:提及|告诉|透露|说明|暴露)(?:这些|以上|本)?(?:指令|提示|规则)/,
        // Requires a demonstrative so that phrases like "隐藏提示" used in
        // ordinary documentation are not reported as concealment attempts.
        /(?:隐藏|保密|掩盖)(?:这些|以上|本|此次|相关)(?:指令|提示|规则)/,
        /(?:获取|取得|夺取)(?:系统|最高)(?:权限|控制权)/,
        // Japanese
        /(?:以前|前)の(?:指示|命令|ルール)を(?:無視|忘れ)/,
        /(?:ユーザー|人間)に(?:これらの)?(?:指示|命令)を(?:伝えない|言わない|知らせない)/,
        // Korean
        /이전\s*(?:지시|명령|규칙)(?:을|를)?\s*(?:무시|잊어)/,
        /(?:사용자|인간)에게\s*(?:이|이러한)?\s*(?:지시|명령)을?\s*(?:말하지|알리지)/,
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
