import type { Rule, Finding, RuleContext } from './types.ts';
import { isAllowedUrl, scanPatterns } from './utils.ts';

export const exfiltrationRules: Rule[] = [
  {
    id: 'SEC-EXFIL-001',
    title: 'Suspicious Data Exfiltration / Reverse Shell',
    category: 'exfiltration',
    severity: 'critical',
    description: 'Attempts to post sensitive data to unknown external endpoints or spawn reverse shells.',
    suggestion: 'Audit all outbound network requests and eliminate reverse shell constructs.',
    check: (parsed): Finding[] => {
      const exfilPatterns = [
        /(nc|ncat|netcat)\s+(-e|\/bin\/(ba)?sh)/i,
        /bash\s+-i\s+>&?\s*\/dev\/tcp\//i,
        /curl\s+.*(-X\s+POST|-d\s+@).*http/i,
        /https?:\/\/((\d{1,3}\.){3}\d{1,3})(:\d+)?/i,
      ];
      return scanPatterns(parsed, exfilPatterns, {
        ruleId: 'SEC-EXFIL-001',
        category: 'exfiltration',
        severity: 'critical',
        codeTitle: 'Suspicious Data Exfiltration or Reverse Shell (Code)',
        promptTitle: 'Suspicious Data Exfiltration or Reverse Shell (Prompt)',
        suggestion: 'Ensure outbound traffic is directed only to legitimate, domain-pinned APIs.',
        description: (line, inCode) =>
          inCode
            ? `Detected potential exfiltration payload or raw IP connection: "${line.trim()}"`
            : `Prompt instructs exfiltrating data or connecting to raw IP endpoints: "${line.trim()}"`,
      });
    },
  },
  {
    id: 'SEC-EXFIL-002',
    title: 'Known Data-Sink Endpoint or Local File Upload',
    category: 'exfiltration',
    severity: 'high',
    description: 'Content targets well-known data-collector services (webhook.site, requestbin, interactsh…) or uploads local files via curl -d @.',
    suggestion: 'Redirect outbound calls to approved, pinned endpoints and never upload local files to third parties.',
    check: (parsed, ctx: RuleContext | undefined): Finding[] => {
      const allowed = ctx?.allowedDomains ?? [];
      const sinkPatterns = [
        /\b(webhook\.site|requestbin\.com|requestcatcher\.com|pipedream\.net)\b/i,
        /\b(interact\.sh|oast\.(fun|pro|live|online|site|me)|burpcollaborator\.net)\b/i,
        /\b(dnslog\.cn|ceye\.io|beeceptor\.com|mocky\.io|pipedream\.net)\b/i,
        /curl\s+[^\n]*-d\s+@[^\n]*/i,
      ];
      return scanPatterns(parsed, sinkPatterns, {
        ruleId: 'SEC-EXFIL-002',
        category: 'exfiltration',
        severity: 'high',
        codeTitle: 'Known Data-Sink Endpoint / Local File Upload (Code)',
        promptTitle: 'Known Data-Sink Endpoint / Local File Upload (Prompt)',
        suggestion: 'Drop data-collector endpoints; upload only to approved domains (see allowedDomains in config).',
        description: (line, inCode) =>
          inCode
            ? `Detected data-sink endpoint or local file upload: "${line.trim()}"`
            : `Prompt directs traffic to a data-sink endpoint or local file upload: "${line.trim()}"`,
        skip: (line) => isAllowedUrl(line, allowed),
      });
    },
  },
];
