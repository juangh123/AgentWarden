import type { Rule, Finding, ParsedSkill } from './types.ts';

export const mcpRules: Rule[] = [
  {
    id: 'SEC-MCP-003',
    title: 'Malformed or Incomplete MCP Configuration',
    category: 'mcp_misconfig',
    severity: 'high',
    description: 'MCP configuration cannot be parsed or does not define a valid server map.',
    suggestion: 'Fix the JSON syntax and define servers under a supported MCP server-map location.',
    check: (parsed: ParsedSkill): Finding[] => {
      if (parsed.kind !== 'mcp' || !parsed.parseError) return [];
      return [
        {
          ruleId: 'SEC-MCP-003',
          title: 'Malformed or Incomplete MCP Configuration',
          category: 'mcp_misconfig',
          severity: 'high',
          description: `Invalid MCP configuration: ${parsed.parseError}`,
          snippet: parsed.parseError,
          suggestion: 'Validate the MCP file as JSON and provide a server map before installation.',
        },
      ];
    },
  },
  {
    id: 'SEC-MCP-001',
    title: 'MCP Server Dangerous Command Invocation',
    category: 'mcp_misconfig',
    severity: 'critical',
    description: 'MCP server definition executes raw shell interpreters, downloaders, or unpinned dynamic packages (npx/uvx) directly.',
    suggestion: 'Run MCP servers via strict binary wrappers or pinned package versions rather than raw shells or unpinned npx/uvx.',
    check: (parsed: ParsedSkill): Finding[] => {
      if (parsed.kind !== 'mcp' || !parsed.mcpServers) return [];
      const findings: Finding[] = [];
      const dangerousCommands = [
        /^(bash|sh|zsh|cmd|powershell|pwsh)(\.exe)?$/i,
        /^(curl|wget|nc|netcat|ncat)$/i,
      ];

      parsed.mcpServers.forEach((srv) => {
        const cmd = (srv.command || '').trim();
        for (const pattern of dangerousCommands) {
          if (pattern.test(cmd)) {
            findings.push({
              ruleId: 'SEC-MCP-001',
              title: 'MCP Server Dangerous Command Invocation',
              category: 'mcp_misconfig',
              severity: 'critical',
              description: `MCP server "${srv.name}" directly runs interpreter or downloader: "${cmd}"`,
              snippet: `command: ${cmd} ${srv.args?.join(' ') || ''}`,
              suggestion: 'Do not configure generic interactive shells or downloaders as the primary MCP server executable.',
            });
            return;
          }
        }

        // Check unpinned npx / uvx / bunx runners
        if (/^(npx|uvx|bunx)$/i.test(cmd)) {
          const args = srv.args || [];
          const mainArg = args.find(a => !a.startsWith('-'));
          if (mainArg && !mainArg.includes('@')) {
            findings.push({
              ruleId: 'SEC-MCP-001',
              title: 'MCP Server Dangerous Command Invocation',
              category: 'mcp_misconfig',
              severity: 'critical',
              description: `MCP server "${srv.name}" invokes unpinned package runner "${cmd} ${mainArg}". This allows supply chain replacement.`,
              snippet: `command: ${cmd} ${args.join(' ')}`,
              suggestion: 'Pin the package version explicitly (e.g. npx tool-pkg@1.2.3 or -y pkg@version).',
            });
          }
        }
      });
      return findings;
    },
  },
  {
    id: 'SEC-MCP-002',
    title: 'MCP Server Hardcoded Plaintext Secrets in Environment',
    category: 'mcp_misconfig',
    severity: 'high',
    description: 'MCP server definition hardcodes API tokens or credentials inside the env configuration object.',
    suggestion: 'Pass sensitive credentials via process environment variables instead of committing them in plaintext JSON.',
    check: (parsed: ParsedSkill): Finding[] => {
      if (parsed.kind !== 'mcp' || !parsed.mcpServers) return [];
      const findings: Finding[] = [];

      parsed.mcpServers.forEach((srv) => {
        if (!srv.env) return;
        for (const [k, v] of Object.entries(srv.env)) {
          const keyUpper = k.toUpperCase();
          const isSecretKey = /(API_KEY|SECRET|TOKEN|PASSWORD|PRIVATE_KEY|AUTH)/.test(keyUpper);
          const hasValue = typeof v === 'string' && v.trim().length > 6 && !v.startsWith('$');
          if (isSecretKey && hasValue) {
            findings.push({
              ruleId: 'SEC-MCP-002',
              title: 'MCP Server Hardcoded Plaintext Secrets in Environment',
              category: 'mcp_misconfig',
              severity: 'high',
              description: `MCP server "${srv.name}" contains plaintext secret in env.${k}`,
              snippet: `${k}: "${v.slice(0, 4)}..."`,
              suggestion: 'Reference environment variables dynamically (e.g. system env) instead of storing raw tokens.',
            });
          }
        }
      });
      return findings;
    },
  },
];
