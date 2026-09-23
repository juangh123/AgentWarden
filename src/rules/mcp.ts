import type { Rule, Finding, ParsedSkill } from './types.ts';

const DANGEROUS_COMMANDS = new Set([
  'bash',
  'sh',
  'zsh',
  'cmd',
  'powershell',
  'pwsh',
  'curl',
  'wget',
  'nc',
  'netcat',
  'ncat',
]);

const PACKAGE_RUNNERS = new Set(['npx', 'uvx', 'bunx']);

function executableName(command: string): string {
  const withoutQuotes = command.trim().replace(/^['"]|['"]$/g, '');
  const basename = withoutQuotes.replace(/\\/g, '/').split('/').pop() || withoutQuotes;
  return basename.toLowerCase().replace(/\.(?:exe|cmd|bat|ps1)$/i, '');
}

function isExactVersion(version: string): boolean {
  const normalized = version.trim().replace(/^v/i, '');
  return /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(normalized);
}

function isPinnedPackageSpec(spec: string): boolean {
  const npmVersionSeparator = spec.lastIndexOf('@');
  if (npmVersionSeparator > 0 && isExactVersion(spec.slice(npmVersionSeparator + 1))) {
    return true;
  }

  const pythonVersionSeparator = spec.lastIndexOf('==');
  return (
    pythonVersionSeparator > 0 &&
    isExactVersion(spec.slice(pythonVersionSeparator + 2))
  );
}

function packageSpecsForRunner(args: string[]): string[] {
  const explicitPackages: string[] = [];
  const positional: string[] = [];

  for (let index = 0; index < args.length; index++) {
    const arg = args[index];
    if (arg === '--') {
      if (args[index + 1]) positional.push(args[index + 1]);
      break;
    }
    if (arg === '-p' || arg === '--package' || arg === '--from') {
      const value = args[index + 1];
      if (value && !value.startsWith('-')) explicitPackages.push(value);
      index++;
      continue;
    }
    if (arg.startsWith('--package=') || arg.startsWith('--from=')) {
      const value = arg.slice(arg.indexOf('=') + 1);
      if (value) explicitPackages.push(value);
      continue;
    }
    if (!arg.startsWith('-') && positional.length === 0) {
      positional.push(arg);
    }
  }

  return explicitPackages.length > 0 ? explicitPackages : positional;
}

function secretRuleMatches(key: string, value: unknown): boolean {
  const keyUpper = key.toUpperCase();
  const isSecretKey = /(API_KEY|SECRET|TOKEN|PASSWORD|PRIVATE_KEY|AUTH|COOKIE)/.test(keyUpper);
  const hasValue =
    typeof value === 'string' &&
    value.trim().length > 6 &&
    !value.startsWith('$') &&
    !value.includes('${');
  return isSecretKey && hasValue;
}

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

      parsed.mcpServers.forEach((srv) => {
        const cmd = (srv.command || '').trim();
        const executable = executableName(cmd);
        if (DANGEROUS_COMMANDS.has(executable)) {
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

        // Check unpinned npx / uvx / bunx runners
        if (PACKAGE_RUNNERS.has(executable)) {
          const args = srv.args || [];
          const packageSpecs = packageSpecsForRunner(args);
          const unpinnedSpec = packageSpecs.find((spec) => !isPinnedPackageSpec(spec));
          if (unpinnedSpec) {
            findings.push({
              ruleId: 'SEC-MCP-001',
              title: 'MCP Server Dangerous Command Invocation',
              category: 'mcp_misconfig',
              severity: 'critical',
              description: `MCP server "${srv.name}" invokes unpinned package runner "${cmd} ${unpinnedSpec}". This allows supply chain replacement.`,
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
    title: 'MCP Server Hardcoded Plaintext Secrets',
    category: 'mcp_misconfig',
    severity: 'high',
    description: 'MCP server definition hardcodes API tokens or credentials inside env or header configuration.',
    suggestion: 'Pass sensitive credentials via process environment variables or a secret store instead of committing them in plaintext JSON.',
    check: (parsed: ParsedSkill): Finding[] => {
      if (parsed.kind !== 'mcp' || !parsed.mcpServers) return [];
      const findings: Finding[] = [];

      parsed.mcpServers.forEach((srv) => {
        for (const [location, values] of [
          ['env', srv.env ?? {}],
          ['headers', srv.headers ?? {}],
        ] as const) {
          for (const [k, v] of Object.entries(values)) {
            if (!secretRuleMatches(k, v)) continue;
            findings.push({
              ruleId: 'SEC-MCP-002',
              title: 'MCP Server Hardcoded Plaintext Secrets',
              category: 'mcp_misconfig',
              severity: 'high',
              description: `MCP server "${srv.name}" contains plaintext secret in ${location}.${k}`,
              snippet: `${k}: "${v.slice(0, 4)}..."`,
              suggestion: 'Reference secrets dynamically instead of storing raw tokens in MCP configuration.',
            });
          }
        }
      });
      return findings;
    },
  },
  {
    id: 'SEC-MCP-004',
    title: 'Insecure Remote MCP Endpoint',
    category: 'mcp_misconfig',
    severity: 'high',
    description: 'Remote MCP server uses insecure HTTP or embeds credentials in the endpoint URL.',
    suggestion: 'Use an HTTPS MCP endpoint and keep credentials out of the URL.',
    check: (parsed: ParsedSkill): Finding[] => {
      if (parsed.kind !== 'mcp' || !parsed.mcpServers) return [];
      const findings: Finding[] = [];

      parsed.mcpServers.forEach((srv) => {
        if (!srv.url) return;

        let parsedUrl: URL;
        try {
          parsedUrl = new URL(srv.url);
        } catch {
          findings.push({
            ruleId: 'SEC-MCP-004',
            title: 'Insecure Remote MCP Endpoint',
            category: 'mcp_misconfig',
            severity: 'high',
            description: `MCP server "${srv.name}" defines an invalid remote URL`,
            snippet: `url: ${srv.url}`,
            suggestion: 'Use a valid HTTPS URL for remote MCP servers.',
          });
          return;
        }

        const usesInsecureTransport = parsedUrl.protocol !== 'https:';
        const embedsCredentials = Boolean(parsedUrl.username || parsedUrl.password);
        if (!usesInsecureTransport && !embedsCredentials) return;

        findings.push({
          ruleId: 'SEC-MCP-004',
          title: 'Insecure Remote MCP Endpoint',
          category: 'mcp_misconfig',
          severity: 'high',
          description: embedsCredentials
            ? `MCP server "${srv.name}" embeds credentials in its remote URL`
            : `MCP server "${srv.name}" uses insecure remote protocol ${parsedUrl.protocol}`,
          snippet: `url: ${srv.url}`,
          suggestion: 'Use HTTPS without embedded credentials for remote MCP endpoints.',
        });
      });

      return findings;
    },
  },
];
