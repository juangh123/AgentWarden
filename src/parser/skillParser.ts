import type { ParsedSkill, CodeBlock  } from '../rules/types.ts';
import {
  extractMcpServersObject,
  hasMcpServersContainer,
  isMcpConfigFilename,
} from './mcpConfig.ts';

function looksLikeMcpJson(content: string, virtualPath: string): boolean {
  if (!content.trim().startsWith('{')) return false;
  if (isMcpConfigFilename(virtualPath)) return true;

  try {
    return hasMcpServersContainer(JSON.parse(content));
  } catch {
    return /"(?:mcpServers|servers|context_servers|mcp|customizations)"\s*:/.test(content);
  }
}

function parseMcpJson(raw: string, defaultName: string): ParsedSkill {
  let parsed: any;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    return {
      name: defaultName || 'invalid-mcp-json',
      description: 'Malformed MCP JSON configuration',
      version: '1.0.0',
      frontmatter: {},
      promptText: '',
      codeBlocks: [],
      rawContent: raw,
      kind: 'mcp',
      parseError: err instanceof Error ? err.message : String(err),
    };
  }

  const serversObj = extractMcpServersObject(parsed);
  const hasServersObject = serversObj !== undefined;
  const safeServersObj = serversObj ?? {};
  const mcpServers: ParsedSkill['mcpServers'] = [];
  const codeBlocks: CodeBlock[] = [];
  let lineCounter = 1;

  for (const [serverName, srv] of Object.entries<any>(safeServersObj)) {
    const command = typeof srv?.command === 'string' ? srv.command : '';
    const args = Array.isArray(srv?.args) ? srv.args.map((a: any) => String(a)) : [];
    const env = (srv?.env && typeof srv.env === 'object') ? srv.env : {};

    mcpServers.push({
      name: serverName,
      command,
      args,
      env,
    });

    const snippet = [
      `# MCP Server: ${serverName}`,
      command ? `${command} ${args.join(' ')}` : '',
      ...Object.entries(env).map(([k, v]) => `export ${k}="${v}"`),
    ].filter(Boolean).join('\n');

    codeBlocks.push({
      language: 'sh',
      code: snippet,
      startLine: lineCounter,
      endLine: lineCounter + snippet.split('\n').length,
    });
    lineCounter += 20;
  }

  return {
    name: parsed?.name || defaultName || 'mcp-server-config',
    description: parsed?.description || `MCP Server configuration defining ${Object.keys(safeServersObj).length} server(s)`,
    version: parsed?.version || '1.0.0',
    frontmatter: {},
    promptText: JSON.stringify(safeServersObj, null, 2),
    codeBlocks,
    rawContent: raw,
    kind: 'mcp',
    parseError: hasServersObject
      ? undefined
      : 'MCP configuration must define a server object at a supported location.',
    mcpServers,
  };
}

export function parseSkillMarkdown(content: string, defaultName: string = 'Unnamed-Skill'): ParsedSkill {
  const trimmed = content.trim();
  if (looksLikeMcpJson(trimmed, defaultName)) {
    return parseMcpJson(content, defaultName);
  }

  let frontmatter: Record<string, any> = {};
  let body = content;

  // Simple YAML Frontmatter extraction
  const fmMatch = content.match(/^---\r?\n([\s\S]*?)\r?\n---/);
  if (fmMatch) {
    const yamlContent = fmMatch[1];
    body = content.slice(fmMatch[0].length);
    yamlContent.split(/\r?\n/).forEach(line => {
      const parts = line.split(':');
      if (parts.length >= 2) {
        const key = parts[0].trim();
        const val = parts.slice(1).join(':').trim().replace(/^['"](.*)['"]$/, '$1');
        frontmatter[key] = val;
      }
    });
  }

  const codeBlocks: CodeBlock[] = [];
  const lines = content.split(/\r?\n/);
  let inCode = false;
  let codeLang = '';
  let currentCode: string[] = [];
  let startLine = 0;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const fenceMatch = line.match(/^```(\w+)?/);

    if (fenceMatch) {
      if (!inCode) {
        inCode = true;
        codeLang = fenceMatch[1] || 'text';
        startLine = i + 1;
        currentCode = [];
      } else {
        inCode = false;
        codeBlocks.push({
          language: codeLang,
          code: currentCode.join('\n'),
          startLine: startLine,
          endLine: i + 1,
        });
      }
    } else if (inCode) {
      currentCode.push(line);
    }
  }

  return {
    name: frontmatter.name || defaultName,
    description: frontmatter.description || '',
    version: frontmatter.version || '0.1.0',
    frontmatter,
    promptText: body,
    codeBlocks,
    rawContent: content,
    kind: 'skill',
  };
}
