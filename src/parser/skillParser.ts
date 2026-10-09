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

/** Remove a single leading UTF-8 BOM so anchors like `^---` keep working. */
function stripBom(content: string): string {
  return content.charCodeAt(0) === 0xfeff ? content.slice(1) : content;
}

function escapeForRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** Character offsets of every line start, used to turn a match index into a line. */
function buildLineStartIndex(text: string): number[] {
  const starts = [0];
  for (let index = 0; index < text.length; index++) {
    if (text.charCodeAt(index) === 10) starts.push(index + 1);
  }
  return starts;
}

function lineNumberAt(starts: number[], index: number): number {
  let low = 0;
  let high = starts.length - 1;
  while (low < high) {
    const mid = Math.ceil((low + high) / 2);
    if (starts[mid] <= index) low = mid;
    else high = mid - 1;
  }
  return low + 1;
}

/**
 * Locate a `"<serverName>":` key in the raw config text so findings can point
 * at a real line instead of a synthesized offset.
 */
function findServerKeyIndex(raw: string, serverName: string, fromIndex: number): number {
  const quoted = JSON.stringify(serverName);
  const direct = raw.indexOf(`${quoted}:`, fromIndex);
  if (direct !== -1) return direct;

  const pattern = new RegExp(`${escapeForRegExp(quoted)}\\s*:`, 'g');
  pattern.lastIndex = fromIndex;
  const match = pattern.exec(raw);
  return match ? match.index : -1;
}

function toObjectRecord(value: unknown): Record<string, unknown> | undefined {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
  return value as Record<string, unknown>;
}

function toStringRecord(value: unknown): Record<string, string> | undefined {
  const record = toObjectRecord(value);
  if (!record) return undefined;

  const output: Record<string, string> = {};
  for (const [key, child] of Object.entries(record)) {
    Object.defineProperty(output, key, {
      value: String(child),
      enumerable: true,
      configurable: true,
      writable: true,
    });
  }
  return output;
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
  const lineStarts = buildLineStartIndex(raw);
  const totalLines = lineStarts.length;
  let searchFrom = 0;

  for (const [serverName, srv] of Object.entries<any>(safeServersObj)) {
    const keyIndex = findServerKeyIndex(raw, serverName, searchFrom);
    const serverLine = keyIndex >= 0 ? lineNumberAt(lineStarts, keyIndex) : 1;
    if (keyIndex >= 0) searchFrom = keyIndex + 1;

    const command = typeof srv?.command === 'string' ? srv.command : '';
    const args = Array.isArray(srv?.args) ? srv.args.map((a: any) => String(a)) : [];
    const env = (srv?.env && typeof srv.env === 'object') ? srv.env : {};
    const type = typeof srv?.type === 'string' ? srv.type : undefined;
    const url = typeof srv?.url === 'string' ? srv.url : undefined;
    const headers = toStringRecord(srv?.headers);
    const oauth = toObjectRecord(srv?.oauth);

    mcpServers.push({
      name: serverName,
      command,
      args,
      env,
      line: serverLine,
      ...(type ? { type } : {}),
      ...(url ? { url } : {}),
      ...(headers ? { headers } : {}),
      ...(oauth ? { oauth } : {}),
    });

    // Synthesize a single command line per server so line-oriented detection
    // lands on the server's real JSON line. Hardcoded env/header secrets are
    // reported structurally by SEC-MCP-002, so they are not duplicated here.
    if (command) {
      codeBlocks.push({
        language: 'sh',
        code: [command, ...args].join(' '),
        // Detection helpers treat the first content line as `startLine + 1`, so
        // anchor the synthesized block on the real JSON key line.
        startLine: Math.max(0, serverLine - 1),
        endLine: Math.min(totalLines, serverLine),
      });
    }
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
  // Normalise a leading UTF-8 BOM up front: without this the frontmatter
  // anchor below never matches and the skill loses its name/description.
  const source = stripBom(content);
  const trimmed = source.trim();
  if (looksLikeMcpJson(trimmed, defaultName)) {
    return parseMcpJson(source, defaultName);
  }

  let frontmatter: Record<string, any> = {};
  let body = source;

  // Simple YAML Frontmatter extraction
  const fmMatch = source.match(/^---\r?\n([\s\S]*?)\r?\n---/);
  if (fmMatch) {
    const yamlContent = fmMatch[1];
    body = source.slice(fmMatch[0].length);
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
  const lines = source.split(/\r?\n/);
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
    rawContent: source,
    kind: 'skill',
  };
}
