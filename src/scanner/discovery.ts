import * as fs from 'node:fs';
import * as path from 'node:path';

const MARKDOWN_EXTENSIONS = new Set(['.md', '.markdown']);

const MCP_CONFIG_FILENAMES = new Set([
  '.mcp.json',
  'mcp.json',
  'mcp-servers.json',
  'mcp_servers.json',
  'claude_desktop_config.json',
]);

const ALLOWED_HIDDEN_DIRECTORIES = new Set(['.claude', '.codex', '.cursor', '.vscode']);

const SKIPPED_DIRECTORIES = new Set([
  '.git',
  '.hg',
  '.svn',
  'coverage',
  'dist',
  'node_modules',
]);

function containsMcpServers(content: string): boolean {
  if (!/"(?:mcpServers|servers|mcp)"\s*:/.test(content)) return false;

  try {
    const parsed = JSON.parse(content) as Record<string, unknown>;
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return false;

    const mcp = parsed.mcp;
    const nestedServers =
      mcp && typeof mcp === 'object' && !Array.isArray(mcp)
        ? (mcp as Record<string, unknown>).servers
        : undefined;

    return [parsed.mcpServers, parsed.servers, nestedServers].some(
      (servers) => servers !== undefined && servers !== null && typeof servers === 'object' && !Array.isArray(servers),
    );
  } catch {
    return false;
  }
}

function isMcpJsonCandidate(filePath: string, content: string): boolean {
  const filename = path.basename(filePath).toLowerCase();
  if (MCP_CONFIG_FILENAMES.has(filename) || /(^|[-_.])mcp([-_.]|$).*\.json$/i.test(filename)) {
    return true;
  }
  return containsMcpServers(content);
}

function collectDirectoryFiles(directory: string): string[] {
  const files: string[] = [];
  const entries = fs.readdirSync(directory, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name));

  for (const entry of entries) {
    if (entry.isSymbolicLink()) continue;

    const fullPath = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      if (SKIPPED_DIRECTORIES.has(entry.name)) continue;
      if (entry.name.startsWith('.') && !ALLOWED_HIDDEN_DIRECTORIES.has(entry.name)) continue;
      files.push(...collectDirectoryFiles(fullPath));
      continue;
    }

    if (!entry.isFile()) continue;

    if (MARKDOWN_EXTENSIONS.has(path.extname(entry.name).toLowerCase())) {
      files.push(fullPath);
      continue;
    }

    if (path.extname(entry.name).toLowerCase() !== '.json') continue;

    const content = fs.readFileSync(fullPath, 'utf8');
    if (isMcpJsonCandidate(fullPath, content)) {
      files.push(fullPath);
    }
  }

  return files;
}

/**
 * Discover Markdown skills and MCP JSON configuration files under one or more paths.
 * Explicit file paths are always returned, even when their extension is non-standard.
 */
export function discoverSkillFiles(targetPaths: string | string[], cwd: string = process.cwd()): string[] {
  const targets = Array.isArray(targetPaths) ? targetPaths : [targetPaths];
  const discovered = new Set<string>();

  for (const target of targets) {
    const absolute = path.resolve(cwd, target);
    const stat = fs.statSync(absolute);

    if (stat.isFile()) {
      discovered.add(absolute);
    } else if (stat.isDirectory()) {
      for (const file of collectDirectoryFiles(absolute)) {
        discovered.add(file);
      }
    }
  }

  return [...discovered].sort((a, b) => a.localeCompare(b));
}
