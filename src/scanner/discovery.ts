import * as fs from 'node:fs';
import * as path from 'node:path';
import { extractMcpServersObject, isMcpConfigFilename } from '../parser/mcpConfig.ts';

const MARKDOWN_EXTENSIONS = new Set(['.md', '.markdown']);

const ALLOWED_HIDDEN_DIRECTORIES = new Set([
  '.claude',
  '.cline',
  '.codeium',
  '.codex',
  '.continue',
  '.copilot',
  '.cursor',
  '.devcontainer',
  '.gemini',
  '.qwen',
  '.roo',
  '.vscode',
  '.windsurf',
  '.zed',
]);

const SKIPPED_DIRECTORIES = new Set([
  '.git',
  '.hg',
  '.svn',
  'coverage',
  'dist',
  'node_modules',
]);

export interface DiscoveryOptions {
  include?: string[];
  exclude?: string[];
}

function toRelativePosix(filePath: string, cwd: string): string {
  const relative = path.isAbsolute(filePath) ? path.relative(cwd, filePath) : filePath;
  return (relative || filePath).replace(/\\/g, '/');
}

function globToRegExp(pattern: string): RegExp {
  const normalized = pattern.trim().replace(/\\/g, '/').replace(/^\.\//, '');
  let source = '';

  for (let index = 0; index < normalized.length; index++) {
    const char = normalized[index];
    if (char === '*') {
      if (normalized[index + 1] === '*') {
        index++;
        if (normalized[index + 1] === '/') {
          index++;
          source += '(?:.*/)?';
        } else {
          source += '.*';
        }
      } else {
        source += '[^/]*';
      }
    } else if (char === '?') {
      source += '[^/]';
    } else {
      source += char.replace(/[|\\{}()[\]^$+?.]/g, '\\$&');
    }
  }

  return new RegExp(`(?:^|/)${source}$`);
}

function matchesAnyGlob(filePath: string, cwd: string, patterns: string[]): boolean {
  if (patterns.length === 0) return false;
  const relative = toRelativePosix(filePath, cwd);
  return patterns.some((pattern) => globToRegExp(pattern).test(relative));
}

function isIncluded(filePath: string, cwd: string, options: DiscoveryOptions): boolean {
  const include = options.include ?? [];
  const exclude = options.exclude ?? [];
  if (matchesAnyGlob(filePath, cwd, exclude)) return false;
  if (include.length === 0) return true;
  return matchesAnyGlob(filePath, cwd, include);
}

function containsMcpServers(content: string): boolean {
  if (!/"(?:mcpServers|servers|mcp|context_servers|customizations)"\s*:/.test(content)) return false;

  try {
    return extractMcpServersObject(JSON.parse(content)) !== undefined;
  } catch {
    return false;
  }
}

function isMcpJsonCandidate(filePath: string, content: string): boolean {
  if (isMcpConfigFilename(filePath)) return true;
  return containsMcpServers(content);
}

/** Return whether a file is a supported Markdown skill or MCP JSON configuration. */
export function isSupportedSkillFile(filePath: string): boolean {
  const extension = path.extname(filePath).toLowerCase();
  if (MARKDOWN_EXTENSIONS.has(extension)) return true;
  if (extension !== '.json') return false;

  try {
    return isMcpJsonCandidate(filePath, fs.readFileSync(filePath, 'utf8'));
  } catch {
    return false;
  }
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

    if (isSupportedSkillFile(fullPath)) {
      files.push(fullPath);
    }
  }

  return files;
}

/**
 * Discover Markdown skills and MCP JSON configuration files under one or more paths.
 * Explicit file paths are always returned, even when their extension is non-standard.
 */
export function discoverSkillFiles(
  targetPaths: string | string[],
  cwd: string = process.cwd(),
  options: DiscoveryOptions = {},
): string[] {
  const targets = Array.isArray(targetPaths) ? targetPaths : [targetPaths];
  const discovered = new Set<string>();

  for (const target of targets) {
    const absolute = path.resolve(cwd, target);
    const stat = fs.statSync(absolute);

    if (stat.isFile()) {
      discovered.add(absolute);
    } else if (stat.isDirectory()) {
      for (const file of collectDirectoryFiles(absolute)) {
        if (isIncluded(file, cwd, options)) {
          discovered.add(file);
        }
      }
    }
  }

  return [...discovered].sort((a, b) => a.localeCompare(b));
}

/** Filter an explicit list of paths to supported skill files within the configured scan scope. */
export function filterSkillFiles(
  filePaths: string[],
  cwd: string = process.cwd(),
  options: DiscoveryOptions = {},
): string[] {
  const discovered = new Set<string>();

  for (const filePath of filePaths) {
    const absolute = path.resolve(cwd, filePath);
    if (!fs.existsSync(absolute)) continue;
    const stat = fs.statSync(absolute);
    if (!stat.isFile() || !isSupportedSkillFile(absolute)) continue;
    if (isIncluded(absolute, cwd, options)) {
      discovered.add(absolute);
    }
  }

  return [...discovered].sort((a, b) => a.localeCompare(b));
}
