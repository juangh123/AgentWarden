import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';

export interface ChangedFilesOptions {
  cwd?: string;
  base?: string;
  includeWorkingTree?: boolean;
  includeUntracked?: boolean;
}

export interface ChangedFilesResult {
  repositoryRoot: string;
  baseRef: string;
  baseSha: string;
  files: string[];
}

export class ChangedFilesError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ChangedFilesError';
  }
}

function canonicalPath(filePath: string): string {
  const resolved = path.resolve(filePath);
  try {
    return fs.realpathSync.native(resolved);
  } catch {
    return resolved;
  }
}

function runGit(cwd: string, args: string[], allowFailure = false): string {
  const result = spawnSync('git', ['-C', cwd, ...args], {
    encoding: 'utf8',
    windowsHide: true,
    maxBuffer: 10 * 1024 * 1024,
  });

  if (result.error) {
    throw new ChangedFilesError(`Unable to run git: ${result.error.message}`);
  }
  if (!allowFailure && result.status !== 0) {
    const detail = (result.stderr || result.stdout || '').trim();
    throw new ChangedFilesError(
      `Git command failed (${args.join(' ')}): ${detail || `exit ${String(result.status)}`}`,
    );
  }
  return result.stdout ?? '';
}

function resolveCommit(cwd: string, ref: string): string | undefined {
  const output = runGit(cwd, ['rev-parse', '--verify', '--quiet', `${ref}^{commit}`], true);
  return output.trim() || undefined;
}

function resolveBase(cwd: string, requested?: string): { ref: string; sha: string } {
  if (requested) {
    const sha = resolveCommit(cwd, requested);
    if (!sha) throw new ChangedFilesError(`Unable to resolve Git base ref "${requested}"`);
    return { ref: requested, sha };
  }

  const environmentRef = process.env.AGENTWARDEN_BASE_REF?.trim();
  const githubRef = process.env.GITHUB_BASE_REF?.trim();
  const candidates = [
    environmentRef,
    githubRef ? `origin/${githubRef}` : undefined,
    githubRef,
    'HEAD~1',
  ].filter((candidate): candidate is string => Boolean(candidate));

  for (const candidate of candidates) {
    const sha = resolveCommit(cwd, candidate);
    if (sha) return { ref: candidate, sha };
  }

  throw new ChangedFilesError(
    'Unable to determine a Git base ref. Pass --changed-from <ref> explicitly.',
  );
}

function parseNullSeparatedPaths(output: string): string[] {
  return output.split('\0').filter(Boolean);
}

function collectExistingFiles(repositoryRoot: string, candidates: Iterable<string>): string[] {
  const files = new Set<string>();
  for (const candidate of candidates) {
    const absolute = path.resolve(repositoryRoot, candidate);
    if (!fs.existsSync(absolute)) continue;
    if (fs.statSync(absolute).isFile()) files.add(absolute);
  }
  return [...files].sort((a, b) => a.localeCompare(b));
}

/** Resolve the Git changes that should participate in an incremental scan. */
export function getChangedFiles(options: ChangedFilesOptions = {}): ChangedFilesResult {
  const cwd = canonicalPath(options.cwd ?? process.cwd());
  if (!fs.existsSync(cwd) || !fs.statSync(cwd).isDirectory()) {
    throw new ChangedFilesError(`Working directory not found at ${cwd}`);
  }

  const repositoryRoot = canonicalPath(runGit(cwd, ['rev-parse', '--show-toplevel']).trim());
  if (!repositoryRoot) {
    throw new ChangedFilesError('Unable to resolve the Git repository root');
  }

  const base = resolveBase(repositoryRoot, options.base);
  const candidates = new Set<string>();
  const committed = runGit(repositoryRoot, [
    'diff',
    '--name-only',
    '-z',
    '--diff-filter=ACMR',
    `${base.sha}...HEAD`,
  ]);
  for (const filePath of parseNullSeparatedPaths(committed)) candidates.add(filePath);

  if (options.includeWorkingTree ?? true) {
    const workingTree = runGit(repositoryRoot, [
      'diff',
      '--name-only',
      '-z',
      '--diff-filter=ACMR',
      'HEAD',
    ]);
    for (const filePath of parseNullSeparatedPaths(workingTree)) candidates.add(filePath);
  }

  if (options.includeUntracked ?? true) {
    const untracked = runGit(repositoryRoot, [
      'ls-files',
      '--others',
      '--exclude-standard',
      '-z',
    ]);
    for (const filePath of parseNullSeparatedPaths(untracked)) candidates.add(filePath);
  }

  return {
    repositoryRoot,
    baseRef: base.ref,
    baseSha: base.sha,
    files: collectExistingFiles(repositoryRoot, candidates),
  };
}
