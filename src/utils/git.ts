import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';

export interface GitRunOptions {
  /** Return git's output even when the command exits non-zero. */
  allowFailure?: boolean;
  /** Wrap failure messages in the caller's error type. */
  wrap?: (message: string) => Error;
}

/** Run a git command inside `cwd` and return its standard output. */
export function runGit(cwd: string, args: string[], options: GitRunOptions = {}): string {
  const result = spawnSync('git', ['-C', cwd, ...args], {
    encoding: 'utf8',
    windowsHide: true,
    maxBuffer: 10 * 1024 * 1024,
  });

  const failure = (message: string): never => {
    throw options.wrap ? options.wrap(message) : new Error(message);
  };
  if (result.error) {
    failure(`Unable to run git: ${result.error.message}`);
  }
  if (!options.allowFailure && result.status !== 0) {
    const detail = (result.stderr || result.stdout || '').trim();
    failure(`Git command failed (${args.join(' ')}): ${detail || `exit ${String(result.status)}`}`);
  }
  return result.stdout ?? '';
}

/** Resolve a path to its real location, falling back to the resolved path. */
export function canonicalPath(filePath: string): string {
  const resolved = path.resolve(filePath);
  try {
    return fs.realpathSync.native(resolved);
  } catch {
    return resolved;
  }
}
