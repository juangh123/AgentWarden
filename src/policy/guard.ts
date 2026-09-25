import * as fs from 'node:fs';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import {
  CONFIG_FILE_NAMES,
  normalizeConfig,
  readConfigTreeFrom,
  type ConfigTreeReader,
  type SkillGuardConfig,
} from '../config/index.ts';
import { diffPolicyConfigs, type PolicyDiff } from './diff.ts';

export class PolicyGuardError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PolicyGuardError';
  }
}

export interface ApprovedPolicyOptions {
  /** Git ref, branch, tag, or commit that carries the approved policy. */
  base: string;
  /** Repository-relative config path. Defaults to auto-discovery on the base ref. */
  configPath?: string;
  /** Working directory used to locate the repository. */
  cwd?: string;
}

export interface ApprovedPolicy {
  repositoryRoot: string;
  baseRef: string;
  /** POSIX path of the config file inside the repository. */
  configPath: string;
  config: SkillGuardConfig;
  /** Repository-relative POSIX paths of the whole inheritance chain. */
  sources: string[];
}

export interface PolicyGuardResult {
  approved: ApprovedPolicy;
  current: {
    configPath: string;
    config: SkillGuardConfig;
  };
  diff: PolicyDiff;
}

function runGit(cwd: string, args: string[], allowFailure = false): string {
  const result = spawnSync('git', ['-C', cwd, ...args], {
    encoding: 'utf8',
    windowsHide: true,
    maxBuffer: 10 * 1024 * 1024,
  });
  if (result.error) {
    throw new PolicyGuardError(`Unable to run git: ${result.error.message}`);
  }
  if (!allowFailure && result.status !== 0) {
    const detail = (result.stderr || result.stdout || '').trim();
    throw new PolicyGuardError(
      `Git command failed (${args.join(' ')}): ${detail || `exit ${String(result.status)}`}`,
    );
  }
  return result.stdout ?? '';
}

function canonicalPath(filePath: string): string {
  const resolved = path.resolve(filePath);
  try {
    return fs.realpathSync.native(resolved);
  } catch {
    return resolved;
  }
}

function repositoryRootFor(cwd: string): string {
  try {
    return canonicalPath(runGit(cwd, ['rev-parse', '--show-toplevel']).trim());
  } catch (error) {
    throw new PolicyGuardError(
      error instanceof Error ? error.message : 'Unable to resolve the Git repository root',
    );
  }
}

function resolveCommit(root: string, ref: string): string {
  const sha = runGit(root, ['rev-parse', '--verify', '--quiet', `${ref}^{commit}`], true).trim();
  if (!sha) throw new PolicyGuardError(`Unable to resolve Git base ref "${ref}"`);
  return sha;
}

function toPosix(relativePath: string): string {
  return relativePath.split(path.sep).join('/');
}

function relativeToRoot(root: string, filePath: string): string {
  return toPosix(path.relative(root, path.resolve(root, filePath)));
}

function repositoryRelativePath(root: string, filePath: string): string {
  const absolute = canonicalPath(filePath);
  const relative = path.relative(root, absolute);
  if (relative === '' || relative.startsWith('..') || path.isAbsolute(relative)) {
    return toPosix(absolute);
  }
  return toPosix(relative);
}

function readBlob(root: string, ref: string, repoPath: string): string | undefined {
  const result = spawnSync('git', ['-C', root, 'show', `${ref}:${repoPath}`], {
    encoding: 'utf8',
    windowsHide: true,
    maxBuffer: 10 * 1024 * 1024,
  });
  if (result.error) {
    throw new PolicyGuardError(`Unable to run git: ${result.error.message}`);
  }
  if (result.status !== 0) {
    if (/does not exist|exists on disk, but not in|Path .* does not exist/i.test(result.stderr ?? '')) {
      return undefined;
    }
    const detail = (result.stderr || result.stdout || '').trim();
    throw new PolicyGuardError(
      `Unable to read ${repoPath} from ${ref}: ${detail || `exit ${String(result.status)}`}`,
    );
  }
  return result.stdout;
}

function refConfigReader(root: string, sha: string): ConfigTreeReader {
  return {
    read(filePath: string): string | undefined {
      return readBlob(root, sha, relativeToRoot(root, filePath));
    },
    identity(filePath: string): string {
      return relativeToRoot(root, filePath);
    },
  };
}

/**
 * Resolve the effective policy committed on a base ref. Explicit paths are
 * resolved relative to the repository root; otherwise the same candidate
 * filenames used in the working tree are tried in order.
 */
export function loadApprovedPolicy(options: ApprovedPolicyOptions): ApprovedPolicy {
  const cwd = path.resolve(options.cwd ?? process.cwd());
  const root = repositoryRootFor(cwd);
  const sha = resolveCommit(root, options.base);
  const requested = options.configPath?.trim();
  const candidates = requested
    ? [toPosix(requested).replace(/^\/+/, '')]
    : CONFIG_FILE_NAMES.map((name) => toPosix(name));
  const reader = refConfigReader(root, sha);
  let lastError: Error | undefined;

  for (const configPath of candidates) {
    if (readBlob(root, sha, configPath) === undefined) continue;
    try {
      const tree = readConfigTreeFrom(path.join(root, configPath), reader);
      return {
        repositoryRoot: root,
        baseRef: options.base,
        configPath,
        config: normalizeConfig(tree.config),
        sources: tree.sources.map((source) => relativeToRoot(root, source)),
      };
    } catch (error) {
      lastError = error instanceof Error ? error : new Error(String(error));
      if (requested) break;
    }
  }

  if (requested) {
    throw new PolicyGuardError(
      lastError
        ? `Approved policy "${requested}" is invalid on ${options.base}: ${lastError.message}`
        : `Approved policy "${requested}" was not found on ${options.base}`,
    );
  }
  if (lastError) {
    throw new PolicyGuardError(
      `Approved policy on ${options.base} is invalid: ${lastError.message}`,
    );
  }
  throw new PolicyGuardError(
    `No approved policy file was found on ${options.base} (looked for ${candidates.join(', ')})`,
  );
}

/**
 * Compare the policy proposed by the working tree with the effective policy
 * committed on the base ref. The comparison uses normalized values, so adding
 * redundant defaults does not trigger a false positive.
 */
export function guardPolicy(
  approved: ApprovedPolicy,
  currentConfig: SkillGuardConfig,
  currentConfigPath?: string,
): PolicyGuardResult {
  const currentPath = currentConfigPath
    ? repositoryRelativePath(approved.repositoryRoot, currentConfigPath)
    : approved.configPath;
  return {
    approved,
    current: {
      configPath: currentPath,
      config: normalizeConfig(currentConfig),
    },
    diff: diffPolicyConfigs(approved.config, currentConfig),
  };
}

