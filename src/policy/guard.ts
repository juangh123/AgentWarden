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
import {
  parseBaselineContent,
  type BaselineEntry,
  type BaselineSchema,
} from '../baseline/index.ts';
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
  /** Resolved commit SHA of the base ref. */
  sha: string;
  /** POSIX path of the config file inside the repository. */
  configPath: string;
  config: SkillGuardConfig;
  /** Repository-relative POSIX paths of the whole inheritance chain. */
  sources: string[];
}

export interface BaselineGuardResult {
  /** Repository-relative POSIX path of the baseline file. */
  path: string;
  /** Entries present on the approved base ref. */
  approvedEntries: number;
  /** Entries present in the working tree. */
  currentEntries: number;
  added: string[];
  removed: string[];
  changes: BaselineGuardChange[];
  changed: boolean;
}

export type BaselineGuardChangeKind = 'added' | 'removed' | 'changed';

export interface BaselineGuardChange {
  field: string;
  key?: string;
  kind: BaselineGuardChangeKind;
  before?: string | number | null | BaselineEntry[];
  after?: string | number | null | BaselineEntry[];
}

export interface PolicyGuardResult {
  approved: ApprovedPolicy;
  current: {
    configPath: string;
    config: SkillGuardConfig;
  };
  diff: PolicyDiff;
  baseline?: BaselineGuardResult;
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

function compareBaselineScalar(
  changes: BaselineGuardChange[],
  field: string,
  before: string | number | undefined,
  after: string | number | undefined,
): void {
  const normalizedBefore = before ?? null;
  const normalizedAfter = after ?? null;
  if (normalizedBefore !== normalizedAfter) {
    changes.push({
      field,
      kind: 'changed',
      before: normalizedBefore,
      after: normalizedAfter,
    });
  }
}

function sortedEntrySnapshots(entries: BaselineEntry[]): BaselineEntry[] {
  const snapshots = entries.map((entry) => ({
    fingerprint: entry.fingerprint,
    ruleId: entry.ruleId,
    file: entry.file,
    ...(entry.line !== undefined ? { line: entry.line } : {}),
    severity: entry.severity,
    ...(entry.acceptedAt !== undefined ? { acceptedAt: entry.acceptedAt } : {}),
  }));
  return snapshots.sort((left, right) =>
    JSON.stringify(left).localeCompare(JSON.stringify(right)),
  );
}

function entriesByFingerprint(baseline: BaselineSchema | undefined): Map<string, BaselineEntry[]> {
  const entries = new Map<string, BaselineEntry[]>();
  for (const entry of baseline?.entries ?? []) {
    const bucket = entries.get(entry.fingerprint) ?? [];
    bucket.push(entry);
    entries.set(entry.fingerprint, bucket);
  }
  return entries;
}

/**
 * Compare accepted-finding baselines by reviewed content. Adding an entry
 * suppresses a finding, while changing expiry or entry metadata can weaken or
 * misrepresent that review, so every non-cosmetic change requires a separate
 * approved update.
 *
 * @param baselinePath Repository-relative POSIX path of the approved baseline.
 */
export function guardBaseline(
  root: string,
  baseSha: string,
  baselinePath: string,
  currentBaseline: BaselineSchema | undefined,
): BaselineGuardResult {
  const repoPath = toPosix(baselinePath.replace(/^\/+/, ''));
  const approvedRaw = readBlob(root, baseSha, repoPath);
  let approved: BaselineSchema | undefined;
  if (approvedRaw !== undefined) {
    try {
      approved = parseBaselineContent(approvedRaw, repoPath);
    } catch (error) {
      throw new PolicyGuardError(
        `Approved baseline "${repoPath}" is invalid: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }

  const approvedEntries = entriesByFingerprint(approved);
  const currentEntries = entriesByFingerprint(currentBaseline);
  const added: string[] = [];
  const removed: string[] = [];
  const changes: BaselineGuardChange[] = [];

  compareBaselineScalar(
    changes,
    'baselineVersion',
    approved?.baselineVersion,
    currentBaseline?.baselineVersion,
  );
  compareBaselineScalar(changes, 'createdAt', approved?.createdAt, currentBaseline?.createdAt);
  compareBaselineScalar(
    changes,
    'review.reviewedAt',
    approved?.review?.reviewedAt,
    currentBaseline?.review?.reviewedAt,
  );
  compareBaselineScalar(
    changes,
    'review.owner',
    approved?.review?.owner,
    currentBaseline?.review?.owner,
  );
  compareBaselineScalar(
    changes,
    'review.expiresAt',
    approved?.review?.expiresAt,
    currentBaseline?.review?.expiresAt,
  );
  compareBaselineScalar(
    changes,
    'review.note',
    approved?.review?.note,
    currentBaseline?.review?.note,
  );

  const fingerprints = [...new Set([...approvedEntries.keys(), ...currentEntries.keys()])].sort();
  for (const fingerprint of fingerprints) {
    const before = approvedEntries.get(fingerprint);
    const after = currentEntries.get(fingerprint);
    if (before === undefined) {
      added.push(fingerprint);
      changes.push({
        field: 'entries',
        key: fingerprint,
        kind: 'added',
        after: sortedEntrySnapshots(after ?? []),
      });
      continue;
    }
    if (after === undefined) {
      removed.push(fingerprint);
      changes.push({
        field: 'entries',
        key: fingerprint,
        kind: 'removed',
        before: sortedEntrySnapshots(before),
      });
      continue;
    }

    const beforeSnapshot = sortedEntrySnapshots(before);
    const afterSnapshot = sortedEntrySnapshots(after);
    if (JSON.stringify(beforeSnapshot) !== JSON.stringify(afterSnapshot)) {
      changes.push({
        field: 'entries',
        key: fingerprint,
        kind: 'changed',
        before: beforeSnapshot,
        after: afterSnapshot,
      });
    }
  }

  return {
    path: repoPath,
    approvedEntries: approved?.entries.length ?? 0,
    currentEntries: currentBaseline?.entries.length ?? 0,
    added,
    removed,
    changes,
    changed: changes.length > 0,
  };
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
        sha,
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
  baseline?: BaselineGuardResult,
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
    ...(baseline ? { baseline } : {}),
  };
}

