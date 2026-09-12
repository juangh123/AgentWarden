import * as fs from 'node:fs';
import * as path from 'node:path';

export interface LockedSkill {
  name: string;
  version: string;
  source: string;
  sha256: string;
  installedAt: string;
  verifiedScore: number;
  sourceType?: 'local' | 'remote';
  remoteUrl?: string;
  resolvedUrl?: string;
  downloadSha256?: string;
  digestVerified?: boolean;
}

export interface LockfileSchema {
  lockfileVersion: number;
  skills: Record<string, LockedSkill>;
}

export const LOCKFILE_NAME = 'skills.lock';

function validateOptionalSourceMetadata(
  entry: Record<string, unknown>,
  name: string,
  lockPath: string,
): void {
  const sourceType = entry.sourceType;
  if (sourceType !== undefined && sourceType !== 'local' && sourceType !== 'remote') {
    throw new Error(
      `Invalid ${LOCKFILE_NAME} at ${lockPath}: entry "${name}" has invalid sourceType.`,
    );
  }

  for (const field of ['remoteUrl', 'resolvedUrl', 'downloadSha256'] as const) {
    if (entry[field] !== undefined && typeof entry[field] !== 'string') {
      throw new Error(
        `Invalid ${LOCKFILE_NAME} at ${lockPath}: entry "${name}" has invalid ${field}.`,
      );
    }
  }
  if (entry.digestVerified !== undefined && typeof entry.digestVerified !== 'boolean') {
    throw new Error(
      `Invalid ${LOCKFILE_NAME} at ${lockPath}: entry "${name}" has invalid digestVerified.`,
    );
  }
  if (
    typeof entry.downloadSha256 === 'string' &&
    !/^[a-f0-9]{64}$/i.test(entry.downloadSha256)
  ) {
    throw new Error(
      `Invalid ${LOCKFILE_NAME} at ${lockPath}: entry "${name}" has invalid downloadSha256.`,
    );
  }

  const hasRemoteMetadata =
    entry.remoteUrl !== undefined ||
    entry.resolvedUrl !== undefined ||
    entry.downloadSha256 !== undefined ||
    entry.digestVerified !== undefined;
  if (hasRemoteMetadata && sourceType !== 'remote') {
    throw new Error(
      `Invalid ${LOCKFILE_NAME} at ${lockPath}: entry "${name}" has remote metadata without sourceType "remote".`,
    );
  }
}

function parseLockfile(raw: string, lockPath: string): LockfileSchema {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new Error(`Invalid ${LOCKFILE_NAME} JSON at ${lockPath}: ${err instanceof Error ? err.message : String(err)}`);
  }

  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error(`Invalid ${LOCKFILE_NAME} at ${lockPath}: expected a top-level object.`);
  }

  const candidate = parsed as Partial<LockfileSchema>;
  if (!candidate.skills || typeof candidate.skills !== 'object' || Array.isArray(candidate.skills)) {
    throw new Error(`Invalid ${LOCKFILE_NAME} at ${lockPath}: missing "skills" object.`);
  }

  const skills = candidate.skills as Record<string, unknown>;
  for (const [name, skill] of Object.entries(skills)) {
    if (!skill || typeof skill !== 'object' || Array.isArray(skill)) {
      throw new Error(`Invalid ${LOCKFILE_NAME} at ${lockPath}: entry "${name}" must be an object.`);
    }
    const entry = skill as Record<string, unknown>;
    if (
      typeof entry.name !== 'string' ||
      typeof entry.version !== 'string' ||
      typeof entry.source !== 'string' ||
      typeof entry.sha256 !== 'string' ||
      typeof entry.installedAt !== 'string' ||
      typeof entry.verifiedScore !== 'number'
    ) {
      throw new Error(`Invalid ${LOCKFILE_NAME} at ${lockPath}: entry "${name}" has missing or invalid fields.`);
    }
    validateOptionalSourceMetadata(entry, name, lockPath);
  }

  return {
    lockfileVersion: typeof candidate.lockfileVersion === 'number' ? candidate.lockfileVersion : 1,
    skills: candidate.skills as Record<string, LockedSkill>,
  };
}

export function normalizePath(p: string): string {
  return p.replace(/\\/g, '/');
}

export function toRelativePosix(targetPath: string, rootDir: string = process.cwd()): string {
  const rel = path.relative(rootDir, targetPath);
  return normalizePath(rel);
}

export function resolveFromRoot(targetPath: string, rootDir: string = process.cwd()): string {
  return path.resolve(rootDir, targetPath);
}

export function readLockfile(cwd: string = process.cwd()): LockfileSchema {
  const lockPath = path.join(cwd, LOCKFILE_NAME);
  if (!fs.existsSync(lockPath)) {
    return { lockfileVersion: 1, skills: {} };
  }
  return parseLockfile(fs.readFileSync(lockPath, 'utf8'), lockPath);
}

export function writeLockfile(data: LockfileSchema, cwd: string = process.cwd()): void {
  const lockPath = path.join(cwd, LOCKFILE_NAME);
  const sorted: LockfileSchema = { lockfileVersion: data.lockfileVersion, skills: {} };
  for (const key of Object.keys(data.skills).sort((a, b) => a.localeCompare(b))) {
    sorted.skills[key] = data.skills[key];
  }
  fs.writeFileSync(lockPath, JSON.stringify(sorted, null, 2) + '\n', 'utf8');
}

export function updateLockfileSkill(skill: LockedSkill, cwd: string = process.cwd()): void {
  const lock = readLockfile(cwd);
  lock.skills[skill.name] = {
    ...skill,
    source: normalizePath(skill.source)
  };
  writeLockfile(lock, cwd);
}

/** Exact match first, then a case-insensitive fallback (returns the stored key). */
export function findSkillKey(lock: LockfileSchema, name: string): string | undefined {
  if (!name) return undefined;
  if (lock.skills[name]) return name;
  const lower = name.toLowerCase();
  return Object.keys(lock.skills).find((k) => k.toLowerCase() === lower);
}

export function removeLockfileSkill(name: string, cwd: string = process.cwd()): boolean {
  const lock = readLockfile(cwd);
  const key = findSkillKey(lock, name);
  if (!key) return false;
  delete lock.skills[key];
  writeLockfile(lock, cwd);
  return true;
}
