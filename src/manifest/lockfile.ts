import * as fs from 'node:fs';
import * as path from 'node:path';

export interface LockedSkill {
  name: string;
  version: string;
  source: string;
  sha256: string;
  installedAt: string;
  verifiedScore: number;
}

export interface LockfileSchema {
  lockfileVersion: number;
  skills: Record<string, LockedSkill>;
}

export const LOCKFILE_NAME = 'skills.lock';

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
  try {
    const raw = fs.readFileSync(lockPath, 'utf8');
    return JSON.parse(raw) as LockfileSchema;
  } catch {
    return { lockfileVersion: 1, skills: {} };
  }
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
