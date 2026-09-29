import * as fs from 'node:fs';
import * as path from 'node:path';
import type { SkillPackageManifestEntry } from '../source/package.ts';
import { writeFileAtomic } from '../utils/atomicWrite.ts';

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
  packageFormat?: 'tar.gz';
  packageSha256?: string;
  packageEntry?: string;
  packageFiles?: SkillPackageManifestEntry[];
  signatureAlgorithm?: 'ed25519';
  signatureVerified?: boolean;
  signatureKeySha256?: string;
  signatureSha256?: string;
  signatureProof?: SignatureProof;
}

export interface SignatureProof {
  algorithm: 'ed25519';
  publicKey: string;
  signature: string;
  payloadSha256: string;
}

export interface LockfileSchema {
  lockfileVersion: number;
  skills: Record<string, LockedSkill>;
}

export const LOCKFILE_NAME = 'skills.lock';

const UNSAFE_SKILL_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

function createSkillMap(): Record<string, LockedSkill> {
  return Object.create(null) as Record<string, LockedSkill>;
}

function isSafeRelativePath(value: string): boolean {
  if (!value || value.includes('\0')) return false;
  const normalized = value.replace(/\\/g, '/');
  if (normalized.startsWith('/') || /^[A-Za-z]:/.test(normalized)) return false;
  return !normalized.split('/').includes('..');
}

function isUnsafeSkillKey(name: string): boolean {
  return UNSAFE_SKILL_KEYS.has(name.trim().toLowerCase());
}

function isCanonicalBase64(value: unknown, expectedBytes?: number): value is string {
  if (typeof value !== 'string' || !value || value.length % 4 !== 0) return false;
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(value)) return false;
  const decoded = Buffer.from(value, 'base64');
  if (decoded.toString('base64') !== value) return false;
  return expectedBytes === undefined || decoded.byteLength === expectedBytes;
}

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

  const signatureFields = [
    entry.signatureAlgorithm,
    entry.signatureVerified,
    entry.signatureKeySha256,
    entry.signatureSha256,
  ];
  if (signatureFields.some((value) => value !== undefined)) {
    if (entry.signatureAlgorithm !== 'ed25519') {
      throw new Error(
        `Invalid ${LOCKFILE_NAME} at ${lockPath}: entry "${name}" has invalid signatureAlgorithm.`,
      );
    }
    if (entry.signatureVerified !== true) {
      throw new Error(
        `Invalid ${LOCKFILE_NAME} at ${lockPath}: entry "${name}" has invalid signatureVerified.`,
      );
    }
    for (const field of ['signatureKeySha256', 'signatureSha256'] as const) {
      if (typeof entry[field] !== 'string' || !/^[a-f0-9]{64}$/i.test(entry[field])) {
        throw new Error(
          `Invalid ${LOCKFILE_NAME} at ${lockPath}: entry "${name}" has invalid ${field}.`,
        );
      }
    }
  }

  const signatureProof = entry.signatureProof;
  if (signatureProof !== undefined) {
    if (!signatureProof || typeof signatureProof !== 'object' || Array.isArray(signatureProof)) {
      throw new Error(
        `Invalid ${LOCKFILE_NAME} at ${lockPath}: entry "${name}" has invalid signatureProof.`,
      );
    }
    const proof = signatureProof as Record<string, unknown>;
    if (proof.algorithm !== 'ed25519') {
      throw new Error(
        `Invalid ${LOCKFILE_NAME} at ${lockPath}: entry "${name}" has invalid signatureProof.algorithm.`,
      );
    }
    if (!isCanonicalBase64(proof.publicKey) || Buffer.from(proof.publicKey, 'base64').byteLength > 16 * 1024) {
      throw new Error(
        `Invalid ${LOCKFILE_NAME} at ${lockPath}: entry "${name}" has invalid signatureProof.publicKey.`,
      );
    }
    if (!isCanonicalBase64(proof.signature, 64)) {
      throw new Error(
        `Invalid ${LOCKFILE_NAME} at ${lockPath}: entry "${name}" has invalid signatureProof.signature.`,
      );
    }
    if (typeof proof.payloadSha256 !== 'string' || !/^[a-f0-9]{64}$/i.test(proof.payloadSha256)) {
      throw new Error(
        `Invalid ${LOCKFILE_NAME} at ${lockPath}: entry "${name}" has invalid signatureProof.payloadSha256.`,
      );
    }
    if (
      entry.signatureAlgorithm !== undefined &&
      entry.signatureAlgorithm !== proof.algorithm
    ) {
      throw new Error(
        `Invalid ${LOCKFILE_NAME} at ${lockPath}: entry "${name}" signatureProof does not match signatureAlgorithm.`,
      );
    }
  }

  const packageFields = [
    entry.packageFormat,
    entry.packageSha256,
    entry.packageEntry,
    entry.packageFiles,
  ];
  const hasPackageMetadata = packageFields.some((value) => value !== undefined);
  if (!hasPackageMetadata) return;

  if (entry.packageFormat !== 'tar.gz') {
    throw new Error(
      `Invalid ${LOCKFILE_NAME} at ${lockPath}: entry "${name}" has invalid packageFormat.`,
    );
  }
  if (
    typeof entry.packageSha256 !== 'string' ||
    !/^[a-f0-9]{64}$/i.test(entry.packageSha256)
  ) {
    throw new Error(
      `Invalid ${LOCKFILE_NAME} at ${lockPath}: entry "${name}" has invalid packageSha256.`,
    );
  }
  if (
    typeof entry.packageEntry !== 'string' ||
    !entry.packageEntry ||
    path.isAbsolute(entry.packageEntry) ||
    entry.packageEntry.replace(/\\/g, '/').split('/').includes('..') ||
    path.posix.basename(entry.packageEntry.replace(/\\/g, '/')).toLowerCase() !== 'skill.md'
  ) {
    throw new Error(
      `Invalid ${LOCKFILE_NAME} at ${lockPath}: entry "${name}" has invalid packageEntry.`,
    );
  }
  if (!Array.isArray(entry.packageFiles) || entry.packageFiles.length === 0) {
    throw new Error(
      `Invalid ${LOCKFILE_NAME} at ${lockPath}: entry "${name}" has invalid packageFiles.`,
    );
  }
  if (entry.packageFiles.length > 256) {
    throw new Error(
      `Invalid ${LOCKFILE_NAME} at ${lockPath}: entry "${name}" has too many packageFiles.`,
    );
  }

  const normalizedPackageFiles = new Set<string>();
  for (const packageFile of entry.packageFiles) {
    if (!packageFile || typeof packageFile !== 'object' || Array.isArray(packageFile)) {
      throw new Error(
        `Invalid ${LOCKFILE_NAME} at ${lockPath}: entry "${name}" has invalid package file metadata.`,
      );
    }
    const candidate = packageFile as Record<string, unknown>;
    if (
      typeof candidate.path !== 'string' ||
      !candidate.path ||
      path.isAbsolute(candidate.path) ||
      candidate.path.replace(/\\/g, '/').split('/').includes('..') ||
      typeof candidate.sha256 !== 'string' ||
      !/^[a-f0-9]{64}$/i.test(candidate.sha256) ||
      typeof candidate.size !== 'number' ||
      !Number.isSafeInteger(candidate.size) ||
      candidate.size < 0
    ) {
      throw new Error(
        `Invalid ${LOCKFILE_NAME} at ${lockPath}: entry "${name}" has invalid package file metadata.`,
      );
    }
    const normalizedPath = candidate.path.replace(/\\/g, '/').toLowerCase();
    if (normalizedPackageFiles.has(normalizedPath)) {
      throw new Error(
        `Invalid ${LOCKFILE_NAME} at ${lockPath}: entry "${name}" has duplicate package file paths.`,
      );
    }
    normalizedPackageFiles.add(normalizedPath);
  }

  const normalizedEntry = entry.packageEntry.replace(/\\/g, '/').toLowerCase();
  if (!normalizedPackageFiles.has(normalizedEntry)) {
    throw new Error(
      `Invalid ${LOCKFILE_NAME} at ${lockPath}: entry "${name}" packageEntry is missing from packageFiles.`,
    );
  }
}

function normalizeLockedEntry(entry: Record<string, unknown>): void {
  entry.sha256 = String(entry.sha256).toLowerCase();
  entry.source = normalizePath(String(entry.source));

  for (const field of ['downloadSha256', 'signatureKeySha256', 'signatureSha256'] as const) {
    if (typeof entry[field] === 'string') {
      entry[field] = entry[field].toLowerCase();
    }
  }

  const proof = entry.signatureProof;
  if (proof && typeof proof === 'object' && !Array.isArray(proof)) {
    const candidate = proof as Record<string, unknown>;
    if (typeof candidate.payloadSha256 === 'string') {
      candidate.payloadSha256 = candidate.payloadSha256.toLowerCase();
    }
  }

  if (!Array.isArray(entry.packageFiles)) return;
  if (typeof entry.packageEntry === 'string') {
    entry.packageEntry = normalizePath(entry.packageEntry);
  }
  if (typeof entry.packageSha256 === 'string') {
    entry.packageSha256 = entry.packageSha256.toLowerCase();
  }
  for (const packageFile of entry.packageFiles) {
    if (!packageFile || typeof packageFile !== 'object' || Array.isArray(packageFile)) continue;
    const candidate = packageFile as Record<string, unknown>;
    if (typeof candidate.path === 'string') {
      candidate.path = normalizePath(candidate.path);
    }
    if (typeof candidate.sha256 === 'string') {
      candidate.sha256 = candidate.sha256.toLowerCase();
    }
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
  const lockfileVersion = candidate.lockfileVersion ?? 1;
  if (
    !Number.isSafeInteger(lockfileVersion) ||
    lockfileVersion < 1 ||
    lockfileVersion > 1
  ) {
    throw new Error(
      `Invalid ${LOCKFILE_NAME} at ${lockPath}: unsupported lockfileVersion.`,
    );
  }
  if (!candidate.skills || typeof candidate.skills !== 'object' || Array.isArray(candidate.skills)) {
    throw new Error(`Invalid ${LOCKFILE_NAME} at ${lockPath}: missing "skills" object.`);
  }

  const skills = candidate.skills as Record<string, unknown>;
  const normalizedKeys = new Set<string>();
  const validatedSkills = createSkillMap();
  for (const [name, skill] of Object.entries(skills)) {
    const normalizedName = name.trim().toLowerCase();
    if (
      !normalizedName ||
      name !== name.trim() ||
      isUnsafeSkillKey(name) ||
      normalizedKeys.has(normalizedName)
    ) {
      throw new Error(
        `Invalid ${LOCKFILE_NAME} at ${lockPath}: duplicate or empty skill key "${name}".`,
      );
    }
    normalizedKeys.add(normalizedName);
    if (!skill || typeof skill !== 'object' || Array.isArray(skill)) {
      throw new Error(`Invalid ${LOCKFILE_NAME} at ${lockPath}: entry "${name}" must be an object.`);
    }
    const entry = skill as Record<string, unknown>;
    if (
      typeof entry.name !== 'string' ||
      !entry.name.trim() ||
      typeof entry.version !== 'string' ||
      !entry.version.trim() ||
      typeof entry.source !== 'string' ||
      !entry.source.trim() ||
      entry.source !== entry.source.trim() ||
      !isSafeRelativePath(entry.source.trim()) ||
      typeof entry.sha256 !== 'string' ||
      !/^[a-f0-9]{64}$/i.test(entry.sha256) ||
      typeof entry.installedAt !== 'string' ||
      Number.isNaN(Date.parse(entry.installedAt)) ||
      typeof entry.verifiedScore !== 'number' ||
      !Number.isSafeInteger(entry.verifiedScore) ||
      entry.verifiedScore < 0 ||
      entry.verifiedScore > 100
    ) {
      throw new Error(`Invalid ${LOCKFILE_NAME} at ${lockPath}: entry "${name}" has missing or invalid fields.`);
    }
    validateOptionalSourceMetadata(entry, name, lockPath);
    normalizeLockedEntry(entry);
    validatedSkills[name] = entry as unknown as LockedSkill;
  }

  return {
    lockfileVersion,
    skills: validatedSkills,
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
    return { lockfileVersion: 1, skills: createSkillMap() };
  }
  return parseLockfile(fs.readFileSync(lockPath, 'utf8'), lockPath);
}

export function writeLockfile(data: LockfileSchema, cwd: string = process.cwd()): void {
  const lockPath = path.join(cwd, LOCKFILE_NAME);
  const sorted: LockfileSchema = {
    lockfileVersion: data.lockfileVersion,
    skills: createSkillMap(),
  };
  for (const key of Object.keys(data.skills).sort((a, b) => a.localeCompare(b))) {
    sorted.skills[key] = data.skills[key];
  }
  const serialized = JSON.stringify(sorted, null, 2) + '\n';
  parseLockfile(serialized, lockPath);
  writeFileAtomic(lockPath, serialized);
}

export function updateLockfileSkill(skill: LockedSkill, cwd: string = process.cwd()): void {
  const lock = readLockfile(cwd);
  if (isUnsafeSkillKey(skill.name) || skill.name !== skill.name.trim() || !skill.name) {
    throw new Error(`Invalid skill name "${skill.name}".`);
  }
  const existingKey = findSkillKey(lock, skill.name);
  if (existingKey && existingKey !== skill.name) {
    delete lock.skills[existingKey];
  }
  lock.skills[skill.name] = {
    ...skill,
    source: normalizePath(skill.source)
  };
  writeLockfile(lock, cwd);
}

/** Exact match first, then a case-insensitive fallback (returns the stored key). */
export function findSkillKey(lock: LockfileSchema, name: string): string | undefined {
  if (!name) return undefined;
  if (Object.hasOwn(lock.skills, name)) return name;
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
