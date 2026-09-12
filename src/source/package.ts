import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as zlib from 'node:zlib';

export const DEFAULT_MAX_COMPRESSED_PACKAGE_BYTES = 5 * 1024 * 1024;
export const DEFAULT_MAX_PACKAGE_FILES = 256;
export const DEFAULT_MAX_PACKAGE_FILE_BYTES = 5 * 1024 * 1024;
export const DEFAULT_MAX_PACKAGE_UNPACKED_BYTES = 20 * 1024 * 1024;

export type SkillPackageErrorCode =
  | 'INVALID_ARCHIVE'
  | 'UNSUPPORTED_ENTRY'
  | 'UNSAFE_PATH'
  | 'DUPLICATE_ENTRY'
  | 'TOO_MANY_FILES'
  | 'FILE_TOO_LARGE'
  | 'PACKAGE_TOO_LARGE'
  | 'MISSING_ENTRY'
  | 'AMBIGUOUS_ENTRY'
  | 'INVALID_LAYOUT'
  | 'INSTALL_FAILED';

export class SkillPackageError extends Error {
  readonly code: SkillPackageErrorCode;

  constructor(code: SkillPackageErrorCode, message: string) {
    super(message);
    this.name = 'SkillPackageError';
    this.code = code;
  }
}

export interface SkillPackageFile {
  path: string;
  data: Buffer;
}

export interface SkillPackageManifestEntry {
  path: string;
  sha256: string;
  size: number;
}

export interface SkillPackage {
  entryPath: string;
  files: SkillPackageFile[];
  manifest: SkillPackageManifestEntry[];
  sha256: string;
  totalBytes: number;
}

export interface ExtractSkillPackageOptions {
  maxFiles?: number;
  maxFileBytes?: number;
  maxUnpackedBytes?: number;
  maxCompressedBytes?: number;
}

export interface ExpectedSkillPackage {
  entryPath: string;
  sha256: string;
  manifest: SkillPackageManifestEntry[];
}

export interface SkillPackageInspection {
  exists: boolean;
  packageMatch: boolean;
  packageSha256?: string;
  files: SkillPackageFile[];
  missingFiles: string[];
  extraFiles: string[];
  modifiedFiles: string[];
  unsafePaths: string[];
}

interface TarEntryMetadata {
  path?: string;
  size?: number;
}

function isZeroBlock(block: Buffer): boolean {
  for (const byte of block) {
    if (byte !== 0) return false;
  }
  return true;
}

function parseTarNumber(field: Buffer, label: string): number {
  const value = field.toString('ascii').replace(/\0/g, ' ').trim();
  if (!value) return 0;
  if (!/^[0-7]+$/.test(value)) {
    throw new SkillPackageError('INVALID_ARCHIVE', `Invalid tar ${label}: "${value}"`);
  }
  const parsed = Number.parseInt(value, 8);
  if (!Number.isSafeInteger(parsed) || parsed < 0) {
    throw new SkillPackageError('INVALID_ARCHIVE', `Tar ${label} is out of range`);
  }
  return parsed;
}

function verifyTarChecksum(header: Buffer): void {
  const expected = parseTarNumber(header.subarray(148, 156), 'checksum');
  const checksumHeader = Buffer.from(header);
  checksumHeader.fill(0x20, 148, 156);
  let actual = 0;
  for (const byte of checksumHeader) actual += byte;
  if (actual !== expected) {
    throw new SkillPackageError(
      'INVALID_ARCHIVE',
      `Tar header checksum mismatch: expected ${expected}, calculated ${actual}`,
    );
  }
}

function readTarString(header: Buffer, start: number, length: number): string {
  const field = header.subarray(start, start + length);
  const end = field.indexOf(0);
  return field.subarray(0, end === -1 ? field.length : end).toString('utf8').trim();
}

function readTarPath(header: Buffer): string {
  const name = readTarString(header, 0, 100);
  const prefix = readTarString(header, 345, 155);
  return prefix ? `${prefix}/${name}` : name;
}

function parsePaxRecords(payload: Buffer): Map<string, string> {
  const records = new Map<string, string>();
  let offset = 0;

  while (offset < payload.length) {
    const space = payload.indexOf(0x20, offset);
    if (space === -1) {
      throw new SkillPackageError('INVALID_ARCHIVE', 'Malformed PAX header record');
    }
    const lengthText = payload.subarray(offset, space).toString('ascii');
    if (!/^[0-9]+$/.test(lengthText)) {
      throw new SkillPackageError('INVALID_ARCHIVE', 'Invalid PAX record length');
    }
    const recordLength = Number.parseInt(lengthText, 10);
    const recordEnd = offset + recordLength;
    if (!Number.isSafeInteger(recordLength) || recordLength <= 0 || recordEnd > payload.length) {
      throw new SkillPackageError('INVALID_ARCHIVE', 'PAX record exceeds its header payload');
    }

    const record = payload.subarray(space + 1, recordEnd).toString('utf8').replace(/\n$/, '');
    const separator = record.indexOf('=');
    if (separator <= 0) {
      throw new SkillPackageError('INVALID_ARCHIVE', 'Malformed PAX key/value record');
    }
    records.set(record.slice(0, separator), record.slice(separator + 1));
    offset = recordEnd;
  }

  return records;
}

function mergeMetadata(
  current: TarEntryMetadata | undefined,
  next: TarEntryMetadata,
): TarEntryMetadata {
  return {
    ...(current?.path !== undefined || next.path !== undefined
      ? { path: next.path ?? current?.path }
      : {}),
    ...(current?.size !== undefined || next.size !== undefined
      ? { size: next.size ?? current?.size }
      : {}),
  };
}

const WINDOWS_RESERVED_NAMES = /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?$/i;

function normalizePackagePath(rawPath: string, allowEmpty = false): string {
  if (rawPath.includes('\0')) {
    throw new SkillPackageError('UNSAFE_PATH', 'Package path contains a NUL byte');
  }

  const normalizedSeparators = rawPath.replace(/\\/g, '/');
  if (normalizedSeparators.startsWith('/') || /^[A-Za-z]:/.test(normalizedSeparators)) {
    throw new SkillPackageError('UNSAFE_PATH', `Package path must be relative: "${rawPath}"`);
  }

  const segments: string[] = [];
  for (const rawSegment of normalizedSeparators.split('/')) {
    if (!rawSegment || rawSegment === '.') continue;
    if (rawSegment === '..') {
      throw new SkillPackageError('UNSAFE_PATH', `Package path escapes its root: "${rawPath}"`);
    }
    if (
      rawSegment.length > 255 ||
      /[\u0000-\u001f<>:"|?*]/.test(rawSegment) ||
      /[ .]$/.test(rawSegment) ||
      WINDOWS_RESERVED_NAMES.test(rawSegment)
    ) {
      throw new SkillPackageError(
        'UNSAFE_PATH',
        `Package path contains a non-portable segment: "${rawPath}"`,
      );
    }
    segments.push(rawSegment);
  }

  const normalized = segments.join('/');
  if (!normalized && !allowEmpty) {
    throw new SkillPackageError('UNSAFE_PATH', 'Package entry path must not be empty');
  }
  if (normalized.length > 1024) {
    throw new SkillPackageError('UNSAFE_PATH', 'Package path exceeds 1024 characters');
  }
  return normalized;
}

function comparePaths(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

function sha256(data: Uint8Array): string {
  return crypto.createHash('sha256').update(data).digest('hex');
}

function calculatePackageSha256(files: SkillPackageFile[]): string {
  const hash = crypto.createHash('sha256');
  hash.update('agentwarden-skill-package-v1\0');

  for (const file of [...files].sort((a, b) => comparePaths(a.path, b.path))) {
    const pathBytes = Buffer.from(file.path, 'utf8');
    const lengthPrefix = Buffer.allocUnsafe(4);
    lengthPrefix.writeUInt32BE(pathBytes.byteLength, 0);
    hash.update(lengthPrefix);
    hash.update(pathBytes);
    lengthPrefix.writeUInt32BE(file.data.byteLength, 0);
    hash.update(lengthPrefix);
    hash.update(file.data);
  }

  return hash.digest('hex');
}

function buildManifest(files: SkillPackageFile[]): SkillPackageManifestEntry[] {
  return [...files]
    .sort((a, b) => comparePaths(a.path, b.path))
    .map((file) => ({
      path: file.path,
      sha256: sha256(file.data),
      size: file.data.byteLength,
    }));
}

function finalizePackage(files: SkillPackageFile[]): SkillPackage {
  if (files.length === 0) {
    throw new SkillPackageError('MISSING_ENTRY', 'Skill package does not contain any files');
  }

  const entries = files.filter((file) => path.posix.basename(file.path).toLowerCase() === 'skill.md');
  if (entries.length === 0) {
    throw new SkillPackageError('MISSING_ENTRY', 'Skill package must contain SKILL.md');
  }
  if (entries.length > 1) {
    throw new SkillPackageError(
      'AMBIGUOUS_ENTRY',
      'Skill package contains more than one SKILL.md entry',
    );
  }

  const entry = entries[0];
  const entryDirectory = path.posix.dirname(entry.path);
  const rootPrefix = entryDirectory === '.' ? '' : `${entryDirectory}/`;
  const normalizedFiles = files.map((file) => {
    if (rootPrefix && !file.path.startsWith(rootPrefix)) {
      throw new SkillPackageError(
        'INVALID_LAYOUT',
        `Package file "${file.path}" is outside the SKILL.md root "${entryDirectory}"`,
      );
    }
    return {
      ...file,
      path: rootPrefix ? file.path.slice(rootPrefix.length) : file.path,
    };
  });

  normalizedFiles.sort((a, b) => comparePaths(a.path, b.path));
  if (new Set(normalizedFiles.map((file) => file.path.toLowerCase())).size !== normalizedFiles.length) {
    throw new SkillPackageError('DUPLICATE_ENTRY', 'Skill package contains duplicate file paths');
  }

  return {
    entryPath: rootPrefix ? entry.path.slice(rootPrefix.length) : entry.path,
    files: normalizedFiles,
    manifest: buildManifest(normalizedFiles),
    sha256: calculatePackageSha256(normalizedFiles),
    totalBytes: normalizedFiles.reduce((total, file) => total + file.data.byteLength, 0),
  };
}

function parseTar(
  archive: Buffer,
  options: Required<ExtractSkillPackageOptions> & {
    maxUnpackedBytes: number;
  },
): SkillPackage {
  const files: SkillPackageFile[] = [];
  const seenEntries = new Map<string, 'file' | 'directory'>();
  let offset = 0;
  let totalBytes = 0;
  let pendingMetadata: TarEntryMetadata | undefined;
  let sawEndMarker = false;

  while (offset + 512 <= archive.length) {
    const header = archive.subarray(offset, offset + 512);
    if (isZeroBlock(header)) {
      sawEndMarker = true;
      break;
    }
    verifyTarChecksum(header);

    const typeFlag = header[156] === 0 ? '0' : String.fromCharCode(header[156]);
    const headerSize = parseTarNumber(header.subarray(124, 136), 'size');
    const effectiveSize = pendingMetadata?.size ?? headerSize;
    const paddedSize = Math.ceil(effectiveSize / 512) * 512;
    const payloadStart = offset + 512;
    const payloadEnd = payloadStart + effectiveSize;
    const nextOffset = payloadStart + paddedSize;

    if (payloadEnd > archive.length || nextOffset > archive.length) {
      throw new SkillPackageError('INVALID_ARCHIVE', 'Tar entry payload is truncated');
    }
    const payload = archive.subarray(payloadStart, payloadEnd);

    if (typeFlag === 'x') {
      const pax = parsePaxRecords(payload);
      const paxSize = pax.get('size');
      pendingMetadata = mergeMetadata(pendingMetadata, {
        ...(pax.has('path') ? { path: pax.get('path') } : {}),
        ...(paxSize !== undefined ? { size: Number.parseInt(paxSize, 10) } : {}),
      });
      if (
        pendingMetadata.size !== undefined &&
        (!Number.isSafeInteger(pendingMetadata.size) || pendingMetadata.size < 0)
      ) {
        throw new SkillPackageError('INVALID_ARCHIVE', 'Invalid PAX file size');
      }
      offset = nextOffset;
      continue;
    }
    if (typeFlag === 'g') {
      throw new SkillPackageError('UNSUPPORTED_ENTRY', 'Global PAX headers are not supported');
    }
    if (typeFlag === 'L') {
      const longName = payload.toString('utf8').replace(/\0.*$/, '');
      pendingMetadata = mergeMetadata(pendingMetadata, { path: longName });
      offset = nextOffset;
      continue;
    }
    if (typeFlag === 'K') {
      throw new SkillPackageError('UNSUPPORTED_ENTRY', 'GNU long link names are not supported');
    }

    const rawPath = pendingMetadata?.path ?? readTarPath(header);
    const normalizedPath = normalizePackagePath(rawPath, typeFlag === '5');
    pendingMetadata = undefined;

    if (typeFlag === '0') {
      if (!normalizedPath) {
        throw new SkillPackageError('UNSAFE_PATH', 'Package file path must not be empty');
      }
      const key = normalizedPath.toLowerCase();
      if (seenEntries.has(key)) {
        throw new SkillPackageError('DUPLICATE_ENTRY', `Duplicate package path "${normalizedPath}"`);
      }
      for (const [seenPath, seenType] of seenEntries) {
        if (seenType === 'file' && key.startsWith(`${seenPath}/`)) {
          throw new SkillPackageError(
            'UNSAFE_PATH',
            `Package file "${normalizedPath}" is nested below another entry`,
          );
        }
      }
      if (files.length >= options.maxFiles) {
        throw new SkillPackageError(
          'TOO_MANY_FILES',
          `Skill package exceeds the ${options.maxFiles}-file limit`,
        );
      }
      if (payload.byteLength > options.maxFileBytes) {
        throw new SkillPackageError(
          'FILE_TOO_LARGE',
          `Package file "${normalizedPath}" exceeds the ${options.maxFileBytes}-byte limit`,
        );
      }
      totalBytes += payload.byteLength;
      if (totalBytes > options.maxUnpackedBytes) {
        throw new SkillPackageError(
          'PACKAGE_TOO_LARGE',
          `Unpacked package exceeds the ${options.maxUnpackedBytes}-byte limit`,
        );
      }
      seenEntries.set(key, 'file');
      files.push({ path: normalizedPath, data: Buffer.from(payload) });
    } else if (typeFlag === '5') {
      if (!normalizedPath) {
        offset = nextOffset;
        continue;
      }
      const key = normalizedPath.toLowerCase();
      if (seenEntries.has(key)) {
        throw new SkillPackageError('DUPLICATE_ENTRY', `Duplicate package path "${normalizedPath}"`);
      }
      seenEntries.set(key, 'directory');
    } else {
      throw new SkillPackageError(
        'UNSUPPORTED_ENTRY',
        `Unsupported tar entry type "${typeFlag}" for "${normalizedPath || rawPath}"`,
      );
    }

    offset = nextOffset;
  }

  if (!sawEndMarker) {
    throw new SkillPackageError('INVALID_ARCHIVE', 'Tar archive is missing its end marker');
  }
  return finalizePackage(files);
}

/** Return true when a source name or content type identifies a gzip-compressed tar package. */
export function isSkillPackageSource(filename: string, contentType?: string): boolean {
  if (/\.(?:tar\.gz|tgz)$/i.test(filename)) return true;
  return Boolean(contentType && /(?:gzip|x-gzip|application\/gzip)/i.test(contentType));
}

/** Safely inspect a gzip-compressed tar package and normalize its SKILL.md root. */
export function extractSkillPackage(
  archive: Uint8Array,
  options: ExtractSkillPackageOptions = {},
): SkillPackage {
  const maxFiles = options.maxFiles ?? DEFAULT_MAX_PACKAGE_FILES;
  const maxFileBytes = options.maxFileBytes ?? DEFAULT_MAX_PACKAGE_FILE_BYTES;
  const maxUnpackedBytes = options.maxUnpackedBytes ?? DEFAULT_MAX_PACKAGE_UNPACKED_BYTES;
  const maxCompressedBytes = options.maxCompressedBytes ?? DEFAULT_MAX_COMPRESSED_PACKAGE_BYTES;

  for (const [label, value] of [
    ['maxFiles', maxFiles],
    ['maxFileBytes', maxFileBytes],
    ['maxUnpackedBytes', maxUnpackedBytes],
    ['maxCompressedBytes', maxCompressedBytes],
  ] as const) {
    if (!Number.isSafeInteger(value) || value < 1) {
      throw new SkillPackageError('INVALID_ARCHIVE', `${label} must be a positive integer`);
    }
  }

  if (archive.byteLength > maxCompressedBytes) {
    throw new SkillPackageError(
      'PACKAGE_TOO_LARGE',
      `Compressed package is ${archive.byteLength} bytes, exceeding the ${maxCompressedBytes}-byte limit`,
    );
  }

  let tarArchive: Buffer;
  try {
    tarArchive = zlib.gunzipSync(archive, { maxOutputLength: maxUnpackedBytes });
  } catch (error) {
    const code =
      error && typeof error === 'object' && 'code' in error
        ? String((error as NodeJS.ErrnoException).code)
        : '';
    if (code === 'ERR_BUFFER_TOO_LARGE') {
      throw new SkillPackageError(
        'PACKAGE_TOO_LARGE',
        `Unpacked package exceeds the ${maxUnpackedBytes}-byte limit`,
      );
    }
    throw new SkillPackageError(
      'INVALID_ARCHIVE',
      `Unable to decompress skill package: ${error instanceof Error ? error.message : String(error)}`,
    );
  }

  return parseTar(tarArchive, {
    maxFiles,
    maxFileBytes,
    maxUnpackedBytes,
    maxCompressedBytes,
  });
}

/** Read and inspect a local .tar.gz or .tgz skill package. */
export function readSkillPackage(
  filePath: string,
  options: ExtractSkillPackageOptions = {},
): SkillPackage {
  const stat = fs.statSync(filePath);
  if (!stat.isFile()) {
    throw new SkillPackageError('INVALID_ARCHIVE', `Skill package is not a file: ${filePath}`);
  }
  const maxCompressedBytes = options.maxCompressedBytes ?? DEFAULT_MAX_COMPRESSED_PACKAGE_BYTES;
  if (stat.size > maxCompressedBytes) {
    throw new SkillPackageError(
      'PACKAGE_TOO_LARGE',
      `Compressed package is ${stat.size} bytes, exceeding the ${maxCompressedBytes}-byte limit`,
    );
  }
  return extractSkillPackage(fs.readFileSync(filePath), options);
}

/** Atomically install package files into a directory, replacing an existing package only after staging succeeds. */
export function writeSkillPackage(skillPackage: SkillPackage, destination: string): void {
  const resolvedDestination = path.resolve(destination);
  const parent = path.dirname(resolvedDestination);
  const suffix = `${process.pid}.${crypto.randomBytes(6).toString('hex')}`;
  const staging = path.join(parent, `.${path.basename(resolvedDestination)}.staging-${suffix}`);
  const backup = path.join(parent, `.${path.basename(resolvedDestination)}.backup-${suffix}`);
  let movedExisting = false;

  fs.mkdirSync(parent, { recursive: true });
  fs.mkdirSync(staging, { recursive: false });

  try {
    for (const file of skillPackage.files) {
      const target = path.join(staging, ...file.path.split('/'));
      const relative = path.relative(staging, target);
      if (relative.startsWith('..') || path.isAbsolute(relative)) {
        throw new SkillPackageError('UNSAFE_PATH', `Package file escapes staging: "${file.path}"`);
      }
      fs.mkdirSync(path.dirname(target), { recursive: true });
      fs.writeFileSync(target, file.data, { flag: 'wx' });
    }

    if (fs.existsSync(resolvedDestination)) {
      if (!fs.statSync(resolvedDestination).isDirectory()) {
        throw new SkillPackageError(
          'INSTALL_FAILED',
          `Package destination exists and is not a directory: ${resolvedDestination}`,
        );
      }
      fs.renameSync(resolvedDestination, backup);
      movedExisting = true;
    }

    try {
      fs.renameSync(staging, resolvedDestination);
    } catch (error) {
      if (movedExisting && !fs.existsSync(resolvedDestination) && fs.existsSync(backup)) {
        fs.renameSync(backup, resolvedDestination);
        movedExisting = false;
      }
      throw error;
    }

    if (movedExisting) {
      fs.rmSync(backup, { recursive: true, force: true });
      movedExisting = false;
    }
  } catch (error) {
    if (error instanceof SkillPackageError) throw error;
    throw new SkillPackageError(
      'INSTALL_FAILED',
      `Unable to install skill package at ${resolvedDestination}: ${error instanceof Error ? error.message : String(error)}`,
    );
  } finally {
    fs.rmSync(staging, { recursive: true, force: true });
    if (movedExisting && fs.existsSync(backup) && !fs.existsSync(resolvedDestination)) {
      fs.renameSync(backup, resolvedDestination);
    }
  }
}

function readInstalledPackageFiles(root: string): {
  exists: boolean;
  files: SkillPackageFile[];
  unsafePaths: string[];
} {
  if (!fs.existsSync(root)) return { exists: false, files: [], unsafePaths: [] };

  const rootStat = fs.lstatSync(root);
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) {
    return { exists: true, files: [], unsafePaths: ['.'] };
  }

  const files: SkillPackageFile[] = [];
  const unsafePaths: string[] = [];
  const seen = new Set<string>();

  function visit(directory: string): void {
    const entries = fs.readdirSync(directory, { withFileTypes: true }).sort((a, b) =>
      comparePaths(a.name, b.name),
    );
    for (const entry of entries) {
      const absolute = path.join(directory, entry.name);
      const relative = path.relative(root, absolute).replace(/\\/g, '/');
      const lower = relative.toLowerCase();
      if (seen.has(lower)) {
        unsafePaths.push(relative);
        continue;
      }
      seen.add(lower);

      const stat = fs.lstatSync(absolute);
      if (stat.isSymbolicLink() || (!stat.isFile() && !stat.isDirectory())) {
        unsafePaths.push(relative);
        continue;
      }
      if (stat.isDirectory()) {
        visit(absolute);
        continue;
      }
      files.push({ path: relative, data: fs.readFileSync(absolute) });
    }
  }

  visit(root);
  return { exists: true, files, unsafePaths };
}

/** Inspect an installed package against its lockfile manifest and whole-package hash. */
export function inspectInstalledSkillPackage(
  root: string,
  expected: ExpectedSkillPackage,
): SkillPackageInspection {
  const installed = readInstalledPackageFiles(root);
  if (!installed.exists) {
    return {
      exists: false,
      packageMatch: false,
      files: [],
      missingFiles: expected.manifest.map((entry) => entry.path),
      extraFiles: [],
      modifiedFiles: [],
      unsafePaths: [],
    };
  }

  const expectedByPath = new Map(expected.manifest.map((entry) => [entry.path, entry]));
  const actualByPath = new Map(installed.files.map((file) => [file.path, file]));
  const missingFiles = expected.manifest
    .filter((entry) => !actualByPath.has(entry.path))
    .map((entry) => entry.path);
  const extraFiles = installed.files
    .filter((file) => !expectedByPath.has(file.path))
    .map((file) => file.path);
  const modifiedFiles = installed.files
    .filter((file) => {
      const entry = expectedByPath.get(file.path);
      return (
        entry !== undefined &&
        (entry.size !== file.data.byteLength || entry.sha256 !== sha256(file.data))
      );
    })
    .map((file) => file.path);

  const packageSha256 =
    installed.unsafePaths.length === 0
      ? calculatePackageSha256(installed.files)
      : undefined;
  const packageMatch =
    installed.unsafePaths.length === 0 &&
    missingFiles.length === 0 &&
    extraFiles.length === 0 &&
    modifiedFiles.length === 0 &&
    installed.files.length === expected.manifest.length &&
    packageSha256 === expected.sha256;

  return {
    exists: true,
    packageMatch,
    ...(packageSha256 ? { packageSha256 } : {}),
    files: installed.files,
    missingFiles,
    extraFiles,
    modifiedFiles,
    unsafePaths: installed.unsafePaths,
  };
}
