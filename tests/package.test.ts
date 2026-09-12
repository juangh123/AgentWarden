import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import * as zlib from 'node:zlib';
import {
  SkillPackageError,
  extractSkillPackage,
  inspectInstalledSkillPackage,
  isSkillPackageSource,
  writeSkillPackage,
  type SkillPackageErrorCode,
} from '../src/source/package.ts';

interface TarFile {
  path: string;
  content: string;
  type?: '0' | '2';
}

function writeOctal(target: Buffer, offset: number, length: number, value: number): void {
  const text = value.toString(8).padStart(length - 1, '0') + '\0';
  target.write(text, offset, length, 'ascii');
}

function tarHeader(file: TarFile): Buffer {
  const data = Buffer.from(file.content, 'utf8');
  const header = Buffer.alloc(512, 0);
  header.write(file.path, 0, 100, 'utf8');
  writeOctal(header, 100, 8, 0o644);
  writeOctal(header, 108, 8, 0);
  writeOctal(header, 116, 8, 0);
  writeOctal(header, 124, 12, data.byteLength);
  writeOctal(header, 136, 12, 0);
  header.write('        ', 148, 8, 'ascii');
  header.write(file.type ?? '0', 156, 1, 'ascii');
  header.write('ustar\0', 257, 6, 'ascii');
  header.write('00', 263, 2, 'ascii');

  let checksum = 0;
  for (const byte of header) checksum += byte;
  header.write(checksum.toString(8).padStart(6, '0') + '\0 ', 148, 8, 'ascii');
  return header;
}

function createTarGz(files: TarFile[]): Buffer {
  const blocks: Buffer[] = [];
  for (const file of files) {
    const data = Buffer.from(file.content, 'utf8');
    blocks.push(tarHeader(file));
    if (data.byteLength > 0) {
      const padded = Buffer.alloc(Math.ceil(data.byteLength / 512) * 512, 0);
      data.copy(padded);
      blocks.push(padded);
    }
  }
  blocks.push(Buffer.alloc(1024, 0));
  return zlib.gzipSync(Buffer.concat(blocks));
}

function expectPackageError(
  operation: () => unknown,
  code: SkillPackageErrorCode,
  pattern: RegExp,
): void {
  assert.throws(operation, (error: unknown) => {
    assert.ok(error instanceof SkillPackageError);
    assert.equal(error.code, code);
    assert.match(error.message, pattern);
    return true;
  });
}

describe('skill packages', () => {
  it('extracts a normalized package and produces a stable whole-package hash', () => {
    const archive = createTarGz([
      { path: 'my-skill/SKILL.md', content: '# Demo\n' },
      { path: 'my-skill/scripts/run.sh', content: 'echo hello\n' },
    ]);
    const first = extractSkillPackage(archive);
    const second = extractSkillPackage(archive);

    assert.equal(first.entryPath, 'SKILL.md');
    assert.deepEqual(
      first.files.map((file) => file.path),
      ['SKILL.md', 'scripts/run.sh'],
    );
    assert.equal(first.manifest.length, 2);
    assert.equal(first.sha256, second.sha256);
    assert.equal(first.sha256.length, 64);
    assert.equal(isSkillPackageSource('skill.tgz'), true);
    assert.equal(isSkillPackageSource('skill.md', 'application/gzip'), true);
  });

  it('rejects traversal, absolute paths, links, and duplicate paths', () => {
    expectPackageError(
      () => extractSkillPackage(createTarGz([{ path: 'pkg/../SKILL.md', content: 'x' }])),
      'UNSAFE_PATH',
      /escapes its root/,
    );
    expectPackageError(
      () => extractSkillPackage(createTarGz([{ path: '/SKILL.md', content: 'x' }])),
      'UNSAFE_PATH',
      /must be relative/,
    );
    expectPackageError(
      () =>
        extractSkillPackage(
          createTarGz([
            { path: 'pkg/SKILL.md', content: 'x' },
            { path: 'pkg/link', content: '../outside', type: '2' },
          ]),
        ),
      'UNSUPPORTED_ENTRY',
      /Unsupported tar entry type/,
    );
    expectPackageError(
      () =>
        extractSkillPackage(
          createTarGz([
            { path: 'pkg/SKILL.md', content: 'x' },
            { path: 'pkg/readme.txt', content: 'a' },
            { path: 'pkg/README.txt', content: 'b' },
          ]),
        ),
      'DUPLICATE_ENTRY',
      /Duplicate package path/,
    );
  });

  it('requires one SKILL.md and enforces file and size limits', () => {
    expectPackageError(
      () => extractSkillPackage(createTarGz([{ path: 'pkg/readme.md', content: 'x' }])),
      'MISSING_ENTRY',
      /must contain SKILL\.md/,
    );
    expectPackageError(
      () =>
        extractSkillPackage(
          createTarGz([
            { path: 'one/SKILL.md', content: 'x' },
            { path: 'two/SKILL.md', content: 'y' },
          ]),
        ),
      'AMBIGUOUS_ENTRY',
      /more than one SKILL\.md/,
    );
    expectPackageError(
      () =>
        extractSkillPackage(
          createTarGz([{ path: 'pkg/SKILL.md', content: 'x' }]),
          { maxFileBytes: 0 },
        ),
      'INVALID_ARCHIVE',
      /maxFileBytes must be a positive integer/,
    );
    expectPackageError(
      () =>
        extractSkillPackage(
          createTarGz([{ path: 'pkg/SKILL.md', content: 'too large' }]),
          { maxFileBytes: 4 },
        ),
      'FILE_TOO_LARGE',
      /exceeds the 4-byte limit/,
    );
  });

  it('writes and inspects an installed package manifest', () => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'skillguard-package-'));
    const destination = path.join(directory, 'installed');
    const skillPackage = extractSkillPackage(
      createTarGz([
        { path: 'pkg/SKILL.md', content: '# Demo\n' },
        { path: 'pkg/scripts/run.sh', content: 'echo hello\n' },
      ]),
    );

    writeSkillPackage(skillPackage, destination);
    const matching = inspectInstalledSkillPackage(destination, {
      entryPath: skillPackage.entryPath,
      sha256: skillPackage.sha256,
      manifest: skillPackage.manifest,
    });
    assert.equal(matching.packageMatch, true);
    assert.equal(matching.files.length, 2);

    fs.appendFileSync(path.join(destination, 'scripts', 'run.sh'), 'echo changed\n');
    const modified = inspectInstalledSkillPackage(destination, {
      entryPath: skillPackage.entryPath,
      sha256: skillPackage.sha256,
      manifest: skillPackage.manifest,
    });
    assert.equal(modified.packageMatch, false);
    assert.deepEqual(modified.modifiedFiles, ['scripts/run.sh']);

    fs.writeFileSync(path.join(destination, 'extra.txt'), 'extra', 'utf8');
    const extra = inspectInstalledSkillPackage(destination, {
      entryPath: skillPackage.entryPath,
      sha256: skillPackage.sha256,
      manifest: skillPackage.manifest,
    });
    assert.deepEqual(extra.extraFiles, ['extra.txt']);
  });
});
