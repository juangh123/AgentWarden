import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { createTarGz } from './helpers/tar.ts';
import {
  SkillPackageError,
  extractSkillPackage,
  inspectInstalledSkillPackage,
  isManagedSkillDirectory,
  isSkillPackageSource,
  prepareSkillPackageWrite,
  readSkillPackageMarker,
  writeSkillPackage,
  type SkillPackageErrorCode,
} from '../src/source/package.ts';

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

  it('refuses to erase an unmanaged destination and marks managed installs', () => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'skillguard-package-'));
    const destination = path.join(directory, 'installed');
    const skillPackage = extractSkillPackage(
      createTarGz([{ path: 'pkg/SKILL.md', content: '# Demo\n' }]),
    );
    fs.mkdirSync(destination);
    fs.writeFileSync(path.join(destination, 'keep.txt'), 'keep', 'utf8');

    expectPackageError(
      () => writeSkillPackage(skillPackage, destination),
      'DESTINATION_NOT_EMPTY',
      /not empty/,
    );
    assert.equal(fs.readFileSync(path.join(destination, 'keep.txt'), 'utf8'), 'keep');

    expectPackageError(
      () => writeSkillPackage(skillPackage, destination, { replaceExisting: true }),
      'DESTINATION_NOT_MANAGED',
      /not created by AgentWarden/,
    );
    assert.equal(fs.readFileSync(path.join(destination, 'keep.txt'), 'utf8'), 'keep');

    const result = writeSkillPackage(skillPackage, destination, {
      replaceExisting: true,
      allowUnmanagedReplacement: true,
    });
    assert.equal(result.replaced, true);
    assert.deepEqual(result.removedEntries, ['keep.txt']);
    assert.equal(fs.existsSync(path.join(destination, 'keep.txt')), false);
    assert.equal(fs.existsSync(path.join(destination, 'SKILL.md')), true);
    assert.equal(isManagedSkillDirectory(destination), true);
    assert.equal(readSkillPackageMarker(destination)?.packageSha256, skillPackage.sha256);

    const reinstalled = writeSkillPackage(skillPackage, destination, { replaceExisting: true });
    assert.equal(reinstalled.replaced, true);
    assert.deepEqual(reinstalled.removedEntries, ['SKILL.md']);
    assert.equal(fs.existsSync(path.join(destination, 'SKILL.md')), true);
  });

  it('refuses to replace the working directory or a directory holding .git', () => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'skillguard-package-'));
    const skillPackage = extractSkillPackage(
      createTarGz([{ path: 'pkg/SKILL.md', content: '# Demo\n' }]),
    );

    expectPackageError(
      () => writeSkillPackage(skillPackage, process.cwd()),
      'DESTINATION_UNSAFE',
      /working directory/,
    );

    const repository = path.join(directory, 'repo');
    fs.mkdirSync(path.join(repository, '.git'), { recursive: true });
    fs.writeFileSync(path.join(repository, 'file.txt'), 'x', 'utf8');
    expectPackageError(
      () =>
        writeSkillPackage(skillPackage, repository, {
          replaceExisting: true,
          allowUnmanagedReplacement: true,
        }),
      'DESTINATION_UNSAFE',
      /\.git/,
    );
    assert.equal(fs.readFileSync(path.join(repository, 'file.txt'), 'utf8'), 'x');
  });

  it('rejects packages that ship the reserved install marker', () => {
    expectPackageError(
      () =>
        extractSkillPackage(
          createTarGz([
            { path: 'pkg/SKILL.md', content: '# Demo\n' },
            { path: 'pkg/.agentwarden-skill.json', content: '{}' },
          ]),
        ),
      'UNSAFE_PATH',
      /reserved/,
    );
  });

  it('bounds installed-package reads and ignores only a valid marker', () => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'skillguard-package-'));
    const destination = path.join(directory, 'installed');
    const skillPackage = extractSkillPackage(
      createTarGz([
        { path: 'pkg/SKILL.md', content: '# Demo\n' },
        { path: 'pkg/scripts/run.sh', content: 'echo hello\n' },
      ]),
    );
    writeSkillPackage(skillPackage, destination);

    const expected = {
      entryPath: skillPackage.entryPath,
      sha256: skillPackage.sha256,
      manifest: skillPackage.manifest,
    };
    assert.equal(inspectInstalledSkillPackage(destination, expected).packageMatch, true);

    expectPackageError(
      () => inspectInstalledSkillPackage(destination, expected, { maxFiles: 1 }),
      'INSTALLED_TOO_LARGE',
      /1-file limit/,
    );
    expectPackageError(
      () => inspectInstalledSkillPackage(destination, expected, { maxBytes: 4 }),
      'INSTALLED_TOO_LARGE',
      /4-byte limit/,
    );

    fs.writeFileSync(path.join(destination, '.agentwarden-skill.json'), 'not json', 'utf8');
    const malformedMarker = inspectInstalledSkillPackage(destination, expected);
    assert.equal(malformedMarker.packageMatch, false);
    assert.deepEqual(malformedMarker.extraFiles, ['.agentwarden-skill.json']);
  });

  it('restores the previous directory when a committed write is rolled back', () => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'skillguard-package-'));
    const destination = path.join(directory, 'installed');
    writeSkillPackage(
      extractSkillPackage(createTarGz([{ path: 'pkg/SKILL.md', content: '# Demo\n' }])),
      destination,
    );
    fs.writeFileSync(path.join(destination, 'local.txt'), 'local', 'utf8');

    const prepared = prepareSkillPackageWrite(
      extractSkillPackage(createTarGz([{ path: 'pkg/SKILL.md', content: '# New\n' }])),
      destination,
      { replaceExisting: true },
    );
    assert.deepEqual(prepared.removedEntries, ['SKILL.md', 'local.txt']);
    prepared.commit();
    assert.equal(fs.readFileSync(path.join(destination, 'SKILL.md'), 'utf8'), '# New\n');
    assert.equal(fs.existsSync(path.join(destination, 'local.txt')), false);

    assert.equal(prepared.restore(), true);
    assert.equal(fs.readFileSync(path.join(destination, 'SKILL.md'), 'utf8'), '# Demo\n');
    assert.equal(fs.readFileSync(path.join(destination, 'local.txt'), 'utf8'), 'local');
    assert.equal(prepared.restore(), false);
  });

  it('flags symlinked entries inside an installed package', { skip: process.platform === 'win32' }, () => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'skillguard-package-'));
    const destination = path.join(directory, 'installed');
    const outside = path.join(directory, 'outside.txt');
    fs.writeFileSync(outside, 'outside', 'utf8');
    const skillPackage = extractSkillPackage(
      createTarGz([{ path: 'pkg/SKILL.md', content: '# Demo\n' }]),
    );
    writeSkillPackage(skillPackage, destination);
    fs.symlinkSync(outside, path.join(destination, 'link.txt'));

    const inspection = inspectInstalledSkillPackage(destination, {
      entryPath: skillPackage.entryPath,
      sha256: skillPackage.sha256,
      manifest: skillPackage.manifest,
    });
    assert.equal(inspection.packageMatch, false);
    assert.deepEqual(inspection.unsafePaths, ['link.txt']);
  });
});
