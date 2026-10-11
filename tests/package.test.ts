import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { syncBuiltinESMExports } from 'node:module';
import fsMutable from 'node:fs';
import { createTarGz, paxRecords } from './helpers/tar.ts';
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

describe('tar reader hardening', () => {
  const skillContent = '---\nname: tar-fixture\nversion: 1.0.0\n---\n# Fixture\n';
  const skillEntry = (content = skillContent) => ({ path: 'SKILL.md', content });
  const paxEntry = (records: Record<string, string>) => ({
    path: 'pax-header-entry',
    content: paxRecords(records),
    typeFlag: 'x',
  });

  it('applies a PAX path header to the following entry', () => {
    // The sibling file only lands inside the package root when the PAX path is honoured:
    // otherwise the entry would sit at the archive root and "nested/extra.md" would be outside it.
    const pkg = extractSkillPackage(
      createTarGz([
        paxEntry({ path: 'nested/SKILL.md' }),
        skillEntry(),
        { path: 'nested/extra.md', content: 'extra\n' },
      ]),
    );

    assert.equal(pkg.entryPath, 'SKILL.md');
    assert.deepEqual(pkg.files.map((file) => file.path), ['SKILL.md', 'extra.md']);
  });

  it('honours a PAX size record over the header size field', () => {
    const content = '---\nname: pax-size\nversion: 1.0.0\n---\n# Size\n';
    const archive = createTarGz([
      paxEntry({ size: String(Buffer.byteLength(content, 'utf8')) }),
      { path: 'SKILL.md', content, declaredSize: 0 },
    ]);

    const pkg = extractSkillPackage(archive);
    assert.equal(pkg.files[0].data.toString('utf8'), content);
  });

  it('applies a GNU long-name header to the following entry', () => {
    const pkg = extractSkillPackage(
      createTarGz([
        { path: 'long-name-entry', content: 'nested/SKILL.md\0', typeFlag: 'L' },
        skillEntry(),
        { path: 'nested/extra.md', content: 'extra\n' },
      ]),
    );

    assert.equal(pkg.entryPath, 'SKILL.md');
    assert.deepEqual(pkg.files.map((file) => file.path), ['SKILL.md', 'extra.md']);
  });

  it('rejects unsupported extended headers', () => {
    const cases: Array<[string, RegExp]> = [
      ['g', /Global PAX headers are not supported/],
      ['K', /GNU long link names are not supported/],
    ];
    for (const [typeFlag, pattern] of cases) {
      expectPackageError(
        () => extractSkillPackage(createTarGz([{ path: 'extended', content: 'x\n', typeFlag }, skillEntry()])),
        'UNSUPPORTED_ENTRY',
        pattern,
      );
    }
  });

  it('rejects forged or truncated tar headers', () => {
    expectPackageError(
      () => extractSkillPackage(createTarGz([{ path: 'SKILL.md', content: 'x', checksumOverride: '000000' }])),
      'INVALID_ARCHIVE',
      /checksum mismatch/,
    );
    expectPackageError(
      () => extractSkillPackage(createTarGz([{ path: 'SKILL.md', content: 'x', checksumOverride: 'zzzzzz' }])),
      'INVALID_ARCHIVE',
      /Invalid tar checksum/,
    );
    expectPackageError(
      () => extractSkillPackage(createTarGz([{ path: 'SKILL.md', content: 'x', declaredSize: 4096 }])),
      'INVALID_ARCHIVE',
      /truncated/,
    );
  });

  it('rejects non-portable and over-long archive paths', () => {
    const unsafe: Array<[string, RegExp]> = [
      ['con/SKILL.md', /non-portable segment/],
      ['trailing /SKILL.md', /non-portable segment/],
      ['bad<>name/SKILL.md', /non-portable segment/],
    ];
    for (const [path, pattern] of unsafe) {
      expectPackageError(
        () => extractSkillPackage(createTarGz([{ path, content: 'x' }])),
        'UNSAFE_PATH',
        pattern,
      );
    }

    expectPackageError(
      () =>
        extractSkillPackage(
          createTarGz([
            paxEntry({
              path: `${Array.from({ length: 300 }, (_, index) => `d${index}`).join('/')}/SKILL.md`,
            }),
            skillEntry(),
          ]),
        ),
      'UNSAFE_PATH',
      /exceeds 1024 characters/,
    );
    expectPackageError(
      () => extractSkillPackage(createTarGz([paxEntry({ path: 'nested/SKILL\0.md' }), skillEntry()])),
      'UNSAFE_PATH',
      /NUL byte/,
    );
    expectPackageError(
      () => extractSkillPackage(createTarGz([{ path: 'a', content: 'x' }, { path: 'a/b', content: 'y' }])),
      'UNSAFE_PATH',
      /nested below another entry/,
    );
  });

  it('enforces explicit file-count and unpacked-size caps', () => {
    expectPackageError(
      () =>
        extractSkillPackage(
          createTarGz([
            { path: 'pkg/SKILL.md', content: 'x' },
            { path: 'pkg/other.md', content: 'y' },
          ]),
          { maxFiles: 1 },
        ),
      'TOO_MANY_FILES',
      /1-file limit/,
    );
    expectPackageError(
      () => extractSkillPackage(createTarGz([{ path: 'SKILL.md', content: '0123456789' }]), { maxUnpackedBytes: 4 }),
      'PACKAGE_TOO_LARGE',
      /4-byte limit/,
    );
  });

  it('ignores absent, malformed, or foreign install markers', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'agentwarden-marker-'));
    try {
      assert.equal(readSkillPackageMarker(path.join(dir, 'missing')), undefined);
      assert.equal(isManagedSkillDirectory(path.join(dir, 'missing')), false);

      const filePath = path.join(dir, 'plain-file');
      fs.writeFileSync(filePath, 'x', 'utf8');
      assert.equal(isManagedSkillDirectory(filePath), false);

      const markerPath = path.join(dir, '.agentwarden-skill.json');
      const valid = {
        schemaVersion: 1,
        tool: 'agentwarden',
        packageSha256: 'a'.repeat(64),
        entryPath: 'SKILL.md',
        installedAt: '2026-10-11T00:00:00.000Z',
      };
      const invalid = [
        { ...valid, tool: 'someone-else' },
        { ...valid, schemaVersion: 2 },
        { ...valid, packageSha256: 'not-a-hash' },
        { ...valid, entryPath: '../SKILL.md' },
        { ...valid, installedAt: 'not-a-date' },
      ];
      for (const marker of invalid) {
        fs.writeFileSync(markerPath, JSON.stringify(marker), 'utf8');
        assert.equal(readSkillPackageMarker(dir), undefined, JSON.stringify(marker).slice(0, 60));
        assert.equal(isManagedSkillDirectory(dir), false);
      }

      fs.writeFileSync(markerPath, JSON.stringify(valid), 'utf8');
      assert.deepEqual(readSkillPackageMarker(dir), valid);
      assert.equal(isManagedSkillDirectory(dir), true);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('transactional package writes and inspection limits', () => {
  const skill = (name = 'txn') =>
    extractSkillPackage(
      createTarGz([{ path: 'SKILL.md', content: `---\nname: ${name}\nversion: 1.0.0\n---\n# ${name}\n` }]),
    );
  const expectedPackage = (name = 'txn') => {
    const pkg = skill(name);
    return { entryPath: pkg.entryPath, sha256: pkg.sha256, manifest: pkg.manifest };
  };

  it('refuses to commit twice and refuses to commit after a rollback', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'agentwarden-txn-'));
    try {
      const dest = path.join(dir, 'skill');
      const prepared = prepareSkillPackageWrite(skill(), dest);
      assert.equal(fs.existsSync(prepared.stagingPath ?? ''), true);
      prepared.commit();
      expectPackageError(() => prepared.commit(), 'INSTALL_FAILED', /already been committed/);
      prepared.finalize();

      const discarded = prepareSkillPackageWrite(skill(), path.join(dir, 'other'));
      assert.equal(discarded.rollback(), true);
      assert.equal(discarded.stagingPath, undefined);
      assert.equal(fs.existsSync(path.join(dir, 'other')), false);
      expectPackageError(() => discarded.commit(), 'INSTALL_FAILED', /no staged files/);
      assert.equal(discarded.rollback(), false);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('restores the previous directory when a committed write is rolled back', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'agentwarden-txn-restore-'));
    try {
      const dest = path.join(dir, 'skill');
      writeSkillPackage(skill('first'), dest);
      fs.writeFileSync(path.join(dest, 'user-added.txt'), 'keep me', 'utf8');

      const prepared = prepareSkillPackageWrite(skill('second'), dest, { replaceExisting: true });
      assert.ok(prepared.removedEntries.includes('user-added.txt'));
      assert.ok(!prepared.removedEntries.includes('.agentwarden-skill.json'));

      prepared.commit();
      assert.equal(fs.existsSync(path.join(dest, 'user-added.txt')), false);

      assert.equal(prepared.rollback(), true);
      assert.equal(fs.readFileSync(path.join(dest, 'user-added.txt'), 'utf8'), 'keep me');
      assert.equal(prepared.restore(), false);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('reports a failed replacement and leaves the previous install intact', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'agentwarden-txn-fail-'));
    const originalRename = fsMutable.renameSync;
    try {
      const dest = path.join(dir, 'skill');
      writeSkillPackage(skill('first'), dest);

      fsMutable.renameSync = ((from: string, to: string) => {
        if (String(from).includes('.staging-')) {
          const error = new Error('target is locked') as NodeJS.ErrnoException;
          error.code = 'EPERM';
          throw error;
        }
        return originalRename(from, to);
      }) as typeof fsMutable.renameSync;
      syncBuiltinESMExports();

      expectPackageError(
        () => writeSkillPackage(skill('second'), dest, { replaceExisting: true }),
        'INSTALL_FAILED',
        /Unable to install skill package/,
      );

      const installed = fs.readFileSync(path.join(dest, 'SKILL.md'), 'utf8');
      assert.match(installed, /name: first/);
      assert.deepEqual(
        fs.readdirSync(dir).filter((entry) => entry.includes('.staging-') || entry.includes('.backup-')),
        [],
      );
    } finally {
      fsMutable.renameSync = originalRename;
      syncBuiltinESMExports();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('reports missing and non-directory installed packages', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'agentwarden-inspect-'));
    try {
      const missing = inspectInstalledSkillPackage(path.join(dir, 'missing'), expectedPackage());
      assert.equal(missing.exists, false);
      assert.equal(missing.packageMatch, false);
      assert.deepEqual(missing.missingFiles, ['SKILL.md']);

      const filePath = path.join(dir, 'not-a-directory');
      fs.writeFileSync(filePath, 'x', 'utf8');
      const notADirectory = inspectInstalledSkillPackage(filePath, expectedPackage());
      assert.equal(notADirectory.exists, true);
      assert.deepEqual(notADirectory.unsafePaths, ['.']);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('validates inspection limits and enforces them', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'agentwarden-inspect-limits-'));
    try {
      const dest = path.join(dir, 'skill');
      writeSkillPackage(skill(), dest);

      const cases: Array<[Record<string, number>, string]> = [
        [{ maxFiles: 0 }, 'maxFiles'],
        [{ maxBytes: -1 }, 'maxBytes'],
        [{ maxDepth: 1.5 }, 'maxDepth'],
      ];
      for (const [options, label] of cases) {
        expectPackageError(
          () => inspectInstalledSkillPackage(dest, expectedPackage(), options),
          'INSTALLED_TOO_LARGE',
          new RegExp(`${label} must be a positive integer`),
        );
      }

      fs.mkdirSync(path.join(dest, 'a', 'b'), { recursive: true });
      fs.writeFileSync(path.join(dest, 'a', 'b', 'deep.md'), 'deep', 'utf8');
      expectPackageError(
        () => inspectInstalledSkillPackage(dest, expectedPackage(), { maxDepth: 1 }),
        'INSTALLED_TOO_LARGE',
        /depth limit/,
      );
      expectPackageError(
        () => inspectInstalledSkillPackage(dest, expectedPackage(), { maxFiles: 1 }),
        'INSTALLED_TOO_LARGE',
        /1-file limit/,
      );
      const byteLimited = path.join(dir, 'byte-limited');
      fs.mkdirSync(byteLimited, { recursive: true });
      fs.writeFileSync(path.join(byteLimited, 'a.md'), 'aaaa', 'utf8');
      fs.writeFileSync(path.join(byteLimited, 'b.md'), 'bbbb', 'utf8');
      expectPackageError(
        () => inspectInstalledSkillPackage(byteLimited, expectedPackage(), { maxBytes: 4 }),
        'INSTALLED_TOO_LARGE',
        /4-byte limit/,
      );
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('malformed tar structures', () => {
  const skillEntry = { path: 'SKILL.md', content: '---\nname: structure\nversion: 1.0.0\n---\n# S\n' };
  const paxEntry = (content: string) => ({ path: 'pax-header-entry', content, typeFlag: 'x' });

  it('rejects malformed PAX records', () => {
    const cases: Array<[string, RegExp]> = [
      ['nospace', /Malformed PAX header record/],
      ['abc x=y\n', /Invalid PAX record length/],
      ['99 x=y\n', /PAX record exceeds its header payload/],
      ['6 abc\n', /Malformed PAX key\/value record/],
    ];
    for (const [content, pattern] of cases) {
      expectPackageError(
        () => extractSkillPackage(createTarGz([paxEntry(content), skillEntry])),
        'INVALID_ARCHIVE',
        pattern,
      );
    }
  });

  it('rejects a file entry whose path normalises to nothing', () => {
    expectPackageError(
      () => extractSkillPackage(createTarGz([{ path: './', content: 'x' }])),
      'UNSAFE_PATH',
      /must not be empty/,
    );
  });

  it('rejects unsupported entry types and layouts outside the SKILL.md root', () => {
    expectPackageError(
      () => extractSkillPackage(createTarGz([{ path: 'odd', content: 'x', typeFlag: '7' }, skillEntry])),
      'UNSUPPORTED_ENTRY',
      /Unsupported tar entry type "7"/,
    );
    expectPackageError(
      () =>
        extractSkillPackage(
          createTarGz([
            { path: 'pkg/SKILL.md', content: skillEntry.content },
            { path: 'outside.md', content: 'x' },
          ]),
        ),
      'INVALID_LAYOUT',
      /outside the SKILL.md root/,
    );
  });

  it('rejects archives without an end marker or without any files', () => {
    expectPackageError(
      () => extractSkillPackage(createTarGz([{ path: 'SKILL.md', content: 'x', omitEndMarker: true }])),
      'INVALID_ARCHIVE',
      /missing its end marker/,
    );

    const directoryOnly = createTarGz([{ path: './', content: '', typeFlag: '5' }]);
    expectPackageError(() => extractSkillPackage(directoryOnly), 'MISSING_ENTRY', /does not contain any files/);
  });

  it('extracts a package that carries explicit directory entries', () => {
    const pkg = extractSkillPackage(
      createTarGz([
        { path: './', content: '', typeFlag: '5' },
        { path: 'nested/', content: '', typeFlag: '5' },
        { path: 'nested/SKILL.md', content: skillEntry.content },
        { path: 'nested/extra.md', content: 'extra\n' },
      ]),
    );

    assert.equal(pkg.entryPath, 'SKILL.md');
    assert.deepEqual(pkg.files.map((file) => file.path), ['SKILL.md', 'extra.md']);
  });

  it('ignores marker files whose entry path is not portable', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'agentwarden-marker-path-'));
    try {
      const markerPath = path.join(dir, '.agentwarden-skill.json');
      const base = {
        schemaVersion: 1,
        tool: 'agentwarden',
        packageSha256: 'a'.repeat(64),
        installedAt: '2026-10-11T00:00:00.000Z',
      };
      for (const entryPath of ['/absolute/SKILL.md', 'nested\\SKILL.md', 'nested/./SKILL.md', 'nested/SKILL\0.md']) {
        fs.writeFileSync(markerPath, JSON.stringify({ ...base, entryPath }), 'utf8');
        assert.equal(readSkillPackageMarker(dir), undefined, entryPath);
      }
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
