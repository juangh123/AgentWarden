import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import {
  LOCKFILE_NAME,
  readLockfile,
  writeLockfile,
  updateLockfileSkill,
  removeLockfileSkill,
  findSkillKey,
  type LockfileSchema,
} from '../src/manifest/lockfile.ts';

function tempDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'skillguard-test-'));
}

describe('lockfile', () => {
  it('round-trips skills and keeps keys sorted', () => {
    const dir = tempDir();
    const lock: LockfileSchema = { lockfileVersion: 1, skills: {} };
    lock.skills['zeta'] = { name: 'zeta', version: '1.0.0', source: 'z.md', sha256: 'a'.repeat(64), installedAt: new Date().toISOString(), verifiedScore: 100 };
    lock.skills['alpha'] = { name: 'alpha', version: '1.0.0', source: 'a.md', sha256: 'b'.repeat(64), installedAt: new Date().toISOString(), verifiedScore: 90 };
    writeLockfile(lock, dir);

    const loaded = readLockfile(dir);
    assert.deepEqual(Object.keys(loaded.skills), ['alpha', 'zeta']);
    assert.ok(fs.existsSync(path.join(dir, LOCKFILE_NAME)));
  });

  it('updateLockfileSkill upserts and removeLockfileSkill deletes case-insensitively', () => {
    const dir = tempDir();
    updateLockfileSkill({ name: 'Demo', version: '1.0.0', source: 'demo.md', sha256: 'c'.repeat(64), installedAt: new Date().toISOString(), verifiedScore: 100 }, dir);
    assert.equal(findSkillKey(readLockfile(dir), 'demo'), 'Demo');
    assert.equal(removeLockfileSkill('DEMO', dir), true);
    assert.equal(removeLockfileSkill('DEMO', dir), false);
    assert.equal(readLockfile(dir).skills.Demo, undefined);
  });

  it('rejects malformed lockfiles instead of treating them as empty', () => {
    const dir = tempDir();
    fs.writeFileSync(path.join(dir, LOCKFILE_NAME), '{"skills":', 'utf8');

    assert.throws(() => readLockfile(dir), /Invalid skills\.lock JSON/);
  });

  it('rejects lock entries with missing integrity fields', () => {
    const dir = tempDir();
    fs.writeFileSync(
      path.join(dir, LOCKFILE_NAME),
      JSON.stringify({ lockfileVersion: 1, skills: { demo: { name: 'demo', source: 'demo.md' } } }),
      'utf8',
    );

    assert.throws(() => readLockfile(dir), /entry "demo" has missing or invalid fields/);
  });

  it('preserves valid remote source metadata', () => {
    const dir = tempDir();
    updateLockfileSkill(
      {
        name: 'remote-demo',
        version: '1.0.0',
        source: '.agentwarden/skills/remote-demo.md',
        sha256: 'd'.repeat(64),
        installedAt: new Date().toISOString(),
        verifiedScore: 100,
        sourceType: 'remote',
        remoteUrl: 'https://example.com/remote-demo.md',
        resolvedUrl: 'https://cdn.example.com/remote-demo.md',
        downloadSha256: 'e'.repeat(64),
        digestVerified: true,
      },
      dir,
    );

    const entry = readLockfile(dir).skills['remote-demo'];
    assert.equal(entry.sourceType, 'remote');
    assert.equal(entry.remoteUrl, 'https://example.com/remote-demo.md');
    assert.equal(entry.resolvedUrl, 'https://cdn.example.com/remote-demo.md');
    assert.equal(entry.downloadSha256, 'e'.repeat(64));
    assert.equal(entry.digestVerified, true);
  });

  it('rejects malformed or orphaned remote source metadata', () => {
    const dir = tempDir();
    const base = {
      name: 'demo',
      version: '1.0.0',
      source: 'demo.md',
      sha256: 'a'.repeat(64),
      installedAt: new Date().toISOString(),
      verifiedScore: 100,
    };

    fs.writeFileSync(
      path.join(dir, LOCKFILE_NAME),
      JSON.stringify({
        lockfileVersion: 1,
        skills: { demo: { ...base, sourceType: 'remote', downloadSha256: 'invalid' } },
      }),
      'utf8',
    );
    assert.throws(() => readLockfile(dir), /invalid downloadSha256/);

    fs.writeFileSync(
      path.join(dir, LOCKFILE_NAME),
      JSON.stringify({
        lockfileVersion: 1,
        skills: { demo: { ...base, remoteUrl: 'https://example.com/demo.md' } },
      }),
      'utf8',
    );
    assert.throws(() => readLockfile(dir), /remote metadata without sourceType "remote"/);
  });

  it('validates and preserves whole-package metadata', () => {
    const dir = tempDir();
    updateLockfileSkill(
      {
        name: 'package-demo',
        version: '1.0.0',
        source: '.agentwarden/skills/package-demo/SKILL.md',
        sha256: 'a'.repeat(64),
        installedAt: new Date().toISOString(),
        verifiedScore: 100,
        sourceType: 'remote',
        remoteUrl: 'https://example.com/package-demo.tar.gz',
        resolvedUrl: 'https://cdn.example.com/package-demo.tar.gz',
        downloadSha256: 'b'.repeat(64),
        digestVerified: true,
        packageFormat: 'tar.gz',
        packageSha256: 'c'.repeat(64),
        packageEntry: 'SKILL.md',
        packageFiles: [
          { path: 'SKILL.md', sha256: 'd'.repeat(64), size: 10 },
          { path: 'scripts/run.sh', sha256: 'e'.repeat(64), size: 20 },
        ],
      },
      dir,
    );

    const entry = readLockfile(dir).skills['package-demo'];
    assert.equal(entry.packageFormat, 'tar.gz');
    assert.equal(entry.packageFiles?.length, 2);
    assert.equal(entry.packageEntry, 'SKILL.md');
  });

  it('rejects package metadata when the entry is absent from the manifest', () => {
    const dir = tempDir();
    fs.writeFileSync(
      path.join(dir, LOCKFILE_NAME),
      JSON.stringify({
        lockfileVersion: 1,
        skills: {
          demo: {
            name: 'demo',
            version: '1.0.0',
            source: 'demo/SKILL.md',
            sha256: 'a'.repeat(64),
            installedAt: new Date().toISOString(),
            verifiedScore: 100,
            packageFormat: 'tar.gz',
            packageSha256: 'b'.repeat(64),
            packageEntry: 'SKILL.md',
            packageFiles: [{ path: 'scripts/run.sh', sha256: 'c'.repeat(64), size: 10 }],
          },
        },
      }),
      'utf8',
    );

    assert.throws(() => readLockfile(dir), /packageEntry is missing from packageFiles/);
  });

  it('validates and preserves Ed25519 provenance metadata', () => {
    const dir = tempDir();
    updateLockfileSkill(
      {
        name: 'signed-demo',
        version: '1.0.0',
        source: 'signed-demo.md',
        sha256: 'a'.repeat(64),
        installedAt: new Date().toISOString(),
        verifiedScore: 100,
        signatureAlgorithm: 'ed25519',
        signatureVerified: true,
        signatureKeySha256: 'b'.repeat(64),
        signatureSha256: 'c'.repeat(64),
      },
      dir,
    );

    const entry = readLockfile(dir).skills['signed-demo'];
    assert.equal(entry.signatureAlgorithm, 'ed25519');
    assert.equal(entry.signatureVerified, true);
    assert.equal(entry.signatureKeySha256, 'b'.repeat(64));
    assert.equal(entry.signatureSha256, 'c'.repeat(64));
  });

  it('rejects malformed signature provenance metadata', () => {
    const dir = tempDir();
    fs.writeFileSync(
      path.join(dir, LOCKFILE_NAME),
      JSON.stringify({
        lockfileVersion: 1,
        skills: {
          demo: {
            name: 'demo',
            version: '1.0.0',
            source: 'demo.md',
            sha256: 'a'.repeat(64),
            installedAt: new Date().toISOString(),
            verifiedScore: 100,
            signatureAlgorithm: 'ed25519',
            signatureVerified: false,
            signatureKeySha256: 'b'.repeat(64),
            signatureSha256: 'c'.repeat(64),
          },
        },
      }),
      'utf8',
    );

    assert.throws(() => readLockfile(dir), /invalid signatureVerified/);
  });
});
