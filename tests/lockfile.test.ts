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
});
