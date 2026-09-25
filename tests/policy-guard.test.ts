import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { guardPolicy, loadApprovedPolicy, PolicyGuardError } from '../src/index.ts';

function tempDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'agentwarden-policy-guard-'));
}

function writeFile(root: string, relativePath: string, content: string): void {
  const target = path.join(root, relativePath);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, content, 'utf8');
}

function git(root: string, args: string[]): void {
  const result = spawnSync('git', ['-C', root, ...args], {
    encoding: 'utf8',
    windowsHide: true,
  });
  assert.equal(result.status, 0, result.stderr || result.stdout);
}

function initializeRepository(root: string): void {
  git(root, ['init']);
  git(root, ['config', 'user.name', 'AgentWarden Tests']);
  git(root, ['config', 'user.email', 'tests@agentwarden.local']);
}

function readJson(filePath: string): Record<string, unknown> {
  return JSON.parse(fs.readFileSync(filePath, 'utf8')) as Record<string, unknown>;
}

describe('policy guard', () => {
  it('detects a pull request that weakens the approved policy', () => {
    const root = tempDir();
    try {
      initializeRepository(root);
      writeFile(root, '.agentwarden/policy.json', JSON.stringify({ profile: 'strict' }, null, 2));
      writeFile(root, 'skills/safe.md', '# Safe skill\n');
      git(root, ['add', '.']);
      git(root, ['commit', '-m', 'approved policy']);

      writeFile(
        root,
        '.agentwarden/policy.json',
        JSON.stringify({ profile: 'legacy', ignoreRules: ['SEC-CRED-001'] }, null, 2),
      );
      git(root, ['add', '.']);
      git(root, ['commit', '-m', 'weakened policy']);

      const approved = loadApprovedPolicy({ base: 'HEAD~1', cwd: root });
      assert.equal(approved.configPath, '.agentwarden/policy.json');
      assert.equal(approved.config.profile, 'strict');

      const result = guardPolicy(
        approved,
        readJson(path.join(root, '.agentwarden', 'policy.json')),
        path.join(root, '.agentwarden', 'policy.json'),
      );

      assert.equal(result.diff.changed, true);
      const fields = result.diff.changes.map((change) => change.field);
      assert.ok(fields.includes('profile'));
      assert.ok(fields.includes('ignoreRules'));
      assert.ok(fields.includes('minScore'));
      assert.equal(result.current.configPath, '.agentwarden/policy.json');
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  it('treats redundant defaults as equivalent to the approved policy', () => {
    const root = tempDir();
    try {
      initializeRepository(root);
      writeFile(root, '.agentwarden/policy.json', JSON.stringify({ profile: 'strict' }, null, 2));
      git(root, ['add', '.']);
      git(root, ['commit', '-m', 'approved policy']);

      writeFile(
        root,
        '.agentwarden/policy.json',
        JSON.stringify({ profile: 'strict', failOn: 'medium', minScore: 90 }, null, 2),
      );
      git(root, ['add', '.']);
      git(root, ['commit', '-m', 'spelled out defaults']);

      const approved = loadApprovedPolicy({ base: 'HEAD~1', cwd: root });
      const result = guardPolicy(
        approved,
        readJson(path.join(root, '.agentwarden', 'policy.json')),
      );

      assert.equal(result.diff.changed, false);
      assert.deepEqual(result.diff.changes, []);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  it('reads an inherited approved policy chain from the base ref', () => {
    const root = tempDir();
    try {
      initializeRepository(root);
      writeFile(root, '.agentwarden/base.json', JSON.stringify({ profile: 'strict' }, null, 2));
      writeFile(
        root,
        '.agentwarden/policy.json',
        JSON.stringify({ extends: './base.json', minScore: 95 }, null, 2),
      );
      git(root, ['add', '.']);
      git(root, ['commit', '-m', 'approved inherited policy']);

      writeFile(
        root,
        '.agentwarden/base.json',
        JSON.stringify({ profile: 'legacy' }, null, 2),
      );
      git(root, ['add', '.']);
      git(root, ['commit', '-m', 'weaken parent policy']);

      const approved = loadApprovedPolicy({ base: 'HEAD~1', cwd: root });
      assert.equal(approved.config.profile, 'strict');
      assert.equal(approved.config.minScore, 95);
      assert.deepEqual(approved.sources, ['.agentwarden/base.json', '.agentwarden/policy.json']);

      const result = guardPolicy(
        approved,
        { extends: './base.json', minScore: 95 },
      );
      assert.equal(result.diff.changed, true);
      assert.deepEqual(
        result.diff.changes.map((change) => change.field),
        ['profile', 'failOn'],
      );
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  it('fails when the approved policy is absent from the base ref', () => {
    const root = tempDir();
    try {
      initializeRepository(root);
      writeFile(root, 'skills/safe.md', '# Safe skill\n');
      git(root, ['add', '.']);
      git(root, ['commit', '-m', 'no policy yet']);

      assert.throws(
        () => loadApprovedPolicy({ base: 'HEAD', cwd: root }),
        (error: unknown) =>
          error instanceof PolicyGuardError && /No approved policy file was found/.test(error.message),
      );
      assert.throws(
        () => loadApprovedPolicy({ base: 'HEAD', cwd: root, configPath: '.agentwarden/policy.json' }),
        (error: unknown) =>
          error instanceof PolicyGuardError && /was not found on HEAD/.test(error.message),
      );
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });
});
