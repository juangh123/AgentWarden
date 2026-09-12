import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { ChangedFilesError, getChangedFiles } from '../src/index.ts';

function tempDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'agentwarden-git-changed-'));
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

function relativeFiles(root: string, files: string[]): string[] {
  const canonicalRoot = fs.realpathSync.native(root);
  return files.map((file) => path.relative(canonicalRoot, file).replace(/\\/g, '/'));
}

describe('Git changed files', () => {
  it('resolves committed changes, additions, and deletions from a base ref', () => {
    const root = tempDir();
    try {
      initializeRepository(root);
      writeFile(root, 'skills/base.md', '# Base skill\n');
      writeFile(root, 'skills/deleted.md', '# Deleted skill\n');
      writeFile(root, 'notes/readme.txt', 'base\n');
      git(root, ['add', '.']);
      git(root, ['commit', '-m', 'base']);

      writeFile(root, 'skills/base.md', '# Changed skill\n');
      writeFile(root, 'skills/new.md', '# New skill\n');
      fs.rmSync(path.join(root, 'skills', 'deleted.md'));
      git(root, ['add', '.']);
      git(root, ['commit', '-m', 'changes']);
      writeFile(root, 'skills/untracked.md', '# Untracked skill\n');
      writeFile(root, 'notes/readme.txt', 'working tree\n');

      const committed = getChangedFiles({
        cwd: root,
        base: 'HEAD~1',
        includeUntracked: false,
      });
      assert.equal(committed.baseRef, 'HEAD~1');
      assert.equal(committed.baseSha.length, 40);
      assert.deepEqual(relativeFiles(root, committed.files), [
        'notes/readme.txt',
        'skills/base.md',
        'skills/new.md',
      ]);

      const withUntracked = getChangedFiles({
        cwd: root,
        base: 'HEAD~1',
        includeUntracked: true,
      });
      assert.deepEqual(relativeFiles(root, withUntracked.files), [
        'notes/readme.txt',
        'skills/base.md',
        'skills/new.md',
        'skills/untracked.md',
      ]);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  it('rejects invalid base refs and non-Git directories', () => {
    const root = tempDir();
    try {
      assert.throws(
        () => getChangedFiles({ cwd: root, base: 'HEAD~1' }),
        (error: unknown) =>
          error instanceof ChangedFilesError && /not a git repository/i.test(error.message),
      );

      initializeRepository(root);
      writeFile(root, 'SKILL.md', '# Skill\n');
      git(root, ['add', '.']);
      git(root, ['commit', '-m', 'initial']);

      assert.throws(
        () => getChangedFiles({ cwd: root, base: 'does-not-exist' }),
        /Unable to resolve Git base ref "does-not-exist"/,
      );
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });
});
