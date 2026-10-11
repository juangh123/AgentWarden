import { afterEach, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { syncBuiltinESMExports } from 'node:module';
import { writeFileAtomic } from '../src/utils/atomicWrite.ts';

const originalRename = fs.renameSync;
const originalPlatform = Object.getOwnPropertyDescriptor(process, 'platform');

function restoreFs(): void {
  fs.renameSync = originalRename;
  if (originalPlatform) {
    Object.defineProperty(process, 'platform', originalPlatform);
  }
  syncBuiltinESMExports();
}

describe('atomic writes', () => {
  afterEach(restoreFs);

  it('restores the previous file when Windows replacement fails', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'agentwarden-atomic-'));
    const filePath = path.join(root, 'output.json');
    fs.writeFileSync(filePath, 'previous', 'utf8');

    let renameCalls = 0;
    try {
      Object.defineProperty(process, 'platform', {
        value: 'win32',
        configurable: true,
      });
      fs.renameSync = ((...args: Parameters<typeof fs.renameSync>) => {
        renameCalls++;
        if (renameCalls === 1) {
          const error = new Error('target is locked') as NodeJS.ErrnoException;
          error.code = 'EPERM';
          throw error;
        }
        if (renameCalls === 3) {
          const error = new Error('replacement failed') as NodeJS.ErrnoException;
          error.code = 'EIO';
          throw error;
        }
        return originalRename(...args);
      }) as typeof fs.renameSync;
      syncBuiltinESMExports();

      assert.throws(
        () => writeFileAtomic(filePath, 'replacement'),
        (error: unknown) =>
          error instanceof Error &&
          (error as NodeJS.ErrnoException).code === 'EIO',
      );
      assert.equal(fs.readFileSync(filePath, 'utf8'), 'previous');
      assert.deepEqual(
        fs.readdirSync(root).filter((entry) => entry.includes('.tmp')),
        [],
      );
    } finally {
      restoreFs();
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  it('completes the Windows fallback replacement and clears its backup', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'agentwarden-atomic-fallback-'));
    const filePath = path.join(root, 'output.json');
    fs.writeFileSync(filePath, 'previous', 'utf8');

    let renameCalls = 0;
    try {
      Object.defineProperty(process, 'platform', { value: 'win32', configurable: true });
      fs.renameSync = ((...args: Parameters<typeof fs.renameSync>) => {
        renameCalls++;
        if (renameCalls === 1) {
          const error = new Error('target is locked') as NodeJS.ErrnoException;
          error.code = 'EPERM';
          throw error;
        }
        return originalRename(...args);
      }) as typeof fs.renameSync;
      syncBuiltinESMExports();

      writeFileAtomic(filePath, 'replacement');

      assert.equal(fs.readFileSync(filePath, 'utf8'), 'replacement');
      assert.deepEqual(fs.readdirSync(root).filter((entry) => entry !== 'output.json'), []);
    } finally {
      restoreFs();
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  it('propagates a replacement failure on non-Windows platforms', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'agentwarden-atomic-posix-'));
    const filePath = path.join(root, 'output.json');
    fs.writeFileSync(filePath, 'previous', 'utf8');

    try {
      Object.defineProperty(process, 'platform', { value: 'linux', configurable: true });
      fs.renameSync = (() => {
        const error = new Error('disk failure') as NodeJS.ErrnoException;
        error.code = 'EIO';
        throw error;
      }) as typeof fs.renameSync;
      syncBuiltinESMExports();

      assert.throws(() => writeFileAtomic(filePath, 'replacement'), /disk failure/);
      assert.equal(fs.readFileSync(filePath, 'utf8'), 'previous');
    } finally {
      restoreFs();
      fs.rmSync(root, { recursive: true, force: true });
    }
  });
});
