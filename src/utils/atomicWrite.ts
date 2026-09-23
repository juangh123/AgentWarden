import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';

/**
 * Write a file through a same-directory temporary file so readers never observe
 * a partial document.
 */
export function writeFileAtomic(filePath: string, content: string): void {
  const directory = path.dirname(filePath);
  fs.mkdirSync(directory, { recursive: true });
  const temporaryPath = path.join(
    directory,
    `.${path.basename(filePath)}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`,
  );

  fs.writeFileSync(temporaryPath, content, { encoding: 'utf8', flag: 'wx' });
  try {
    replaceFile(temporaryPath, filePath);
  } finally {
    fs.rmSync(temporaryPath, { force: true });
  }
}

function replaceFile(temporaryPath: string, filePath: string): void {
  try {
    fs.renameSync(temporaryPath, filePath);
    return;
  } catch (error) {
    const code =
      error && typeof error === 'object' && 'code' in error
        ? String((error as NodeJS.ErrnoException).code)
        : '';
    if (
      process.platform !== 'win32' ||
      (code !== 'EEXIST' && code !== 'EPERM' && code !== 'EACCES')
    ) {
      throw error;
    }
  }

  const backupPath = `${temporaryPath}.backup`;
  let movedExisting = false;
  let replaced = false;

  try {
    if (fs.existsSync(filePath)) {
      fs.renameSync(filePath, backupPath);
      movedExisting = true;
    }

    try {
      fs.renameSync(temporaryPath, filePath);
      replaced = true;
    } catch (error) {
      if (movedExisting && !fs.existsSync(filePath) && fs.existsSync(backupPath)) {
        try {
          fs.renameSync(backupPath, filePath);
          movedExisting = false;
        } catch {
          // The backup remains beside the target so callers can recover it manually.
        }
      }
      throw error;
    }
  } finally {
    if (movedExisting && replaced) {
      try {
        fs.rmSync(backupPath, { force: true });
      } catch {
        // A stale backup is safer than failing a completed replacement.
      }
    }
  }
}
