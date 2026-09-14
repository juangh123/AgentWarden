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
    try {
      fs.renameSync(temporaryPath, filePath);
    } catch (error) {
      const code =
        error && typeof error === 'object' && 'code' in error
          ? String((error as NodeJS.ErrnoException).code)
          : '';
      if (
        process.platform === 'win32' &&
        (code === 'EEXIST' || code === 'EPERM' || code === 'EACCES')
      ) {
        fs.rmSync(filePath, { force: true });
        fs.renameSync(temporaryPath, filePath);
      } else {
        throw error;
      }
    }
  } finally {
    fs.rmSync(temporaryPath, { force: true });
  }
}
