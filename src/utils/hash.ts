import * as crypto from 'node:crypto';

/** Lowercase hex SHA-256 over the given bytes, or over UTF-8 text. */
export function sha256(value: string | Uint8Array): string {
  return crypto.createHash('sha256').update(value).digest('hex');
}
