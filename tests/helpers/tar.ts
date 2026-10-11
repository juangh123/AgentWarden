import * as zlib from 'node:zlib';

export interface TarFile {
  path: string;
  content: string;
  type?: '0' | '2';
  /** Explicit tar type flag, for extended-header entries such as `x`, `g`, `L`, `K`. */
  typeFlag?: string;
  /** Header size field override, so tests can declare a truncated or PAX-driven size. */
  declaredSize?: number;
  /** Raw six-character value for the checksum field, to forge a bad header. */
  checksumOverride?: string;
  /** Skip block padding, for archives whose payload deliberately runs past the end. */
  omitPadding?: boolean;
}

function writeOctal(target: Buffer, offset: number, length: number, value: number): void {
  const text = value.toString(8).padStart(length - 1, '0') + '\0';
  target.write(text, offset, length, 'ascii');
}

function tarHeader(file: TarFile): Buffer {
  const data = Buffer.from(file.content, 'utf8');
  const header = Buffer.alloc(512, 0);
  header.write(file.path, 0, 100, 'utf8');
  writeOctal(header, 100, 8, 0o644);
  writeOctal(header, 108, 8, 0);
  writeOctal(header, 116, 8, 0);
  writeOctal(header, 124, 12, file.declaredSize ?? data.byteLength);
  writeOctal(header, 136, 12, 0);
  header.write('        ', 148, 8, 'ascii');
  header.write(file.typeFlag ?? file.type ?? '0', 156, 1, 'ascii');
  header.write('ustar\0', 257, 6, 'ascii');
  header.write('00', 263, 2, 'ascii');

  let checksum = 0;
  for (const byte of header) checksum += byte;
  const field = file.checksumOverride
    ? file.checksumOverride.padEnd(6, ' ').slice(0, 6) + '\0 '
    : checksum.toString(8).padStart(6, '0') + '\0 ';
  header.write(field, 148, 8, 'ascii');
  return header;
}

/** Build a PAX extended-header payload: "<length> <key>=<value>\n" records. */
export function paxRecords(records: Record<string, string>): string {
  return Object.entries(records)
    .map(([key, value]) => {
      const body = `${key}=${value}\n`;
      const bodyBytes = Buffer.byteLength(body, 'utf8');
      let total = bodyBytes + 2;
      while (bodyBytes + String(total).length + 1 !== total) {
        total = bodyBytes + String(total).length + 1;
      }
      return `${total} ${body}`;
    })
    .join('');
}

export function createTarGz(files: TarFile[]): Buffer {
  const blocks: Buffer[] = [];
  for (const file of files) {
    const data = Buffer.from(file.content, 'utf8');
    blocks.push(tarHeader(file));
    if (data.byteLength > 0 && !file.omitPadding) {
      const padded = Buffer.alloc(Math.ceil(data.byteLength / 512) * 512, 0);
      data.copy(padded);
      blocks.push(padded);
    } else if (data.byteLength > 0) {
      blocks.push(data);
    }
  }
  blocks.push(Buffer.alloc(1024, 0));
  return zlib.gzipSync(Buffer.concat(blocks));
}
