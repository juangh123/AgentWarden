import * as zlib from 'node:zlib';

export interface TarFile {
  path: string;
  content: string;
  type?: '0' | '2';
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
  writeOctal(header, 124, 12, data.byteLength);
  writeOctal(header, 136, 12, 0);
  header.write('        ', 148, 8, 'ascii');
  header.write(file.type ?? '0', 156, 1, 'ascii');
  header.write('ustar\0', 257, 6, 'ascii');
  header.write('00', 263, 2, 'ascii');

  let checksum = 0;
  for (const byte of header) checksum += byte;
  header.write(checksum.toString(8).padStart(6, '0') + '\0 ', 148, 8, 'ascii');
  return header;
}

export function createTarGz(files: TarFile[]): Buffer {
  const blocks: Buffer[] = [];
  for (const file of files) {
    const data = Buffer.from(file.content, 'utf8');
    blocks.push(tarHeader(file));
    if (data.byteLength > 0) {
      const padded = Buffer.alloc(Math.ceil(data.byteLength / 512) * 512, 0);
      data.copy(padded);
      blocks.push(padded);
    }
  }
  blocks.push(Buffer.alloc(1024, 0));
  return zlib.gzipSync(Buffer.concat(blocks));
}
