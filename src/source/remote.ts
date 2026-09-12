import * as crypto from 'node:crypto';
import * as path from 'node:path';

export const DEFAULT_MAX_REMOTE_BYTES = 5 * 1024 * 1024;
export const DEFAULT_FETCH_TIMEOUT_MS = 30_000;

export type RemoteSkillErrorCode =
  | 'INVALID_URL'
  | 'INVALID_DIGEST'
  | 'INSECURE_URL'
  | 'FETCH_FAILED'
  | 'HTTP_ERROR'
  | 'TOO_LARGE'
  | 'EMPTY_CONTENT'
  | 'DIGEST_MISMATCH';

export class RemoteSkillError extends Error {
  readonly code: RemoteSkillErrorCode;

  constructor(code: RemoteSkillErrorCode, message: string) {
    super(message);
    this.name = 'RemoteSkillError';
    this.code = code;
  }
}

export interface FetchRemoteSkillOptions {
  url: string;
  expectedSha256?: string;
  allowHttp?: boolean;
  maxBytes?: number;
  timeoutMs?: number;
  fetchImpl?: typeof globalThis.fetch;
}

export interface RemoteSkillDownload {
  requestedUrl: string;
  resolvedUrl: string;
  filename: string;
  contentType?: string;
  content: string;
  sha256: string;
  size: number;
  digestVerified: boolean;
}

export function normalizeExpectedSha256(value: string): string {
  const normalized = value.trim().toLowerCase().replace(/^sha256:/, '');
  if (!/^[a-f0-9]{64}$/.test(normalized)) {
    throw new RemoteSkillError(
      'INVALID_DIGEST',
      `Invalid SHA-256 "${value}" (expected 64 hexadecimal characters)`,
    );
  }
  return normalized;
}

function parseRemoteUrl(value: string, allowHttp: boolean): URL {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new RemoteSkillError('INVALID_URL', `Invalid remote URL "${value}"`);
  }

  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    throw new RemoteSkillError(
      'INVALID_URL',
      `Unsupported remote URL protocol "${url.protocol}" (expected https)`,
    );
  }
  if (url.protocol === 'http:' && !allowHttp) {
    throw new RemoteSkillError(
      'INSECURE_URL',
      `Refusing insecure HTTP URL "${url.href}". Use --allow-http only for trusted local testing.`,
    );
  }
  if (url.username || url.password) {
    throw new RemoteSkillError('INVALID_URL', 'Remote URLs must not contain embedded credentials');
  }
  return url;
}

function resolveFilename(url: URL, contentType: string | null): string {
  let basename = 'remote-skill';
  try {
    basename = path.basename(decodeURIComponent(url.pathname)) || basename;
  } catch {
    basename = path.basename(url.pathname) || basename;
  }
  basename = basename.replace(/[^a-zA-Z0-9._-]/g, '_');

  const extension = path.extname(basename).toLowerCase();
  if (extension === '.md' || extension === '.markdown') return basename;
  if (extension === '.json') return basename;
  if (contentType?.toLowerCase().includes('json')) return `${basename}.json`;
  return `${basename.replace(/\.+$/, '') || 'remote-skill'}.md`;
}

async function readResponseBody(
  response: Response,
  maxBytes: number,
): Promise<Buffer> {
  const declaredHeader = response.headers.get('content-length');
  if (declaredHeader !== null) {
    const declaredLength = Number(declaredHeader);
    if (Number.isFinite(declaredLength) && declaredLength > maxBytes) {
      throw new RemoteSkillError(
        'TOO_LARGE',
        `Remote content is ${declaredLength} bytes, exceeding the ${maxBytes}-byte limit`,
      );
    }
  }

  if (!response.body) {
    const buffer = Buffer.from(await response.arrayBuffer());
    if (buffer.byteLength > maxBytes) {
      throw new RemoteSkillError(
        'TOO_LARGE',
        `Remote content exceeds the ${maxBytes}-byte limit`,
      );
    }
    return buffer;
  }

  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of response.body as AsyncIterable<Uint8Array>) {
    const buffer = Buffer.from(chunk);
    size += buffer.byteLength;
    if (size > maxBytes) {
      throw new RemoteSkillError(
        'TOO_LARGE',
        `Remote content exceeds the ${maxBytes}-byte limit`,
      );
    }
    chunks.push(buffer);
  }
  return Buffer.concat(chunks, size);
}

/** Download one remote skill payload and verify its transport, size, and optional SHA-256 digest. */
export async function fetchRemoteSkill(
  options: FetchRemoteSkillOptions,
): Promise<RemoteSkillDownload> {
  const maxBytes = options.maxBytes ?? DEFAULT_MAX_REMOTE_BYTES;
  const timeoutMs = options.timeoutMs ?? DEFAULT_FETCH_TIMEOUT_MS;
  if (!Number.isFinite(maxBytes) || maxBytes < 1) {
    throw new RemoteSkillError('TOO_LARGE', 'Maximum remote size must be a positive number');
  }
  if (!Number.isFinite(timeoutMs) || timeoutMs < 1) {
    throw new RemoteSkillError('FETCH_FAILED', 'Remote timeout must be a positive number');
  }

  const requestedUrl = parseRemoteUrl(options.url, Boolean(options.allowHttp));
  const expectedSha256 =
    options.expectedSha256 !== undefined
      ? normalizeExpectedSha256(options.expectedSha256)
      : undefined;
  const fetcher = options.fetchImpl ?? globalThis.fetch;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetcher(requestedUrl, {
      redirect: 'follow',
      signal: controller.signal,
      headers: {
        accept: 'text/markdown, application/json;q=0.9, text/plain;q=0.8, */*;q=0.1',
        'user-agent': 'AgentWarden/remote-install',
      },
    });

    if (!response.ok) {
      throw new RemoteSkillError(
        'HTTP_ERROR',
        `Remote server returned HTTP ${response.status} ${response.statusText}`.trim(),
      );
    }

    const resolvedUrl = parseRemoteUrl(response.url || requestedUrl.href, Boolean(options.allowHttp));
    const contentBuffer = await readResponseBody(response, maxBytes);
    if (contentBuffer.byteLength === 0) {
      throw new RemoteSkillError('EMPTY_CONTENT', 'Remote skill content is empty');
    }

    const sha256 = crypto.createHash('sha256').update(contentBuffer).digest('hex');
    if (expectedSha256 && sha256 !== expectedSha256) {
      throw new RemoteSkillError(
        'DIGEST_MISMATCH',
        `Remote SHA-256 mismatch: expected ${expectedSha256}, received ${sha256}`,
      );
    }

    const content = contentBuffer.toString('utf8').replace(/^\uFEFF/, '');
    const contentType = response.headers.get('content-type') ?? undefined;
    return {
      requestedUrl: requestedUrl.href,
      resolvedUrl: resolvedUrl.href,
      filename: resolveFilename(resolvedUrl, response.headers.get('content-type')),
      ...(contentType ? { contentType } : {}),
      content,
      sha256,
      size: contentBuffer.byteLength,
      digestVerified: expectedSha256 !== undefined,
    };
  } catch (error) {
    if (error instanceof RemoteSkillError) throw error;
    const detail =
      error instanceof Error && error.name === 'AbortError'
        ? `request timed out after ${timeoutMs}ms`
        : error instanceof Error
          ? error.message
          : String(error);
    throw new RemoteSkillError('FETCH_FAILED', `Unable to download ${requestedUrl.href}: ${detail}`);
  } finally {
    clearTimeout(timer);
  }
}
