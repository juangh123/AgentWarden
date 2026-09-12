import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import * as crypto from 'node:crypto';
import {
  RemoteSkillError,
  fetchRemoteSkill,
  type RemoteSkillErrorCode,
} from '../src/source/remote.ts';

function sha256(value: string | Uint8Array): string {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function expectRemoteError(
  operation: Promise<unknown>,
  code: RemoteSkillErrorCode,
  messagePattern: RegExp,
): Promise<void> {
  return assert.rejects(operation, (error: unknown) => {
    assert.ok(error instanceof RemoteSkillError);
    assert.equal(error.code, code);
    assert.match(error.message, messagePattern);
    return true;
  });
}

describe('remote skill fetching', () => {
  it('rejects HTTP by default before making a request', async () => {
    let called = false;
    await expectRemoteError(
      fetchRemoteSkill({
        url: 'http://example.com/skill.md',
        fetchImpl: async () => {
          called = true;
          return new Response('unused');
        },
      }),
      'INSECURE_URL',
      /Refusing insecure HTTP URL/,
    );
    assert.equal(called, false);
  });

  it('rejects embedded URL credentials', async () => {
    await expectRemoteError(
      fetchRemoteSkill({ url: 'https://user:secret@example.com/skill.md' }),
      'INVALID_URL',
      /must not contain embedded credentials/,
    );
  });

  it('uses a dedicated error for invalid SHA-256 pins', async () => {
    await expectRemoteError(
      fetchRemoteSkill({
        url: 'https://example.com/skill.md',
        expectedSha256: 'not-a-digest',
      }),
      'INVALID_DIGEST',
      /Invalid SHA-256/,
    );
  });

  it('reports HTTP status failures', async () => {
    await expectRemoteError(
      fetchRemoteSkill({
        url: 'https://example.com/missing.md',
        fetchImpl: async () => new Response('missing', { status: 404, statusText: 'Not Found' }),
      }),
      'HTTP_ERROR',
      /HTTP 404 Not Found/,
    );
  });

  it('aborts downloads that exceed the timeout', async () => {
    await expectRemoteError(
      fetchRemoteSkill({
        url: 'https://example.com/slow.md',
        timeoutMs: 10,
        fetchImpl: (_input, init) =>
          new Promise<Response>((_resolve, reject) => {
            init?.signal?.addEventListener('abort', () => {
              const error = new Error('aborted');
              error.name = 'AbortError';
              reject(error);
            });
          }),
      }),
      'FETCH_FAILED',
      /timed out after 10ms/,
    );
  });

  it('rejects empty responses', async () => {
    await expectRemoteError(
      fetchRemoteSkill({
        url: 'https://example.com/empty.md',
        fetchImpl: async () => new Response(''),
      }),
      'EMPTY_CONTENT',
      /content is empty/,
    );
  });

  it('rejects a declared content length above the limit', async () => {
    await expectRemoteError(
      fetchRemoteSkill({
        url: 'https://example.com/large.md',
        maxBytes: 4,
        fetchImpl: async () =>
          new Response('hello', {
            headers: { 'content-length': '5', 'content-type': 'text/markdown' },
          }),
      }),
      'TOO_LARGE',
      /exceeding the 4-byte limit/,
    );
  });

  it('rejects a streamed body above the limit even without content length', async () => {
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode('abc'));
        controller.enqueue(new TextEncoder().encode('def'));
        controller.close();
      },
    });

    await expectRemoteError(
      fetchRemoteSkill({
        url: 'https://example.com/stream.md',
        maxBytes: 5,
        fetchImpl: async () => new Response(stream),
      }),
      'TOO_LARGE',
      /exceeds the 5-byte limit/,
    );
  });

  it('verifies a matching SHA-256 pin and rejects a mismatch', async () => {
    const content = '---\nname: remote-demo\n---\nBe helpful.\n';
    const digest = sha256(content);
    const download = await fetchRemoteSkill({
      url: 'https://example.com/skill.md',
      expectedSha256: `sha256:${digest.toUpperCase()}`,
      fetchImpl: async () =>
        new Response(content, {
          headers: { 'content-type': 'text/markdown; charset=utf-8' },
        }),
    });

    assert.equal(download.sha256, digest);
    assert.equal(download.digestVerified, true);
    assert.equal(download.filename, 'skill.md');
    assert.equal(download.content, content);

    await expectRemoteError(
      fetchRemoteSkill({
        url: 'https://example.com/skill.md',
        expectedSha256: '0'.repeat(64),
        fetchImpl: async () => new Response(content),
      }),
      'DIGEST_MISMATCH',
      /Remote SHA-256 mismatch/,
    );
  });

  it('rejects a final redirect back to plain HTTP when HTTPS is required', async () => {
    const response = {
      ok: true,
      status: 200,
      statusText: 'OK',
      url: 'http://example.com/skill.md',
      headers: new Headers({ 'content-type': 'text/markdown' }),
      body: null,
      arrayBuffer: async () => new TextEncoder().encode('remote').buffer,
    } as unknown as Response;

    await expectRemoteError(
      fetchRemoteSkill({
        url: 'https://example.com/redirect',
        fetchImpl: async () => response,
      }),
      'INSECURE_URL',
      /Refusing insecure HTTP URL/,
    );
  });

  it('derives a safe filename and strips a UTF-8 BOM from text content', async () => {
    const bytes = Buffer.concat([
      Buffer.from([0xef, 0xbb, 0xbf]),
      Buffer.from('# Remote skill\n', 'utf8'),
    ]);
    const download = await fetchRemoteSkill({
      url: 'https://example.com/skills/My%20Skill.md?download=1',
      expectedSha256: sha256(bytes),
      fetchImpl: async () =>
        new Response(bytes, {
          headers: { 'content-type': 'text/markdown; charset=utf-8' },
        }),
    });

    assert.equal(download.filename, 'My_Skill.md');
    assert.equal(download.content, '# Remote skill\n');
    assert.equal(download.sha256, sha256(bytes));
    assert.equal(download.size, bytes.byteLength);
  });
});
