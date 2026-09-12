import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import {
  SignatureError,
  loadEd25519PublicKey,
  resolveSignatureBytes,
  verifyPayloadSignature,
  type SignatureErrorCode,
} from '../src/source/signature.ts';

function createSigningMaterial(): {
  publicDerBase64: string;
  publicKey: crypto.KeyObject;
  privateKey: crypto.KeyObject;
} {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const publicDer = publicKey.export({ type: 'spki', format: 'der' });
  return {
    publicDerBase64: Buffer.from(publicDer).toString('base64'),
    publicKey,
    privateKey,
  };
}

function expectSignatureError(
  operation: () => unknown,
  code: SignatureErrorCode,
  pattern: RegExp,
): void {
  assert.throws(operation, (error: unknown) => {
    assert.ok(error instanceof SignatureError);
    assert.equal(error.code, code);
    assert.match(error.message, pattern);
    return true;
  });
}

describe('Ed25519 signature verification', () => {
  it('verifies inline Ed25519 keys and detached signatures', async () => {
    const { publicDerBase64, privateKey } = createSigningMaterial();
    const payload = Buffer.from('signed skill payload\n', 'utf8');
    const signature = crypto.sign(null, payload, privateKey);

    const result = await verifyPayloadSignature(payload, {
      publicKey: `base64:${publicDerBase64}`,
      signature: `base64:${signature.toString('base64')}`,
    });

    assert.equal(result.algorithm, 'ed25519');
    assert.equal(result.publicKeySha256.length, 64);
    assert.equal(result.signatureSha256, crypto.createHash('sha256').update(signature).digest('hex'));
  });

  it('reads PEM public keys and raw, hex, or base64 signature files', async () => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'skillguard-signature-'));
    const { publicKey, privateKey } = createSigningMaterial();
    const payload = Buffer.from('package bytes', 'utf8');
    const signature = crypto.sign(null, payload, privateKey);
    const publicPath = path.join(directory, 'publisher.pub.pem');
    fs.writeFileSync(publicPath, publicKey.export({ type: 'spki', format: 'pem' }), 'utf8');

    for (const [filename, data] of [
      ['raw.sig', signature],
      ['hex.sig', signature.toString('hex')],
      ['base64.sig', signature.toString('base64')],
    ] as const) {
      const signaturePath = path.join(directory, filename);
      fs.writeFileSync(signaturePath, data);
      const result = await verifyPayloadSignature(payload, {
        publicKey: publicPath,
        signature: signaturePath,
        cwd: directory,
      });
      assert.equal(result.signatureSha256.length, 64);
    }
  });

  it('rejects tampered payloads and signatures from another key', async () => {
    const first = createSigningMaterial();
    const second = createSigningMaterial();
    const payload = Buffer.from('original payload', 'utf8');
    const signature = crypto.sign(null, payload, first.privateKey);

    await assert.rejects(
      verifyPayloadSignature(Buffer.from('tampered payload', 'utf8'), {
        publicKey: `base64:${first.publicDerBase64}`,
        signature: `base64:${signature.toString('base64')}`,
      }),
      (error: unknown) => error instanceof SignatureError && error.code === 'SIGNATURE_MISMATCH',
    );
    await assert.rejects(
      verifyPayloadSignature(payload, {
        publicKey: `base64:${second.publicDerBase64}`,
        signature: `base64:${signature.toString('base64')}`,
      }),
      (error: unknown) => error instanceof SignatureError && error.code === 'SIGNATURE_MISMATCH',
    );
  });

  it('rejects invalid signature encodings and non-Ed25519 keys', async () => {
    const { privateKey } = createSigningMaterial();
    const rsa = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const rsaPublicDer = rsa.publicKey.export({ type: 'spki', format: 'der' });

    expectSignatureError(
      () => loadEd25519PublicKey(`base64:${Buffer.from(rsaPublicDer).toString('base64')}`),
      'UNSUPPORTED_ALGORITHM',
      /expected Ed25519/,
    );
    expectSignatureError(
      () =>
        loadEd25519PublicKey(
          `pem:${privateKey.export({ type: 'pkcs8', format: 'pem' }).toString()}`,
        ),
      'INVALID_PUBLIC_KEY',
      /private key material/,
    );
    await assert.rejects(
      resolveSignatureBytes('hex:not-a-signature'),
      (error: unknown) =>
        error instanceof SignatureError &&
        error.code === 'INVALID_SIGNATURE' &&
        /64-byte hex/.test(error.message),
    );
  });

  it('downloads signatures from HTTP with an explicit test override', async () => {
    const { publicDerBase64, privateKey } = createSigningMaterial();
    const payload = Buffer.from('remote payload', 'utf8');
    const signature = crypto.sign(null, payload, privateKey);

    const result = await verifyPayloadSignature(payload, {
      publicKey: `base64:${publicDerBase64}`,
      signature: 'http://127.0.0.1:8080/payload.sig',
      allowHttp: true,
      fetchImpl: async () => new Response(signature.toString('base64')),
    });
    assert.equal(result.signatureSource, 'http://127.0.0.1:8080/payload.sig');
  });
});
