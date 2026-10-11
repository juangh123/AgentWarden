import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import {
  DEFAULT_MAX_PUBLIC_KEY_BYTES,
  DEFAULT_MAX_SIGNATURE_BYTES,
  SignatureError,
  loadEd25519PublicKey,
  resolveSignatureBytes,
  verifyEd25519Signature,
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

describe('signature reference handling', () => {
  it('reads a bare base64 key file and prefixed signature references', async () => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'skillguard-signature-refs-'));
    try {
      const { publicDerBase64, privateKey } = createSigningMaterial();
      const payload = Buffer.from('prefixed payload', 'utf8');
      const signature = crypto.sign(null, payload, privateKey);

      // A .pub file holding the base64 text of a SPKI DER key, with no prefix.
      const bareKey = path.join(directory, 'publisher-bare.pub');
      fs.writeFileSync(bareKey, publicDerBase64, 'utf8');
      const loaded = loadEd25519PublicKey(bareKey, directory);
      assert.equal(loaded.key.asymmetricKeyType, 'ed25519');
      assert.equal(loaded.sha256.length, 64);

      const viaHex = await resolveSignatureBytes(`hex:${signature.toString('hex')}`);
      assert.equal(viaHex.bytes.byteLength, 64);
      const viaBase64 = await resolveSignatureBytes(`base64:${signature.toString('base64')}`);
      assert.equal(viaBase64.bytes.byteLength, 64);

      const verified = await verifyPayloadSignature(payload, {
        publicKey: bareKey,
        signature: `hex:${signature.toString('hex')}`,
        cwd: directory,
      });
      assert.equal(verified.signatureSha256.length, 64);
    } finally {
      fs.rmSync(directory, { recursive: true, force: true });
    }
  });

  it('rejects signature text that is not raw, hex, or canonical base64', async () => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'skillguard-signature-text-'));
    try {
      const cases: Array<[string, string, RegExp]> = [
        ['base64 text of the wrong length', 'AAAAA', /raw 64-byte Ed25519 signature, hex, or base64/],
        ['non-canonical base64', 'QR==', /canonical base64/],
        ['unparseable text', 'zz!!not-a-signature', /raw 64-byte Ed25519 signature, hex, or base64/],
      ];
      for (const [label, content, pattern] of cases) {
        const file = path.join(directory, `${label.replace(/\s+/g, '-')}.sig`);
        fs.writeFileSync(file, content, 'utf8');
        await assert.rejects(
          resolveSignatureBytes(file, { cwd: directory }),
          (error: unknown) => {
            assert.ok(error instanceof SignatureError, `${label} should raise SignatureError`);
            assert.equal(error.code, 'INVALID_SIGNATURE', label);
            assert.match(error.message, pattern, label);
            return true;
          },
        );
      }
    } finally {
      fs.rmSync(directory, { recursive: true, force: true });
    }
  });

  it('rejects inline key references that are unusable or oversized', () => {
    expectSignatureError(
      () => loadEd25519PublicKey('base64:!!!not-base64!!!'),
      'INVALID_PUBLIC_KEY',
      /not valid base64 data/,
    );
    expectSignatureError(
      () =>
        loadEd25519PublicKey(
          `base64:${Buffer.alloc(DEFAULT_MAX_PUBLIC_KEY_BYTES + 1).toString('base64')}`,
        ),
      'INVALID_PUBLIC_KEY',
      /exceeds the 16384-byte limit/,
    );
  });

  it('rejects signature files that are too large or unreadable', async () => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'skillguard-signature-files-'));
    try {
      const asDirectory = path.join(directory, 'folder.sig');
      fs.mkdirSync(asDirectory);
      await assert.rejects(
        resolveSignatureBytes(asDirectory, { cwd: directory }),
        (error: unknown) =>
          error instanceof SignatureError &&
          error.code === 'INVALID_SIGNATURE' &&
          /not a file/.test(error.message),
      );

      const oversized = path.join(directory, 'oversized.sig');
      fs.writeFileSync(oversized, 'x');
      fs.truncateSync(oversized, DEFAULT_MAX_SIGNATURE_BYTES + 1);
      await assert.rejects(
        resolveSignatureBytes(oversized, { cwd: directory }),
        (error: unknown) =>
          error instanceof SignatureError &&
          error.code === 'INVALID_SIGNATURE' &&
          /exceeds the 4096-byte limit/.test(error.message),
      );

      await assert.rejects(
        resolveSignatureBytes(path.join(directory, 'missing.sig'), { cwd: directory }),
        (error: unknown) =>
          error instanceof SignatureError &&
          error.code === 'READ_FAILED' &&
          /Unable to read signature/.test(error.message),
      );
    } finally {
      fs.rmSync(directory, { recursive: true, force: true });
    }
  });

  it('rejects a 32-byte signature when verifying directly', () => {
    const { publicDerBase64 } = createSigningMaterial();
    const loaded = loadEd25519PublicKey(`base64:${publicDerBase64}`);
    expectSignatureError(
      () => verifyEd25519Signature(Buffer.from('payload', 'utf8'), Buffer.alloc(32, 1), loaded),
      'INVALID_SIGNATURE',
      /must be 64 bytes/,
    );
  });

  it('maps a failed remote signature download to a read error', async () => {
    const { publicDerBase64 } = createSigningMaterial();
    await assert.rejects(
      verifyPayloadSignature(Buffer.from('payload', 'utf8'), {
        publicKey: `base64:${publicDerBase64}`,
        signature: 'https://publisher.example/weather.md.sig',
        fetchImpl: async () => {
          throw new Error('network unreachable');
        },
      }),
      (error: unknown) =>
        error instanceof SignatureError &&
        error.code === 'READ_FAILED' &&
        /Unable to download signature/.test(error.message),
    );
  });
});
