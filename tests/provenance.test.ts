import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import type { LockedSkill } from '../src/manifest/lockfile.ts';
import {
  createSignatureProof,
  evaluateLockedPublisherPolicy,
  signatureAttestationPath,
} from '../src/source/proof.ts';
import { evaluatePublisherPolicy } from '../src/source/provenance.ts';
import { verifyPayloadSignature } from '../src/source/signature.ts';

const trustedKey = 'a'.repeat(64);
const revokedKey = 'b'.repeat(64);
const unknownKey = 'c'.repeat(64);

describe('publisher provenance policy', () => {
  it('allows unsigned installs when a signature is optional', () => {
    assert.deepEqual(evaluatePublisherPolicy(undefined, undefined), { passed: true });
    assert.deepEqual(
      evaluatePublisherPolicy(
        { requireSignature: false, trustedKeys: [trustedKey], revokedKeys: [] },
        undefined,
      ),
      { passed: true },
    );
  });

  it('requires a verified signature when configured', () => {
    const decision = evaluatePublisherPolicy({ requireSignature: true }, undefined);
    assert.equal(decision.passed, false);
    assert.equal(decision.code, 'SIGNATURE_REQUIRED');
  });

  it('enforces trusted and revoked key fingerprints', () => {
    assert.deepEqual(
      evaluatePublisherPolicy(
        { trustedKeys: [trustedKey] },
        { signatureVerified: true, signatureKeySha256: trustedKey },
      ),
      { passed: true, keySha256: trustedKey },
    );

    const untrusted = evaluatePublisherPolicy(
      { trustedKeys: [trustedKey] },
      { signatureVerified: true, signatureKeySha256: unknownKey },
    );
    assert.equal(untrusted.code, 'UNTRUSTED_PUBLISHER');

    const revoked = evaluatePublisherPolicy(
      { trustedKeys: [revokedKey], revokedKeys: [revokedKey] },
      { signatureVerified: true, signatureKeySha256: revokedKey },
    );
    assert.equal(revoked.code, 'REVOKED_PUBLISHER');
  });

  it('rejects incomplete verified signature metadata', () => {
    const decision = evaluatePublisherPolicy(
      {},
      { signatureVerified: true, signatureKeySha256: 'not-a-key' },
    );
    assert.equal(decision.passed, false);
    assert.equal(decision.code, 'INVALID_SIGNATURE_METADATA');
  });

  it('fails closed when a direct SDK policy contains malformed fingerprints', () => {
    const decision = evaluatePublisherPolicy(
      { trustedKeys: ['not-a-fingerprint'] },
      { signatureVerified: true, signatureKeySha256: trustedKey },
    );
    assert.equal(decision.passed, false);
    assert.equal(decision.code, 'INVALID_PUBLISHER_POLICY');
  });
});

describe('locked publisher provenance', () => {
  async function signedEntry(cwd: string) {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const payload = Buffer.from('---\nname: signed-demo\n---\n# Demo\n', 'utf8');
    const signature = crypto.sign(null, payload, privateKey);
    const verification = await verifyPayloadSignature(payload, {
      publicKey: `base64:${publicKey.export({ type: 'spki', format: 'der' }).toString('base64')}`,
      signature: `base64:${signature.toString('base64')}`,
    });
    const proof = createSignatureProof(verification, payload, cwd);
    const sha256 = crypto
      .createHash('sha256')
      .update(payload.toString('utf8').replace(/\r\n/g, '\n'))
      .digest('hex');
    const entry: LockedSkill = {
      name: 'signed-demo',
      version: '1.0.0',
      source: 'signed-demo.md',
      sha256,
      installedAt: new Date().toISOString(),
      verifiedScore: 100,
      sourceType: 'local',
      signatureAlgorithm: 'ed25519',
      signatureVerified: true,
      signatureKeySha256: verification.publicKeySha256,
      signatureSha256: verification.signatureSha256,
      signatureProof: proof,
    };
    return { entry, key: verification.publicKeySha256 };
  }

  it('ignores self-reported legacy signature fields', () => {
    const entry: LockedSkill = {
      name: 'forged-demo',
      version: '1.0.0',
      source: 'forged-demo.md',
      sha256: 'a'.repeat(64),
      installedAt: new Date().toISOString(),
      verifiedScore: 100,
      signatureAlgorithm: 'ed25519',
      signatureVerified: true,
      signatureKeySha256: trustedKey,
      signatureSha256: 'b'.repeat(64),
    };
    const decision = evaluateLockedPublisherPolicy(entry, {
      requireSignature: true,
      trustedKeys: [trustedKey],
    });

    assert.equal(decision.passed, false);
    assert.equal(decision.code, 'SIGNATURE_REQUIRED');
    assert.equal(decision.proofVerified, false);
  });

  it('re-verifies a cryptographic proof and binds it to the locked content', async () => {
    const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'agentwarden-proof-'));
    try {
      const { entry, key } = await signedEntry(cwd);
      const passed = evaluateLockedPublisherPolicy(
        entry,
        { requireSignature: true, trustedKeys: [key] },
        cwd,
      );
      assert.equal(passed.passed, true);
      assert.equal(passed.proofVerified, true);
      assert.equal(passed.keySha256, key);

      const tampered = { ...entry, sha256: 'f'.repeat(64) };
      const rejected = evaluateLockedPublisherPolicy(
        tampered,
        { requireSignature: true, trustedKeys: [key] },
        cwd,
      );
      assert.equal(rejected.passed, false);
      assert.equal(rejected.code, 'INVALID_SIGNATURE_PROOF');
      assert.match(rejected.message ?? '', /does not match/);
    } finally {
      fs.rmSync(cwd, { recursive: true, force: true });
    }
  });

  it('binds remote signatures after the documented BOM normalization', async () => {
    const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'agentwarden-proof-bom-'));
    try {
      const content = '---\nname: signed-demo\n---\n# Demo\n';
      const payload = Buffer.from(`\uFEFF${content}`, 'utf8');
      const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
      const signature = crypto.sign(null, payload, privateKey);
      const verification = await verifyPayloadSignature(payload, {
        publicKey: `base64:${publicKey.export({ type: 'spki', format: 'der' }).toString('base64')}`,
        signature: `base64:${signature.toString('base64')}`,
      });
      const entry: LockedSkill = {
        name: 'signed-demo',
        version: '1.0.0',
        source: '.agentwarden/skills/signed-demo.md',
        sha256: crypto.createHash('sha256').update(content).digest('hex'),
        installedAt: new Date().toISOString(),
        verifiedScore: 100,
        sourceType: 'remote',
        signatureProof: createSignatureProof(verification, payload, cwd),
      };

      const decision = evaluateLockedPublisherPolicy(
        entry,
        { requireSignature: true, trustedKeys: [verification.publicKeySha256] },
        cwd,
      );
      assert.equal(decision.passed, true);
      assert.equal(decision.proofVerified, true);
    } finally {
      fs.rmSync(cwd, { recursive: true, force: true });
    }
  });

  it('rejects unsafe attestation hashes', () => {
    assert.throws(
      () => signatureAttestationPath('../../outside', process.cwd()),
      /64-character SHA-256/,
    );
  });

  it('rejects malformed runtime proof metadata', () => {
    const entry = {
      name: 'forged-demo',
      version: '1.0.0',
      source: 'forged-demo.md',
      sha256: 'a'.repeat(64),
      installedAt: new Date().toISOString(),
      verifiedScore: 100,
      signatureProof: {
        algorithm: 'rsa',
        publicKey: '',
        signature: '',
        payloadSha256: 'b'.repeat(64),
      },
    } as unknown as LockedSkill;
    const decision = evaluateLockedPublisherPolicy(entry, { requireSignature: true });

    assert.equal(decision.passed, false);
    assert.equal(decision.code, 'INVALID_SIGNATURE_PROOF');
    assert.equal(decision.proofVerified, false);
  });
});
