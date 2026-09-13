import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { evaluatePublisherPolicy } from '../src/source/provenance.ts';

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
