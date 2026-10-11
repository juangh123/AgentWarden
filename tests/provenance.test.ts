import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import type { LockedSkill } from '../src/manifest/lockfile.ts';
import {
  createSignatureProof,
  DEFAULT_MAX_SIGNATURE_PAYLOAD_BYTES,
  evaluateLockedPublisherPolicy,
  signatureAttestationPath,
} from '../src/source/proof.ts';
import { evaluatePublisherPolicy } from '../src/source/provenance.ts';
import { verifyPayloadSignature } from '../src/source/signature.ts';
import { extractSkillPackage } from '../src/source/package.ts';
import { createTarGz } from './helpers/tar.ts';

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

  it('rejects attestation paths that are not regular files', async () => {
    const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'agentwarden-proof-nonfile-'));
    try {
      const { entry } = await signedEntry(cwd);
      const attestation = signatureAttestationPath(entry.signatureProof!.payloadSha256, cwd);
      fs.rmSync(attestation);
      fs.mkdirSync(attestation);

      const decision = evaluateLockedPublisherPolicy(entry, { requireSignature: true }, cwd);
      assert.equal(decision.passed, false);
      assert.equal(decision.code, 'INVALID_SIGNATURE_PROOF');
      assert.match(decision.message ?? '', /not a file/);
    } finally {
      fs.rmSync(cwd, { recursive: true, force: true });
    }
  });

  it('rejects attestations larger than the configured limit', async () => {
    const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'agentwarden-proof-large-'));
    try {
      const { entry } = await signedEntry(cwd);
      const attestation = signatureAttestationPath(entry.signatureProof!.payloadSha256, cwd);
      fs.truncateSync(attestation, DEFAULT_MAX_SIGNATURE_PAYLOAD_BYTES + 1);

      const decision = evaluateLockedPublisherPolicy(entry, { requireSignature: true }, cwd);
      assert.equal(decision.passed, false);
      assert.equal(decision.code, 'INVALID_SIGNATURE_PROOF');
      assert.match(decision.message ?? '', /exceeds/);
    } finally {
      fs.rmSync(cwd, { recursive: true, force: true });
    }
  });
});

async function signedPackageFixture(cwd: string) {
  const skillContent = '---\nname: signed-package\n---\n# Demo\n';
  const archive = createTarGz([{ path: 'SKILL.md', content: skillContent }]);
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const signature = crypto.sign(null, archive, privateKey);
  const verification = await verifyPayloadSignature(archive, {
    publicKey: `base64:${publicKey.export({ type: 'spki', format: 'der' }).toString('base64')}`,
    signature: `base64:${signature.toString('base64')}`,
  });
  const packaged = extractSkillPackage(archive);
  const entry: LockedSkill = {
    name: 'signed-package',
    version: '1.0.0',
    source: '.agentwarden/skills/signed-package',
    sha256: crypto.createHash('sha256').update(skillContent.replace(/\r\n/g, '\n')).digest('hex'),
    installedAt: new Date().toISOString(),
    verifiedScore: 100,
    sourceType: 'local',
    packageFormat: 'tar.gz',
    packageSha256: packaged.sha256,
    packageEntry: packaged.entryPath,
    packageFiles: packaged.manifest,
    signatureProof: createSignatureProof(verification, archive, cwd),
  };
  return { archive, entry, verification };
}

describe('locked package signature proofs', () => {
  it('binds a signed tar.gz payload to the lockfile package metadata', async () => {
    const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'agentwarden-proof-pkg-'));
    try {
      const { entry, verification } = await signedPackageFixture(cwd);
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

  it('rejects package proofs whose metadata does not match the lockfile', async () => {
    const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'agentwarden-proof-pkg-mismatch-'));
    try {
      const { entry } = await signedPackageFixture(cwd);
      const cases: Array<[string, (base: LockedSkill) => LockedSkill, RegExp]> = [
        ['package hash', (base) => ({ ...base, packageSha256: 'f'.repeat(64) }), /package hash/],
        ['entry path', (base) => ({ ...base, packageEntry: 'nested/SKILL.md' }), /entry path/],
        ['entry content', (base) => ({ ...base, sha256: 'f'.repeat(64) }), /entry hash/],
        [
          'manifest',
          (base) => ({
            ...base,
            packageFiles: [...(base.packageFiles ?? []), { path: 'extra.md', sha256: 'a'.repeat(64), size: 1 }],
          }),
          /manifest/,
        ],
      ];

      for (const [label, mutate, pattern] of cases) {
        const decision = evaluateLockedPublisherPolicy(mutate(entry), { requireSignature: true }, cwd);
        assert.equal(decision.passed, false, `${label} should be rejected`);
        assert.equal(decision.code, 'INVALID_SIGNATURE_PROOF', `${label} should be an invalid proof`);
        assert.match(decision.message ?? '', pattern);
      }
    } finally {
      fs.rmSync(cwd, { recursive: true, force: true });
    }
  });

  it('rejects a signed package entry that carries no package metadata', async () => {
    const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'agentwarden-proof-pkg-bare-'));
    try {
      const { entry } = await signedPackageFixture(cwd);
      const { packageSha256, packageEntry, packageFiles, ...withoutPackageMetadata } = entry;
      const decision = evaluateLockedPublisherPolicy(
        withoutPackageMetadata as LockedSkill,
        { requireSignature: true },
        cwd,
      );
      assert.equal(decision.passed, false);
      assert.match(decision.message ?? '', /missing package metadata/);
    } finally {
      fs.rmSync(cwd, { recursive: true, force: true });
    }
  });

  it('rejects a signed payload that cannot be parsed as a package', async () => {
    const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'agentwarden-proof-pkg-corrupt-'));
    try {
      const corrupt = Buffer.from('this is not a tar.gz archive', 'utf8');
      const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
      const signature = crypto.sign(null, corrupt, privateKey);
      const verification = await verifyPayloadSignature(corrupt, {
        publicKey: `base64:${publicKey.export({ type: 'spki', format: 'der' }).toString('base64')}`,
        signature: `base64:${signature.toString('base64')}`,
      });
      const entry: LockedSkill = {
        name: 'corrupt-package',
        version: '1.0.0',
        source: '.agentwarden/skills/corrupt-package',
        sha256: 'a'.repeat(64),
        installedAt: new Date().toISOString(),
        verifiedScore: 100,
        packageFormat: 'tar.gz',
        packageSha256: 'b'.repeat(64),
        packageEntry: 'SKILL.md',
        packageFiles: [{ path: 'SKILL.md', sha256: 'a'.repeat(64), size: 1 }],
        signatureProof: createSignatureProof(verification, corrupt, cwd),
      };

      const decision = evaluateLockedPublisherPolicy(entry, { requireSignature: true }, cwd);
      assert.equal(decision.passed, false);
      assert.match(decision.message ?? '', /Unable to inspect signed package payload/);
    } finally {
      fs.rmSync(cwd, { recursive: true, force: true });
    }
  });
});

describe('signature proof error paths', () => {
  async function proofFixture(cwd: string) {
    const payload = Buffer.from('---\nname: proof-errors\n---\n# Demo\n', 'utf8');
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const signature = crypto.sign(null, payload, privateKey);
    const verification = await verifyPayloadSignature(payload, {
      publicKey: `base64:${publicKey.export({ type: 'spki', format: 'der' }).toString('base64')}`,
      signature: `base64:${signature.toString('base64')}`,
    });
    const proof = createSignatureProof(verification, payload, cwd);
    const sha256 = crypto.createHash('sha256').update(payload.toString('utf8').replace(/\r\n/g, '\n')).digest('hex');
    const entry: LockedSkill = {
      name: 'proof-errors',
      version: '1.0.0',
      source: 'proof-errors.md',
      sha256,
      installedAt: new Date().toISOString(),
      verifiedScore: 100,
      signatureProof: proof,
    };
    return { entry, payload, verification };
  }

  it('refuses to store a payload over the attestation limit', async () => {
    const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'agentwarden-proof-limit-'));
    try {
      const { verification } = await proofFixture(cwd);
      const oversized = Buffer.alloc(DEFAULT_MAX_SIGNATURE_PAYLOAD_BYTES + 1);
      assert.throws(() => createSignatureProof(verification, oversized, cwd), /exceeds/);
    } finally {
      fs.rmSync(cwd, { recursive: true, force: true });
    }
  });

  it('refuses to overwrite a colliding attestation', async () => {
    const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'agentwarden-proof-collide-'));
    try {
      const payload = Buffer.from('collision probe', 'utf8');
      const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
      const signature = crypto.sign(null, payload, privateKey);
      const verification = await verifyPayloadSignature(payload, {
        publicKey: `base64:${publicKey.export({ type: 'spki', format: 'der' }).toString('base64')}`,
        signature: `base64:${signature.toString('base64')}`,
      });
      const payloadSha256 = crypto.createHash('sha256').update(payload).digest('hex');
      const target = signatureAttestationPath(payloadSha256, cwd);
      fs.mkdirSync(path.dirname(target), { recursive: true });
      fs.writeFileSync(target, Buffer.from('a different payload with the same path'));

      assert.throws(() => createSignatureProof(verification, payload, cwd), /collision/);
    } finally {
      fs.rmSync(cwd, { recursive: true, force: true });
    }
  });

  it('rejects a proof whose attestation is missing or altered', async () => {
    const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'agentwarden-proof-attestation-'));
    try {
      const { entry } = await proofFixture(cwd);
      const attestation = signatureAttestationPath(entry.signatureProof!.payloadSha256, cwd);

      fs.rmSync(attestation);
      const missing = evaluateLockedPublisherPolicy(entry, { requireSignature: true }, cwd);
      assert.equal(missing.passed, false);
      assert.match(missing.message ?? '', /is missing/);

      fs.writeFileSync(attestation, Buffer.from('altered attestation bytes'));
      const altered = evaluateLockedPublisherPolicy(entry, { requireSignature: true }, cwd);
      assert.equal(altered.passed, false);
      assert.match(altered.message ?? '', /attestation hash does not match/);
    } finally {
      fs.rmSync(cwd, { recursive: true, force: true });
    }
  });

  it('rejects a tampered or mistyped signature', async () => {
    const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'agentwarden-proof-signature-'));
    try {
      const { entry } = await proofFixture(cwd);
      const proof = entry.signatureProof!;

      const wrongLength = { ...entry, signatureProof: { ...proof, signature: Buffer.alloc(32, 3).toString('base64') } };
      const short = evaluateLockedPublisherPolicy(wrongLength, { requireSignature: true }, cwd);
      assert.equal(short.passed, false);
      assert.match(short.message ?? '', /64-byte/);

      const tampered = { ...entry, signatureProof: { ...proof, signature: Buffer.alloc(64, 9).toString('base64') } };
      const failed = evaluateLockedPublisherPolicy(tampered, { requireSignature: true }, cwd);
      assert.equal(failed.passed, false);
      assert.equal(failed.code, 'INVALID_SIGNATURE_PROOF');
    } finally {
      fs.rmSync(cwd, { recursive: true, force: true });
    }
  });

  it('rejects a proof whose public key cannot be loaded', async () => {
    const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'agentwarden-proof-key-'));
    try {
      const { entry } = await proofFixture(cwd);
      const broken = { ...entry, signatureProof: { ...entry.signatureProof!, publicKey: 'not-a-real-key' } };
      const decision = evaluateLockedPublisherPolicy(broken, { requireSignature: true }, cwd);
      assert.equal(decision.passed, false);
      assert.equal(decision.code, 'INVALID_SIGNATURE_PROOF');
      assert.equal(decision.proofVerified, false);
    } finally {
      fs.rmSync(cwd, { recursive: true, force: true });
    }
  });

  it('rejects lockfile fingerprints that do not match the proof', async () => {
    const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'agentwarden-proof-fingerprint-'));
    try {
      const { entry } = await proofFixture(cwd);
      const cases: Array<[string, LockedSkill, RegExp]> = [
        ['algorithm', { ...entry, signatureAlgorithm: 'rsa' }, /algorithm/],
        ['public key', { ...entry, signatureKeySha256: 'f'.repeat(64) }, /public-key fingerprint/],
        ['signature', { ...entry, signatureSha256: 'f'.repeat(64) }, /signature fingerprint/],
      ];

      for (const [label, candidate, pattern] of cases) {
        const decision = evaluateLockedPublisherPolicy(candidate, { requireSignature: true }, cwd);
        assert.equal(decision.passed, false, `${label} should be rejected`);
        assert.match(decision.message ?? '', pattern);
      }
    } finally {
      fs.rmSync(cwd, { recursive: true, force: true });
    }
  });
});
