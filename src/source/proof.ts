import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import type { PublisherPolicy } from '../config/index.ts';
import type { LockedSkill, SignatureProof } from '../manifest/lockfile.ts';
import { extractSkillPackage } from './package.ts';
import { evaluatePublisherPolicy, type PublisherPolicyDecision } from './provenance.ts';
import {
  SignatureError,
  loadEd25519PublicKey,
  verifyEd25519Signature,
  type SignatureVerificationResult,
} from './signature.ts';

export const SIGNATURE_ATTESTATION_DIR = '.agentwarden/attestations';
export const DEFAULT_MAX_SIGNATURE_PAYLOAD_BYTES = 20 * 1024 * 1024;

export interface LockedPublisherPolicyDecision extends PublisherPolicyDecision {
  proofVerified: boolean;
}

interface SignatureAttestationReadResult {
  payload?: Buffer;
  error?: string;
}

function sha256(value: string | Uint8Array): string {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function normalizedContentSha256(value: Uint8Array, stripBom = false): string {
  let content = Buffer.from(value).toString('utf8');
  if (stripBom) content = content.replace(/^\uFEFF/, '');
  return sha256(content.replace(/\r\n/g, '\n'));
}

function canonicalPath(value: string): string {
  return value.replace(/\\/g, '/').replace(/^\.\//, '');
}

function packageManifestMatches(
  actual: Array<{ path: string; sha256: string; size: number }>,
  expected: Array<{ path: string; sha256: string; size: number }>,
): boolean {
  if (actual.length !== expected.length) return false;
  const actualPaths = new Set(actual.map((entry) => canonicalPath(entry.path)));
  return expected.every((entry) => {
    const normalized = canonicalPath(entry.path);
    if (!actualPaths.has(normalized)) return false;
    return actual.some(
      (candidate) =>
        canonicalPath(candidate.path) === normalized &&
        candidate.sha256.toLowerCase() === entry.sha256.toLowerCase() &&
        candidate.size === entry.size,
    );
  });
}

function invalidProof(message: string): LockedPublisherPolicyDecision {
  return {
    passed: false,
    code: 'INVALID_SIGNATURE_PROOF',
    message,
    proofVerified: false,
  };
}

export function signatureAttestationPath(payloadSha256: string, cwd = process.cwd()): string {
  if (!/^[a-f0-9]{64}$/i.test(payloadSha256)) {
    throw new Error('Signature payload hash must be a 64-character SHA-256 value');
  }
  return path.join(cwd, SIGNATURE_ATTESTATION_DIR, `${payloadSha256.toLowerCase()}.bin`);
}

function readSignatureAttestation(filePath: string): SignatureAttestationReadResult {
  let descriptor: number | undefined;
  try {
    descriptor = fs.openSync(filePath, 'r');
    const stat = fs.fstatSync(descriptor);
    if (!stat.isFile()) {
      return { error: `Signed payload attestation is not a file: ${filePath}` };
    }
    if (stat.size > DEFAULT_MAX_SIGNATURE_PAYLOAD_BYTES) {
      return {
        error: `Signed payload attestation exceeds the ${DEFAULT_MAX_SIGNATURE_PAYLOAD_BYTES}-byte limit`,
      };
    }

    const payload = Buffer.alloc(stat.size);
    let offset = 0;
    while (offset < payload.byteLength) {
      const read = fs.readSync(
        descriptor,
        payload,
        offset,
        payload.byteLength - offset,
        offset,
      );
      if (read === 0) {
        return { error: 'Signed payload attestation changed while it was being read' };
      }
      offset += read;
    }

    const extra = Buffer.alloc(1);
    if (fs.readSync(descriptor, extra, 0, 1, stat.size) > 0) {
      return {
        error: `Signed payload attestation exceeds the ${DEFAULT_MAX_SIGNATURE_PAYLOAD_BYTES}-byte limit`,
      };
    }
    return { payload };
  } catch {
    return { error: `Signed payload attestation is missing: ${filePath}` };
  } finally {
    if (descriptor !== undefined) {
      try {
        fs.closeSync(descriptor);
      } catch {
        // The handle is already closed or the filesystem is shutting down.
      }
    }
  }
}

/** Persist the exact signed payload in a content-addressed local attestation store. */
export function createSignatureProof(
  signature: SignatureVerificationResult,
  payload: Uint8Array,
  cwd = process.cwd(),
): SignatureProof {
  if (payload.byteLength > DEFAULT_MAX_SIGNATURE_PAYLOAD_BYTES) {
    throw new Error(
      `Signed payload exceeds the ${DEFAULT_MAX_SIGNATURE_PAYLOAD_BYTES}-byte attestation limit`,
    );
  }
  const payloadSha256 = sha256(payload);
  const target = signatureAttestationPath(payloadSha256, cwd);
  const directory = path.dirname(target);
  fs.mkdirSync(directory, { recursive: true });

  const expected = Buffer.from(payload);
  if (fs.existsSync(target)) {
    const existing = readSignatureAttestation(target);
    if (
      existing.error ||
      !existing.payload ||
      sha256(existing.payload) !== payloadSha256 ||
      !existing.payload.equals(expected)
    ) {
      throw new Error(`Signature attestation collision at ${target}`);
    }
  } else {
    const temporary = path.join(
      directory,
      `.${path.basename(target)}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`,
    );
    try {
      fs.writeFileSync(temporary, expected, { flag: 'wx' });
      fs.renameSync(temporary, target);
    } catch (error) {
      if (!fs.existsSync(target)) throw error;
      const existing = readSignatureAttestation(target);
      if (
        existing.error ||
        !existing.payload ||
        sha256(existing.payload) !== payloadSha256 ||
        !existing.payload.equals(expected)
      ) {
        throw new Error(`Signature attestation collision at ${target}`);
      }
    } finally {
      fs.rmSync(temporary, { force: true });
    }
  }

  return {
    algorithm: signature.algorithm,
    publicKey: signature.publicKeySpkiBase64,
    signature: signature.signatureBase64,
    payloadSha256,
  };
}

function proofBindsToEntry(
  entry: LockedSkill,
  payload: Uint8Array,
): string | undefined {
  if (entry.packageFormat === 'tar.gz') {
    if (!entry.packageSha256 || !entry.packageEntry || !entry.packageFiles) {
      return 'Signed package entry is missing package metadata';
    }
    try {
      const packaged = extractSkillPackage(payload);
      if (packaged.sha256 !== entry.packageSha256.toLowerCase()) {
        return 'Signed package content does not match the lockfile package hash';
      }
      if (canonicalPath(packaged.entryPath) !== canonicalPath(entry.packageEntry)) {
        return 'Signed package entry path does not match the lockfile';
      }
      const packagedEntry = packaged.files.find(
        (file) => canonicalPath(file.path) === canonicalPath(packaged.entryPath),
      );
      if (
        !packagedEntry ||
        normalizedContentSha256(packagedEntry.data, true) !== entry.sha256.toLowerCase()
      ) {
        return 'Signed package entry hash does not match the lockfile';
      }
      if (!packageManifestMatches(packaged.manifest, entry.packageFiles)) {
        return 'Signed package manifest does not match the lockfile';
      }
    } catch (error) {
      return `Unable to inspect signed package payload: ${
        error instanceof Error ? error.message : String(error)
      }`;
    }
    return undefined;
  }

  if (
    normalizedContentSha256(payload, entry.sourceType === 'remote') !==
    entry.sha256.toLowerCase()
  ) {
    return 'Signed payload does not match the lockfile content hash';
  }
  return undefined;
}

/**
 * Re-verify a lockfile signature proof and bind it to the locked artifact.
 * Legacy self-reported signature booleans are deliberately treated as absent.
 */
export function evaluateLockedPublisherPolicy(
  entry: LockedSkill,
  policy: PublisherPolicy | undefined,
  cwd = process.cwd(),
): LockedPublisherPolicyDecision {
  const proof = entry.signatureProof;
  if (!proof) {
    return {
      ...evaluatePublisherPolicy(policy, undefined),
      proofVerified: false,
    };
  }
  if (
    typeof proof !== 'object' ||
    proof.algorithm !== 'ed25519' ||
    typeof proof.publicKey !== 'string' ||
    typeof proof.signature !== 'string' ||
    typeof proof.payloadSha256 !== 'string' ||
    !/^[a-f0-9]{64}$/i.test(proof.payloadSha256)
  ) {
    return invalidProof('Publisher signature proof has invalid metadata');
  }

  let publicKey;
  let signatureBytes: Buffer;
  try {
    publicKey = loadEd25519PublicKey(`base64:${proof.publicKey}`, cwd);
    signatureBytes = Buffer.from(proof.signature, 'base64');
    if (signatureBytes.byteLength !== 64) {
      return invalidProof('Publisher signature proof is not a 64-byte Ed25519 signature');
    }
  } catch (error) {
    return invalidProof(
      error instanceof SignatureError
        ? error.message
        : `Unable to load publisher signature proof: ${
            error instanceof Error ? error.message : String(error)
          }`,
    );
  }

  let attestation: string;
  try {
    attestation = signatureAttestationPath(proof.payloadSha256, cwd);
  } catch (error) {
    return invalidProof(
      error instanceof Error ? error.message : 'Invalid signature payload hash',
    );
  }
  const attestationRead = readSignatureAttestation(attestation);
  if (attestationRead.error || !attestationRead.payload) {
    return invalidProof(
      attestationRead.error ?? `Signed payload attestation is missing: ${attestation}`,
    );
  }
  const payload = attestationRead.payload;
  if (sha256(payload) !== proof.payloadSha256.toLowerCase()) {
    return invalidProof('Signed payload attestation hash does not match the lockfile');
  }

  try {
    verifyEd25519Signature(payload, signatureBytes, publicKey);
  } catch (error) {
    return invalidProof(
      error instanceof SignatureError
        ? error.message
        : `Publisher signature verification failed: ${
            error instanceof Error ? error.message : String(error)
          }`,
    );
  }

  if (
    entry.signatureAlgorithm !== undefined &&
    entry.signatureAlgorithm !== proof.algorithm
  ) {
    return invalidProof('Publisher signature algorithm does not match the lockfile');
  }
  if (
    entry.signatureKeySha256 !== undefined &&
    entry.signatureKeySha256.toLowerCase() !== publicKey.sha256
  ) {
    return invalidProof('Publisher public-key fingerprint does not match the lockfile');
  }
  if (
    entry.signatureSha256 !== undefined &&
    entry.signatureSha256.toLowerCase() !== sha256(signatureBytes)
  ) {
    return invalidProof('Publisher signature fingerprint does not match the lockfile');
  }

  const bindingError = proofBindsToEntry(entry, payload);
  if (bindingError) return invalidProof(bindingError);

  return {
    ...evaluatePublisherPolicy(policy, {
      signatureVerified: true,
      signatureKeySha256: publicKey.sha256,
    }),
    proofVerified: true,
  };
}
