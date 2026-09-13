import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { RemoteSkillError, fetchRemoteSkill } from './remote.ts';

export const DEFAULT_MAX_SIGNATURE_BYTES = 4 * 1024;
export const DEFAULT_MAX_PUBLIC_KEY_BYTES = 16 * 1024;

export type SignatureErrorCode =
  | 'INVALID_PUBLIC_KEY'
  | 'INVALID_SIGNATURE'
  | 'UNSUPPORTED_ALGORITHM'
  | 'SIGNATURE_MISMATCH'
  | 'READ_FAILED';

export class SignatureError extends Error {
  readonly code: SignatureErrorCode;

  constructor(code: SignatureErrorCode, message: string) {
    super(message);
    this.name = 'SignatureError';
    this.code = code;
  }
}

export interface LoadedEd25519PublicKey {
  key: crypto.KeyObject;
  sha256: string;
  source: string;
}

export interface SignatureVerificationResult {
  algorithm: 'ed25519';
  publicKeySha256: string;
  signatureSha256: string;
  publicKeySource: string;
  signatureSource: string;
}

export interface ResolveSignatureOptions {
  cwd?: string;
  allowHttp?: boolean;
  fetchImpl?: typeof globalThis.fetch;
}

export interface VerifyPayloadSignatureOptions extends ResolveSignatureOptions {
  signature: string;
  publicKey: string;
}

function sha256(value: Uint8Array): string {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function decodeStrictBase64(value: string): Buffer {
  const normalized = value.replace(/\s+/g, '');
  if (
    !normalized ||
    normalized.length % 4 !== 0 ||
    !/^[A-Za-z0-9+/]+={0,2}$/.test(normalized)
  ) {
    throw new SignatureError('INVALID_SIGNATURE', 'Signature is not valid base64 data');
  }
  const decoded = Buffer.from(normalized, 'base64');
  if (decoded.toString('base64') !== normalized) {
    throw new SignatureError('INVALID_SIGNATURE', 'Signature is not valid canonical base64 data');
  }
  return decoded;
}

function decodeDetachedSignature(data: Buffer): Buffer {
  if (data.byteLength === 64) return data;

  const text = data.toString('utf8').trim();
  if (/^[a-f0-9]{128}$/i.test(text)) {
    return Buffer.from(text, 'hex');
  }

  const normalized = text.replace(/\s+/g, '');
  if (/^[A-Za-z0-9+/]+={0,2}$/.test(normalized) && normalized.length % 4 === 0) {
    return decodeStrictBase64(normalized);
  }

  throw new SignatureError(
    'INVALID_SIGNATURE',
    'Detached signature must be a raw 64-byte Ed25519 signature, hex, or base64 text',
  );
}

function createPublicKeyFromData(data: Buffer, source: string): crypto.KeyObject {
  const text = data.toString('utf8').trim();
  if (/PRIVATE KEY/.test(text)) {
    throw new SignatureError(
      'INVALID_PUBLIC_KEY',
      `Public key reference "${source}" contains private key material`,
    );
  }

  let key: crypto.KeyObject | undefined;
  if (text.includes('BEGIN PUBLIC KEY')) {
    try {
      key = crypto.createPublicKey(text);
    } catch {
      // Fall through to the stable public-key error below.
    }
  } else {
    try {
      key = crypto.createPublicKey({ key: data, format: 'der', type: 'spki' });
    } catch {
      // Try a base64-encoded DER key below.
    }
  }

  if (!key && /^[A-Za-z0-9+/=\s]+$/.test(text)) {
    try {
      key = crypto.createPublicKey({
        key: decodeStrictBase64(text),
        format: 'der',
        type: 'spki',
      });
    } catch {
      // Fall through to the stable public-key error below.
    }
  }

  if (!key) {
    throw new SignatureError(
      'INVALID_PUBLIC_KEY',
      `Unable to parse an Ed25519 public key from "${source}"`,
    );
  }
  return key;
}

/** Load a trusted Ed25519 public key from a local file or inline DER/PEM reference. */
export function loadEd25519PublicKey(
  reference: string,
  cwd: string = process.cwd(),
): LoadedEd25519PublicKey {
  let data: Buffer;
  if (reference.startsWith('base64:')) {
    try {
      data = decodeStrictBase64(reference.slice('base64:'.length));
    } catch {
      throw new SignatureError('INVALID_PUBLIC_KEY', 'Inline public key is not valid base64 data');
    }
  } else if (reference.startsWith('pem:')) {
    data = Buffer.from(reference.slice('pem:'.length).replace(/\\n/g, '\n'), 'utf8');
  } else {
    const keyPath = path.resolve(cwd, reference);
    try {
      const stat = fs.statSync(keyPath);
      if (!stat.isFile()) {
        throw new SignatureError(
          'INVALID_PUBLIC_KEY',
          `Public key is not a file: ${keyPath}`,
        );
      }
      if (stat.size > DEFAULT_MAX_PUBLIC_KEY_BYTES) {
        throw new SignatureError(
          'INVALID_PUBLIC_KEY',
          `Public key exceeds the ${DEFAULT_MAX_PUBLIC_KEY_BYTES}-byte limit`,
        );
      }
      data = fs.readFileSync(keyPath);
    } catch (error) {
      if (error instanceof SignatureError) throw error;
      throw new SignatureError(
        'READ_FAILED',
        `Unable to read public key "${reference}": ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }

  if (data.byteLength > DEFAULT_MAX_PUBLIC_KEY_BYTES) {
    throw new SignatureError(
      'INVALID_PUBLIC_KEY',
      `Public key exceeds the ${DEFAULT_MAX_PUBLIC_KEY_BYTES}-byte limit`,
    );
  }

  const key = createPublicKeyFromData(data, reference);
  if (key.type !== 'public') {
    throw new SignatureError(
      'INVALID_PUBLIC_KEY',
      `Public key reference "${reference}" does not contain a public key`,
    );
  }
  if (key.asymmetricKeyType !== 'ed25519') {
    throw new SignatureError(
      'UNSUPPORTED_ALGORITHM',
      `Public key "${reference}" uses "${key.asymmetricKeyType ?? 'unknown'}", expected Ed25519`,
    );
  }

  const der = key.export({ type: 'spki', format: 'der' });
  return {
    key,
    sha256: sha256(der),
    source: reference,
  };
}

/** Resolve a detached Ed25519 signature from inline text, a local file, or an HTTP(S) URL. */
export async function resolveSignatureBytes(
  reference: string,
  options: ResolveSignatureOptions = {},
): Promise<{ bytes: Buffer; source: string }> {
  const cwd = options.cwd ?? process.cwd();
  if (reference.startsWith('base64:')) {
    return {
      bytes: decodeDetachedSignature(Buffer.from(reference.slice('base64:'.length), 'utf8')),
      source: reference,
    };
  }
  if (reference.startsWith('hex:')) {
    const value = reference.slice('hex:'.length).trim();
    if (!/^[a-f0-9]{128}$/i.test(value)) {
      throw new SignatureError('INVALID_SIGNATURE', 'Inline signature is not a 64-byte hex value');
    }
    return { bytes: Buffer.from(value, 'hex'), source: reference };
  }

  if (/^https?:\/\//i.test(reference)) {
    try {
      const download = await fetchRemoteSkill({
        url: reference,
        allowHttp: options.allowHttp,
        maxBytes: DEFAULT_MAX_SIGNATURE_BYTES,
        timeoutMs: 10_000,
        ...(options.fetchImpl ? { fetchImpl: options.fetchImpl } : {}),
      });
      return {
        bytes: decodeDetachedSignature(Buffer.from(download.bytes)),
        source: download.resolvedUrl,
      };
    } catch (error) {
      if (error instanceof RemoteSkillError) {
        throw new SignatureError('READ_FAILED', `Unable to download signature: ${error.message}`);
      }
      throw error;
    }
  }

  const signaturePath = path.resolve(cwd, reference);
  try {
    const stat = fs.statSync(signaturePath);
    if (!stat.isFile()) {
      throw new SignatureError('INVALID_SIGNATURE', `Signature is not a file: ${signaturePath}`);
    }
    if (stat.size > DEFAULT_MAX_SIGNATURE_BYTES) {
      throw new SignatureError(
        'INVALID_SIGNATURE',
        `Signature exceeds the ${DEFAULT_MAX_SIGNATURE_BYTES}-byte limit`,
      );
    }
    return {
      bytes: decodeDetachedSignature(fs.readFileSync(signaturePath)),
      source: signaturePath,
    };
  } catch (error) {
    if (error instanceof SignatureError) throw error;
    throw new SignatureError(
      'READ_FAILED',
      `Unable to read signature "${reference}": ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

/** Verify a detached Ed25519 signature and return stable key/signature fingerprints. */
export function verifyEd25519Signature(
  payload: Uint8Array,
  signature: Uint8Array,
  publicKey: LoadedEd25519PublicKey,
): SignatureVerificationResult {
  if (signature.byteLength !== 64) {
    throw new SignatureError(
      'INVALID_SIGNATURE',
      `Ed25519 signatures must be 64 bytes, received ${signature.byteLength}`,
    );
  }

  let valid = false;
  try {
    valid = crypto.verify(null, payload, publicKey.key, signature);
  } catch (error) {
    throw new SignatureError(
      'INVALID_SIGNATURE',
      `Unable to verify Ed25519 signature: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  if (!valid) {
    throw new SignatureError(
      'SIGNATURE_MISMATCH',
      `Ed25519 signature does not match public key ${publicKey.sha256}`,
    );
  }

  return {
    algorithm: 'ed25519',
    publicKeySha256: publicKey.sha256,
    signatureSha256: sha256(signature),
    publicKeySource: publicKey.source,
    signatureSource: 'detached',
  };
}

/** Resolve and verify a detached signature over one payload. */
export async function verifyPayloadSignature(
  payload: Uint8Array,
  options: VerifyPayloadSignatureOptions,
): Promise<SignatureVerificationResult> {
  const publicKey = loadEd25519PublicKey(options.publicKey, options.cwd);
  const signature = await resolveSignatureBytes(options.signature, options);
  const result = verifyEd25519Signature(payload, signature.bytes, publicKey);
  return { ...result, signatureSource: signature.source };
}
