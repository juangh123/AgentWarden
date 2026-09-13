import type { PublisherPolicy } from '../config/index.ts';

export type PublisherPolicyViolationCode =
  | 'SIGNATURE_REQUIRED'
  | 'INVALID_PUBLISHER_POLICY'
  | 'INVALID_SIGNATURE_METADATA'
  | 'UNTRUSTED_PUBLISHER'
  | 'REVOKED_PUBLISHER';

export interface PublisherProvenance {
  signatureVerified?: boolean;
  signatureKeySha256?: string;
}

export interface PublisherPolicyDecision {
  passed: boolean;
  code?: PublisherPolicyViolationCode;
  message?: string;
  keySha256?: string;
}

function normalizedFingerprint(value: string | undefined): string | undefined {
  if (value === undefined) return undefined;
  const normalized = value.trim().toLowerCase().replace(/^sha256:/, '');
  return /^[a-f0-9]{64}$/.test(normalized) ? normalized : undefined;
}

function normalizedFingerprintSet(values: string[] | undefined): Set<string> | undefined {
  const normalized = new Set<string>();
  for (const value of values ?? []) {
    const fingerprint = normalizedFingerprint(value);
    if (!fingerprint) return undefined;
    normalized.add(fingerprint);
  }
  return normalized;
}

/**
 * Enforce publisher presence, allowlist, and revocation requirements.
 * Revocation takes precedence over trust and cannot be bypassed by signature presence.
 */
export function evaluatePublisherPolicy(
  policy: PublisherPolicy | undefined,
  provenance: PublisherProvenance | undefined,
): PublisherPolicyDecision {
  const requireSignature = policy?.requireSignature === true;
  const trustedKeys = normalizedFingerprintSet(policy?.trustedKeys);
  const revokedKeys = normalizedFingerprintSet(policy?.revokedKeys);
  if (!trustedKeys || !revokedKeys) {
    return {
      passed: false,
      code: 'INVALID_PUBLISHER_POLICY',
      message: 'Publisher policy contains an invalid key fingerprint',
    };
  }
  const keySha256 = normalizedFingerprint(provenance?.signatureKeySha256);
  const hasSignature = provenance?.signatureVerified === true;

  if (!hasSignature) {
    if (provenance?.signatureVerified === false || provenance?.signatureKeySha256 !== undefined) {
      return {
        passed: false,
        code: 'INVALID_SIGNATURE_METADATA',
        message: 'Publisher signature metadata is incomplete or not verified',
      };
    }
    return requireSignature
      ? {
          passed: false,
          code: 'SIGNATURE_REQUIRED',
          message: 'A verified Ed25519 publisher signature is required by policy',
        }
      : { passed: true };
  }

  if (!keySha256) {
    return {
      passed: false,
      code: 'INVALID_SIGNATURE_METADATA',
      message: 'Verified publisher signature is missing a valid key fingerprint',
    };
  }
  if (revokedKeys.has(keySha256)) {
    return {
      passed: false,
      code: 'REVOKED_PUBLISHER',
      message: `Publisher key ${keySha256} is revoked by policy`,
      keySha256,
    };
  }
  if (trustedKeys.size > 0 && !trustedKeys.has(keySha256)) {
    return {
      passed: false,
      code: 'UNTRUSTED_PUBLISHER',
      message: `Publisher key ${keySha256} is not listed in trustedKeys`,
      keySha256,
    };
  }
  return { passed: true, keySha256 };
}
