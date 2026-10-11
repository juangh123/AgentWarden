import * as fs from 'node:fs';
import * as path from 'node:path';
import { chalk } from '../../reporter/chalk.ts';
import { scanSkillContent } from '../../scanner/index.ts';
import { redactReportValue, redactText, renderScanReport, toReportScanResult, type ReportFormat } from '../../reporter/index.ts';
import { readLockfile, updateLockfileSkill, toRelativePosix } from '../../manifest/lockfile.ts';
import { type SkillGuardConfig } from '../../config/index.ts';
import type { Finding, ScanResult } from '../../rules/types.ts';
import { RemoteSkillError, fetchRemoteSkill } from '../../source/remote.ts';
import { SkillPackageError, extractSkillPackage, isSkillPackageSource, prepareSkillPackageWrite, readSkillPackageBytes, type SkillPackage } from '../../source/package.ts';
import { calculateScore } from '../../scanner/scoring.ts';
import {
  SignatureError,
  verifyPayloadSignature,
  type SignatureVerificationResult,
} from '../../source/signature.ts';
import {
  evaluatePublisherPolicy,
  type PublisherPolicyDecision,
  type PublisherProvenance,
} from '../../source/provenance.ts';
import { createSignatureProof } from '../../source/proof.ts';
import { writeFileAtomic } from '../../utils/atomicWrite.ts';
import { type ParsedArgs, usageError, EXIT_FAIL, reportOptions } from '../args.ts';
import { warnIfPublisherIdentityUnpinned, resolvePath } from '../shared.ts';
import { buildConfig } from '../config.ts';

export interface InstallSignatureOptions {
  signature: string;
  publicKey: string;
}

export function installSignatureOptions(options: ParsedArgs['options']): InstallSignatureOptions | undefined {
  const signature =
    options.signature !== undefined ? String(options.signature).trim() : undefined;
  const publicKey =
    options['public-key'] !== undefined ? String(options['public-key']).trim() : undefined;

  if (!signature && !publicKey) return undefined;
  if (!signature || !publicKey) {
    usageError('--signature and --public-key must be provided together');
  }
  return { signature, publicKey };
}

export async function verifyInstallSignature(
  payload: Uint8Array,
  signatureOptions: InstallSignatureOptions | undefined,
  allowHttp: boolean,
): Promise<SignatureVerificationResult | undefined> {
  if (!signatureOptions) return undefined;
  try {
    return await verifyPayloadSignature(payload, {
      signature: signatureOptions.signature,
      publicKey: signatureOptions.publicKey,
      allowHttp,
    });
  } catch (error) {
    if (
      error instanceof SignatureError &&
      (error.code === 'INVALID_PUBLIC_KEY' ||
        error.code === 'UNSUPPORTED_ALGORITHM' ||
        error.code === 'INVALID_SIGNATURE')
    ) {
      usageError(error.message);
    }
    throw error;
  }
}

export function signatureReport(signature: SignatureVerificationResult | undefined) {
  return signature
    ? {
        algorithm: signature.algorithm,
        verified: true,
        keySha256: signature.publicKeySha256,
        signatureSha256: signature.signatureSha256,
        publicKeySource: signature.publicKeySource,
        signatureSource: signature.signatureSource,
      }
    : undefined;
}

export function signatureLockMetadata(
  signature: SignatureVerificationResult | undefined,
  payload: Uint8Array | undefined,
) {
  if (!signature) return {};
  if (!payload) {
    throw new Error('Signed payload is required when recording publisher provenance');
  }
  return {
    signatureAlgorithm: signature.algorithm,
    signatureVerified: true,
    signatureKeySha256: signature.publicKeySha256,
    signatureSha256: signature.signatureSha256,
    signatureProof: createSignatureProof(signature, payload),
  };
}

export function signatureProvenance(
  signature: SignatureVerificationResult | undefined,
): PublisherProvenance | undefined {
  return signature
    ? {
        signatureVerified: true,
        signatureKeySha256: signature.publicKeySha256,
      }
    : undefined;
}

export function failPublisherPolicy(
  decision: PublisherPolicyDecision,
  format: ReportFormat,
  operation: string,
): never {
  const message = decision.message ?? 'Publisher policy rejected the operation';
  if (format === 'json') {
    console.log(
      JSON.stringify(
        {
          passed: false,
          error: {
            code: decision.code ?? 'PUBLISHER_POLICY_FAILED',
            message,
          },
        },
        null,
        2,
      ),
    );
  } else {
    console.error(chalk.red.bold(`❌ Publisher policy blocked ${operation}: ${message}`));
  }
  process.exit(EXIT_FAIL);
}

export function enforcePublisherPolicy(
  config: SkillGuardConfig,
  provenance: PublisherProvenance | undefined,
  format: ReportFormat,
  operation: string,
): void {
  warnIfPublisherIdentityUnpinned(config);
  const decision = evaluatePublisherPolicy(config.publishers, provenance);
  if (!decision.passed) failPublisherPolicy(decision, format, operation);
}

export function resolveRemoteInstallPath(filename: string, output: unknown): string {
  const requestedOutput =
    output !== undefined ? String(output).trim() : path.join('.agentwarden', 'skills', filename);
  if (!requestedOutput) usageError('Remote install output path must not be empty');

  const destination = path.resolve(process.cwd(), requestedOutput);
  if (fs.existsSync(destination) && fs.statSync(destination).isDirectory()) {
    usageError(`Remote install output path is a directory: ${destination}`);
  }
  return destination;
}

export interface ScannedSkillPackage {
  result: ScanResult;
  scannedFiles: string[];
}

export function decodePackageText(file: { path: string; data: Buffer }): string {
  if (file.data.includes(0)) {
    throw new SkillPackageError(
      'UNSUPPORTED_ENTRY',
      `Skill package file "${file.path}" contains binary NUL bytes`,
    );
  }

  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(file.data).replace(/^\uFEFF/, '');
  } catch {
    throw new SkillPackageError(
      'UNSUPPORTED_ENTRY',
      `Skill package file "${file.path}" is not valid UTF-8 text`,
    );
  }
}

export function scanSkillPackage(skillPackage: SkillPackage, config: SkillGuardConfig): ScannedSkillPackage {
  const results = skillPackage.files.map((file) => {
    const content = decodePackageText(file);
    return scanSkillContent(content, file.path, config);
  });
  const entryIndex = skillPackage.files.findIndex(
    (file) => file.path.toLowerCase() === skillPackage.entryPath.toLowerCase(),
  );
  if (entryIndex === -1) {
    throw new SkillPackageError('MISSING_ENTRY', 'Skill package entry file is missing');
  }

  const findings: Finding[] = results.flatMap((result) =>
    result.findings.map((finding) => ({
      ...finding,
      filePath: finding.filePath ?? result.filePath,
    })),
  );
  const suppressedFindings: Finding[] = results.flatMap((result) =>
    (result.suppressedFindings ?? []).map((finding) => ({
      ...finding,
      filePath: finding.filePath ?? result.filePath,
    })),
  );
  const entryResult = results[entryIndex];
  if (entryResult === undefined) {
    throw new SkillPackageError('MISSING_ENTRY', 'Skill package entry file could not be scanned');
  }

  return {
    result: {
      ...entryResult,
      findings,
      ...(suppressedFindings.length > 0 ? { suppressedFindings } : {}),
      score: calculateScore(findings),
      passed: results.every((result) => result.passed),
    },
    scannedFiles: skillPackage.files.map((file) => file.path),
  };
}

export function packageSlug(
  skillPackage: SkillPackage,
  result: ScanResult,
  archiveFilename: string,
): string {
  const entryName = path.posix.basename(skillPackage.entryPath);
  const parsedName = result.parsedSkill.name?.trim();
  const fallback = path
    .basename(archiveFilename)
    .replace(/\.(?:tar\.gz|tgz)$/i, '')
    .trim();
  const candidate =
    parsedName && parsedName !== skillPackage.entryPath && parsedName !== entryName
      ? parsedName
      : fallback || 'skill-package';
  const slug = candidate
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, '-')
    .replace(/^[.-]+|[.-]+$/g, '')
    .slice(0, 80);
  return slug || 'skill-package';
}

export interface PackageInstallSource {
  type: 'local' | 'remote';
  requestedUrl?: string;
  resolvedUrl?: string;
  downloadSha256?: string;
  digestVerified?: boolean;
  signature?: SignatureVerificationResult;
  signaturePayload?: Uint8Array;
}

export function installSkillPackage(
  skillPackage: SkillPackage,
  archiveFilename: string,
  source: PackageInstallSource,
  options: ParsedArgs['options'],
  format: ReportFormat,
  config: SkillGuardConfig,
  force: boolean,
): void {
  const scanned = scanSkillPackage(skillPackage, config);
  const slug = packageSlug(skillPackage, scanned.result, archiveFilename);
  const parsedName = scanned.result.parsedSkill.name?.trim();
  const entryName = path.posix.basename(skillPackage.entryPath);
  if (!parsedName || parsedName === skillPackage.entryPath || parsedName === entryName) {
    scanned.result.parsedSkill = { ...scanned.result.parsedSkill, name: slug };
  }
  const destination =
    options.output !== undefined
      ? path.resolve(process.cwd(), String(options.output))
      : path.resolve(process.cwd(), '.agentwarden', 'skills', slug);

  if (fs.existsSync(destination) && !fs.statSync(destination).isDirectory()) {
    usageError(`Skill package destination is not a directory: ${destination}`);
  }

  const relativeDirectory = toRelativePosix(destination);
  const sourcePath = toRelativePosix(
    path.join(destination, ...skillPackage.entryPath.split('/')),
  );
  const installAborted = !scanned.result.passed && !force;
  const {
    signature: verifiedSignature,
    signaturePayload: _signaturePayload,
    ...sourceFields
  } = source;
  const safeSourceFields = redactReportValue(sourceFields);
  const sourceDetails = {
    ...safeSourceFields,
    path: sourcePath,
    packagePath: relativeDirectory,
    packageFormat: 'tar.gz',
    packageSha256: skillPackage.sha256,
    packageEntry: skillPackage.entryPath,
    packageFiles: skillPackage.manifest.length,
    scannedFiles: scanned.scannedFiles.length,
    ...(verifiedSignature
      ? { signature: redactReportValue(signatureReport(verifiedSignature)) }
      : {}),
  };

  if (format === 'json') {
    console.log(
      JSON.stringify(
        {
          ...toReportScanResult(scanned.result, reportOptions(options)),
          source: sourceDetails,
          installAborted,
        },
        null,
        2,
      ),
    );
  } else {
    renderScanReport(scanned.result, format, reportOptions(options));
  }

  if (installAborted) {
    if (format === 'pretty') {
      console.log(chalk.red('🚫 Aborted installation due to security risk. Use --force to override.\n'));
    }
    // Set the exit code and return instead of exiting so the report that was
    // just printed cannot be truncated.
    process.exitCode = EXIT_FAIL;
    return;
  }

  const lock = readLockfile();
  const previous = lock.skills[scanned.result.parsedSkill.name];
  if (previous && format === 'pretty') {
    console.log(chalk.gray(`ℹ️  Updating existing lock entry for "${scanned.result.parsedSkill.name}" (was: ${previous.source}).`));
  }

  // Stage the whole directory first and only swap it in on commit, then keep
  // the previous directory until the lockfile write has succeeded. `--force`
  // alone never erases a directory AgentWarden did not install; that requires
  // the explicit `--replace-directory` opt-in.
  const prepared = prepareSkillPackageWrite(skillPackage, destination, {
    replaceExisting: options.output === undefined || force,
    allowUnmanagedReplacement: Boolean(options['replace-directory']),
  });

  if (prepared.removedEntries.length > 0 && format === 'pretty') {
    console.log(
      chalk.yellow(
        `⚠️  Replacing managed skill directory ${relativeDirectory}; removing: ${prepared.removedEntries.join(', ')}\n`,
      ),
    );
  }

  try {
    prepared.commit();
  } catch (error) {
    prepared.rollback();
    throw error;
  }

  try {
    updateLockfileSkill({
      name: scanned.result.parsedSkill.name,
      version: scanned.result.parsedSkill.version || '0.1.0',
      source: sourcePath,
      sha256: scanned.result.sha256,
      installedAt: new Date().toISOString(),
      verifiedScore: scanned.result.score,
      sourceType: source.type,
      ...(safeSourceFields.requestedUrl
        ? { remoteUrl: safeSourceFields.requestedUrl }
        : {}),
      ...(safeSourceFields.resolvedUrl
        ? { resolvedUrl: safeSourceFields.resolvedUrl }
        : {}),
      ...(source.downloadSha256 ? { downloadSha256: source.downloadSha256 } : {}),
      ...(source.digestVerified !== undefined
        ? { digestVerified: source.digestVerified }
        : {}),
      packageFormat: 'tar.gz',
      packageSha256: skillPackage.sha256,
      packageEntry: skillPackage.entryPath,
      packageFiles: skillPackage.manifest,
      ...signatureLockMetadata(source.signature, source.signaturePayload),
    });
  } catch (error) {
    // A failed lockfile write must not leave the previous directory destroyed.
    prepared.restore();
    throw error;
  }
  prepared.finalize();

  if (format === 'pretty') {
    console.log(
      chalk.green(
        `🔒 Successfully verified and locked skill package to skills.lock (${skillPackage.manifest.length} files, package: ${skillPackage.sha256.slice(0, 16)}${source.signature ? `, signer: ${source.signature.publicKeySha256.slice(0, 16)}` : ''}...).\n`,
      ),
    );
  }
}

export async function cmdInstallLocal(
  target: string,
  options: ParsedArgs['options'],
  format: ReportFormat,
): Promise<void> {
  const force = Boolean(options.force);
  const fullPath = resolvePath(target);
  const config = buildConfig(options);
  const signatureOptions = installSignatureOptions(options);

  if (format === 'pretty') {
    console.log(chalk.cyan(`\n🔍 Analyzing skill package: ${target}...`));
  }
  const bytes = fs.readFileSync(fullPath);
  const signature = await verifyInstallSignature(bytes, signatureOptions, false);
  enforcePublisherPolicy(config, signatureProvenance(signature), format, `local install "${target}"`);
  const result = scanSkillContent(bytes.toString('utf8'), fullPath, config);
  if (format === 'json') {
    console.log(
      JSON.stringify(
        {
          ...toReportScanResult(result, reportOptions(options)),
          ...(signature
            ? { signature: redactReportValue(signatureReport(signature)) }
            : {}),
          installAborted: !result.passed && !force,
        },
        null,
        2,
      ),
    );
  } else {
    renderScanReport(result, format, reportOptions(options));
  }

  if (!result.passed && !force) {
    if (format === 'pretty') {
      console.log(chalk.red('🚫 Aborted installation due to security risk. Use --force to override.\n'));
    }
    process.exitCode = EXIT_FAIL;
    return;
  }

  const lock = readLockfile();
  const previous = lock.skills[result.parsedSkill.name];
  if (previous && format === 'pretty') {
    console.log(chalk.gray(`ℹ️  Updating existing lock entry for "${result.parsedSkill.name}" (was: ${previous.source}).`));
  }

  const relativePosix = toRelativePosix(fullPath);
  updateLockfileSkill({
    name: result.parsedSkill.name,
    version: result.parsedSkill.version || '0.1.0',
    source: relativePosix,
    sha256: result.sha256,
    installedAt: new Date().toISOString(),
    verifiedScore: result.score,
    sourceType: 'local',
    ...signatureLockMetadata(signature, bytes),
  });

  if (format === 'pretty') {
    const signer = signature
      ? `, signer: ${signature.publicKeySha256.slice(0, 16)}`
      : '';
    console.log(chalk.green(`🔒 Successfully verified and locked signature to skills.lock (source: ${relativePosix}${signer})!\n`));
  }
}

export async function cmdInstallRemote(
  target: string,
  options: ParsedArgs['options'],
  format: ReportFormat,
): Promise<void> {
  const force = Boolean(options.force);
  const signatureOptions = installSignatureOptions(options);
  const expectedSha256 = options.sha256 !== undefined ? String(options.sha256) : undefined;
  if (!expectedSha256) {
    usageError('Remote installs require --sha256 <digest> to pin the downloaded content');
  }

  const config = buildConfig(options);
  if (!signatureOptions) {
    enforcePublisherPolicy(config, undefined, format, `remote install "${target}"`);
  }
  if (format === 'pretty') {
    console.log(chalk.cyan(`\n⬇️  Downloading remote skill: ${target}...`));
  }

  let download: Awaited<ReturnType<typeof fetchRemoteSkill>>;
  try {
    download = await fetchRemoteSkill({
      url: target,
      expectedSha256,
      allowHttp: Boolean(options['allow-http']),
    });
  } catch (error) {
    if (
      error instanceof RemoteSkillError &&
      (error.code === 'INVALID_URL' ||
        error.code === 'INVALID_DIGEST' ||
        error.code === 'INSECURE_URL')
    ) {
      usageError(error.message);
    }
    throw error;
  }
  const signature = await verifyInstallSignature(
    download.bytes,
    signatureOptions,
    Boolean(options['allow-http']),
  );
  enforcePublisherPolicy(
    config,
    signatureProvenance(signature),
    format,
    `remote install "${target}"`,
  );

  if (isSkillPackageSource(download.filename, download.contentType)) {
    const skillPackage = extractSkillPackage(download.bytes);
    installSkillPackage(
      skillPackage,
      download.filename,
      {
        type: 'remote',
        requestedUrl: download.requestedUrl,
        resolvedUrl: download.resolvedUrl,
        downloadSha256: download.sha256,
        digestVerified: download.digestVerified,
        ...(signature ? { signature } : {}),
        ...(signature ? { signaturePayload: download.bytes } : {}),
      },
      options,
      format,
      config,
      force,
    );
    return;
  }

  const destination = resolveRemoteInstallPath(download.filename, options.output);
  const relativePosix = toRelativePosix(destination);
  const result = scanSkillContent(download.content, download.filename, config);
  const installAborted = !result.passed && !force;
  const safeRequestedUrl = redactText(download.requestedUrl);
  const safeResolvedUrl = redactText(download.resolvedUrl);
  const sourceDetails = {
    type: 'remote',
    path: relativePosix,
    requestedUrl: safeRequestedUrl,
    resolvedUrl: safeResolvedUrl,
    downloadSha256: download.sha256,
    digestVerified: download.digestVerified,
    size: download.size,
    ...(signature
      ? { signature: redactReportValue(signatureReport(signature)) }
      : {}),
  };

  if (format === 'json') {
    console.log(
      JSON.stringify(
        {
          ...toReportScanResult(result, reportOptions(options)),
          source: sourceDetails,
          installAborted,
        },
        null,
        2,
      ),
    );
  } else {
    renderScanReport(result, format, reportOptions(options));
  }

  if (installAborted) {
    if (format === 'pretty') {
      console.log(chalk.red('🚫 Aborted installation due to security risk. Use --force to override.\n'));
    }
    process.exitCode = EXIT_FAIL;
    return;
  }

  const lock = readLockfile();
  const previous = lock.skills[result.parsedSkill.name];
  if (previous && format === 'pretty') {
    console.log(chalk.gray(`ℹ️  Updating existing lock entry for "${result.parsedSkill.name}" (was: ${previous.source}).`));
  }

  writeFileAtomic(destination, download.content);
  updateLockfileSkill({
    name: result.parsedSkill.name,
    version: result.parsedSkill.version || '0.1.0',
    source: relativePosix,
    sha256: result.sha256,
    installedAt: new Date().toISOString(),
    verifiedScore: result.score,
    sourceType: 'remote',
    remoteUrl: safeRequestedUrl,
    resolvedUrl: safeResolvedUrl,
    downloadSha256: download.sha256,
    digestVerified: download.digestVerified,
    ...signatureLockMetadata(signature, download.bytes),
  });

  if (format === 'pretty') {
    console.log(
      chalk.green(
        `🔒 Successfully verified and locked remote signature to skills.lock (source: ${relativePosix}, URL: ${safeResolvedUrl}${signature ? `, signer: ${signature.publicKeySha256.slice(0, 16)}` : ''})!\n`,
      ),
    );
  }
}

export async function cmdInstallLocalPackage(
  target: string,
  options: ParsedArgs['options'],
  format: ReportFormat,
): Promise<void> {
  const fullPath = resolvePath(target);
  const config = buildConfig(options);
  const signatureOptions = installSignatureOptions(options);
  if (format === 'pretty') {
    console.log(chalk.cyan(`\n📦 Analyzing local skill package: ${target}...`));
  }
  const bytes = readSkillPackageBytes(fullPath);
  const signature = await verifyInstallSignature(bytes, signatureOptions, false);
  enforcePublisherPolicy(
    config,
    signatureProvenance(signature),
    format,
    `local package install "${target}"`,
  );
  const skillPackage = extractSkillPackage(bytes);
  installSkillPackage(
    skillPackage,
    path.basename(fullPath),
    {
      type: 'local',
      ...(signature ? { signature, signaturePayload: bytes } : {}),
    },
    options,
    format,
    config,
    Boolean(options.force),
  );
}

export async function cmdInstall(
  target: string,
  options: ParsedArgs['options'],
  format: ReportFormat,
): Promise<void> {
  installSignatureOptions(options);
  if (/^https?:\/\//i.test(target)) {
    await cmdInstallRemote(target, options, format);
    return;
  }

  if (options.sha256 !== undefined) {
    usageError('--sha256 is only valid when installing a remote HTTPS or HTTP source');
  }
  if (options['allow-http']) {
    usageError('--allow-http is only valid when installing a remote HTTP source');
  }
  if (isSkillPackageSource(target)) {
    await cmdInstallLocalPackage(target, options, format);
    return;
  }
  if (options.output !== undefined) {
    usageError('--output is only valid for baseline writes or remote installs');
  }
  await cmdInstallLocal(target, options, format);
}

