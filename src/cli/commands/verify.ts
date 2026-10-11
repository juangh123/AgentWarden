import * as path from 'node:path';
import { chalk } from '../../reporter/chalk.ts';
import { scanSkillFile } from '../../scanner/index.ts';
import { readLockfile, findSkillKey, resolveFromRoot } from '../../manifest/lockfile.ts';
import { type SkillGuardConfig } from '../../config/index.ts';
import { type ReportFormat } from '../../reporter/index.ts';
import { inspectInstalledSkillPackage, type SkillPackage } from '../../source/package.ts';
import { evaluateLockedPublisherPolicy } from '../../source/proof.ts';
import { warnIfPublisherIdentityUnpinned, resolvePath } from '../shared.ts';
import { EXIT_FAIL } from '../args.ts';
import { scanSkillPackage } from './install.ts';

/** Machine-readable verdict for `verify`, so CI can consume the result. */
export interface VerifyVerdict {
  target: string;
  kind: 'package' | 'skill';
  key: string | null;
  verified: boolean;
  score: number | null;
  expectedSha256: string | null;
  actualSha256: string | null;
  publisherPolicyPassed: boolean;
  signerKeySha256: string | null;
  filesChecked?: number;
  missingFiles?: string[];
  extraFiles?: string[];
  modifiedFiles?: string[];
  unsafePaths?: string[];
  /** Failure code; absent when the verification passed. */
  reason?: string;
  /** Human-readable detail for the failure code. */
  message?: string;
  /** Operation label used by the publisher-policy failure message. */
  operation?: string;
}

function verdictBase(target: string, kind: 'package' | 'skill', key: string | null): VerifyVerdict {
  return {
    target,
    kind,
    key,
    verified: false,
    score: null,
    expectedSha256: null,
    actualSha256: null,
    publisherPolicyPassed: false,
    signerKeySha256: null,
  };
}

function evaluatePackage(target: string, fullPath: string, config: SkillGuardConfig): VerifyVerdict {
  const lock = readLockfile();
  const packageKey = Object.keys(lock.skills).find((candidate) => {
    const item = lock.skills[candidate];
    if (item === undefined) return false;
    if (!item.packageFormat) return false;
    const packageRoot = path.dirname(resolveFromRoot(item.source));
    const relative = path.relative(packageRoot, fullPath);
    return relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative));
  });
  if (packageKey === undefined) return verdictBase(target, 'skill', null);

  const lockedEntry = lock.skills[packageKey];
  if (lockedEntry === undefined) {
    return { ...verdictBase(target, 'package', packageKey), reason: 'package-missing' };
  }
  if (!lockedEntry.packageSha256 || !lockedEntry.packageEntry || !lockedEntry.packageFiles) {
    return { ...verdictBase(target, 'package', packageKey), reason: 'package-metadata' };
  }

  const verdict = verdictBase(target, 'package', packageKey);
  const publisherDecision = evaluateLockedPublisherPolicy(lockedEntry, config.publishers);
  verdict.publisherPolicyPassed = publisherDecision.passed;
  verdict.signerKeySha256 = publisherDecision.keySha256 ?? null;
  if (!publisherDecision.passed) {
    return {
      ...verdict,
      reason: 'publisher-policy',
      operation: `package verification "${packageKey}"`,
      message: publisherDecision.message ?? 'Publisher policy rejected the operation',
    };
  }

  const packageRoot = path.dirname(resolveFromRoot(lockedEntry.source));
  const inspection = inspectInstalledSkillPackage(packageRoot, {
    entryPath: lockedEntry.packageEntry,
    sha256: lockedEntry.packageSha256,
    manifest: lockedEntry.packageFiles,
  });
  verdict.filesChecked = inspection.files.length;
  verdict.missingFiles = inspection.missingFiles;
  verdict.extraFiles = inspection.extraFiles;
  verdict.modifiedFiles = inspection.modifiedFiles;
  verdict.unsafePaths = inspection.unsafePaths;
  verdict.expectedSha256 = lockedEntry.packageSha256;
  verdict.actualSha256 = inspection.packageSha256 ?? null;
  if (!inspection.packageMatch) return { ...verdict, reason: 'package-tampered' };

  try {
    const installedPackage: SkillPackage = {
      entryPath: lockedEntry.packageEntry,
      files: inspection.files,
      manifest: lockedEntry.packageFiles,
      sha256: lockedEntry.packageSha256,
      totalBytes: inspection.files.reduce((total, file) => total + file.data.byteLength, 0),
    };
    const result = scanSkillPackage(installedPackage, config).result;
    verdict.score = result.score;
    if (!result.passed) return { ...verdict, reason: 'package-policy' };
  } catch (error) {
    return {
      ...verdict,
      reason: 'package-scan-error',
      message: error instanceof Error ? error.message : String(error),
    };
  }

  return { ...verdict, verified: true };
}

function evaluateSkill(target: string, fullPath: string, config: SkillGuardConfig): VerifyVerdict {
  const lock = readLockfile();
  const result = scanSkillFile(fullPath, config);
  const skillName = result.parsedSkill.name;
  const key = findSkillKey(lock, skillName);
  const lockedEntry = key ? lock.skills[key] : undefined;
  if (!lockedEntry) {
    return { ...verdictBase(target, 'skill', key ?? skillName), reason: 'not-registered', message: skillName };
  }

  const verdict = verdictBase(target, 'skill', key ?? skillName);
  verdict.expectedSha256 = lockedEntry.sha256;
  verdict.actualSha256 = result.sha256;
  verdict.score = lockedEntry.verifiedScore;

  const publisherDecision = evaluateLockedPublisherPolicy(lockedEntry, config.publishers);
  verdict.publisherPolicyPassed = publisherDecision.passed;
  verdict.signerKeySha256 = publisherDecision.keySha256 ?? null;
  if (!publisherDecision.passed) {
    return {
      ...verdict,
      reason: 'publisher-policy',
      operation: `skill verification "${key ?? skillName}"`,
      message: publisherDecision.message ?? 'Publisher policy rejected the operation',
    };
  }

  if (lockedEntry.sha256 !== result.sha256) return { ...verdict, reason: 'tampered' };
  return { ...verdict, verified: true };
}

export function evaluateVerify(target: string, config: SkillGuardConfig): VerifyVerdict {
  warnIfPublisherIdentityUnpinned(config);
  const fullPath = resolvePath(target);
  const packageVerdict = evaluatePackage(target, fullPath, config);
  if (packageVerdict.kind === 'package') return packageVerdict;
  return evaluateSkill(target, fullPath, config);
}

function printPretty(verdict: VerifyVerdict): void {
  const key = verdict.key ?? verdict.target;
  if (verdict.verified) {
    if (verdict.kind === 'package') {
      console.log(
        chalk.green.bold(
          `✓ Package integrity verified: "${key}" matches ${verdict.filesChecked} locked file(s) (Score: ${verdict.score}/100).`,
        ),
      );
    } else {
      console.log(
        chalk.green.bold(`✓ Integrity verified: "${key}" matches skills.lock record (Score: ${verdict.score}/100).`),
      );
    }
    return;
  }

  switch (verdict.reason) {
    case 'package-missing':
      console.error(chalk.red(`Skill "${key}" is missing from skills.lock.`));
      return;
    case 'package-metadata':
      console.error(chalk.red(`❌ Invalid package metadata for skill "${key}".`));
      return;
    case 'publisher-policy':
      console.error(
        chalk.red.bold(
          `❌ Publisher policy blocked ${verdict.operation ?? key}: ${verdict.message}`,
        ),
      );
      return;
    case 'package-tampered':
      console.error(chalk.red.bold(`❌ TAMPERING DETECTED: Package "${key}" does not match skills.lock!`));
      if (verdict.missingFiles && verdict.missingFiles.length > 0) {
        console.error(chalk.gray(`  Missing: ${verdict.missingFiles.join(', ')}`));
      }
      if (verdict.extraFiles && verdict.extraFiles.length > 0) {
        console.error(chalk.gray(`  Unexpected: ${verdict.extraFiles.join(', ')}`));
      }
      if (verdict.modifiedFiles && verdict.modifiedFiles.length > 0) {
        console.error(chalk.gray(`  Modified: ${verdict.modifiedFiles.join(', ')}`));
      }
      if (verdict.unsafePaths && verdict.unsafePaths.length > 0) {
        console.error(chalk.gray(`  Unsafe entries: ${verdict.unsafePaths.join(', ')}`));
      }
      return;
    case 'package-policy':
      console.error(
        chalk.red.bold(`❌ Package "${key}" failed current policy checks (Score: ${verdict.score}/100).`),
      );
      return;
    case 'package-scan-error':
      console.error(chalk.red(`❌ Unable to scan package "${key}": ${verdict.message}`));
      return;
    case 'not-registered':
      console.error(
        chalk.yellow(
          `⚠️  Skill "${verdict.message}" is not registered in skills.lock. Run "agentwarden install ${verdict.target}" first.`,
        ),
      );
      return;
    case 'tampered':
      console.error(chalk.red.bold(`❌ TAMPERING DETECTED: Hash mismatch for skill "${key}"!`));
      console.error(chalk.gray(`  Expected: ${verdict.expectedSha256}`));
      console.error(chalk.gray(`  Actual:   ${verdict.actualSha256}`));
      return;
    default:
      console.error(chalk.red(`❌ Verification failed for "${key}".`));
  }
}

export function cmdVerify(
  target: string,
  config: SkillGuardConfig,
  format: ReportFormat = 'pretty',
): void {
  const verdict = evaluateVerify(target, config);
  if (format === 'json') {
    console.log(JSON.stringify(verdict, null, 2));
  } else if (format === 'sarif') {
    console.log(JSON.stringify(verdict, null, 2));
  } else {
    printPretty(verdict);
  }
  if (!verdict.verified) process.exitCode = EXIT_FAIL;
}
