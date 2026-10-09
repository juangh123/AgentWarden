import * as fs from 'node:fs';
import * as path from 'node:path';
import { chalk } from '../../reporter/chalk.ts';
import { scanSkillFile } from '../../scanner/index.ts';
import { type ReportFormat } from '../../reporter/index.ts';
import { readLockfile, resolveFromRoot } from '../../manifest/lockfile.ts';
import { type SkillGuardConfig } from '../../config/index.ts';
import { inspectInstalledSkillPackage, type SkillPackage } from '../../source/package.ts';
import { evaluateLockedPublisherPolicy } from '../../source/proof.ts';
import { type ParsedArgs, EXIT_FAIL } from '../args.ts';
import { warnIfPublisherIdentityUnpinned } from '../shared.ts';
import { scanSkillPackage } from './install.ts';

export function cmdAudit(
  _options: ParsedArgs['options'],
  config: SkillGuardConfig,
  format: ReportFormat,
): void {
  warnIfPublisherIdentityUnpinned(config);
  const lock = readLockfile();
  const keys = Object.keys(lock.skills).sort();

  interface AuditEntry {
    version: string;
    source: string;
    sha256: string;
    exists: boolean;
    hashMatch: boolean;
    lockedScore: number;
    currentScore: number | null;
    policyPassed: boolean;
    currentFindingCount: number | null;
    packageMatch: boolean | null;
    packageFilesChecked: number | null;
    publisherPolicyPassed: boolean;
    publisherPolicyCode: string | null;
    signerKeySha256: string | null;
  }
  const auditResult: { auditedAt: string; passed?: boolean; skills: Record<string, AuditEntry> } = {
    auditedAt: new Date().toISOString(),
    skills: {},
  };
  let hasFailure = false;

  for (const name of keys) {
    const item = lock.skills[name];
    const resolvedPath = resolveFromRoot(item.source);
    const exists = fs.existsSync(item.packageFormat ? path.dirname(resolvedPath) : resolvedPath);
    let hashMatch = false;
    let currentScore: number | null = null;
    let policyPassed = false;
    let currentFindingCount: number | null = null;
    let packageMatch: boolean | null = null;
    let packageFilesChecked: number | null = null;
    const publisherDecision = evaluateLockedPublisherPolicy(
      item,
      config.publishers,
    );

    if (item.packageFormat === 'tar.gz' && item.packageSha256 && item.packageEntry && item.packageFiles) {
      const packageRoot = path.dirname(resolvedPath);
      const inspection = inspectInstalledSkillPackage(packageRoot, {
        entryPath: item.packageEntry,
        sha256: item.packageSha256,
        manifest: item.packageFiles,
      });
      packageMatch = inspection.packageMatch;
      packageFilesChecked = inspection.files.length;
      hashMatch = inspection.packageMatch;

      if (inspection.exists) {
        try {
          const installedPackage: SkillPackage = {
            entryPath: item.packageEntry,
            files: inspection.files,
            manifest: item.packageFiles,
            sha256: item.packageSha256,
            totalBytes: inspection.files.reduce((total, file) => total + file.data.byteLength, 0),
          };
          const currentResult = scanSkillPackage(installedPackage, config).result;
          currentScore = currentResult.score;
          policyPassed = currentResult.passed;
          currentFindingCount = currentResult.findings.length;
        } catch {
          policyPassed = false;
        }
      }
    } else if (exists) {
      const currentResult = scanSkillFile(resolvedPath, config);
      hashMatch = currentResult.sha256 === item.sha256;
      currentScore = currentResult.score;
      policyPassed = currentResult.passed;
      currentFindingCount = currentResult.findings.length;
    } else {
      hasFailure = true;
    }
    if (!exists || !hashMatch || !policyPassed || !publisherDecision.passed) hasFailure = true;

    auditResult.skills[name] = {
      version: item.version,
      source: item.source,
      sha256: item.sha256,
      exists,
      hashMatch,
      lockedScore: item.verifiedScore,
      currentScore,
      policyPassed,
      currentFindingCount,
      packageMatch,
      packageFilesChecked,
      publisherPolicyPassed: publisherDecision.passed,
      publisherPolicyCode: publisherDecision.code ?? null,
      signerKeySha256: publisherDecision.keySha256 ?? null,
    };
  }

  if (format === 'json') {
    auditResult.passed = !hasFailure;
    console.log(JSON.stringify(auditResult, null, 2));
    if (hasFailure) process.exitCode = EXIT_FAIL;
    return;
  }

  console.log(chalk.bold.cyan('\n📦 Auditing Installed Skills in skills.lock...'));
  console.log(chalk.gray('═'.repeat(60)));
  if (keys.length === 0) {
    console.log(chalk.gray('  No installed skills recorded yet.\n'));
    return;
  }

  for (const name of keys) {
    const entry = auditResult.skills[name];
    console.log(`\n• Skill: ${chalk.bold.white(name)} (${chalk.gray('v' + entry.version)})`);
    console.log(`  Source: ${entry.source}`);
    console.log(`  Locked Hash: ${chalk.gray(entry.sha256.slice(0, 16))}...`);
    if (entry.packageMatch !== null) {
      console.log(
        `  Package: ${chalk.gray('tar.gz')} (${entry.packageFilesChecked ?? 0} files checked)`,
      );
    }
    console.log(`  Last Security Score: ${entry.lockedScore}/100`);
    if (entry.signerKeySha256) {
      console.log(`  Publisher Key:    ${chalk.gray(entry.signerKeySha256)}`);
    }

    if (!entry.exists) {
      console.log(chalk.yellow(`  ⚠️  Source file not found on disk at: ${entry.source}`));
    } else if (!entry.hashMatch) {
      console.log(
        chalk.red.bold(
          entry.packageMatch !== null
            ? '  ⚠️  TAMPERING DETECTED! Package contents do NOT match the lockfile manifest!'
            : '  ⚠️  TAMPERING DETECTED! File content hash does NOT match lockfile!',
        ),
      );
    } else {
      console.log(
        chalk.green(
          entry.packageMatch !== null
            ? '  ✓ Package integrity verified against the locked manifest and SHA256.'
            : '  ✓ Content integrity verified against locked SHA256.',
        ),
      );
    }
    if (!entry.exists) {
      console.log(chalk.red.bold('  ✗ Current policy check could not run because the source file is missing.'));
    } else if (!entry.policyPassed) {
      console.log(
        chalk.red.bold(
          `  ✗ Current policy check FAILED (${entry.currentFindingCount ?? 0} findings, score ${entry.currentScore ?? 0}/100).`,
        ),
      );
    } else {
      console.log(chalk.green('  ✓ Current security policy check passed.'));
    }
    if (!entry.publisherPolicyPassed) {
      console.log(
        chalk.red.bold(
          `  ✗ Publisher policy check FAILED (${entry.publisherPolicyCode ?? 'PUBLISHER_POLICY_FAILED'}).`,
        ),
      );
    } else if (entry.signerKeySha256) {
      console.log(chalk.green('  ✓ Publisher policy check passed.'));
    }
    if (entry.currentScore !== null && entry.currentScore !== entry.lockedScore) {
      console.log(chalk.yellow(`  ℹ️  Re-scan score drift: locked ${entry.lockedScore}/100, now ${entry.currentScore}/100 (rule updates may affect this).`));
    }
  }

  console.log('\n' + chalk.gray('═'.repeat(60)));
  if (hasFailure) {
    console.log(chalk.red.bold('❌ Audit completed: integrity or security policy failures detected!\n'));
    process.exitCode = EXIT_FAIL;
    return;
  }
  console.log(chalk.green.bold('✅ All installed skills passed integrity and current policy checks.\n'));
}

