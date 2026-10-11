import * as path from 'node:path';
import { chalk } from '../../reporter/chalk.ts';
import { scanSkillFile } from '../../scanner/index.ts';
import { readLockfile, findSkillKey, resolveFromRoot } from '../../manifest/lockfile.ts';
import { type SkillGuardConfig } from '../../config/index.ts';
import { inspectInstalledSkillPackage, type SkillPackage } from '../../source/package.ts';
import { evaluateLockedPublisherPolicy } from '../../source/proof.ts';
import { warnIfPublisherIdentityUnpinned, resolvePath } from '../shared.ts';
import { EXIT_FAIL } from '../args.ts';
import { failPublisherPolicy, scanSkillPackage } from './install.ts';

export function cmdVerify(target: string, config: SkillGuardConfig): void {
  warnIfPublisherIdentityUnpinned(config);
  const fullPath = resolvePath(target);
  const lock = readLockfile();
  const packageKey = Object.keys(lock.skills).find((candidate) => {
    const item = lock.skills[candidate];
    if (item === undefined) return false;
    if (!item.packageFormat) return false;
    const packageRoot = path.dirname(resolveFromRoot(item.source));
    const relative = path.relative(packageRoot, fullPath);
    return relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative));
  });

  if (packageKey) {
    const lockedEntry = lock.skills[packageKey];
    if (lockedEntry === undefined) {
      console.error(chalk.red(`Skill "${packageKey}" is missing from skills.lock.`));
      process.exit(EXIT_FAIL);
    }
    if (
      !lockedEntry.packageSha256 ||
      !lockedEntry.packageEntry ||
      !lockedEntry.packageFiles
    ) {
      console.error(chalk.red(`❌ Invalid package metadata for skill "${packageKey}".`));
      process.exit(EXIT_FAIL);
    }
    const publisherDecision = evaluateLockedPublisherPolicy(
      lockedEntry,
      config.publishers,
    );
    if (!publisherDecision.passed) {
      failPublisherPolicy(
        publisherDecision,
        'pretty',
        `package verification "${packageKey}"`,
      );
    }

    const packageRoot = path.dirname(resolveFromRoot(lockedEntry.source));
    const inspection = inspectInstalledSkillPackage(packageRoot, {
      entryPath: lockedEntry.packageEntry,
      sha256: lockedEntry.packageSha256,
      manifest: lockedEntry.packageFiles,
    });
    if (!inspection.packageMatch) {
      console.error(chalk.red.bold(`❌ TAMPERING DETECTED: Package "${packageKey}" does not match skills.lock!`));
      if (inspection.missingFiles.length > 0) {
        console.error(chalk.gray(`  Missing: ${inspection.missingFiles.join(', ')}`));
      }
      if (inspection.extraFiles.length > 0) {
        console.error(chalk.gray(`  Unexpected: ${inspection.extraFiles.join(', ')}`));
      }
      if (inspection.modifiedFiles.length > 0) {
        console.error(chalk.gray(`  Modified: ${inspection.modifiedFiles.join(', ')}`));
      }
      if (inspection.unsafePaths.length > 0) {
        console.error(chalk.gray(`  Unsafe entries: ${inspection.unsafePaths.join(', ')}`));
      }
      process.exit(EXIT_FAIL);
    }

    try {
      const installedPackage: SkillPackage = {
        entryPath: lockedEntry.packageEntry,
        files: inspection.files,
        manifest: lockedEntry.packageFiles,
        sha256: lockedEntry.packageSha256,
        totalBytes: inspection.files.reduce((total, file) => total + file.data.byteLength, 0),
      };
      const result = scanSkillPackage(installedPackage, config).result;
      if (!result.passed) {
        console.error(
          chalk.red.bold(
            `❌ Package "${packageKey}" failed current policy checks (Score: ${result.score}/100).`,
          ),
        );
        process.exit(EXIT_FAIL);
      }
      console.log(
        chalk.green.bold(
          `✓ Package integrity verified: "${packageKey}" matches ${lockedEntry.packageFiles.length} locked file(s) (Score: ${result.score}/100).`,
        ),
      );
    } catch (error) {
      console.error(
        chalk.red(
          `❌ Unable to scan package "${packageKey}": ${error instanceof Error ? error.message : String(error)}`,
        ),
      );
      process.exit(EXIT_FAIL);
    }
    return;
  }

  const result = scanSkillFile(fullPath, config);
  const skillName = result.parsedSkill.name;
  const key = findSkillKey(lock, skillName);
  const lockedEntry = key ? lock.skills[key] : undefined;

  if (!lockedEntry) {
    console.error(chalk.yellow(`⚠️  Skill "${skillName}" is not registered in skills.lock. Run "agentwarden install ${target}" first.`));
    process.exit(EXIT_FAIL);
  }
  const publisherDecision = evaluateLockedPublisherPolicy(
    lockedEntry,
    config.publishers,
  );
  if (!publisherDecision.passed) {
    failPublisherPolicy(
      publisherDecision,
      'pretty',
      `skill verification "${key}"`,
    );
  }

  if (lockedEntry.sha256 !== result.sha256) {
    console.error(chalk.red.bold(`❌ TAMPERING DETECTED: Hash mismatch for skill "${key}"!`));
    console.error(chalk.gray(`  Expected: ${lockedEntry.sha256}`));
    console.error(chalk.gray(`  Actual:   ${result.sha256}`));
    process.exit(EXIT_FAIL);
  }

  console.log(chalk.green.bold(`✓ Integrity verified: "${key}" matches skills.lock record (Score: ${lockedEntry.verifiedScore}/100).`));
}

