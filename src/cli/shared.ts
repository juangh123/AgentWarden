import * as fs from 'node:fs';
import * as path from 'node:path';
import { chalk } from '../reporter/chalk.ts';
import { type SkillGuardConfig } from '../config/index.ts';
import { EXIT_USAGE, type ParsedArgs } from './args.ts';

export function resolvePath(target: string): string {
  const fullPath = path.resolve(process.cwd(), target);
  if (!fs.existsSync(fullPath)) {
    console.error(chalk.red(`Error: Path not found at ${fullPath}`));
    process.exit(EXIT_USAGE);
  }
  return fullPath;
}

export function canonicalCliPath(filePath: string): string {
  const resolved = path.resolve(filePath);
  try {
    return fs.realpathSync.native(resolved);
  } catch {
    return resolved;
  }
}

export function isPathWithinTarget(filePath: string, targetPath: string): boolean {
  const target = canonicalCliPath(targetPath);
  const file = canonicalCliPath(filePath);
  const targetStat = fs.statSync(target);
  if (targetStat.isFile()) return file === target;
  const relative = path.relative(target, file);
  return relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative));
}

export function changedScanRequested(options: ParsedArgs['options']): boolean {
  return Boolean(options.changed) || options['changed-from'] !== undefined;
}

export let publisherTrustWarningEmitted = false;

/**
 * `requireSignature` without `trustedKeys` only proves that *some* valid
 * signature exists; it does not pin a publisher identity. Say so once per run
 * so that a "publisher policy passed" line is never mistaken for identity
 * assurance.
 */
export function warnIfPublisherIdentityUnpinned(config: SkillGuardConfig): void {
  if (publisherTrustWarningEmitted) return;
  const publishers = config.publishers;
  if (!publishers?.requireSignature) return;
  if ((publishers.trustedKeys ?? []).length > 0) return;

  publisherTrustWarningEmitted = true;
  console.error(
    chalk.yellow(
      'Warning: publishers.requireSignature is enabled but publishers.trustedKeys is empty, ' +
        'so any valid signature is accepted and no publisher identity is pinned. ' +
        'Add trustedKeys to enforce a specific publisher.',
    ),
  );
}

