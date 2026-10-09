import * as fs from 'node:fs';
import * as path from 'node:path';
import { chalk } from '../../reporter/chalk.ts';
import { type ReportFormat } from '../../reporter/index.ts';
import { parseBaselineContent } from '../../baseline/index.ts';
import { diffPolicyConfigs } from '../../policy/diff.ts';
import {
  guardBaseline,
  guardPolicy,
  loadApprovedPolicy,
  PolicyGuardError,
  type BaselineGuardResult,
} from '../../policy/guard.ts';
import { type BuiltConfig, resolvePolicySide, buildConfigDetails } from '../config.ts';
import { warnIfPublisherIdentityUnpinned, canonicalCliPath } from '../shared.ts';
import { usageError, type ParsedArgs, EXIT_FAIL, EXIT_USAGE } from '../args.ts';

export function policySnapshot(details: BuiltConfig) {
  const { config, source, sources, explicit } = details;
  return {
    profile: config.profile ?? 'legacy',
    configSource: source ?? null,
    configSources: sources,
    configExplicit: explicit,
    failOn: config.failOn ?? 'high',
    minScore: config.minScore ?? 60,
    ignoreRules: config.ignoreRules ?? [],
    allowedDomains: config.allowedDomains ?? [],
    baseline: config.baseline ?? null,
    publishers: config.publishers ?? {
      requireSignature: false,
      trustedKeys: [],
      revokedKeys: [],
    },
    severityOverrides: config.severityOverrides ?? {},
    include: config.include ?? [],
    exclude: config.exclude ?? [],
  };
}

export function cmdPolicy(details: BuiltConfig, format: ReportFormat): void {
  warnIfPublisherIdentityUnpinned(details.config);
  const policy = policySnapshot(details);
  if (format === 'json') {
    console.log(JSON.stringify(policy, null, 2));
    return;
  }

  console.log(chalk.bold.cyan('\nEffective Security Policy\n'));
  console.log(chalk.gray('─'.repeat(78)));
  console.log(`  Profile:          ${chalk.bold.white(policy.profile)}`);
  console.log(`  Config Source:    ${policy.configSource ? chalk.gray(policy.configSource) : chalk.gray('(built-in defaults)')}`);
  if (policy.configSources.length > 1) {
    console.log(`  Config Chain:     ${chalk.gray(policy.configSources.join(' -> '))}`);
  }
  console.log(`  Fail On:          ${chalk.yellow(policy.failOn)}`);
  console.log(`  Minimum Score:    ${chalk.yellow(String(policy.minScore))}`);
  console.log(`  Baseline:         ${policy.baseline ? chalk.gray(policy.baseline) : chalk.gray('(disabled)')}`);
  console.log(
    `  Require Signature:${policy.publishers.requireSignature ? ' ' + chalk.yellow('yes') : ' ' + chalk.gray('no')}`,
  );
  console.log(
    `  Trusted Keys:     ${policy.publishers.trustedKeys?.length ? policy.publishers.trustedKeys.join(', ') : chalk.gray('(any valid signer)')}`,
  );
  console.log(
    `  Revoked Keys:     ${policy.publishers.revokedKeys?.length ? policy.publishers.revokedKeys.join(', ') : chalk.gray('(none)')}`,
  );
  console.log(`  Ignored Rules:    ${policy.ignoreRules.length ? policy.ignoreRules.join(', ') : chalk.gray('(none)')}`);
  console.log(`  Allowed Domains:  ${policy.allowedDomains.length ? policy.allowedDomains.join(', ') : chalk.gray('(none)')}`);
  console.log(`  Include Globs:    ${policy.include.length ? policy.include.join(', ') : chalk.gray('(all)')}`);
  console.log(`  Exclude Globs:    ${policy.exclude.length ? policy.exclude.join(', ') : chalk.gray('(none)')}`);
  const overrides = Object.entries(policy.severityOverrides);
  console.log(
    `  Severity Override:${overrides.length ? ' ' + overrides.map(([id, severity]) => `${id}=${severity}`).join(', ') : ' ' + chalk.gray('(none)')}`,
  );
  console.log(chalk.gray('─'.repeat(78)) + '\n');
}

export function formatPolicyDiffValue(value: string | number | boolean | null | undefined): string {
  if (value === undefined || value === null) return '(none)';
  return String(value);
}

export function repositoryRelativeBaselinePath(root: string, baselinePath: string): string {
  const absolute = path.resolve(baselinePath);
  let canonicalAbsolute: string;
  try {
    canonicalAbsolute = fs.realpathSync.native(absolute);
  } catch {
    canonicalAbsolute = path.join(
      canonicalCliPath(path.dirname(absolute)),
      path.basename(absolute),
    );
  }
  const relative = path.relative(canonicalCliPath(root), canonicalAbsolute);
  if (
    relative === '' ||
    relative === '..' ||
    relative.startsWith(`..${path.sep}`) ||
    path.isAbsolute(relative)
  ) {
    usageError(`Policy guard baseline must be inside the repository: ${baselinePath}`);
  }
  return relative.split(path.sep).join('/');
}

export function cmdPolicyDiff(
  fromInput: string,
  toInput: string,
  options: ParsedArgs['options'],
  format: ReportFormat,
): void {
  if (format === 'sarif') usageError('policy diff supports pretty|json output only');

  const from = resolvePolicySide(fromInput, options);
  const to = resolvePolicySide(toInput, options);
  const difference = diffPolicyConfigs(from.details.config, to.details.config);
  const report = {
    from: {
      label: from.label,
      ...policySnapshot(from.details),
    },
    to: {
      label: to.label,
      ...policySnapshot(to.details),
    },
    changed: difference.changed,
    changes: difference.changes,
  };

  if (format === 'json') {
    console.log(JSON.stringify(report, null, 2));
  } else {
    console.log(chalk.bold.cyan('\nPolicy Diff\n'));
    console.log(chalk.gray('─'.repeat(78)));
    console.log(`  From: ${chalk.white(from.label)}`);
    console.log(`  To:   ${chalk.white(to.label)}`);
    console.log(chalk.gray('─'.repeat(78)));

    if (!difference.changed) {
      console.log(chalk.green.bold('\n✓ Policies are equivalent.\n'));
    } else {
      for (const change of difference.changes) {
        const field = change.key ? `${change.field}[${change.key}]` : change.field;
        if (change.kind === 'added') {
          console.log(
            `  ${chalk.green('+')} ${field}: ${chalk.gray(formatPolicyDiffValue(change.after))}`,
          );
        } else if (change.kind === 'removed') {
          console.log(
            `  ${chalk.red('-')} ${field}: ${chalk.gray(formatPolicyDiffValue(change.before))}`,
          );
        } else {
          console.log(
            `  ${chalk.yellow('~')} ${field}: ` +
              `${chalk.gray(formatPolicyDiffValue(change.before))} -> ${chalk.white(formatPolicyDiffValue(change.after))}`,
          );
        }
      }
      console.log(chalk.gray(`\n${difference.changes.length} change(s) detected.\n`));
    }
  }

  if (options['fail-on-diff'] && difference.changed) {
    process.exitCode = EXIT_FAIL;
  }
}

export function cmdPolicyGuard(
  baseRef: string,
  options: ParsedArgs['options'],
  format: ReportFormat,
): void {
  if (format === 'sarif') usageError('policy guard supports pretty|json output only');
  if (options['fail-on-diff'] !== undefined) {
    usageError('policy guard always fails on policy changes; --fail-on-diff is not supported');
  }

  const configPath = options.config !== undefined ? String(options.config) : undefined;
  let approved: ReturnType<typeof loadApprovedPolicy>;
  try {
    approved = loadApprovedPolicy({ base: baseRef, configPath });
  } catch (error) {
    if (error instanceof PolicyGuardError) {
      console.error(chalk.red(`Error: ${error.message}`));
      process.exit(EXIT_USAGE);
    }
    throw error;
  }

  if (configPath !== undefined && !fs.existsSync(path.resolve(configPath))) {
    if (format === 'json') {
      console.log(
        JSON.stringify(
          {
            changed: true,
            baseRef,
            approvedPolicy: approved.configPath,
            currentPolicy: null,
            reason: `Current policy file was removed: ${configPath}`,
          },
          null,
          2,
        ),
      );
    } else {
      console.error(chalk.red(`\nPolicy change detected: ${chalk.white(configPath)} was removed.\n`));
    }
    process.exit(EXIT_FAIL);
  }

  const current = buildConfigDetails(options);
  let baselineGuard: BaselineGuardResult | undefined;
  const baselinePath = current.config.baseline;
  if (baselinePath !== undefined) {
    const resolvedBaseline = path.resolve(baselinePath);
    let currentBaseline;
    if (fs.existsSync(resolvedBaseline)) {
      try {
        currentBaseline = parseBaselineContent(
          fs.readFileSync(resolvedBaseline, 'utf8'),
          resolvedBaseline,
        );
      } catch (error) {
        console.error(
          chalk.red(
            `Error: ${error instanceof Error ? error.message : String(error)}`,
          ),
        );
        process.exit(EXIT_USAGE);
      }
    }
    baselineGuard = guardBaseline(
      approved.repositoryRoot,
      approved.sha,
      repositoryRelativeBaselinePath(approved.repositoryRoot, baselinePath),
      currentBaseline,
    );
  }

  const result = guardPolicy(approved, current.config, current.source, baselineGuard);
  const changed = result.diff.changed || (baselineGuard?.changed ?? false);
  const report = {
    changed,
    baseRef,
    approvedPolicy: approved.configPath,
    approvedSources: approved.sources,
    currentPath: result.current.configPath,
    currentPolicy: current.source ?? null,
    changes: result.diff.changes,
    ...(baselineGuard ? { baseline: baselineGuard } : {}),
  };

  if (format === 'json') {
    console.log(JSON.stringify(report, null, 2));
  } else {
    console.log(chalk.bold.cyan('\nPolicy Guard\n'));
    console.log(chalk.gray('─'.repeat(78)));
    console.log(`  Approved: ${chalk.white(`${baseRef}:${approved.configPath}`)}`);
    console.log(`  Current:  ${chalk.white(result.current.configPath)}`);
    console.log(chalk.gray('─'.repeat(78)));

    if (!changed) {
      console.log(chalk.green.bold('\n✓ Policy matches the approved base ref.\n'));
    } else {
      for (const change of result.diff.changes) {
        const field = change.key ? `${change.field}[${change.key}]` : change.field;
        if (change.kind === 'added') {
          console.log(
            `  ${chalk.green('+')} ${field}: ${chalk.gray(formatPolicyDiffValue(change.after))}`,
          );
        } else if (change.kind === 'removed') {
          console.log(
            `  ${chalk.red('-')} ${field}: ${chalk.gray(formatPolicyDiffValue(change.before))}`,
          );
        } else {
          console.log(
            `  ${chalk.yellow('~')} ${field}: ` +
              `${chalk.gray(formatPolicyDiffValue(change.before))} -> ${chalk.white(formatPolicyDiffValue(change.after))}`,
          );
        }
      }
      console.log(chalk.gray(`\n${result.diff.changes.length} policy change(s) detected.\n`));
    }

    if (baselineGuard?.changed) {
      console.log(
        chalk.gray(
          `\nBaseline ${baselineGuard.path}: ${baselineGuard.approvedEntries} approved -> ` +
            `${baselineGuard.currentEntries} current\n`,
        ),
      );
      for (const fingerprint of baselineGuard.added) {
        console.log(`  ${chalk.red('+')} accepted finding ${chalk.gray(fingerprint.slice(0, 16))}`);
      }
      for (const fingerprint of baselineGuard.removed) {
        console.log(`  ${chalk.yellow('-')} dropped finding ${chalk.gray(fingerprint.slice(0, 16))}`);
      }
      for (const change of baselineGuard.changes) {
        if (change.field !== 'entries' || change.kind !== 'changed') continue;
        console.log(
          `  ${chalk.yellow('~')} revised finding ${chalk.gray((change.key ?? '').slice(0, 16))}`,
        );
      }
      for (const change of baselineGuard.changes) {
        if (change.field === 'entries') continue;
        console.log(
          `  ${chalk.yellow('~')} ${change.field}: ` +
            `${chalk.gray(String(change.before ?? '(unset)'))} -> ` +
            `${chalk.white(String(change.after ?? '(unset)'))}`,
        );
      }
    }
  }

  if (changed) {
    process.exitCode = EXIT_FAIL;
  }
}

