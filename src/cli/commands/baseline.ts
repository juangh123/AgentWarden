import * as fs from 'node:fs';
import * as path from 'node:path';
import { chalk } from '../../reporter/chalk.ts';
import { scanSkillFile } from '../../scanner/index.ts';
import { discoverSkillFiles } from '../../scanner/discovery.ts';
import { type ReportFormat } from '../../reporter/index.ts';
import { DEFAULT_BASELINE_NAME, createBaseline, inspectBaseline, pruneBaseline, readBaseline, updateBaseline, writeBaseline } from '../../baseline/index.ts';
import { type ParsedArgs, usageError, EXIT_USAGE, EXIT_FAIL } from '../args.ts';
import { changedScanRequested, resolvePath } from '../shared.ts';
import { buildConfig } from '../config.ts';

export function resolveBaselineExpiry(options: ParsedArgs['options']): string | undefined {
  const expiresIn = options['expires-in'];
  const expiresAt = options['expires-at'];
  if (expiresIn !== undefined && expiresAt !== undefined) {
    usageError('Use either --expires-in or --expires-at, not both');
  }

  if (expiresIn !== undefined) {
    const days = Number(expiresIn);
    if (!Number.isFinite(days) || days < 1 || days > 3650) {
      usageError(`Invalid --expires-in "${String(expiresIn)}" (expected 1-3650 days)`);
    }
    return new Date(Date.now() + days * 24 * 60 * 60 * 1000).toISOString();
  }

  if (expiresAt !== undefined) {
    const timestamp = Date.parse(String(expiresAt));
    if (!Number.isFinite(timestamp)) {
      usageError(`Invalid --expires-at "${String(expiresAt)}" (expected ISO date)`);
    }
    return new Date(timestamp).toISOString();
  }

  return undefined;
}

export function resolveExpiringWithin(options: ParsedArgs['options']): number {
  if (options['expiring-within'] === undefined) return 30;
  const days = Number(options['expiring-within']);
  if (!Number.isFinite(days) || days < 1 || days > 3650) {
    usageError(
      `Invalid --expiring-within "${String(options['expiring-within'])}" (expected 1-3650 days)`,
    );
  }
  return Math.ceil(days);
}

export function cmdBaselineStatus(
  targets: string[],
  options: ParsedArgs['options'],
  format: ReportFormat,
): void {
  if (format === 'sarif') usageError('baseline status supports pretty|json output only');
  if (changedScanRequested(options)) {
    usageError('baseline status requires the full configured scan scope; --changed is only supported by scan');
  }

  const config = buildConfig(options);
  const baselinePath = config.baseline ?? DEFAULT_BASELINE_NAME;
  delete config.baseline;
  const files = discoverSkillFiles(targets.map(resolvePath), process.cwd(), {
    include: config.include,
    exclude: config.exclude,
  });
  if (files.length === 0) {
    console.error(
      chalk.yellow(
        `No skill or MCP configuration files found in: ${targets.join(', ')} ` +
          `(nothing to scan; check the path or the include/exclude filters)`,
      ),
    );
    process.exitCode = EXIT_USAGE;
    return;
  }

  const baseline = readBaseline(baselinePath, process.cwd());
  const results = files.map((file) => scanSkillFile(file, config));
  const inspection = inspectBaseline(results, baseline, { cwd: process.cwd() });
  const expiringWithinDays = resolveExpiringWithin(options);
  const expiring =
    !inspection.expired &&
    inspection.daysUntilExpiry !== undefined &&
    inspection.daysUntilExpiry <= expiringWithinDays;
  const unmatchedEntries = inspection.entries.filter((entry) => !entry.matched);
  const report = {
    path: path.resolve(process.cwd(), baselinePath),
    baselineVersion: inspection.baselineVersion,
    reviewedAt: inspection.reviewedAt ?? null,
    owner: inspection.owner ?? null,
    expiresAt: inspection.expiresAt ?? null,
    expired: inspection.expired,
    expiring,
    expiringWithinDays,
    daysUntilExpiry: inspection.daysUntilExpiry ?? null,
    summary: inspection.summary,
    entries: inspection.entries.map((entry) => ({
      fingerprint: entry.fingerprint,
      ruleId: entry.ruleId,
      file: entry.file,
      line: entry.line ?? null,
      severity: entry.severity,
      acceptedAt: entry.acceptedAt ?? null,
      ageDays: entry.ageDays ?? null,
      matched: entry.matched,
    })),
  };

  if (format === 'json') {
    console.log(JSON.stringify(report, null, 2));
  } else {
    const state = inspection.expired
      ? chalk.red.bold('EXPIRED')
      : expiring
        ? chalk.yellow.bold('EXPIRING SOON')
        : chalk.green.bold('ACTIVE');
    console.log(chalk.bold.cyan('\nBaseline Status\n'));
    console.log(chalk.gray('─'.repeat(88)));
    console.log(`  Path:      ${chalk.gray(report.path)}`);
    console.log(`  Version:   ${chalk.white(String(report.baselineVersion))}`);
    console.log(`  Status:    ${state}`);
    console.log(`  Owner:     ${report.owner ?? chalk.gray('(unassigned)')}`);
    console.log(`  Reviewed:  ${report.reviewedAt ?? chalk.gray('(legacy baseline)')}`);
    console.log(`  Expires:   ${report.expiresAt ?? chalk.gray('(never)')}`);
    if (report.daysUntilExpiry !== null) {
      console.log(`  Remaining: ${chalk.white(String(report.daysUntilExpiry) + ' day(s)')}`);
    }
    console.log(
      `  Entries:   ${chalk.white(String(report.summary.total))} total, ` +
        `${chalk.green(String(report.summary.matched))} matched, ` +
        `${chalk.yellow(String(report.summary.unmatched))} unmatched`,
    );

    if (unmatchedEntries.length > 0) {
      console.log(chalk.yellow.bold('\nUnmatched entries:'));
      for (const entry of unmatchedEntries) {
        const location = entry.line ? `${entry.file}:${entry.line}` : entry.file;
        const age = entry.ageDays !== undefined ? `, ${entry.ageDays} day(s) old` : '';
        console.log(`  • ${chalk.white(entry.ruleId)} ${chalk.gray(location)}${chalk.gray(age)}`);
      }
    }
    console.log(chalk.gray('─'.repeat(88)) + '\n');
  }

  if (
    inspection.expired ||
    (options['fail-on-expiring'] && expiring) ||
    (options['fail-on-unmatched'] && unmatchedEntries.length > 0)
  ) {
    process.exitCode = EXIT_FAIL;
  }
}

export function cmdBaselineMaintenance(
  mode: 'prune' | 'update',
  targets: string[],
  options: ParsedArgs['options'],
  format: ReportFormat,
): void {
  if (format === 'sarif') usageError(`baseline ${mode} supports pretty|json output only`);
  if (changedScanRequested(options)) {
    usageError(`baseline ${mode} requires the full configured scan scope; --changed is only supported by scan`);
  }
  if (options['dry-run'] && options.force) {
    usageError('Use either --dry-run or --force, not both');
  }

  const config = buildConfig(options);
  const baselinePath = config.baseline ?? DEFAULT_BASELINE_NAME;
  delete config.baseline;
  const files = discoverSkillFiles(targets.map(resolvePath), process.cwd(), {
    include: config.include,
    exclude: config.exclude,
  });
  if (files.length === 0) {
    console.error(
      chalk.yellow(
        `No skill or MCP configuration files found in: ${targets.join(', ')} ` +
          `(nothing to scan; check the path or the include/exclude filters)`,
      ),
    );
    process.exitCode = EXIT_USAGE;
    return;
  }

  const baseline = readBaseline(baselinePath, process.cwd());
  const results = files.map((file) => scanSkillFile(file, config));
  const maintenanceOptions = {
    cwd: process.cwd(),
    owner: options.owner !== undefined ? String(options.owner) : undefined,
    expiresAt: resolveBaselineExpiry(options),
    note: options.note !== undefined ? String(options.note) : undefined,
  };
  const maintenance =
    mode === 'prune'
      ? pruneBaseline(results, baseline, maintenanceOptions)
      : updateBaseline(results, baseline, maintenanceOptions);
  const output = String(options.output || baselinePath);
  const resolvedOutput = path.resolve(process.cwd(), output);
  const requestedDryRun = Boolean(options['dry-run']);
  const dryRun = requestedDryRun || (maintenance.changed && !options.force);
  const applied = maintenance.changed && !requestedDryRun && Boolean(options.force);

  if (applied) {
    writeBaseline(maintenance.baseline, output);
  }

  const report = {
    ok: true,
    mode,
    path: path.resolve(process.cwd(), baselinePath),
    output: resolvedOutput,
    dryRun,
    changed: maintenance.changed,
    applied,
    filesScanned: files.length,
    baselineVersion: maintenance.baseline.baselineVersion,
    reviewedAt: maintenance.baseline.review?.reviewedAt ?? null,
    owner: maintenance.baseline.review?.owner ?? null,
    expiresAt: maintenance.baseline.review?.expiresAt ?? null,
    summary: maintenance.summary,
    removed: maintenance.removed.map((entry) => ({
      fingerprint: entry.fingerprint,
      ruleId: entry.ruleId,
      file: entry.file,
      line: entry.line ?? null,
      severity: entry.severity,
      acceptedAt: entry.acceptedAt ?? null,
    })),
    added: maintenance.added.map((entry) => ({
      fingerprint: entry.fingerprint,
      ruleId: entry.ruleId,
      file: entry.file,
      line: entry.line ?? null,
      severity: entry.severity,
      acceptedAt: entry.acceptedAt ?? null,
    })),
  };

  if (format === 'json') {
    console.log(JSON.stringify(report, null, 2));
  } else {
    const state = maintenance.changed
      ? applied
        ? chalk.green.bold('UPDATED')
        : chalk.yellow.bold('DRY RUN')
      : chalk.green.bold('NO CHANGES');
    console.log(chalk.bold.cyan(`\nBaseline ${mode === 'prune' ? 'Prune' : 'Update'}\n`));
    console.log(chalk.gray('─'.repeat(88)));
    console.log(`  Path:      ${chalk.gray(report.path)}`);
    console.log(`  Output:    ${chalk.gray(report.output)}`);
    console.log(`  Status:    ${state}`);
    console.log(
      `  Entries:   ${chalk.white(String(report.summary.before))} before, ` +
        `${chalk.white(String(report.summary.after))} after`,
    );
    console.log(
      `  Changes:   ${chalk.green(String(report.summary.kept))} kept, ` +
        `${chalk.yellow(String(report.summary.removed))} removed, ` +
        `${chalk.cyan(String(report.summary.added))} added`,
    );
    if (report.removed.length > 0) {
      console.log(chalk.yellow.bold('\nEntries to remove:'));
      for (const entry of report.removed) {
        const location = entry.line ? `${entry.file}:${entry.line}` : entry.file;
        console.log(`  • ${chalk.white(entry.ruleId)} ${chalk.gray(location)}`);
      }
    }
    if (report.added.length > 0) {
      console.log(chalk.cyan.bold('\nEntries to add:'));
      for (const entry of report.added) {
        const location = entry.line ? `${entry.file}:${entry.line}` : entry.file;
        console.log(`  • ${chalk.white(entry.ruleId)} ${chalk.gray(location)}`);
      }
    }
    if (maintenance.changed && !applied) {
      console.log(chalk.yellow('\nPreview only. Re-run with --force to write these changes.'));
    }
    console.log(chalk.gray('─'.repeat(88)) + '\n');
  }
}

export function cmdBaseline(targets: string[], options: ParsedArgs['options'], format: ReportFormat): void {
  const config = buildConfig(options, true);
  const files = discoverSkillFiles(targets.map(resolvePath), process.cwd(), {
    include: config.include,
    exclude: config.exclude,
  });
  if (files.length === 0) {
    console.error(
      chalk.yellow(
        `No skill or MCP configuration files found in: ${targets.join(', ')} ` +
          `(nothing to scan; check the path or the include/exclude filters)`,
      ),
    );
    process.exitCode = EXIT_USAGE;
    return;
  }

  const results = files.map((file) => scanSkillFile(file, config));
  const expiresAt = resolveBaselineExpiry(options);
  const baseline = createBaseline(results, process.cwd(), {
    owner: options.owner !== undefined ? String(options.owner) : undefined,
    expiresAt,
    note: options.note !== undefined ? String(options.note) : undefined,
  });
  const output = String(options.output || DEFAULT_BASELINE_NAME);
  const resolvedOutput = path.resolve(process.cwd(), output);

  if (fs.existsSync(resolvedOutput) && !options.force) {
    console.error(chalk.red(`Error: Baseline already exists at ${resolvedOutput}. Use --force to overwrite.`));
    process.exit(EXIT_FAIL);
  }

  writeBaseline(baseline, output);

  if (format === 'json') {
    console.log(
      JSON.stringify(
        {
          ok: true,
          output: resolvedOutput,
          filesScanned: files.length,
          findingsAccepted: baseline.entries.length,
          baseline,
        },
        null,
        2,
      ),
    );
    return;
  }

  console.log(chalk.green.bold(`\n✓ Baseline created: ${resolvedOutput}`));
  console.log(`  Files: ${files.length}`);
  console.log(`  Accepted findings: ${baseline.entries.length}`);
  if (baseline.review?.owner) console.log(`  Review owner: ${baseline.review.owner}`);
  if (baseline.review?.expiresAt) console.log(`  Expires at: ${baseline.review.expiresAt}`);
  console.log(chalk.gray('  Enable it with --baseline <file> or the "baseline" config field.\n'));
}

