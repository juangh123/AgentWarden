import { chalk } from '../../reporter/chalk.ts';
import { scanSkillFile } from '../../scanner/index.ts';
import {
  discoverSkillFiles,
  filterSkillFiles,
} from '../../scanner/discovery.ts';
import { ChangedFilesError, getChangedFiles } from '../../git/changed.ts';
import { renderScanReports, type ReportFormat } from '../../reporter/index.ts';
import { type SkillGuardConfig } from '../../config/index.ts';
import type { ScanResult } from '../../rules/types.ts';
import { type ParsedArgs, usageError, reportOptions, EXIT_USAGE, EXIT_FAIL } from '../args.ts';
import { resolvePath, changedScanRequested, canonicalCliPath, isPathWithinTarget } from '../shared.ts';

export function scanTargets(
  targets: string[],
  config: SkillGuardConfig,
  format: ReportFormat,
  options: ParsedArgs['options'],
): void {
  const targetPaths = targets.map(resolvePath);
  const changedFrom =
    options['changed-from'] !== undefined ? String(options['changed-from']).trim() : undefined;
  const changedMode = changedScanRequested(options);
  let files: string[];
  let changedBase: string | undefined;

  if (changedMode) {
    if (changedFrom !== undefined && !changedFrom) {
      usageError('Option --changed-from requires a Git ref');
    }
    try {
      const changed = getChangedFiles({
        cwd: process.cwd(),
        ...(changedFrom ? { base: changedFrom } : {}),
      });
      const scanCwd = canonicalCliPath(process.cwd());
      changedBase = changed.baseRef;
      files = filterSkillFiles(changed.files, scanCwd, {
        include: config.include,
        exclude: config.exclude,
      }).filter((file) => targetPaths.some((target) => isPathWithinTarget(file, target)));
    } catch (error) {
      if (error instanceof ChangedFilesError) usageError(error.message);
      throw error;
    }
  } else {
    files = discoverSkillFiles(targetPaths, process.cwd(), {
      include: config.include,
      exclude: config.exclude,
    });
  }

  if (files.length === 0) {
    if (changedMode) {
      renderScanReports([], format, reportOptions(options));
      if (format === 'pretty') {
        console.log(
          chalk.gray(`No changed skill or MCP configuration files to scan (base: ${changedBase}).`),
        );
      }
      return;
    }
    console.error(
      chalk.yellow(
        `No skill or MCP configuration files found in: ${targets.join(', ')} ` +
          `(nothing to scan; check the path or the include/exclude filters)`,
      ),
    );
    process.exitCode = EXIT_USAGE;
    return;
  }

  if (changedMode && format === 'pretty') {
    console.log(
      chalk.gray(
        `Changed scan scope: ${files.length} skill/MCP file(s) from Git base ${changedBase}.`,
      ),
    );
  }

  const scanResults: ScanResult[] = files.map((file) => scanSkillFile(file, config));
  renderScanReports(scanResults, format, reportOptions(options));

  // Set the exit code instead of calling process.exit so a large JSON/SARIF
  // report is always flushed before the process ends.
  if (scanResults.some((r) => !r.passed)) process.exitCode = EXIT_FAIL;
}

