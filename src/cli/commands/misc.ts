import * as path from 'node:path';
import { chalk } from '../../reporter/chalk.ts';
import { redactText, type ReportFormat } from '../../reporter/index.ts';
import { readLockfile, removeLockfileSkill, findSkillKey, normalizePath, type LockedSkill, type LockfileSchema } from '../../manifest/lockfile.ts';
import { POLICY_PROFILES, type PolicyProfileName, type SkillGuardConfig } from '../../config/index.ts';
import { allRules } from '../../rules/index.ts';
import { buildCycloneDxSbom } from '../../sbom/index.ts';
import {
  InitError,
  initializeAgentWarden,
} from '../../init/index.ts';
import { writeFileAtomic } from '../../utils/atomicWrite.ts';
import { type ParsedArgs, usageError, EXIT_FAIL, resolveFormat } from '../args.ts';
import { buildConfig } from '../config.ts';

export function cmdList(lock: LockfileSchema, format: ReportFormat): void {
  const names = Object.keys(lock.skills).sort();

  if (format === 'json') {
    const skills = names.map((name): LockedSkill => {
      const entry = lock.skills[name];
      if (entry === undefined) {
        throw new Error(`skills.lock entry "${name}" is missing.`);
      }
      return {
        ...entry,
        ...(entry.remoteUrl ? { remoteUrl: redactText(entry.remoteUrl) } : {}),
        ...(entry.resolvedUrl ? { resolvedUrl: redactText(entry.resolvedUrl) } : {}),
      };
    });
    console.log(JSON.stringify({ count: skills.length, skills }, null, 2));
    return;
  }

  if (names.length === 0) {
    console.log(chalk.gray('  No installed skills recorded in skills.lock yet.'));
    return;
  }

  console.log(chalk.bold.cyan('\n📦 Installed Skills\n'));
  console.log(chalk.gray('─'.repeat(78)));
  for (const name of names) {
    const item = lock.skills[name];
    if (item === undefined) continue;
    const src = normalizePath(item.source);
    console.log(
      `  ${chalk.bold.white(name.padEnd(28))} ${chalk.gray('v' + String(item.version).padEnd(8))} ` +
        `${chalk.green(String(item.verifiedScore).padStart(3) + '/100 ')} ${chalk.gray(src)}`,
    );
  }
  console.log(chalk.gray('─'.repeat(78)) + '\n');
}

export function resolveSbomFormat(options: ParsedArgs['options']): 'pretty' | 'json' {
  if (options.sarif) usageError('sbom supports pretty|json output only');
  if (options.json) return 'json';
  if (options.format !== undefined) {
    const value = String(options.format).toLowerCase();
    if (value !== 'pretty' && value !== 'json') {
      usageError(`Invalid --format "${String(options.format)}" (expected pretty|json)`);
    }
    return value;
  }
  return 'json';
}

export function cmdSbom(options: ParsedArgs['options']): void {
  const format = resolveSbomFormat(options);
  const result = buildCycloneDxSbom({
    cwd: process.cwd(),
    config: buildConfig(options),
  });
  const document = `${JSON.stringify(result.bom, null, 2)}\n`;
  const requestedOutput =
    options.output !== undefined ? String(options.output).trim() : undefined;
  if (options.output !== undefined && !requestedOutput) {
    usageError('SBOM output path must not be empty');
  }
  const output = requestedOutput ? path.resolve(process.cwd(), requestedOutput) : undefined;
  if (output) writeFileAtomic(output, document);

  if (!output && format === 'json') {
    process.stdout.write(document);
  } else if (format === 'pretty' || output) {
    const integrityFailures = result.inspections.filter(
      (inspection) => inspection.integrityPassed === false,
    ).length;
    const publisherFailures = result.inspections.filter(
      (inspection) => !inspection.publisherPolicyPassed,
    ).length;
    console.log(chalk.bold.cyan('\nCycloneDX SBOM\n'));
    console.log(chalk.gray('─'.repeat(78)));
    if (output) console.log(`  Output:          ${chalk.gray(output)}`);
    console.log(`  Spec:            ${chalk.white('CycloneDX 1.5')}`);
    console.log(`  Components:      ${chalk.white(String(result.componentCount))}`);
    console.log(`  Package files:   ${chalk.white(String(result.packageFileCount))}`);
    console.log(`  Document SHA256: ${chalk.gray(result.documentSha256)}`);
    console.log(
      `  Integrity:       ${
        integrityFailures === 0
          ? chalk.green('passed')
          : chalk.red(`${integrityFailures} failure(s)`)
      }`,
    );
    console.log(
      `  Publisher policy:${
        publisherFailures === 0
          ? ' ' + chalk.green('passed')
          : ' ' + chalk.red(`${publisherFailures} failure(s)`)
      }`,
    );
    console.log(chalk.gray('─'.repeat(78)) + '\n');
  }

  if (!result.passed) process.exitCode = EXIT_FAIL;
}

export function resolveInitFormat(options: ParsedArgs['options']): 'pretty' | 'json' {
  if (options.sarif) usageError('init supports pretty|json output only');
  const format = resolveFormat(options);
  if (format === 'sarif') usageError('init supports pretty|json output only');
  return format === 'json' ? 'json' : 'pretty';
}

export function cmdInit(options: ParsedArgs['options'], format: 'pretty' | 'json'): void {
  const requestedProfile =
    options.profile !== undefined
      ? (String(options.profile).trim().toLowerCase() as PolicyProfileName)
      : 'balanced';
  if (!Object.hasOwn(POLICY_PROFILES, requestedProfile)) {
    usageError(`Invalid --profile "${String(options.profile)}" (expected legacy|balanced|strict)`);
  }

  const workflowPath =
    options['workflow-path'] === undefined ? undefined : String(options['workflow-path']);
  const actionRef = options['action-ref'] === undefined ? undefined : String(options['action-ref']);
  if (options['no-workflow'] && (workflowPath !== undefined || actionRef !== undefined)) {
    usageError('Use either --no-workflow or --workflow-path/--action-ref, not both');
  }
  const dryRun = Boolean(options['dry-run']);

  let result: ReturnType<typeof initializeAgentWarden>;
  try {
    result = initializeAgentWarden(process.cwd(), {
      profile: requestedProfile,
      workflow: !options['no-workflow'],
      force: Boolean(options.force),
      workflowPath,
      actionRef,
      dryRun,
    });
  } catch (error) {
    if (error instanceof InitError) usageError(error.message);
    throw error;
  }

  if (format === 'json') {
    console.log(JSON.stringify(result, null, 2));
    return;
  }

  const defaults = POLICY_PROFILES[result.profile];
  console.log(chalk.bold.cyan('\nAgentWarden initialization\n'));
  if (dryRun) {
    console.log(chalk.yellow('  Dry run: no files were written\n'));
  }
  console.log(chalk.gray('─'.repeat(78)));
  const createdLabel = (dryRun ? 'Would create:' : 'Created:').padEnd(18);
  const replacedLabel = (dryRun ? 'Would replace:' : 'Replaced:').padEnd(18);
  for (const filePath of result.created) {
    console.log(`  ${createdLabel}${chalk.green(filePath)}`);
  }
  for (const filePath of result.overwritten) {
    console.log(`  ${replacedLabel}${chalk.yellow(filePath)}`);
  }
  console.log(
    `  Profile:          ${chalk.bold.white(result.profile)} ` +
      chalk.gray(`(failOn: ${defaults.failOn}, minScore: ${defaults.minScore})`),
  );
  console.log(chalk.gray('─'.repeat(78)));
  console.log(chalk.gray('\nNext steps:'));
  if (dryRun) {
    console.log(`  1. Re-run without ${chalk.gray('--dry-run')} to write these files`);
    console.log('');
    return;
  }
  console.log(`  1. Review ${chalk.gray(result.configPath)}`);
  console.log(`  2. Run ${chalk.gray('agentwarden scan .')}`);
  console.log(
    `  3. Commit the generated file${result.workflowPath ? 's' : ''}` +
      (result.workflowPath ? `, including ${chalk.gray(result.workflowPath)}` : ''),
  );
  console.log('');
}

export function cmdRules(config: SkillGuardConfig, format: ReportFormat): void {
  const ignored = new Set(config.ignoreRules ?? []);
  const overrides = config.severityOverrides ?? {};
  const rules = allRules.map((rule) => {
    const effectiveSeverity = overrides[rule.id] ?? rule.severity;
    return {
      id: rule.id,
      title: rule.title,
      category: rule.category,
      severity: rule.severity,
      effectiveSeverity,
      overridden: effectiveSeverity !== rule.severity,
      ignored: ignored.has(rule.id),
      description: rule.description,
      suggestion: rule.suggestion,
    };
  });

  if (format === 'json') {
    console.log(JSON.stringify({ count: rules.length, rules }, null, 2));
    return;
  }

  console.log(chalk.bold.cyan('\nSecurity Rule Catalog\n'));
  console.log(chalk.gray('─'.repeat(104)));
  for (const rule of rules) {
    const stateLabel = rule.ignored
      ? 'IGNORED'
      : rule.overridden
        ? `${rule.effectiveSeverity.toUpperCase()} override`
        : rule.effectiveSeverity.toUpperCase();
    const state = rule.ignored
      ? chalk.red(stateLabel.padEnd(20))
      : rule.overridden
        ? chalk.yellow(stateLabel.padEnd(20))
        : chalk.green(stateLabel.padEnd(20));
    console.log(
      `  ${chalk.bold.white(rule.id.padEnd(17))} ${state} ` +
        `${chalk.gray(rule.category.padEnd(20))} ${rule.title}`,
    );
  }
  console.log(chalk.gray('─'.repeat(104)) + '\n');
}

export function cmdUninstall(name: string, format: ReportFormat): void {
  const lock = readLockfile();
  const key = findSkillKey(lock, name);
  if (!key) {
    console.error(chalk.yellow(`⚠️  Skill "${name}" is not registered in skills.lock.`));
    process.exit(EXIT_FAIL);
  }
  removeLockfileSkill(key);
  if (format === 'json') {
    console.log(JSON.stringify({ removed: key, ok: true }, null, 2));
  } else {
    console.log(chalk.green(`🗑️  Removed "${key}" from skills.lock.`));
  }
}

