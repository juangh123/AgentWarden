#!/usr/bin/env node
import * as fs from 'node:fs';
import * as path from 'node:path';
import { chalk, setColorEnabled } from './reporter/chalk.ts';
import { scanSkillFile } from './scanner/index.ts';
import { discoverSkillFiles } from './scanner/discovery.ts';
import {
  renderScanReport,
  renderScanReports,
  toReportScanResult,
  type ReportFormat,
  type ReportOptions,
} from './reporter/index.ts';
import {
  readLockfile,
  updateLockfileSkill,
  removeLockfileSkill,
  findSkillKey,
  toRelativePosix,
  resolveFromRoot,
  normalizePath,
  type LockfileSchema,
} from './manifest/lockfile.ts';
import { loadConfig, normalizeConfig, type SkillGuardConfig } from './config/index.ts';
import { readPackageVersion } from './version.ts';
import type { ScanResult, Severity } from './rules/types.ts';
import { DEFAULT_BASELINE_NAME, createBaseline, writeBaseline } from './baseline/index.ts';
import { allRules } from './rules/index.ts';

const VERSION = readPackageVersion();

const EXIT_OK = 0;
const EXIT_FAIL = 1;
const EXIT_USAGE = 2;

const VALID_FORMATS = new Set(['pretty', 'json', 'sarif']);
const VALID_FAIL_ON: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

const VALUE_OPTIONS = new Set([
  'format',
  'fail-on',
  'min-score',
  'cwd',
  'ignore-rule',
  'severity-override',
  'baseline',
  'output',
]);
const BOOLEAN_OPTIONS = new Set(['force', 'help', 'version', 'json', 'sarif', 'no-color', 'no-redact']);
const SHORT_FLAGS: Record<string, string> = { f: 'force', h: 'help', v: 'version', C: 'cwd' };

interface ParsedArgs {
  positionals: string[];
  options: Record<string, string | string[] | boolean>;
  errors: string[];
}

function parseArgs(argv: string[]): ParsedArgs {
  const positionals: string[] = [];
  const options: Record<string, string | string[] | boolean> = {};
  const errors: string[] = [];

  let i = 0;
  while (i < argv.length) {
    const arg = argv[i];
    if (arg === '--') {
      positionals.push(...argv.slice(i + 1));
      break;
    }
    if (arg.startsWith('--')) {
      const eq = arg.indexOf('=');
      const key = eq === -1 ? arg.slice(2) : arg.slice(2, eq);
      const inline = eq === -1 ? undefined : arg.slice(eq + 1);
      if (VALUE_OPTIONS.has(key)) {
        let value = inline;
        if (value === undefined) value = argv[++i];
        if (value === undefined || value.startsWith('-')) {
          errors.push(`Option --${key} requires a value`);
          continue;
        }
        if (key === 'ignore-rule' || key === 'severity-override') {
          const optionKey = key === 'ignore-rule' ? 'ignoreRule' : 'severityOverride';
          const list = (options[optionKey] as string[] | undefined) ?? [];
          list.push(value);
          options[optionKey] = list;
        } else {
          options[key] = value;
        }
      } else if (BOOLEAN_OPTIONS.has(key)) {
        if (inline !== undefined) errors.push(`Option --${key} does not take a value`);
        options[key] = true;
      } else {
        errors.push(`Unknown option: --${key}`);
      }
    } else if (arg.startsWith('-') && arg.length > 1) {
      const short = arg.slice(1);
      const long = SHORT_FLAGS[short];
      if (!long) {
        errors.push(`Unknown option: -${short}`);
      } else if (VALUE_OPTIONS.has(long)) {
        const value = argv[++i];
        if (value === undefined) {
          errors.push(`Option -${short} requires a value`);
        } else {
          options[long] = value;
        }
      } else {
        options[long] = true;
      }
    } else {
      positionals.push(arg);
    }
    i++;
  }

  return { positionals, options, errors };
}

function usageError(message: string): never {
  console.error(chalk.red(`Error: ${message}`));
  console.error(`Run ${chalk.yellow('"agentwarden help"')} for usage.`);
  process.exit(EXIT_USAGE);
}

function resolveFormat(options: ParsedArgs['options'], isJson = false): ReportFormat {
  if (options.json || isJson) return 'json';
  if (options.sarif) return 'sarif';
  if (options.format !== undefined) {
    const value = String(options.format).toLowerCase();
    if (!VALID_FORMATS.has(value)) usageError(`Invalid --format "${String(options.format)}" (expected pretty|json|sarif)`);
    return value as ReportFormat;
  }
  return 'pretty';
}

function reportOptions(options: ParsedArgs['options']): ReportOptions {
  return { redact: !options['no-redact'] };
}

function buildConfig(options: ParsedArgs['options'], ignoreBaseline = false): SkillGuardConfig {
  const base = loadConfig();
  const override: Partial<SkillGuardConfig> = {};

  if (options['fail-on'] !== undefined) {
    const value = String(options['fail-on']).toLowerCase() as Severity;
    if (!VALID_FAIL_ON.includes(value)) usageError(`Invalid --fail-on "${String(options['fail-on'])}"`);
    override.failOn = value;
  }
  if (options['min-score'] !== undefined) {
    const value = Number(options['min-score']);
    if (!Number.isFinite(value)) usageError(`Invalid --min-score "${String(options['min-score'])}" (expected 0-100)`);
    override.minScore = value;
  }

  const extraIgnores = (options.ignoreRule as string[] | undefined) ?? [];
  if (options.baseline !== undefined) override.baseline = String(options.baseline);

  const severityOverrides: Record<string, Severity> = { ...(base.severityOverrides ?? {}) };
  for (const specification of (options.severityOverride as string[] | undefined) ?? []) {
    const separator = specification.indexOf('=');
    if (separator <= 0) {
      usageError(`Invalid --severity-override "${specification}" (expected RULE_ID=severity)`);
    }
    const ruleId = specification.slice(0, separator).trim().toUpperCase();
    const severity = specification.slice(separator + 1).trim().toLowerCase() as Severity;
    if (!ruleId || !VALID_FAIL_ON.includes(severity)) {
      usageError(`Invalid --severity-override "${specification}" (expected RULE_ID=critical|high|medium|low|info)`);
    }
    severityOverrides[ruleId] = severity;
  }
  override.severityOverrides = severityOverrides;

  const merged: Partial<SkillGuardConfig> = {
    ...base,
    ...override,
    ignoreRules: [...(base.ignoreRules ?? []), ...extraIgnores],
  };
  if (ignoreBaseline) delete merged.baseline;

  return normalizeConfig(merged);
}

function resolvePath(target: string): string {
  const fullPath = path.resolve(process.cwd(), target);
  if (!fs.existsSync(fullPath)) {
    console.error(chalk.red(`Error: Path not found at ${fullPath}`));
    process.exit(EXIT_USAGE);
  }
  return fullPath;
}

function printHelp(): void {
  console.log(`
${chalk.bold.cyan('🛡️  AgentWarden')} v${VERSION} - Zero-Dependency Security Warden & Integrity Manager for Agent Skills

${chalk.bold('USAGE:')}
  agentwarden <command> [options] [paths...]
  warden <command> [options] [paths...]

${chalk.bold('COMMANDS:')}
  ${chalk.green('scan <file|dir>...')}    Audit skill markdown files or directories of skills
  ${chalk.green('install <file>')}       Pre-scan, then securely record fingerprint to skills.lock
  ${chalk.green('verify <file>')}        Verify a single skill file against skills.lock fingerprint
  ${chalk.green('audit')}                Audit all installed skills in skills.lock against local tampering
  ${chalk.green('rules')}                List active security rules and effective severity
  ${chalk.green('list')}                 List skills recorded in skills.lock
  ${chalk.green('uninstall <name>')}     Remove a skill entry from skills.lock
  ${chalk.green('baseline [path...]')}   Create an explicit baseline of accepted findings
  ${chalk.green('help')}                 Show this help manual

${chalk.bold('OPTIONS:')}
  ${chalk.yellow('-f, --force')}            Bypass install warning or overwrite an existing baseline
  ${chalk.yellow('--format <type>')}        Report format: pretty (default), json, sarif
  ${chalk.yellow('--json')}                 Shorthand for --format json
  ${chalk.yellow('--sarif')}                Shorthand for --format sarif
  ${chalk.yellow('--fail-on <sev>')}        Fail threshold: critical|high|medium|low|info (default: high)
  ${chalk.yellow('--min-score <n>')}        Minimum safety score 0-100 (default: 60)
  ${chalk.yellow('--ignore-rule <id>')}     Skip a rule id (repeatable)
  ${chalk.yellow('--severity-override <rule=sev>')} Override a rule severity (repeatable)
  ${chalk.yellow('--baseline <file>')}      Suppress exact findings recorded in a baseline
  ${chalk.yellow('--output <file>')}        Baseline output path (default: ${DEFAULT_BASELINE_NAME})
  ${chalk.yellow('-C, --cwd <dir>')}        Run as if started from <dir>
  ${chalk.yellow('--no-color')}             Disable ANSI colors (also honors NO_COLOR env)
  ${chalk.yellow('--no-redact')}            Include raw snippets and file content in reports
  ${chalk.yellow('-v, --version')}          Show version

${chalk.bold('EXIT CODES:')}
  0 = clean  1 = security failure  2 = usage / file error
`);
}

function scanTargets(
  targets: string[],
  config: SkillGuardConfig,
  format: ReportFormat,
  options: ParsedArgs['options'],
): void {
  const files = discoverSkillFiles(targets.map(resolvePath));

  if (files.length === 0) {
    console.error(chalk.yellow(`No skill or MCP configuration files found in: ${targets.join(', ')}`));
    process.exit(EXIT_FAIL);
  }

  const scanResults: ScanResult[] = files.map((file) => scanSkillFile(file, config));
  renderScanReports(scanResults, format, reportOptions(options));

  if (scanResults.some((r) => !r.passed)) process.exit(EXIT_FAIL);
}

function cmdInstall(target: string, options: ParsedArgs['options'], format: ReportFormat): void {
  const force = Boolean(options.force);
  const fullPath = resolvePath(target);
  const config = buildConfig(options);

  if (format === 'pretty') {
    console.log(chalk.cyan(`\n🔍 Analyzing skill package: ${target}...`));
  }
  const result = scanSkillFile(fullPath, config);
  if (format === 'json') {
    console.log(
      JSON.stringify(
        {
          ...toReportScanResult(result, reportOptions(options)),
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
    process.exit(EXIT_FAIL);
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
  });

  if (format === 'pretty') {
    console.log(chalk.green(`🔒 Successfully verified and locked signature to skills.lock (source: ${relativePosix})!\n`));
  }
}

function cmdVerify(target: string, config: SkillGuardConfig): void {
  const fullPath = resolvePath(target);
  const lock = readLockfile();
  const result = scanSkillFile(fullPath, config);
  const skillName = result.parsedSkill.name;
  const key = findSkillKey(lock, skillName);
  const lockedEntry = key ? lock.skills[key] : undefined;

  if (!lockedEntry) {
    console.error(chalk.yellow(`⚠️  Skill "${skillName}" is not registered in skills.lock. Run "skillguard install ${target}" first.`));
    process.exit(EXIT_FAIL);
  }

  if (lockedEntry.sha256 !== result.sha256) {
    console.error(chalk.red.bold(`❌ TAMPERING DETECTED: Hash mismatch for skill "${key}"!`));
    console.error(chalk.gray(`  Expected: ${lockedEntry.sha256}`));
    console.error(chalk.gray(`  Actual:   ${result.sha256}`));
    process.exit(EXIT_FAIL);
  }

  console.log(chalk.green.bold(`✓ Integrity verified: "${key}" matches skills.lock record (Score: ${lockedEntry.verifiedScore}/100).`));
}

function cmdAudit(options: ParsedArgs['options'], config: SkillGuardConfig, format: ReportFormat): void {
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
  }
  const auditResult: { auditedAt: string; passed?: boolean; skills: Record<string, AuditEntry> } = {
    auditedAt: new Date().toISOString(),
    skills: {},
  };
  let hasFailure = false;

  for (const name of keys) {
    const item = lock.skills[name];
    const resolvedPath = resolveFromRoot(item.source);
    const exists = fs.existsSync(resolvedPath);
    let hashMatch = false;
    let currentScore: number | null = null;
    let policyPassed = false;
    let currentFindingCount: number | null = null;

    if (exists) {
      const currentResult = scanSkillFile(resolvedPath, config);
      hashMatch = currentResult.sha256 === item.sha256;
      currentScore = currentResult.score;
      policyPassed = currentResult.passed;
      currentFindingCount = currentResult.findings.length;
      if (!hashMatch || !policyPassed) hasFailure = true;
    } else {
      hasFailure = true;
    }

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
    };
  }

  if (format === 'json') {
    auditResult.passed = !hasFailure;
    console.log(JSON.stringify(auditResult, null, 2));
    if (hasFailure) process.exit(EXIT_FAIL);
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
    console.log(`  Last Security Score: ${entry.lockedScore}/100`);

    if (!entry.exists) {
      console.log(chalk.yellow(`  ⚠️  Source file not found on disk at: ${entry.source}`));
    } else if (!entry.hashMatch) {
      console.log(chalk.red.bold('  ⚠️  TAMPERING DETECTED! File content hash does NOT match lockfile!'));
    } else {
      console.log(chalk.green('  ✓ Content integrity verified against locked SHA256.'));
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
    if (entry.currentScore !== null && entry.currentScore !== entry.lockedScore) {
      console.log(chalk.yellow(`  ℹ️  Re-scan score drift: locked ${entry.lockedScore}/100, now ${entry.currentScore}/100 (rule updates may affect this).`));
    }
  }

  console.log('\n' + chalk.gray('═'.repeat(60)));
  if (hasFailure) {
    console.log(chalk.red.bold('❌ Audit completed: integrity or security policy failures detected!\n'));
    process.exit(EXIT_FAIL);
  }
  console.log(chalk.green.bold('✅ All installed skills passed integrity and current policy checks.\n'));
}

function cmdList(lock: LockfileSchema, format: ReportFormat): void {
  const names = Object.keys(lock.skills).sort();

  if (format === 'json') {
    console.log(JSON.stringify({ count: names.length, skills: names.map((n) => lock.skills[n]) }, null, 2));
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
    const src = normalizePath(item.source);
    console.log(
      `  ${chalk.bold.white(name.padEnd(28))} ${chalk.gray('v' + String(item.version).padEnd(8))} ` +
        `${chalk.green(String(item.verifiedScore).padStart(3) + '/100 ')} ${chalk.gray(src)}`,
    );
  }
  console.log(chalk.gray('─'.repeat(78)) + '\n');
}

function cmdRules(config: SkillGuardConfig, format: ReportFormat): void {
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

function cmdUninstall(name: string, format: ReportFormat): void {
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

function cmdBaseline(targets: string[], options: ParsedArgs['options'], format: ReportFormat): void {
  const files = discoverSkillFiles(targets.map(resolvePath));
  if (files.length === 0) {
    console.error(chalk.yellow(`No skill or MCP configuration files found in: ${targets.join(', ')}`));
    process.exit(EXIT_FAIL);
  }

  const config = buildConfig(options, true);
  const results = files.map((file) => scanSkillFile(file, config));
  const baseline = createBaseline(results);
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
  console.log(chalk.gray('  Enable it with --baseline <file> or the "baseline" config field.\n'));
}

function main(): void {
  const { positionals, options, errors } = parseArgs(process.argv.slice(2));

  if (options['no-color']) setColorEnabled(false);

  if (options.cwd !== undefined) {
    const dir = path.resolve(process.cwd(), String(options.cwd));
    if (!fs.existsSync(dir) || !fs.statSync(dir).isDirectory()) {
      console.error(chalk.red(`Error: --cwd directory not found at ${dir}`));
      process.exit(EXIT_USAGE);
    }
    process.chdir(dir);
  }

  if (errors.length > 0) {
    for (const error of errors) console.error(chalk.red(`Error: ${error}`));
    console.error(`Run ${chalk.yellow('"skillguard help"')} for usage.`);
    process.exit(EXIT_USAGE);
  }

  if (options.version) {
    console.log(`skillguard v${VERSION}`);
    return;
  }

  const command = positionals[0];
  if (!command || command === 'help' || command === '--help' || command === '-h' || options.help) {
    printHelp();
    return;
  }

  if (command === 'scan') {
    const targets = positionals.slice(1);
    if (targets.length === 0) usageError(`Missing file or directory path to scan. Usage: skillguard scan <path> [--format pretty|json|sarif]`);
    scanTargets(targets, buildConfig(options), resolveFormat(options), options);
    return;
  }

  if (command === 'install') {
    const target = positionals[1];
    if (!target) usageError(`Missing skill path to install. Usage: skillguard install <path/to/SKILL.md>`);
    cmdInstall(target, options, resolveFormat(options));
    return;
  }

  if (command === 'verify') {
    const target = positionals[1];
    if (!target) usageError(`Missing skill path to verify. Usage: skillguard verify <path/to/SKILL.md>`);
    cmdVerify(target, buildConfig(options));
    return;
  }

  if (command === 'audit') {
    cmdAudit(options, buildConfig(options), resolveFormat(options));
    return;
  }

  if (command === 'rules') {
    cmdRules(buildConfig(options), resolveFormat(options));
    return;
  }

  if (command === 'list') {
    cmdList(readLockfile(), resolveFormat(options));
    return;
  }

  if (command === 'uninstall') {
    const name = positionals[1];
    if (!name) usageError(`Missing skill name to uninstall. Usage: skillguard uninstall <name>`);
    cmdUninstall(name, resolveFormat(options));
    return;
  }

  if (command === 'baseline') {
    const targets = positionals.slice(1);
    cmdBaseline(targets.length > 0 ? targets : ['.'], options, resolveFormat(options));
    return;
  }

  if (command === 'version') {
    console.log(`skillguard v${VERSION}`);
    return;
  }

  usageError(`Unknown command: "${command}"`);
}

try {
  main();
} catch (err) {
  console.error(chalk.red(`Fatal: ${err instanceof Error ? err.message : String(err)}`));
  process.exit(EXIT_FAIL);
}
