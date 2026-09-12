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
import {
  ConfigError,
  loadConfigWithMetadata,
  normalizeConfig,
  POLICY_PROFILES,
  type PolicyProfileName,
  type SkillGuardConfig,
} from './config/index.ts';
import { readPackageVersion } from './version.ts';
import type { ScanResult, Severity } from './rules/types.ts';
import { DEFAULT_BASELINE_NAME, createBaseline, writeBaseline } from './baseline/index.ts';
import { allRules } from './rules/index.ts';
import { diffPolicyConfigs } from './policy/diff.ts';

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
  'profile',
  'config',
  'cwd',
  'ignore-rule',
  'severity-override',
  'include',
  'exclude',
  'baseline',
  'output',
  'owner',
  'note',
  'expires-in',
  'expires-at',
]);
const BOOLEAN_OPTIONS = new Set([
  'force',
  'help',
  'version',
  'json',
  'sarif',
  'no-color',
  'no-redact',
  'fail-on-diff',
]);
const SHORT_FLAGS: Record<string, string> = { f: 'force', h: 'help', v: 'version', C: 'cwd' };
const REPEATABLE_OPTIONS: Record<string, string> = {
  'ignore-rule': 'ignoreRule',
  'severity-override': 'severityOverride',
  include: 'include',
  exclude: 'exclude',
};

interface ParsedArgs {
  positionals: string[];
  options: Record<string, string | string[] | boolean>;
  errors: string[];
}

interface BuiltConfig {
  config: SkillGuardConfig;
  source?: string;
  sources: string[];
  explicit: boolean;
}

interface PolicySide {
  label: string;
  details: BuiltConfig;
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
        const repeatableKey = REPEATABLE_OPTIONS[key];
        if (repeatableKey) {
          const optionKey = repeatableKey;
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

function buildConfigDetails(options: ParsedArgs['options'], ignoreBaseline = false): BuiltConfig {
  const configPath = options.config !== undefined ? String(options.config) : undefined;
  let loaded: ReturnType<typeof loadConfigWithMetadata>;
  try {
    loaded = loadConfigWithMetadata(process.cwd(), configPath);
  } catch (error) {
    if (error instanceof ConfigError) usageError(error.message);
    throw error;
  }

  const base = loaded.config;
  const override: Partial<SkillGuardConfig> = {};

  if (options.profile !== undefined) {
    const value = String(options.profile).trim().toLowerCase() as PolicyProfileName;
    if (!Object.hasOwn(POLICY_PROFILES, value)) {
      usageError(`Invalid --profile "${String(options.profile)}" (expected legacy|balanced|strict)`);
    }
    override.profile = value;
    override.failOn = POLICY_PROFILES[value].failOn;
    override.minScore = POLICY_PROFILES[value].minScore;
  }
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
  const extraIncludes = (options.include as string[] | undefined) ?? [];
  const extraExcludes = (options.exclude as string[] | undefined) ?? [];
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
    include: [...(base.include ?? []), ...extraIncludes],
    exclude: [...(base.exclude ?? []), ...extraExcludes],
  };
  if (ignoreBaseline) delete merged.baseline;

  return {
    config: normalizeConfig(merged),
    source: loaded.source,
    sources: loaded.sources,
    explicit: loaded.explicit,
  };
}

function buildConfig(options: ParsedArgs['options'], ignoreBaseline = false): SkillGuardConfig {
  return buildConfigDetails(options, ignoreBaseline).config;
}

function resolvePolicySide(input: string, options: ParsedArgs['options']): PolicySide {
  const normalizedInput = input.trim();
  const profile = normalizedInput.toLowerCase() as PolicyProfileName;
  if (Object.hasOwn(POLICY_PROFILES, profile)) {
    return {
      label: profile,
      details: {
        config: normalizeConfig({ profile }),
        sources: [],
        explicit: false,
      },
    };
  }

  if (normalizedInput.toLowerCase() === 'current') {
    return {
      label: 'current',
      details: buildConfigDetails(options),
    };
  }

  let loaded: ReturnType<typeof loadConfigWithMetadata>;
  try {
    loaded = loadConfigWithMetadata(process.cwd(), normalizedInput);
  } catch (error) {
    if (error instanceof ConfigError) usageError(error.message);
    throw error;
  }

  return {
    label: normalizedInput,
    details: {
      config: loaded.config,
      source: loaded.source,
      sources: loaded.sources,
      explicit: loaded.explicit,
    },
  };
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
  ${chalk.green('policy [diff <from> <to>]')} Show effective policy or compare two policies
  ${chalk.green('list')}                 List skills recorded in skills.lock
  ${chalk.green('uninstall <name>')}     Remove a skill entry from skills.lock
  ${chalk.green('baseline [path...]')}   Create an explicit baseline of accepted findings
  ${chalk.green('help')}                 Show this help manual

${chalk.bold('OPTIONS:')}
  ${chalk.yellow('-f, --force')}            Bypass install warning or overwrite an existing baseline
  ${chalk.yellow('--format <type>')}        Report format: pretty (default), json, sarif
  ${chalk.yellow('--json')}                 Shorthand for --format json
  ${chalk.yellow('--sarif')}                Shorthand for --format sarif
  ${chalk.yellow('--profile <name>')}       Policy preset: legacy|balanced|strict (default: legacy)
  ${chalk.yellow('--config <file>')}        Load an explicit JSON configuration file
  ${chalk.yellow('--fail-on <sev>')}        Fail threshold: critical|high|medium|low|info (default: high)
  ${chalk.yellow('--min-score <n>')}        Minimum safety score 0-100 (default: 60)
  ${chalk.yellow('--ignore-rule <id>')}     Skip a rule id (repeatable)
  ${chalk.yellow('--severity-override <rule=sev>')} Override a rule severity (repeatable)
  ${chalk.yellow('--include <glob>')}       Limit directory scans to matching paths (repeatable)
  ${chalk.yellow('--exclude <glob>')}       Exclude matching paths from directory scans (repeatable)
  ${chalk.yellow('--fail-on-diff')}         Exit 1 when policy diff detects changes
  ${chalk.yellow('--baseline <file>')}      Suppress exact findings recorded in a baseline
  ${chalk.yellow('--output <file>')}        Baseline output path (default: ${DEFAULT_BASELINE_NAME})
  ${chalk.yellow('--owner <name>')}         Baseline review owner or team
  ${chalk.yellow('--expires-in <days>')}    Expire a new baseline after 1-3650 days
  ${chalk.yellow('--expires-at <date>')}    Explicit baseline expiry date
  ${chalk.yellow('--note <text>')}          Baseline review note
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
  const files = discoverSkillFiles(targets.map(resolvePath), process.cwd(), {
    include: config.include,
    exclude: config.exclude,
  });

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

function policySnapshot(details: BuiltConfig) {
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
    severityOverrides: config.severityOverrides ?? {},
    include: config.include ?? [],
    exclude: config.exclude ?? [],
  };
}

function cmdPolicy(details: BuiltConfig, format: ReportFormat): void {
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

function formatPolicyDiffValue(value: string | number | null | undefined): string {
  if (value === undefined || value === null) return '(none)';
  return String(value);
}

function cmdPolicyDiff(
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
    process.exit(EXIT_FAIL);
  }
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

function resolveBaselineExpiry(options: ParsedArgs['options']): string | undefined {
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

function cmdBaseline(targets: string[], options: ParsedArgs['options'], format: ReportFormat): void {
  const config = buildConfig(options, true);
  const files = discoverSkillFiles(targets.map(resolvePath), process.cwd(), {
    include: config.include,
    exclude: config.exclude,
  });
  if (files.length === 0) {
    console.error(chalk.yellow(`No skill or MCP configuration files found in: ${targets.join(', ')}`));
    process.exit(EXIT_FAIL);
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

  if (command === 'policy') {
    const subcommand = positionals[1];
    if (subcommand === 'diff') {
      const from = positionals[2];
      const to = positionals[3];
      if (!from || !to) {
        usageError('Missing policy comparison inputs. Usage: skillguard policy diff <from> <to>');
      }
      if (positionals.length > 4) {
        usageError('policy diff accepts exactly two comparison inputs');
      }
      cmdPolicyDiff(from, to, options, resolveFormat(options));
      return;
    }
    if (subcommand !== undefined) {
      usageError(`Unknown policy subcommand: "${subcommand}"`);
    }
    cmdPolicy(buildConfigDetails(options), resolveFormat(options));
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
