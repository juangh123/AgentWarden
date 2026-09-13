#!/usr/bin/env node
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { chalk, setColorEnabled } from './reporter/chalk.ts';
import { scanSkillContent, scanSkillFile } from './scanner/index.ts';
import {
  discoverSkillFiles,
  filterSkillFiles,
} from './scanner/discovery.ts';
import { ChangedFilesError, getChangedFiles } from './git/changed.ts';
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
import type { Finding, ScanResult, Severity } from './rules/types.ts';
import {
  DEFAULT_BASELINE_NAME,
  createBaseline,
  inspectBaseline,
  pruneBaseline,
  readBaseline,
  updateBaseline,
  writeBaseline,
} from './baseline/index.ts';
import { allRules } from './rules/index.ts';
import { diffPolicyConfigs } from './policy/diff.ts';
import { RemoteSkillError, fetchRemoteSkill } from './source/remote.ts';
import {
  SkillPackageError,
  extractSkillPackage,
  inspectInstalledSkillPackage,
  isSkillPackageSource,
  readSkillPackageBytes,
  writeSkillPackage,
  type SkillPackage,
} from './source/package.ts';
import { calculateScore } from './scanner/scoring.ts';
import {
  SignatureError,
  verifyPayloadSignature,
  type SignatureVerificationResult,
} from './source/signature.ts';
import {
  evaluatePublisherPolicy,
  type PublisherPolicyDecision,
  type PublisherProvenance,
} from './source/provenance.ts';
import { buildCycloneDxSbom } from './sbom/index.ts';

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
  'expiring-within',
  'changed-from',
  'sha256',
  'signature',
  'public-key',
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
  'fail-on-expiring',
  'fail-on-unmatched',
  'dry-run',
  'changed',
  'allow-http',
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
  ${chalk.green('install <file|archive|https://url>')} Pre-scan, then securely record fingerprint to skills.lock
  ${chalk.green('verify <file>')}        Verify a single skill file against skills.lock fingerprint
  ${chalk.green('audit')}                Audit all installed skills in skills.lock against local tampering
  ${chalk.green('sbom')}                 Generate a CycloneDX 1.5 SBOM from skills.lock
  ${chalk.green('rules')}                List active security rules and effective severity
  ${chalk.green('policy [diff <from> <to>]')} Show effective policy or compare two policies
  ${chalk.green('list')}                 List skills recorded in skills.lock
  ${chalk.green('uninstall <name>')}     Remove a skill entry from skills.lock
  ${chalk.green('baseline [create|status|prune|update] [path...]')} Manage accepted findings
  ${chalk.green('help')}                 Show this help manual

${chalk.bold('OPTIONS:')}
  ${chalk.yellow('-f, --force')}            Bypass install warning or apply baseline write changes
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
  ${chalk.yellow('--changed')}              Scan only files changed from the detected Git base
  ${chalk.yellow('--changed-from <ref>')}   Scan only files changed since a Git ref
  ${chalk.yellow('--fail-on-diff')}         Exit 1 when policy diff detects changes
  ${chalk.yellow('--baseline <file>')}      Suppress exact findings recorded in a baseline
  ${chalk.yellow('--output <file>')}        Baseline, package, or SBOM output path
  ${chalk.yellow('--sha256 <digest>')}      Required SHA-256 pin for remote installs
  ${chalk.yellow('--signature <ref>')}      Detached Ed25519 signature file, URL, base64:, or hex:
  ${chalk.yellow('--public-key <ref>')}     Trusted Ed25519 public key file or inline pem:/base64:
  ${chalk.yellow('--allow-http')}           Allow HTTP remote installs (trusted local testing only)
  ${chalk.yellow('--owner <name>')}         Baseline review owner or team
  ${chalk.yellow('--expires-in <days>')}    Expire a new baseline after 1-3650 days
  ${chalk.yellow('--expires-at <date>')}    Explicit baseline expiry date
  ${chalk.yellow('--note <text>')}          Baseline review note
  ${chalk.yellow('--expiring-within <days>')} Warn when a baseline expires within N days (default: 30)
  ${chalk.yellow('--fail-on-expiring')}      Exit 1 when a baseline is nearing expiry
  ${chalk.yellow('--fail-on-unmatched')}     Exit 1 when baseline entries no longer match
  ${chalk.yellow('--dry-run')}               Preview baseline prune/update without writing
  ${chalk.yellow('-C, --cwd <dir>')}        Run as if started from <dir>
  ${chalk.yellow('--no-color')}             Disable ANSI colors (also honors NO_COLOR env)
  ${chalk.yellow('--no-redact')}            Include raw snippets and file content in reports
  ${chalk.yellow('-v, --version')}          Show version

${chalk.bold('EXIT CODES:')}
  0 = clean  1 = security failure  2 = usage / file error
`);
}

function canonicalCliPath(filePath: string): string {
  const resolved = path.resolve(filePath);
  try {
    return fs.realpathSync.native(resolved);
  } catch {
    return resolved;
  }
}

function isPathWithinTarget(filePath: string, targetPath: string): boolean {
  const target = canonicalCliPath(targetPath);
  const file = canonicalCliPath(filePath);
  const targetStat = fs.statSync(target);
  if (targetStat.isFile()) return file === target;
  const relative = path.relative(target, file);
  return relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative));
}

function changedScanRequested(options: ParsedArgs['options']): boolean {
  return Boolean(options.changed) || options['changed-from'] !== undefined;
}

function scanTargets(
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
    console.error(chalk.yellow(`No skill or MCP configuration files found in: ${targets.join(', ')}`));
    process.exit(EXIT_FAIL);
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

  if (scanResults.some((r) => !r.passed)) process.exit(EXIT_FAIL);
}

interface InstallSignatureOptions {
  signature: string;
  publicKey: string;
}

function installSignatureOptions(options: ParsedArgs['options']): InstallSignatureOptions | undefined {
  const signature =
    options.signature !== undefined ? String(options.signature).trim() : undefined;
  const publicKey =
    options['public-key'] !== undefined ? String(options['public-key']).trim() : undefined;

  if (!signature && !publicKey) return undefined;
  if (!signature || !publicKey) {
    usageError('--signature and --public-key must be provided together');
  }
  return { signature, publicKey };
}

async function verifyInstallSignature(
  payload: Uint8Array,
  signatureOptions: InstallSignatureOptions | undefined,
  allowHttp: boolean,
): Promise<SignatureVerificationResult | undefined> {
  if (!signatureOptions) return undefined;
  try {
    return await verifyPayloadSignature(payload, {
      signature: signatureOptions.signature,
      publicKey: signatureOptions.publicKey,
      allowHttp,
    });
  } catch (error) {
    if (
      error instanceof SignatureError &&
      (error.code === 'INVALID_PUBLIC_KEY' ||
        error.code === 'UNSUPPORTED_ALGORITHM' ||
        error.code === 'INVALID_SIGNATURE')
    ) {
      usageError(error.message);
    }
    throw error;
  }
}

function signatureReport(signature: SignatureVerificationResult | undefined) {
  return signature
    ? {
        algorithm: signature.algorithm,
        verified: true,
        keySha256: signature.publicKeySha256,
        signatureSha256: signature.signatureSha256,
        publicKeySource: signature.publicKeySource,
        signatureSource: signature.signatureSource,
      }
    : undefined;
}

function signatureLockMetadata(signature: SignatureVerificationResult | undefined) {
  return signature
    ? {
        signatureAlgorithm: signature.algorithm,
        signatureVerified: true,
        signatureKeySha256: signature.publicKeySha256,
        signatureSha256: signature.signatureSha256,
      }
    : {};
}

function signatureProvenance(
  signature: SignatureVerificationResult | undefined,
): PublisherProvenance | undefined {
  return signature
    ? {
        signatureVerified: true,
        signatureKeySha256: signature.publicKeySha256,
      }
    : undefined;
}

function failPublisherPolicy(
  decision: PublisherPolicyDecision,
  format: ReportFormat,
  operation: string,
): never {
  const message = decision.message ?? 'Publisher policy rejected the operation';
  if (format === 'json') {
    console.log(
      JSON.stringify(
        {
          passed: false,
          error: {
            code: decision.code ?? 'PUBLISHER_POLICY_FAILED',
            message,
          },
        },
        null,
        2,
      ),
    );
  } else {
    console.error(chalk.red.bold(`❌ Publisher policy blocked ${operation}: ${message}`));
  }
  process.exit(EXIT_FAIL);
}

function enforcePublisherPolicy(
  config: SkillGuardConfig,
  provenance: PublisherProvenance | undefined,
  format: ReportFormat,
  operation: string,
): void {
  const decision = evaluatePublisherPolicy(config.publishers, provenance);
  if (!decision.passed) failPublisherPolicy(decision, format, operation);
}

function writeFileAtomic(filePath: string, content: string): void {
  const directory = path.dirname(filePath);
  fs.mkdirSync(directory, { recursive: true });
  const temporaryPath = path.join(
    directory,
    `.${path.basename(filePath)}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`,
  );

  fs.writeFileSync(temporaryPath, content, { encoding: 'utf8', flag: 'wx' });
  try {
    try {
      fs.renameSync(temporaryPath, filePath);
    } catch (error) {
      const code =
        error && typeof error === 'object' && 'code' in error
          ? String((error as NodeJS.ErrnoException).code)
          : '';
      if (
        process.platform === 'win32' &&
        (code === 'EEXIST' || code === 'EPERM' || code === 'EACCES')
      ) {
        fs.rmSync(filePath, { force: true });
        fs.renameSync(temporaryPath, filePath);
      } else {
        throw error;
      }
    }
  } finally {
    fs.rmSync(temporaryPath, { force: true });
  }
}

function resolveRemoteInstallPath(filename: string, output: unknown): string {
  const requestedOutput =
    output !== undefined ? String(output).trim() : path.join('.agentwarden', 'skills', filename);
  if (!requestedOutput) usageError('Remote install output path must not be empty');

  const destination = path.resolve(process.cwd(), requestedOutput);
  if (fs.existsSync(destination) && fs.statSync(destination).isDirectory()) {
    usageError(`Remote install output path is a directory: ${destination}`);
  }
  return destination;
}

interface ScannedSkillPackage {
  result: ScanResult;
  scannedFiles: string[];
}

function decodePackageText(file: { path: string; data: Buffer }): string {
  if (file.data.includes(0)) {
    throw new SkillPackageError(
      'UNSUPPORTED_ENTRY',
      `Skill package file "${file.path}" contains binary NUL bytes`,
    );
  }

  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(file.data).replace(/^\uFEFF/, '');
  } catch {
    throw new SkillPackageError(
      'UNSUPPORTED_ENTRY',
      `Skill package file "${file.path}" is not valid UTF-8 text`,
    );
  }
}

function scanSkillPackage(skillPackage: SkillPackage, config: SkillGuardConfig): ScannedSkillPackage {
  const results = skillPackage.files.map((file) => {
    const content = decodePackageText(file);
    return scanSkillContent(content, file.path, config);
  });
  const entryIndex = skillPackage.files.findIndex(
    (file) => file.path.toLowerCase() === skillPackage.entryPath.toLowerCase(),
  );
  if (entryIndex === -1) {
    throw new SkillPackageError('MISSING_ENTRY', 'Skill package entry file is missing');
  }

  const findings: Finding[] = results.flatMap((result) =>
    result.findings.map((finding) => ({
      ...finding,
      filePath: finding.filePath ?? result.filePath,
    })),
  );
  const suppressedFindings: Finding[] = results.flatMap((result) =>
    (result.suppressedFindings ?? []).map((finding) => ({
      ...finding,
      filePath: finding.filePath ?? result.filePath,
    })),
  );
  const entryResult = results[entryIndex];

  return {
    result: {
      ...entryResult,
      findings,
      ...(suppressedFindings.length > 0 ? { suppressedFindings } : {}),
      score: calculateScore(findings),
      passed: results.every((result) => result.passed),
    },
    scannedFiles: skillPackage.files.map((file) => file.path),
  };
}

function packageSlug(
  skillPackage: SkillPackage,
  result: ScanResult,
  archiveFilename: string,
): string {
  const entryName = path.posix.basename(skillPackage.entryPath);
  const parsedName = result.parsedSkill.name?.trim();
  const fallback = path
    .basename(archiveFilename)
    .replace(/\.(?:tar\.gz|tgz)$/i, '')
    .trim();
  const candidate =
    parsedName && parsedName !== skillPackage.entryPath && parsedName !== entryName
      ? parsedName
      : fallback || 'skill-package';
  const slug = candidate
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, '-')
    .replace(/^[.-]+|[.-]+$/g, '')
    .slice(0, 80);
  return slug || 'skill-package';
}

interface PackageInstallSource {
  type: 'local' | 'remote';
  requestedUrl?: string;
  resolvedUrl?: string;
  downloadSha256?: string;
  digestVerified?: boolean;
  signature?: SignatureVerificationResult;
}

function installSkillPackage(
  skillPackage: SkillPackage,
  archiveFilename: string,
  source: PackageInstallSource,
  options: ParsedArgs['options'],
  format: ReportFormat,
  config: SkillGuardConfig,
  force: boolean,
): void {
  const scanned = scanSkillPackage(skillPackage, config);
  const slug = packageSlug(skillPackage, scanned.result, archiveFilename);
  const parsedName = scanned.result.parsedSkill.name?.trim();
  const entryName = path.posix.basename(skillPackage.entryPath);
  if (!parsedName || parsedName === skillPackage.entryPath || parsedName === entryName) {
    scanned.result.parsedSkill = { ...scanned.result.parsedSkill, name: slug };
  }
  const destination =
    options.output !== undefined
      ? path.resolve(process.cwd(), String(options.output))
      : path.resolve(process.cwd(), '.agentwarden', 'skills', slug);

  if (fs.existsSync(destination) && !fs.statSync(destination).isDirectory()) {
    usageError(`Skill package destination is not a directory: ${destination}`);
  }

  const relativeDirectory = toRelativePosix(destination);
  const sourcePath = toRelativePosix(
    path.join(destination, ...skillPackage.entryPath.split('/')),
  );
  const installAborted = !scanned.result.passed && !force;
  const { signature: verifiedSignature, ...sourceFields } = source;
  const sourceDetails = {
    ...sourceFields,
    path: sourcePath,
    packagePath: relativeDirectory,
    packageFormat: 'tar.gz',
    packageSha256: skillPackage.sha256,
    packageEntry: skillPackage.entryPath,
    packageFiles: skillPackage.manifest.length,
    scannedFiles: scanned.scannedFiles.length,
    ...(verifiedSignature ? { signature: signatureReport(verifiedSignature) } : {}),
  };

  if (format === 'json') {
    console.log(
      JSON.stringify(
        {
          ...toReportScanResult(scanned.result, reportOptions(options)),
          source: sourceDetails,
          installAborted,
        },
        null,
        2,
      ),
    );
  } else {
    renderScanReport(scanned.result, format, reportOptions(options));
  }

  if (installAborted) {
    if (format === 'pretty') {
      console.log(chalk.red('🚫 Aborted installation due to security risk. Use --force to override.\n'));
    }
    process.exit(EXIT_FAIL);
  }

  const lock = readLockfile();
  const previous = lock.skills[scanned.result.parsedSkill.name];
  if (previous && format === 'pretty') {
    console.log(chalk.gray(`ℹ️  Updating existing lock entry for "${scanned.result.parsedSkill.name}" (was: ${previous.source}).`));
  }

  writeSkillPackage(skillPackage, destination);
  updateLockfileSkill({
    name: scanned.result.parsedSkill.name,
    version: scanned.result.parsedSkill.version || '0.1.0',
    source: sourcePath,
    sha256: scanned.result.sha256,
    installedAt: new Date().toISOString(),
    verifiedScore: scanned.result.score,
    sourceType: source.type,
    ...(source.requestedUrl ? { remoteUrl: source.requestedUrl } : {}),
    ...(source.resolvedUrl ? { resolvedUrl: source.resolvedUrl } : {}),
    ...(source.downloadSha256 ? { downloadSha256: source.downloadSha256 } : {}),
    ...(source.digestVerified !== undefined
      ? { digestVerified: source.digestVerified }
      : {}),
    packageFormat: 'tar.gz',
    packageSha256: skillPackage.sha256,
    packageEntry: skillPackage.entryPath,
    packageFiles: skillPackage.manifest,
    ...signatureLockMetadata(source.signature),
  });

  if (format === 'pretty') {
    console.log(
      chalk.green(
        `🔒 Successfully verified and locked skill package to skills.lock (${skillPackage.manifest.length} files, package: ${skillPackage.sha256.slice(0, 16)}${source.signature ? `, signer: ${source.signature.publicKeySha256.slice(0, 16)}` : ''}...).\n`,
      ),
    );
  }
}

async function cmdInstallLocal(
  target: string,
  options: ParsedArgs['options'],
  format: ReportFormat,
): Promise<void> {
  const force = Boolean(options.force);
  const fullPath = resolvePath(target);
  const config = buildConfig(options);
  const signatureOptions = installSignatureOptions(options);

  if (format === 'pretty') {
    console.log(chalk.cyan(`\n🔍 Analyzing skill package: ${target}...`));
  }
  const bytes = fs.readFileSync(fullPath);
  const signature = await verifyInstallSignature(bytes, signatureOptions, false);
  enforcePublisherPolicy(config, signatureProvenance(signature), format, `local install "${target}"`);
  const result = scanSkillContent(bytes.toString('utf8'), fullPath, config);
  if (format === 'json') {
    console.log(
      JSON.stringify(
        {
          ...toReportScanResult(result, reportOptions(options)),
          ...(signature ? { signature: signatureReport(signature) } : {}),
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
    sourceType: 'local',
    ...signatureLockMetadata(signature),
  });

  if (format === 'pretty') {
    const signer = signature
      ? `, signer: ${signature.publicKeySha256.slice(0, 16)}`
      : '';
    console.log(chalk.green(`🔒 Successfully verified and locked signature to skills.lock (source: ${relativePosix}${signer})!\n`));
  }
}

async function cmdInstallRemote(
  target: string,
  options: ParsedArgs['options'],
  format: ReportFormat,
): Promise<void> {
  const force = Boolean(options.force);
  const signatureOptions = installSignatureOptions(options);
  const expectedSha256 = options.sha256 !== undefined ? String(options.sha256) : undefined;
  if (!expectedSha256) {
    usageError('Remote installs require --sha256 <digest> to pin the downloaded content');
  }

  const config = buildConfig(options);
  if (!signatureOptions) {
    enforcePublisherPolicy(config, undefined, format, `remote install "${target}"`);
  }
  if (format === 'pretty') {
    console.log(chalk.cyan(`\n⬇️  Downloading remote skill: ${target}...`));
  }

  let download: Awaited<ReturnType<typeof fetchRemoteSkill>>;
  try {
    download = await fetchRemoteSkill({
      url: target,
      expectedSha256,
      allowHttp: Boolean(options['allow-http']),
    });
  } catch (error) {
    if (
      error instanceof RemoteSkillError &&
      (error.code === 'INVALID_URL' ||
        error.code === 'INVALID_DIGEST' ||
        error.code === 'INSECURE_URL')
    ) {
      usageError(error.message);
    }
    throw error;
  }
  const signature = await verifyInstallSignature(
    download.bytes,
    signatureOptions,
    Boolean(options['allow-http']),
  );
  enforcePublisherPolicy(
    config,
    signatureProvenance(signature),
    format,
    `remote install "${target}"`,
  );

  if (isSkillPackageSource(download.filename, download.contentType)) {
    const skillPackage = extractSkillPackage(download.bytes);
    installSkillPackage(
      skillPackage,
      download.filename,
      {
        type: 'remote',
        requestedUrl: download.requestedUrl,
        resolvedUrl: download.resolvedUrl,
        downloadSha256: download.sha256,
        digestVerified: download.digestVerified,
        ...(signature ? { signature } : {}),
      },
      options,
      format,
      config,
      force,
    );
    return;
  }

  const destination = resolveRemoteInstallPath(download.filename, options.output);
  const relativePosix = toRelativePosix(destination);
  const result = scanSkillContent(download.content, download.filename, config);
  const installAborted = !result.passed && !force;
  const sourceDetails = {
    type: 'remote',
    path: relativePosix,
    requestedUrl: download.requestedUrl,
    resolvedUrl: download.resolvedUrl,
    downloadSha256: download.sha256,
    digestVerified: download.digestVerified,
    size: download.size,
    ...(signature ? { signature: signatureReport(signature) } : {}),
  };

  if (format === 'json') {
    console.log(
      JSON.stringify(
        {
          ...toReportScanResult(result, reportOptions(options)),
          source: sourceDetails,
          installAborted,
        },
        null,
        2,
      ),
    );
  } else {
    renderScanReport(result, format, reportOptions(options));
  }

  if (installAborted) {
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

  writeFileAtomic(destination, download.content);
  updateLockfileSkill({
    name: result.parsedSkill.name,
    version: result.parsedSkill.version || '0.1.0',
    source: relativePosix,
    sha256: result.sha256,
    installedAt: new Date().toISOString(),
    verifiedScore: result.score,
    sourceType: 'remote',
    remoteUrl: download.requestedUrl,
    resolvedUrl: download.resolvedUrl,
    downloadSha256: download.sha256,
    digestVerified: download.digestVerified,
    ...signatureLockMetadata(signature),
  });

  if (format === 'pretty') {
    console.log(
      chalk.green(
        `🔒 Successfully verified and locked remote signature to skills.lock (source: ${relativePosix}, URL: ${download.resolvedUrl}${signature ? `, signer: ${signature.publicKeySha256.slice(0, 16)}` : ''})!\n`,
      ),
    );
  }
}

async function cmdInstallLocalPackage(
  target: string,
  options: ParsedArgs['options'],
  format: ReportFormat,
): Promise<void> {
  const fullPath = resolvePath(target);
  const config = buildConfig(options);
  const signatureOptions = installSignatureOptions(options);
  if (format === 'pretty') {
    console.log(chalk.cyan(`\n📦 Analyzing local skill package: ${target}...`));
  }
  const bytes = readSkillPackageBytes(fullPath);
  const signature = await verifyInstallSignature(bytes, signatureOptions, false);
  enforcePublisherPolicy(
    config,
    signatureProvenance(signature),
    format,
    `local package install "${target}"`,
  );
  const skillPackage = extractSkillPackage(bytes);
  installSkillPackage(
    skillPackage,
    path.basename(fullPath),
    { type: 'local', ...(signature ? { signature } : {}) },
    options,
    format,
    config,
    Boolean(options.force),
  );
}

async function cmdInstall(
  target: string,
  options: ParsedArgs['options'],
  format: ReportFormat,
): Promise<void> {
  installSignatureOptions(options);
  if (/^https?:\/\//i.test(target)) {
    await cmdInstallRemote(target, options, format);
    return;
  }

  if (options.sha256 !== undefined) {
    usageError('--sha256 is only valid when installing a remote HTTPS or HTTP source');
  }
  if (options['allow-http']) {
    usageError('--allow-http is only valid when installing a remote HTTP source');
  }
  if (isSkillPackageSource(target)) {
    await cmdInstallLocalPackage(target, options, format);
    return;
  }
  if (options.output !== undefined) {
    usageError('--output is only valid for baseline writes or remote installs');
  }
  await cmdInstallLocal(target, options, format);
}

function cmdVerify(target: string, config: SkillGuardConfig): void {
  const fullPath = resolvePath(target);
  const lock = readLockfile();
  const packageKey = Object.keys(lock.skills).find((candidate) => {
    const item = lock.skills[candidate];
    if (!item.packageFormat) return false;
    const packageRoot = path.dirname(resolveFromRoot(item.source));
    const relative = path.relative(packageRoot, fullPath);
    return relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative));
  });

  if (packageKey) {
    const lockedEntry = lock.skills[packageKey];
    if (
      !lockedEntry.packageSha256 ||
      !lockedEntry.packageEntry ||
      !lockedEntry.packageFiles
    ) {
      console.error(chalk.red(`❌ Invalid package metadata for skill "${packageKey}".`));
      process.exit(EXIT_FAIL);
    }
    enforcePublisherPolicy(
      config,
      {
        signatureVerified: lockedEntry.signatureVerified,
        signatureKeySha256: lockedEntry.signatureKeySha256,
      },
      'pretty',
      `package verification "${packageKey}"`,
    );

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
  enforcePublisherPolicy(
    config,
    {
      signatureVerified: lockedEntry.signatureVerified,
      signatureKeySha256: lockedEntry.signatureKeySha256,
    },
    'pretty',
    `skill verification "${key}"`,
  );

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
    const publisherDecision = evaluatePublisherPolicy(config.publishers, {
      signatureVerified: item.signatureVerified,
      signatureKeySha256: item.signatureKeySha256,
    });

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
      signerKeySha256: publisherDecision.keySha256 ?? item.signatureKeySha256 ?? null,
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

function resolveSbomFormat(options: ParsedArgs['options']): 'pretty' | 'json' {
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

function cmdSbom(options: ParsedArgs['options']): void {
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

  if (!result.passed) process.exit(EXIT_FAIL);
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

function formatPolicyDiffValue(value: string | number | boolean | null | undefined): string {
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

function resolveExpiringWithin(options: ParsedArgs['options']): number {
  if (options['expiring-within'] === undefined) return 30;
  const days = Number(options['expiring-within']);
  if (!Number.isFinite(days) || days < 1 || days > 3650) {
    usageError(
      `Invalid --expiring-within "${String(options['expiring-within'])}" (expected 1-3650 days)`,
    );
  }
  return Math.ceil(days);
}

function cmdBaselineStatus(
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
    console.error(chalk.yellow(`No skill or MCP configuration files found in: ${targets.join(', ')}`));
    process.exit(EXIT_FAIL);
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
    process.exit(EXIT_FAIL);
  }
}

function cmdBaselineMaintenance(
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
    console.error(chalk.yellow(`No skill or MCP configuration files found in: ${targets.join(', ')}`));
    process.exit(EXIT_FAIL);
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

async function main(): Promise<void> {
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
    console.error(`Run ${chalk.yellow('"agentwarden help"')} for usage.`);
    process.exit(EXIT_USAGE);
  }

  if (options.version) {
    console.log(`agentwarden v${VERSION}`);
    return;
  }

  const command = positionals[0];
  if (!command || command === 'help' || command === '--help' || command === '-h' || options.help) {
    printHelp();
    return;
  }

  if (command === 'scan') {
    const targets = positionals.slice(1);
    if (targets.length === 0) usageError(`Missing file or directory path to scan. Usage: agentwarden scan <path> [--format pretty|json|sarif]`);
    scanTargets(targets, buildConfig(options), resolveFormat(options), options);
    return;
  }

  if (command === 'install') {
    const target = positionals[1];
    if (!target) usageError(`Missing skill path to install. Usage: agentwarden install <path/to/SKILL.md|https://url> --sha256 <digest>`);
    await cmdInstall(target, options, resolveFormat(options));
    return;
  }

  if (command === 'verify') {
    const target = positionals[1];
    if (!target) usageError(`Missing skill path to verify. Usage: agentwarden verify <path/to/SKILL.md>`);
    cmdVerify(target, buildConfig(options));
    return;
  }

  if (command === 'audit') {
    cmdAudit(options, buildConfig(options), resolveFormat(options));
    return;
  }

  if (command === 'sbom') {
    if (positionals.length > 1) {
      usageError('sbom does not accept positional paths');
    }
    cmdSbom(options);
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
        usageError('Missing policy comparison inputs. Usage: agentwarden policy diff <from> <to>');
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
    if (!name) usageError(`Missing skill name to uninstall. Usage: agentwarden uninstall <name>`);
    cmdUninstall(name, resolveFormat(options));
    return;
  }

  if (command === 'baseline') {
    const subcommand = positionals[1];
    if (subcommand === 'status') {
      const targets = positionals.length > 2 ? positionals.slice(2) : ['.'];
      cmdBaselineStatus(targets, options, resolveFormat(options));
      return;
    }
    if (subcommand === 'prune' || subcommand === 'update') {
      const targets = positionals.length > 2 ? positionals.slice(2) : ['.'];
      cmdBaselineMaintenance(subcommand, targets, options, resolveFormat(options));
      return;
    }
    const targets = subcommand === 'create' ? positionals.slice(2) : positionals.slice(1);
    cmdBaseline(targets.length > 0 ? targets : ['.'], options, resolveFormat(options));
    return;
  }

  if (command === 'version') {
    console.log(`agentwarden v${VERSION}`);
    return;
  }

  usageError(`Unknown command: "${command}"`);
}

try {
  await main();
} catch (err) {
  console.error(chalk.red(`Fatal: ${err instanceof Error ? err.message : String(err)}`));
  process.exit(EXIT_FAIL);
}
