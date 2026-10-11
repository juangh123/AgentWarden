import { chalk } from '../reporter/chalk.ts';
import { type ReportFormat, type ReportOptions } from '../reporter/index.ts';
import { readPackageVersion } from '../version.ts';
import type { Severity } from '../rules/types.ts';

export const VERSION = readPackageVersion();

// 0 is the implicit success code; failures set process.exitCode explicitly.
export const EXIT_FAIL = 1;
export const EXIT_USAGE = 2;

export const VALID_FORMATS = new Set(['pretty', 'json', 'sarif']);
export const VALID_FAIL_ON: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

export const VALUE_OPTIONS = new Set([
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
  'workflow-path',
  'action-ref',
]);
export const BOOLEAN_OPTIONS = new Set([
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
  'no-workflow',
  'replace-directory',
]);

/**
 * Options that only make sense for specific commands.
 *
 * Anything not listed here is accepted everywhere. Listing an option here means
 * a misplaced flag fails with exit code 2 instead of being silently ignored,
 * which previously let CI believe a gate was active when it was not.
 */
export const COMMAND_SCOPED_OPTIONS: ReadonlyArray<{
  option: string;
  commands: ReadonlySet<string>;
}> = [
  { option: 'fail-on-diff', commands: new Set(['policy']) },
  { option: 'output', commands: new Set(['install', 'sbom', 'baseline']) },
  { option: 'sha256', commands: new Set(['install']) },
  { option: 'signature', commands: new Set(['install']) },
  { option: 'public-key', commands: new Set(['install']) },
  { option: 'allow-http', commands: new Set(['install']) },
  { option: 'changed', commands: new Set(['scan']) },
  { option: 'changed-from', commands: new Set(['scan']) },
  { option: 'sarif', commands: new Set(['scan', 'install']) },
  { option: 'no-workflow', commands: new Set(['init']) },
  { option: 'workflow-path', commands: new Set(['init']) },
  { option: 'action-ref', commands: new Set(['init']) },
  { option: 'dry-run', commands: new Set(['init', 'baseline']) },
  { option: 'force', commands: new Set(['init', 'install', 'baseline']) },
  { option: 'replace-directory', commands: new Set(['install']) },
  { option: 'expires-in', commands: new Set(['baseline']) },
  { option: 'expires-at', commands: new Set(['baseline']) },
  { option: 'expiring-within', commands: new Set(['baseline']) },
  { option: 'fail-on-expiring', commands: new Set(['baseline']) },
  { option: 'fail-on-unmatched', commands: new Set(['baseline']) },
  { option: 'owner', commands: new Set(['baseline']) },
  { option: 'note', commands: new Set(['baseline']) },
];

export function validateCommandOptions(command: string, options: ParsedArgs['options']): void {
  for (const rule of COMMAND_SCOPED_OPTIONS) {
    if (options[rule.option] === undefined) continue;
    if (rule.commands.has(command)) continue;
    usageError(
      `Option --${rule.option} is not supported by "${command}" ` +
        `(expected: ${[...rule.commands].join(', ')})`,
    );
  }
}

export const SHORT_FLAGS: Record<string, string> = { f: 'force', h: 'help', v: 'version', C: 'cwd' };
export const REPEATABLE_OPTIONS: Record<string, string> = {
  'ignore-rule': 'ignoreRule',
  'severity-override': 'severityOverride',
  include: 'include',
  exclude: 'exclude',
};

export interface ParsedArgs {
  positionals: string[];
  options: Record<string, string | string[] | boolean>;
  errors: string[];
}

export function parseArgs(argv: string[]): ParsedArgs {
  const positionals: string[] = [];
  const options: Record<string, string | string[] | boolean> = {};
  const errors: string[] = [];

  let i = 0;
  while (i < argv.length) {
    const arg = argv[i];
    if (arg === undefined) break;
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

export function usageError(message: string): never {
  console.error(chalk.red(`Error: ${message}`));
  console.error(`Run ${chalk.yellow('"agentwarden help"')} for usage.`);
  process.exit(EXIT_USAGE);
}

export function resolveFormat(options: ParsedArgs['options'], isJson = false): ReportFormat {
  if (options.json || isJson) return 'json';
  if (options.sarif) return 'sarif';
  if (options.format !== undefined) {
    const value = String(options.format).toLowerCase();
    if (!VALID_FORMATS.has(value)) usageError(`Invalid --format "${String(options.format)}" (expected pretty|json|sarif)`);
    return value as ReportFormat;
  }
  return 'pretty';
}

export function reportOptions(options: ParsedArgs['options']): ReportOptions {
  return { redact: !options['no-redact'] };
}

