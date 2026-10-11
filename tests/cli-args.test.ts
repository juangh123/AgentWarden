import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  parseArgs,
  reportOptions,
  resolveFormat,
  validateCommandOptions,
} from '../src/cli/args.ts';

interface ExitProbe {
  code: number | undefined;
  stderr: string;
}

/** Run `operation`, capturing the usage error it raises instead of exiting. */
function interceptExit(operation: () => void): ExitProbe {
  const originalExit = process.exit;
  const originalError = console.error;
  let code: number | undefined;
  const messages: string[] = [];
  process.exit = ((value?: number) => {
    code = value;
    throw new Error('__exit__');
  }) as never;
  console.error = (...args: unknown[]) => {
    messages.push(args.map((value) => String(value)).join(' '));
  };
  try {
    operation();
  } catch (error) {
    if (!(error instanceof Error) || error.message !== '__exit__') throw error;
  } finally {
    process.exit = originalExit;
    console.error = originalError;
  }
  return { code, stderr: messages.join('\n') };
}

describe('CLI argument parsing', () => {
  it('separates positionals from options', () => {
    assert.deepEqual(parseArgs(['scan', 'skills/', 'extra.md']), {
      positionals: ['scan', 'skills/', 'extra.md'],
      options: {},
      errors: [],
    });
  });

  it('accepts value options with a space or an inline equals sign', () => {
    assert.deepEqual(parseArgs(['--format', 'json']).options, { format: 'json' });
    assert.deepEqual(parseArgs(['--format=json']).options, { format: 'json' });
    assert.deepEqual(parseArgs(['--format=SARIF']).options, { format: 'SARIF' });
    assert.deepEqual(parseArgs(['--min-score', '0']).options, { 'min-score': '0' });
  });

  it('sets boolean flags and rejects values on them', () => {
    assert.deepEqual(parseArgs(['--json', '--no-color']).options, { json: true, 'no-color': true });
    const withValue = parseArgs(['--json=1']);
    assert.deepEqual(withValue.options, { json: true });
    assert.deepEqual(withValue.errors, ['Option --json does not take a value']);
  });

  it('accumulates repeatable options under their canonical keys', () => {
    const parsed = parseArgs([
      '--ignore-rule', 'SEC-CRED-001',
      '--ignore-rule', 'SEC-INJ-002',
      '--include', 'skills/**',
      '--include=docs/**',
      '--exclude', 'vendor/**',
      '--severity-override', 'SEC-INJ-002=low',
    ]);
    assert.deepEqual(parsed.options.ignoreRule, ['SEC-CRED-001', 'SEC-INJ-002']);
    assert.deepEqual(parsed.options.include, ['skills/**', 'docs/**']);
    assert.deepEqual(parsed.options.exclude, ['vendor/**']);
    assert.deepEqual(parsed.options.severityOverride, ['SEC-INJ-002=low']);
    assert.deepEqual(parsed.errors, []);
  });

  it('reports missing values and unknown options without throwing', () => {
    assert.deepEqual(parseArgs(['--format']).errors, ['Option --format requires a value']);
    assert.deepEqual(parseArgs(['--unknown']).errors, ['Unknown option: --unknown']);
    assert.deepEqual(parseArgs(['-x']).errors, ['Unknown option: -x']);
    assert.deepEqual(parseArgs(['-C']).errors, ['Option -C requires a value']);
  });

  it('treats a following flag as a missing value and then parses that flag', () => {
    const parsed = parseArgs(['--format', '--json']);
    assert.deepEqual(parsed.errors, ['Option --format requires a value']);
    assert.deepEqual(parsed.options, { json: true });
  });

  it('supports short flags and the positional separator', () => {
    assert.deepEqual(parseArgs(['-f']).options, { force: true });
    assert.deepEqual(parseArgs(['-v']).options, { version: true });
    assert.deepEqual(parseArgs(['-h']).options, { help: true });
    assert.deepEqual(parseArgs(['-C', 'repo']).options, { cwd: 'repo' });
    assert.deepEqual(parseArgs(['scan', '--', '-weird.md']).positionals, ['scan', '-weird.md']);
    assert.deepEqual(parseArgs(['-']).positionals, ['-']);
  });

  it('resolves the report format, with explicit flags winning', () => {
    assert.equal(resolveFormat({}), 'pretty');
    assert.equal(resolveFormat({}, true), 'json');
    assert.equal(resolveFormat({ json: true }), 'json');
    assert.equal(resolveFormat({ sarif: true }), 'sarif');
    assert.equal(resolveFormat({ json: true, sarif: true }), 'json');
    assert.equal(resolveFormat({ format: 'JSON' }), 'json');
    assert.equal(resolveFormat({ format: 'sarif' }), 'sarif');

    const rejected = interceptExit(() => resolveFormat({ format: 'yaml' }));
    assert.equal(rejected.code, 2);
    assert.match(rejected.stderr, /Invalid --format "yaml"/);
  });

  it('defaults to redacted reports unless disabled', () => {
    assert.deepEqual(reportOptions({}), { redact: true });
    assert.deepEqual(reportOptions({ 'no-redact': true }), { redact: false });
  });

  it('accepts scoped options on their command and rejects them elsewhere', () => {
    assert.doesNotThrow(() => validateCommandOptions('scan', { changed: true }));
    assert.doesNotThrow(() => validateCommandOptions('install', { 'replace-directory': true }));
    assert.doesNotThrow(() => validateCommandOptions('baseline', { 'expires-in': '30' }));

    const rejected = interceptExit(() => validateCommandOptions('scan', { output: 'x.json' }));
    assert.equal(rejected.code, 2);
    assert.match(rejected.stderr, /Option --output is not supported by "scan"/);

    const auditSarif = interceptExit(() => validateCommandOptions('audit', { sarif: true }));
    assert.equal(auditSarif.code, 2);
    assert.match(auditSarif.stderr, /Option --sarif is not supported by "audit"/);
  });
});
