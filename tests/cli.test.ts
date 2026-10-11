import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { readPackageVersion } from '../src/version.ts';

const CLI_ENTRY = path.resolve(process.cwd(), 'src/cli.ts');
const PROJECT_ROOT = process.cwd();

interface CliRun {
  status: number | null;
  stdout: string;
  stderr: string;
}

/**
 * Run the real CLI in a child process.
 *
 * The CLI executes `main()` at module scope, so it cannot be imported into a
 * unit test; exercising the published entry point is the only way to assert the
 * documented exit codes and the machine-readable output contracts.
 */
function runCli(args: string[], cwd: string = PROJECT_ROOT): CliRun {
  const result = spawnSync(
    process.execPath,
    ['--experimental-strip-types', '--no-warnings', CLI_ENTRY, ...args],
    {
      cwd,
      encoding: 'utf8',
      env: { ...process.env, NO_COLOR: '1' },
    },
  );
  return {
    status: result.status,
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? '',
  };
}

function tempDir(prefix: string): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

describe('CLI contract', () => {
  it('reports the package version and exits 0', () => {
    const result = runCli(['--version']);
    assert.equal(result.status, 0);
    assert.match(result.stdout, new RegExp(readPackageVersion().replace(/\./g, '\\.')));
  });

  it('prints help and exits 0', () => {
    const result = runCli(['help']);
    assert.equal(result.status, 0);
    assert.match(result.stdout, /USAGE:/);
    assert.match(result.stdout, /--replace-directory/);
  });

  it('scans a clean fixture with exit code 0 and valid JSON', () => {
    const result = runCli(['scan', 'fixtures/safe-skill.md', '--json']);
    assert.equal(result.status, 0);
    const report = JSON.parse(result.stdout) as { passed: boolean; score: number };
    assert.equal(report.passed, true);
    assert.equal(report.score, 100);
  });

  it('scans a malicious fixture with exit code 1 and valid JSON on stdout', () => {
    const result = runCli(['scan', 'fixtures/malicious-skill.md', '--json']);
    assert.equal(result.status, 1);
    const report = JSON.parse(result.stdout) as { passed: boolean; findings: unknown[] };
    assert.equal(report.passed, false);
    assert.ok(report.findings.length > 0);
  });

  it('emits complete, parseable SARIF when the scan fails', () => {
    const result = runCli(['scan', 'fixtures/malicious-skill.md', '--sarif']);
    assert.equal(result.status, 1);
    const sarif = JSON.parse(result.stdout) as {
      version: string;
      runs: Array<{ results: unknown[] }>;
    };
    assert.equal(sarif.version, '2.1.0');
    assert.ok(sarif.runs[0].results.length > 0);
    // A truncated stream would not end with the closing brace of the document.
    assert.ok(result.stdout.trimEnd().endsWith('}'));
  });

  it('exits 2 when a scan scope contains no scannable files', () => {
    const dir = tempDir('agentwarden-cli-empty-');
    try {
      const result = runCli(['scan', dir]);
      assert.equal(result.status, 2);
      assert.match(result.stderr, /nothing to scan/);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('exits 2 for unknown flags and for options a command does not support', () => {
    assert.equal(runCli(['--unknown-flag']).status, 2);
    assert.equal(runCli(['scan', 'fixtures/safe-skill.md', '--output', 'x.json']).status, 2);
    assert.equal(runCli(['scan', 'fixtures/safe-skill.md', '--fail-on-diff']).status, 2);
    assert.equal(runCli(['audit', '--sarif']).status, 2);
  });

  it('exits 2 when a config field has the wrong type', () => {
    const dir = tempDir('agentwarden-cli-config-');
    try {
      const config = path.join(dir, 'policy.json');
      fs.writeFileSync(config, JSON.stringify({ minScore: '95' }), 'utf8');
      const result = runCli(['policy', '--config', config, '--json']);
      assert.equal(result.status, 2);
      assert.match(result.stderr, /minScore/);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('keeps a multi-file JSON report complete and deterministic', () => {
    const first = runCli(['scan', 'fixtures', '--json']);
    const second = runCli(['scan', 'fixtures', '--json']);

    const report = JSON.parse(first.stdout) as { results: unknown[] };
    assert.ok(report.results.length > 1);
    assert.ok(first.stdout.trimEnd().endsWith('}'));
    // Two runs over the same tree must produce identical bytes.
    assert.equal(first.stdout, second.stdout);
  });

  it('warns on stderr, never stdout, when no publisher identity is pinned', () => {
    const dir = tempDir('agentwarden-cli-publisher-');
    try {
      const config = path.join(dir, 'policy.json');
      fs.writeFileSync(
        config,
        JSON.stringify({ publishers: { requireSignature: true, trustedKeys: [] } }),
        'utf8',
      );
      const result = runCli(['policy', '--config', config, '--json']);
      assert.equal(result.status, 0);
      assert.match(result.stderr, /trustedKeys is empty/);
      // stdout must stay machine-readable.
      assert.doesNotThrow(() => JSON.parse(result.stdout));
      assert.ok(!result.stdout.includes('trustedKeys is empty'));
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('verifies a locked skill and reports a machine-readable verdict', () => {
    const dir = tempDir('agentwarden-cli-verify-');
    try {
      fs.copyFileSync(
        path.join(PROJECT_ROOT, 'fixtures', 'safe-skill.md'),
        path.join(dir, 'safe-skill.md'),
      );
      const installed = runCli(['-C', dir, 'install', 'safe-skill.md', '--json'], PROJECT_ROOT);
      assert.equal(installed.status, 0, installed.stderr);

      const verified = runCli(['-C', dir, 'verify', 'safe-skill.md', '--json'], PROJECT_ROOT);
      assert.equal(verified.status, 0);
      const verdict = JSON.parse(verified.stdout) as {
        verified: boolean;
        key: string;
        score: number;
        expectedSha256: string;
        actualSha256: string;
        publisherPolicyPassed: boolean;
      };
      assert.equal(verdict.verified, true);
      assert.equal(verdict.key, 'safe-weather-reporter');
      assert.equal(verdict.score, 100);
      assert.equal(verdict.expectedSha256, verdict.actualSha256);
      assert.equal(verdict.publisherPolicyPassed, true);

      fs.appendFileSync(path.join(dir, 'safe-skill.md'), '\n<!-- tampered -->\n');
      const tampered = runCli(['-C', dir, 'verify', 'safe-skill.md', '--json'], PROJECT_ROOT);
      assert.equal(tampered.status, 1);
      const tamperedVerdict = JSON.parse(tampered.stdout) as {
        verified: boolean;
        reason: string;
        expectedSha256: string;
        actualSha256: string;
      };
      assert.equal(tamperedVerdict.verified, false);
      assert.equal(tamperedVerdict.reason, 'tampered');
      assert.notEqual(tamperedVerdict.expectedSha256, tamperedVerdict.actualSha256);

      const missingPath = runCli(['-C', dir, 'verify', 'does-not-exist.md', '--json'], PROJECT_ROOT);
      assert.equal(missingPath.status, 2);

      fs.writeFileSync(
        path.join(dir, 'unregistered.md'),
        '---\nname: unregistered-skill\nversion: 1.0.0\n---\n# U\n',
        'utf8',
      );
      const unregistered = runCli(['-C', dir, 'verify', 'unregistered.md', '--json'], PROJECT_ROOT);
      assert.equal(unregistered.status, 1);
      const unregisteredVerdict = JSON.parse(unregistered.stdout) as { verified: boolean; reason: string };
      assert.equal(unregisteredVerdict.verified, false);
      assert.equal(unregisteredVerdict.reason, 'not-registered');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
