import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { performance } from 'node:perf_hooks';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const cli = path.join(root, 'dist', 'cli.js');
const manifest = JSON.parse(
  fs.readFileSync(path.join(root, 'package.json'), 'utf8'),
);
const argv = process.argv.slice(2);
const network = argv.includes('--network');
const json = argv.includes('--json');
const version = readOption('--version') ?? manifest.version;
const runs = parseRuns(readOption('--runs'));
const networkRuns = parseNetworkRuns(readOption('--network-runs'));
const maliciousFixture = path.join(root, 'examples', 'malicious-skill.md');

function readOption(name) {
  const value = argv.find((arg) => arg.startsWith(`${name}=`));
  return value?.slice(name.length + 1);
}

function parseRuns(value) {
  if (value === undefined) return 10;
  const count = Number(value);
  if (!Number.isInteger(count) || count < 1 || count > 50) {
    throw new Error('--runs must be an integer from 1 to 50');
  }
  return count;
}

function parseNetworkRuns(value) {
  if (value === undefined) return 1;
  const count = Number(value);
  if (!Number.isInteger(count) || count < 1 || count > 10) {
    throw new Error('--network-runs must be an integer from 1 to 10');
  }
  return count;
}

function resolveNpmCli(name) {
  const npmExecPath = process.env.npm_execpath;
  const filename = name === 'npm' ? 'npm-cli.js' : 'npx-cli.js';
  const candidates = [
    npmExecPath ? path.join(path.dirname(npmExecPath), filename) : null,
    path.join(
      path.dirname(process.execPath),
      'node_modules',
      'npm',
      'bin',
      filename,
    ),
  ].filter(Boolean);
  return candidates.find((candidate) => fs.existsSync(candidate)) ?? null;
}

function runProcess(command, args, cwd, env, shell = false) {
  const result = spawnSync(command, args, {
    cwd,
    encoding: 'utf8',
    windowsHide: true,
    shell,
    timeout: 180_000,
    maxBuffer: 10 * 1024 * 1024,
    env: { ...process.env, ...env },
  });
  if (result.error) throw result.error;
  return {
    status: result.status ?? -1,
    stdout: (result.stdout ?? '').trim(),
    stderr: (result.stderr ?? '').trim(),
  };
}

function runNpm(name, args, cwd, env) {
  const npmCli = resolveNpmCli(name);
  if (npmCli) {
    return runProcess(process.execPath, [npmCli, ...args], cwd, env);
  }
  return runProcess(
    name,
    args,
    cwd,
    env,
    process.platform === 'win32',
  );
}

function runNode(args, cwd = root, env = {}) {
  return runProcess(process.execPath, args, cwd, env);
}

function elapsed(fn) {
  const start = performance.now();
  const result = fn();
  return { durationMs: performance.now() - start, result };
}

function summarize(samples) {
  const sorted = [...samples].sort((left, right) => left - right);
  const middle = sorted[Math.floor(sorted.length / 2)];
  const percentileIndex = Math.min(
    sorted.length - 1,
    Math.ceil(sorted.length * 0.9) - 1,
  );
  return {
    runs: sorted.length,
    min: sorted[0],
    median: middle,
    p90: sorted[percentileIndex],
    max: sorted[sorted.length - 1],
    mean: samples.reduce((total, sample) => total + sample, 0) / samples.length,
  };
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function failStatus(label, expected, result) {
  throw new Error(
    `${label} exited ${result.status}, expected ${expected}: ${
      result.stderr || result.stdout
    }`,
  );
}

function benchmarkLocal(label, args, expectedStatus) {
  const warmup = runNode(args, root, { NO_COLOR: '1' });
  if (warmup.status !== expectedStatus) {
    failStatus(`${label} warmup`, expectedStatus, warmup);
  }

  const samples = [];
  for (let index = 0; index < runs; index += 1) {
    const { durationMs, result } = elapsed(() =>
      runNode(args, root, { NO_COLOR: '1' }),
    );
    if (result.status !== expectedStatus) {
      failStatus(label, expectedStatus, result);
    }
    samples.push(durationMs);
  }
  return { label, ...summarize(samples) };
}

function makeNetworkWorkspace(prefix) {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  const cache = path.join(temp, 'npm-cache');
  const work = path.join(temp, 'work');
  const config = path.join(temp, 'empty-npmrc');
  fs.mkdirSync(cache, { recursive: true });
  fs.mkdirSync(work, { recursive: true });
  fs.writeFileSync(config, '', 'utf8');
  fs.copyFileSync(maliciousFixture, path.join(work, 'malicious-skill.md'));
  return { temp, cache, work, config };
}

function networkEnv(workspace) {
  return {
    npm_config_cache: workspace.cache,
    npm_config_userconfig: workspace.config,
    npm_config_audit: 'false',
    npm_config_fund: 'false',
    npm_config_update_notifier: 'false',
    NO_COLOR: '1',
  };
}

function npx(workspace, args) {
  return runNpm('npx', args, workspace.work, networkEnv(workspace));
}

function formatMs(value) {
  return `${value.toFixed(1)} ms`;
}

function printStats(stats, indent = '') {
  console.log(
    `${indent}${stats.label.padEnd(26)} median ${formatMs(stats.median).padStart(10)}  ` +
      `p90 ${formatMs(stats.p90).padStart(10)}  ` +
      `min ${formatMs(stats.min).padStart(10)}  ` +
      `max ${formatMs(stats.max).padStart(10)}`,
  );
}

const workspaces = [];
let report;

try {
  if (!fs.existsSync(cli)) {
    throw new Error('dist/cli.js is missing; run npm run build first');
  }

  const local = {
    baseline: benchmarkLocal('node empty script', ['-e', ''], 0),
    version: benchmarkLocal('cli --version', [cli, '--version'], 0),
    help: benchmarkLocal('cli --help', [cli, '--help'], 0),
    scanMalicious: benchmarkLocal(
      'cli scan malicious',
      [cli, 'scan', maliciousFixture],
      1,
    ),
  };

  let networkReport = null;
  if (network) {
    const spec = `agentwarden-cli@${version}`;
    const samples = {
      coldVersion: [],
      coldFirstFinding: [],
      warmVersion: [],
      offlineVersion: [],
      warmFirstFinding: [],
    };

    for (let index = 0; index < networkRuns; index += 1) {
      const coldVersionWorkspace = makeNetworkWorkspace(
        'agentwarden-bench-version-',
      );
      workspaces.push(coldVersionWorkspace);
      const coldScanWorkspace = makeNetworkWorkspace('agentwarden-bench-scan-');
      workspaces.push(coldScanWorkspace);

      const coldVersion = elapsed(() =>
        npx(coldVersionWorkspace, ['--yes', spec, '--version']),
      );
      if (coldVersion.result.status !== 0) {
        failStatus(`cold npx --version run ${index + 1}`, 0, coldVersion.result);
      }
      assert(
        coldVersion.result.stdout.includes(`v${version}`),
        `cold npx --version did not report v${version}: ${coldVersion.result.stdout}`,
      );
      samples.coldVersion.push(coldVersion.durationMs);

      const coldScan = elapsed(() =>
        npx(coldScanWorkspace, [
          '--yes',
          spec,
          'scan',
          'malicious-skill.md',
        ]),
      );
      if (coldScan.result.status !== 1) {
        failStatus(`cold npx scan run ${index + 1}`, 1, coldScan.result);
      }
      assert(
        /Found \d+ security issues?/.test(coldScan.result.stdout),
        `cold npx scan did not report findings: ${coldScan.result.stdout}`,
      );
      samples.coldFirstFinding.push(coldScan.durationMs);

      const warmVersion = elapsed(() =>
        npx(coldVersionWorkspace, ['--yes', spec, '--version']),
      );
      if (warmVersion.result.status !== 0) {
        failStatus(`warm npx --version run ${index + 1}`, 0, warmVersion.result);
      }
      samples.warmVersion.push(warmVersion.durationMs);

      const offlineVersion = elapsed(() =>
        npx(coldVersionWorkspace, [
          '--offline',
          '--yes',
          spec,
          '--version',
        ]),
      );
      if (offlineVersion.result.status !== 0) {
        failStatus(
          `offline npx --version run ${index + 1}`,
          0,
          offlineVersion.result,
        );
      }
      samples.offlineVersion.push(offlineVersion.durationMs);

      const warmScan = elapsed(() =>
        npx(coldScanWorkspace, [
          '--yes',
          spec,
          'scan',
          'malicious-skill.md',
        ]),
      );
      if (warmScan.result.status !== 1) {
        failStatus(`warm npx scan run ${index + 1}`, 1, warmScan.result);
      }
      samples.warmFirstFinding.push(warmScan.durationMs);
    }

    networkReport = {
      packageSpec: spec,
      runs: networkRuns,
      metrics: Object.fromEntries(
        Object.entries(samples).map(([name, values]) => [
          name,
          summarize(values),
        ]),
      ),
    };
  }

  report = {
    generatedAt: new Date().toISOString(),
    platform: process.platform,
    arch: process.arch,
    node: process.version,
    npm: runNpm('npm', ['--version'], root, {}).stdout,
    packageVersion: manifest.version,
    runs,
    local,
    network: networkReport,
  };

  if (json) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    console.log(
      `Cold-start benchmark: ${report.platform}/${report.arch}, ` +
        `Node ${report.node}, npm ${report.npm}, package ${report.packageVersion}`,
    );
    console.log(`Local (${runs} runs; one warmup excluded)`);
    for (const stats of Object.values(local)) printStats(stats);
    if (networkReport) {
      console.log(
        `Network (fresh npm cache per run; ${networkReport.runs} run(s); ${networkReport.packageSpec})`,
      );
      for (const stats of Object.values(networkReport.metrics)) {
        printStats(stats, '  ');
      }
    }
    console.log('PASS: cold-start checks passed');
  }
} catch (error) {
  console.error(
    `FAIL: ${error instanceof Error ? error.message : String(error)}`,
  );
  process.exitCode = 1;
} finally {
  for (const workspace of workspaces) {
    fs.rmSync(workspace.temp, { recursive: true, force: true });
  }
}
