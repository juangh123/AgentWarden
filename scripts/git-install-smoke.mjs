import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';

// Guards the git-sourced install path: cloning this repository must produce a
// working CLI through the `prepare` lifecycle hook, without relying on npm
// publish or on a prebuilt dist/ directory.

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'agentwarden-git-install-'));
const clone = path.join(temp, 'source');
const consumer = path.join(temp, 'consumer');

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function resolveNpmCli() {
  const fromEnv = process.env.npm_execpath;
  if (fromEnv && fs.existsSync(fromEnv)) return fromEnv;
  const besideNode = path.join(
    path.dirname(process.execPath),
    'node_modules',
    'npm',
    'bin',
    'npm-cli.js',
  );
  return fs.existsSync(besideNode) ? besideNode : null;
}

function runNpm(args, cwd) {
  const npmCli = resolveNpmCli();
  const command = npmCli ? process.execPath : 'npm';
  const commandArgs = npmCli ? [npmCli, ...args] : args;
  const result = spawnSync(command, commandArgs, {
    cwd,
    encoding: 'utf8',
    windowsHide: true,
    shell: !npmCli && process.platform === 'win32',
    env: {
      ...process.env,
      npm_config_audit: 'false',
      npm_config_fund: 'false',
      npm_config_update_notifier: 'false',
    },
  });
  if (result.error) throw result.error;
  return {
    status: result.status,
    stdout: (result.stdout ?? '').trim(),
    stderr: (result.stderr ?? '').trim(),
  };
}

try {
  fs.mkdirSync(consumer, { recursive: true });

  const head = spawnSync('git', ['-C', root, 'rev-parse', 'HEAD'], {
    encoding: 'utf8',
    windowsHide: true,
  });
  assert(head.status === 0, `git rev-parse failed: ${head.stderr || head.stdout}`);
  const revision = (head.stdout ?? '').trim();
  assert(revision.length > 0, 'could not resolve the current commit');

  const cloned = spawnSync('git', ['clone', '--quiet', '--no-hardlinks', root, clone], {
    encoding: 'utf8',
    windowsHide: true,
  });
  assert(
    cloned.status === 0,
    `git clone failed: ${cloned.stderr || cloned.stdout || 'unknown error'}`,
  );

  // Check out the exact revision under test so a detached CI checkout still
  // produces a populated work tree.
  const checkedOut = spawnSync('git', ['-C', clone, 'checkout', '--quiet', '--detach', revision], {
    encoding: 'utf8',
    windowsHide: true,
  });
  assert(
    checkedOut.status === 0,
    `git checkout ${revision} failed: ${checkedOut.stderr || checkedOut.stdout}`,
  );
  assert(
    !fs.existsSync(path.join(clone, 'dist')),
    'the clone unexpectedly shipped a prebuilt dist/, so this check cannot prove anything',
  );

  fs.writeFileSync(
    path.join(consumer, 'package.json'),
    `${JSON.stringify({ name: 'agentwarden-git-install-smoke', private: true }, null, 2)}\n`,
    'utf8',
  );

  const source = `git+${pathToFileURL(clone).href}`;
  const installed = runNpm(['install', source, '--no-audit', '--no-fund'], consumer);
  assert(installed.status === 0, `git install failed: ${installed.stderr || installed.stdout}`);

  const packageDirectory = path.join(consumer, 'node_modules', 'agentwarden-cli');
  const cli = path.join(packageDirectory, 'dist', 'cli.js');
  assert(fs.existsSync(cli), 'git install did not build dist/cli.js through the prepare script');
  assert(
    !fs.existsSync(path.join(packageDirectory, 'src')),
    'the published file whitelist should keep src/ out of the installed package',
  );

  const binName = process.platform === 'win32' ? 'warden.cmd' : 'warden';
  assert(
    fs.existsSync(path.join(consumer, 'node_modules', '.bin', binName)),
    `git install did not link the ${binName} binary`,
  );

  const version = spawnSync(process.execPath, [cli, '--version'], {
    encoding: 'utf8',
    windowsHide: true,
  });
  assert(
    version.status === 0 && /agentwarden v\d+\.\d+\.\d+/.test(version.stdout ?? ''),
    `installed CLI failed --version: ${version.stderr || version.stdout}`,
  );

  const initDirectory = path.join(temp, 'init-project');
  fs.mkdirSync(initDirectory, { recursive: true });
  const init = spawnSync(process.execPath, [cli, 'init', '--dry-run', '--json'], {
    cwd: initDirectory,
    encoding: 'utf8',
    windowsHide: true,
  });
  assert(
    init.status === 0,
    `installed CLI failed init --dry-run: ${init.stderr || init.stdout}`,
  );
  const initResult = JSON.parse((init.stdout ?? '').trim());
  assert(initResult.dryRun === true, 'init --dry-run did not report a dry run');
  assert(
    !fs.existsSync(path.join(initDirectory, '.agentwarden')),
    'init --dry-run wrote files to disk',
  );

  console.log(
    'Git install smoke passed: clone, install via prepare, bin link, and init dry-run verified.',
  );
} finally {
  fs.rmSync(temp, { recursive: true, force: true });
}