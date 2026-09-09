import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const cli = path.join(root, 'dist', 'cli.js');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'skillguard-e2e-'));
const results = [];

function run(args) {
  const res = spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8' });
  return { status: res.status, stdout: (res.stdout ?? '').trim(), stderr: (res.stderr ?? '').trim() };
}

function check(name, cond, extra = '') {
  results.push({ name, ok: Boolean(cond) });
  console.log(`${cond ? 'PASS' : 'FAIL'}: ${name}${extra ? ' -- ' + extra : ''}`);
}

fs.copyFileSync(path.join(root, 'fixtures', 'safe-skill.md'), path.join(tmp, 'safe-skill.md'));
fs.copyFileSync(path.join(root, 'fixtures', 'malicious-skill.md'), path.join(tmp, 'malicious-skill.md'));

let r = run(['-C', tmp, 'install', 'safe-skill.md', '--json']);
check('install success exit 0', r.status === 0, `status=${r.status}`);
const installJson = JSON.parse(r.stdout);
check('install json fields', installJson.parsedSkill?.name === 'safe-weather-reporter' && installJson.sha256?.length === 64);

r = run(['-C', tmp, 'install', 'malicious-skill.md', '--json']);
check('install blocks malicious (exit 1)', r.status === 1, `status=${r.status}`);
check('install json marks aborted', JSON.parse(r.stdout).installAborted === true);

r = run(['-C', tmp, 'list', '--json']);
const listJson = JSON.parse(r.stdout);
check('list shows installed skill', r.status === 0 && listJson.count === 1 && listJson.skills[0].name === 'safe-weather-reporter');

r = run(['-C', tmp, 'verify', 'safe-skill.md']);
check('verify ok', r.status === 0 && r.stdout.includes('Integrity verified'));

r = run(['-C', tmp, 'audit', '--json']);
check('audit clean', r.status === 0 && JSON.parse(r.stdout).passed === true);

fs.appendFileSync(path.join(tmp, 'safe-skill.md'), '\n# tampered\n');
r = run(['-C', tmp, 'audit', '--json']);
check('audit detects tampering', r.status === 1 && JSON.parse(r.stdout).passed === false);

const lines = fs.readFileSync(path.join(tmp, 'safe-skill.md'), 'utf8').split(/\r?\n/).filter((l) => !l.includes('tampered'));
fs.writeFileSync(path.join(tmp, 'safe-skill.md'), lines.join('\n'), 'utf8');

r = run(['-C', tmp, 'uninstall', 'safe-weather-reporter', '--json']);
check('uninstall ok', r.status === 0 && JSON.parse(r.stdout).removed === 'safe-weather-reporter');
r = run(['-C', tmp, 'list', '--json']);
check('list empty after uninstall', JSON.parse(r.stdout).count === 0);

r = run(['scan']);
check('usage error exit 2', r.status === 2);
r = run(['--unknown-flag']);
check('unknown flag exit 2', r.status === 2);

fs.rmSync(tmp, { recursive: true, force: true });

const failed = results.filter((x) => !x.ok);
console.log(`\n${results.length - failed.length}/${results.length} checks passed`);
process.exit(failed.length === 0 ? 0 : 1);
