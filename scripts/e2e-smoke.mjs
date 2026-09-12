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
fs.copyFileSync(path.join(root, 'fixtures', 'hardcoded-secrets.md'), path.join(tmp, 'hardcoded-secrets.md'));
fs.writeFileSync(
  path.join(tmp, '.mcp.json'),
  JSON.stringify({ mcpServers: { unsafe: { command: 'npx', args: ['unpinned-tool'] } } }, null, 2),
);
fs.mkdirSync(path.join(tmp, 'scope', 'included'), { recursive: true });
fs.mkdirSync(path.join(tmp, 'scope', 'excluded'), { recursive: true });
fs.copyFileSync(path.join(root, 'fixtures', 'safe-skill.md'), path.join(tmp, 'scope', 'included', 'safe.md'));
fs.copyFileSync(
  path.join(root, 'fixtures', 'malicious-skill.md'),
  path.join(tmp, 'scope', 'excluded', 'malicious.md'),
);
fs.writeFileSync(
  path.join(tmp, 'medium-profile.md'),
  [
    '---',
    'name: medium-profile-demo',
    '---',
    'const decoded = atob("c2VjcmV0");',
    'const letters = String.fromCharCode(65, 66, 67);',
    '',
  ].join('\n'),
  'utf8',
);
fs.writeFileSync(
  path.join(tmp, 'custom-policy.json'),
  JSON.stringify({ profile: 'strict', include: ['skills/**'] }, null, 2),
  'utf8',
);
fs.writeFileSync(
  path.join(tmp, 'inherited-base-policy.json'),
  JSON.stringify({ profile: 'strict', include: ['skills/**'] }, null, 2),
  'utf8',
);
fs.writeFileSync(
  path.join(tmp, 'inherited-policy.json'),
  JSON.stringify({
    extends: './inherited-base-policy.json',
    exclude: ['skills/vendor/**'],
    minScore: 95,
  }),
  'utf8',
);
fs.writeFileSync(path.join(tmp, 'malformed-policy.json'), '{"profile":', 'utf8');

let r = run(['-C', tmp, 'scan', '.', '--json']);
const directoryScan = JSON.parse(r.stdout);
check(
  'directory scan includes MCP config',
  r.status === 1 && directoryScan.results.some((result) => result.parsedSkill.kind === 'mcp'),
  `status=${r.status}`,
);

r = run(['-C', tmp, 'scan', '.', '--include', 'scope/**', '--exclude', 'scope/excluded/**', '--json']);
const scopedScan = JSON.parse(r.stdout);
check(
  'include and exclude scope a directory scan',
  r.status === 0 &&
    scopedScan.parsedSkill.name === 'safe-weather-reporter' &&
    !r.stdout.includes('evil-credential-stealer'),
  `status=${r.status}`,
);

r = run(['-C', tmp, 'scan', 'medium-profile.md', '--profile', 'legacy', '--json']);
check('legacy profile tolerates medium finding below score floor', r.status === 0, `status=${r.status}`);

r = run(['-C', tmp, 'scan', 'medium-profile.md', '--profile', 'balanced', '--json']);
check('balanced profile enforces the 80 score floor', r.status === 1, `status=${r.status}`);

r = run([
  '-C',
  tmp,
  'scan',
  'medium-profile.md',
  '--profile',
  'balanced',
  '--min-score',
  '50',
  '--json',
]);
check('explicit CLI threshold overrides profile default', r.status === 0, `status=${r.status}`);

r = run(['-C', tmp, 'scan', 'medium-profile.md', '--profile', 'unknown', '--json']);
check('unknown profile is a usage error', r.status === 2, `status=${r.status}`);

r = run([
  '-C',
  tmp,
  'baseline',
  'scope',
  '--exclude',
  'scope/excluded/**',
  '--output',
  'scope-baseline.json',
  '--json',
]);
const scopedBaseline = JSON.parse(r.stdout);
check(
  'baseline honors directory exclusions',
  r.status === 0 && scopedBaseline.filesScanned === 1 && scopedBaseline.findingsAccepted === 0,
  `status=${r.status}`,
);

r = run(['-C', tmp, 'scan', 'hardcoded-secrets.md', '--json']);
check(
  'JSON reports are redacted by default',
  r.status === 1 && !r.stdout.includes('sk-proj-EXAMPLETOKEN1234567890abcdef'),
  `status=${r.status}`,
);

r = run(['-C', tmp, 'scan', 'hardcoded-secrets.md', '--json', '--no-redact']);
check(
  'explicit no-redact preserves raw report data',
  r.status === 1 && r.stdout.includes('sk-proj-EXAMPLETOKEN1234567890abcdef'),
  `status=${r.status}`,
);

r = run(['-C', tmp, 'baseline', 'malicious-skill.md', '--output', 'baseline.json', '--json']);
const baselineJson = JSON.parse(r.stdout);
check(
  'baseline command records findings without raw snippets',
  r.status === 0 && baselineJson.findingsAccepted > 0 && !r.stdout.includes('id_rsa'),
  `status=${r.status}`,
);

r = run(['-C', tmp, 'scan', 'malicious-skill.md', '--baseline', 'baseline.json', '--json']);
const baselinedScan = JSON.parse(r.stdout);
check(
  'explicit baseline suppresses existing findings',
  r.status === 0 &&
    baselinedScan.findings.length === 0 &&
    baselinedScan.suppressedFindings.length === baselineJson.findingsAccepted,
  `status=${r.status}`,
);

r = run(['-C', tmp, 'baseline', 'malicious-skill.md', '--output', 'baseline.json', '--json']);
check('baseline refuses implicit overwrite', r.status === 1, `status=${r.status}`);

r = run(['-C', tmp, 'rules', '--json']);
const rulesJson = JSON.parse(r.stdout);
check('rules catalog lists security rules', r.status === 0 && rulesJson.count >= 10, `status=${r.status}`);

r = run(['-C', tmp, 'rules', '--json', '--severity-override', 'SEC-CRED-001=medium']);
const overriddenRules = JSON.parse(r.stdout).rules.find((rule) => rule.id === 'SEC-CRED-001');
check(
  'rules catalog shows effective severity override',
  r.status === 0 && overriddenRules?.severity === 'critical' && overriddenRules?.effectiveSeverity === 'medium',
  `status=${r.status}`,
);

r = run([
  '-C',
  tmp,
  'policy',
  '--json',
  '--profile',
  'strict',
  '--include',
  'skills/**',
  '--exclude',
  'skills/vendor/**',
]);
const effectivePolicy = JSON.parse(r.stdout);
check(
  'policy command shows effective profile and scan scope',
  r.status === 0 &&
    effectivePolicy.profile === 'strict' &&
    effectivePolicy.failOn === 'medium' &&
    effectivePolicy.minScore === 90 &&
    effectivePolicy.configSource === null &&
    effectivePolicy.include[0] === 'skills/**' &&
    effectivePolicy.exclude[0] === 'skills/vendor/**',
  `status=${r.status}`,
);

r = run(['-C', tmp, 'policy', '--config', 'custom-policy.json', '--json']);
const explicitPolicy = JSON.parse(r.stdout);
check(
  'policy command reports explicit config source',
  r.status === 0 &&
    explicitPolicy.profile === 'strict' &&
    explicitPolicy.configSource === path.join(tmp, 'custom-policy.json') &&
    explicitPolicy.include[0] === 'skills/**',
  `status=${r.status}`,
);

r = run(['-C', tmp, 'policy', '--config', 'inherited-policy.json', '--json']);
const inheritedPolicy = JSON.parse(r.stdout);
check(
  'policy command reports the config inheritance chain',
  r.status === 0 &&
    inheritedPolicy.profile === 'strict' &&
    inheritedPolicy.minScore === 95 &&
    inheritedPolicy.configSources.length === 2 &&
    inheritedPolicy.configSources[0] === path.join(tmp, 'inherited-base-policy.json') &&
    inheritedPolicy.configSources[1] === path.join(tmp, 'inherited-policy.json') &&
    inheritedPolicy.include[0] === 'skills/**' &&
    inheritedPolicy.exclude[0] === 'skills/vendor/**',
  `status=${r.status}`,
);

r = run(['-C', tmp, 'policy', 'diff', 'legacy', 'strict', '--json']);
const policyDiff = JSON.parse(r.stdout);
check(
  'policy diff reports changes between profiles',
  r.status === 0 &&
    policyDiff.changed === true &&
    policyDiff.from.label === 'legacy' &&
    policyDiff.to.label === 'strict' &&
    policyDiff.changes.some((change) => change.field === 'minScore' && change.before === 60 && change.after === 90),
  `status=${r.status}`,
);

r = run([
  '-C',
  tmp,
  'policy',
  'diff',
  'legacy',
  'current',
  '--config',
  'custom-policy.json',
  '--json',
]);
const currentPolicyDiff = JSON.parse(r.stdout);
check(
  'policy diff resolves the current explicit config',
  r.status === 0 &&
    currentPolicyDiff.to.label === 'current' &&
    currentPolicyDiff.to.configSource === path.join(tmp, 'custom-policy.json') &&
    currentPolicyDiff.to.profile === 'strict',
  `status=${r.status}`,
);

r = run(['-C', tmp, 'policy', 'diff', 'legacy', 'strict', '--fail-on-diff', '--json']);
check('policy diff can fail CI on policy changes', r.status === 1, `status=${r.status}`);

r = run(['-C', tmp, 'policy', 'diff', 'legacy', 'strict', '--sarif']);
check('policy diff rejects SARIF output', r.status === 2, `status=${r.status}`);

r = run(['-C', tmp, 'scan', 'medium-profile.md', '--config', 'custom-policy.json', '--json']);
check('explicit config controls scan policy', r.status === 1, `status=${r.status}`);

r = run([
  '-C',
  tmp,
  'scan',
  'medium-profile.md',
  '--config',
  'custom-policy.json',
  '--profile',
  'legacy',
  '--json',
]);
check('CLI policy overrides explicit config defaults', r.status === 0, `status=${r.status}`);

r = run(['-C', tmp, 'policy', '--config', 'missing-policy.json', '--json']);
check('missing explicit config fails as a usage error', r.status === 2, `status=${r.status}`);

r = run(['-C', tmp, 'policy', '--config', 'malformed-policy.json', '--json']);
check('malformed explicit config fails as a usage error', r.status === 2, `status=${r.status}`);

r = run(['-C', tmp, 'install', 'safe-skill.md', '--json']);
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

r = run(['-C', tmp, 'install', 'malicious-skill.md', '--force', '--json']);
check('force install locks risky skill', r.status === 0, `status=${r.status}`);
r = run(['-C', tmp, 'audit', '--json']);
const policyAudit = JSON.parse(r.stdout);
check(
  'audit rejects unchanged skill that fails current policy',
  r.status === 1 &&
    policyAudit.passed === false &&
    policyAudit.skills['evil-credential-stealer']?.hashMatch === true &&
    policyAudit.skills['evil-credential-stealer']?.policyPassed === false,
  `status=${r.status}`,
);

fs.writeFileSync(path.join(tmp, 'skills.lock'), '{"skills":', 'utf8');
r = run(['-C', tmp, 'audit', '--json']);
check(
  'malformed lockfile fails closed',
  r.status === 1 && r.stderr.includes('Invalid skills.lock JSON'),
  `status=${r.status}`,
);

r = run(['scan']);
check('usage error exit 2', r.status === 2);
r = run(['--unknown-flag']);
check('unknown flag exit 2', r.status === 2);

fs.rmSync(tmp, { recursive: true, force: true });

const failed = results.filter((x) => !x.ok);
console.log(`\n${results.length - failed.length}/${results.length} checks passed`);
process.exit(failed.length === 0 ? 0 : 1);
