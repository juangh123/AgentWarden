import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import {
  buildSarifReport,
  createBaseline,
  redactText,
  scanSkillContent,
  toReportScanResult,
} from '../src/index.ts';

const secret = 'sk-proj-EXAMPLETOKEN1234567890abcdef';

function scanSecretsFixture() {
  const fixture = fs.readFileSync(path.resolve(process.cwd(), 'fixtures/hardcoded-secrets.md'), 'utf8');
  return scanSkillContent(fixture, 'skills/hardcoded-secrets.md');
}

describe('report redaction', () => {
  it('redacts secret values and raw file content from report projections', () => {
    const result = scanSecretsFixture();
    const report = toReportScanResult(result);
    const serialized = JSON.stringify(report);

    assert.ok(!serialized.includes(secret));
    assert.ok(!serialized.includes('b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAA'));
    assert.ok(serialized.includes('[REDACTED]'));
    assert.equal(report.parsedSkill.rawContent, '[REDACTED]');
    assert.equal(report.parsedSkill.promptText, '[REDACTED]');
    assert.equal(result.parsedSkill.rawContent.includes(secret), true);
  });

  it('redacts SARIF by default and supports an explicit raw report', () => {
    const result = scanSecretsFixture();
    const redactedSarif = JSON.stringify(buildSarifReport([result]));
    const rawSarif = JSON.stringify(buildSarifReport([result], { redact: false }));

    assert.ok(!redactedSarif.includes(secret));
    assert.ok(redactedSarif.includes('[REDACTED]'));
    assert.ok(rawSarif.includes(secret));
  });

  it('redacts authorization headers, URL credentials, and private-key headers', () => {
    const text = [
      'Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456',
      'curl https://user:supersecret@example.com/path',
      '-----BEGIN OPENSSH PRIVATE KEY-----',
    ].join('\n');
    const redacted = redactText(text);

    assert.ok(!redacted.includes('abcdefghijklmnopqrstuvwxyz123456'));
    assert.ok(!redacted.includes('supersecret'));
    assert.ok(!redacted.includes('BEGIN OPENSSH PRIVATE KEY'));
    assert.ok(redacted.includes('[REDACTED]'));
    assert.ok(redacted.includes('[REDACTED PRIVATE KEY]'));
  });

  it('emits line-stable SARIF fingerprints shared with baselines', () => {
    const content = [
      '---',
      'name: fingerprint-demo',
      '---',
      '```bash',
      'cat ~/.ssh/id_rsa',
      '```',
    ].join('\n');
    const shiftedContent = `\n\n${content}`;
    const first = scanSkillContent(content, 'skills/fingerprint-demo.md');
    const shifted = scanSkillContent(shiftedContent, 'skills/fingerprint-demo.md');
    const firstFinding = first.findings.find((finding) => finding.ruleId === 'SEC-CRED-001');
    const shiftedFinding = shifted.findings.find((finding) => finding.ruleId === 'SEC-CRED-001');

    assert.ok(firstFinding);
    assert.ok(shiftedFinding);
    assert.notEqual(firstFinding.line, shiftedFinding.line);

    const firstResult = buildSarifReport([first]).runs[0].results.find(
      (result) => result.ruleId === 'SEC-CRED-001',
    );
    const shiftedResult = buildSarifReport([shifted]).runs[0].results.find(
      (result) => result.ruleId === 'SEC-CRED-001',
    );
    const baseline = createBaseline([first]);

    assert.ok(firstResult);
    assert.ok(shiftedResult);
    assert.match(firstResult.partialFingerprints['agentwarden/v1'], /^[a-f0-9]{64}$/);
    assert.equal(
      firstResult.partialFingerprints['agentwarden/v1'],
      shiftedResult.partialFingerprints['agentwarden/v1'],
    );
    assert.equal(
      firstResult.partialFingerprints['agentwarden/v1'],
      baseline.entries.find((entry) => entry.ruleId === 'SEC-CRED-001')?.fingerprint,
    );
  });
});
