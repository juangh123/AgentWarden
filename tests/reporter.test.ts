import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import {
  buildSarifReport,
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
});
