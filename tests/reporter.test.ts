import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import {
  buildSarifReport,
  createBaseline,
  redactText,
  redactReportValue,
  renderScanReports,
  scanSkillContent,
  toReportScanResult,
  type ScanResult,
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

  it('withholds code fence bodies from the default report but keeps them under --no-redact', () => {
    const content = [
      '---',
      'name: code-fence-redaction',
      '---',
      '',
      '```js',
      'const dbPassword = "hunter2-prod-value";',
      '```',
      '',
    ].join('\n');
    const result = scanSkillContent(content, 'code-fence-redaction.md');

    const report = toReportScanResult(result);
    assert.equal(report.parsedSkill.codeBlocks[0].code, '[REDACTED CODE]');
    assert.equal(report.parsedSkill.codeBlocks[0].language, 'js');
    assert.ok(!JSON.stringify(report).includes('hunter2-prod-value'));

    const raw = toReportScanResult(result, { redact: false });
    assert.ok(raw.parsedSkill.codeBlocks[0].code.includes('hunter2-prod-value'));
  });

  it('strips terminal control characters while keeping tabs and newlines', () => {
    const escaped = redactText(`evil\u001b[2Jhere\u001b]0;title\u0007end`);
    assert.ok(!/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/.test(escaped));
    assert.equal(escaped, 'evil[2Jhere]0;titleend');
    assert.equal(redactText('a\tb\nc'), 'a\tb\nc');
  });

  it('removes URL fragments as well as credentials and sensitive query parameters', () => {
    const redacted = redactText(
      'https://user:pass@example.com/x?token=abc123&safe=1#fragment-secret',
    );
    assert.ok(!redacted.includes('user:pass'));
    assert.ok(!redacted.includes('abc123'));
    assert.ok(!redacted.includes('fragment-secret'));
    assert.ok(redacted.includes('safe=1'));
  });

  it('redacts camelCase secret assignments that a keyword-only match would miss', () => {
    assert.equal(redactText('const dbPassword = "hunter2-prod";'), 'const dbPassword = "[REDACTED]";');
    assert.equal(
      redactText('const apiAccessToken = "zzz-live-token-value";'),
      'const apiAccessToken = "[REDACTED]";',
    );
    assert.equal(redactText('const apiKey = "${API_KEY}";'), 'const apiKey = "${API_KEY}";');
  });

  it('redacts authorization headers, URL credentials, and private-key headers', () => {
    const text = [
      'Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456',
      'curl https://user:supersecret@example.com/path',
      'curl https://:passwordonly@example.com/path',
      '-----BEGIN OPENSSH PRIVATE KEY-----',
    ].join('\n');
    const redacted = redactText(text);

    assert.ok(!redacted.includes('abcdefghijklmnopqrstuvwxyz123456'));
    assert.ok(!redacted.includes('supersecret'));
    assert.ok(!redacted.includes('passwordonly'));
    assert.ok(!redacted.includes('BEGIN OPENSSH PRIVATE KEY'));
    assert.ok(redacted.includes('[REDACTED]'));
    assert.ok(redacted.includes('[REDACTED PRIVATE KEY]'));
  });

  it('redacts credentials in URL query parameters without removing safe parameters', () => {
    const querySecret = 'QUERY_SECRET_1234567890';
    const text = [
      `https://example.com/mcp?api_key=${querySecret}&mode=safe`,
      `https://example.com/callback#access_token=${querySecret}&mode=safe`,
      `https://example.com/artifact?signature=${querySecret}&mode=safe`,
      `api_key=${querySecret}&token=ANOTHER_SECRET`,
    ].join('\n');
    const redacted = redactText(text);

    assert.ok(!redacted.includes(querySecret));
    assert.ok(!redacted.includes('ANOTHER_SECRET'));
    assert.ok(redacted.includes('mode=safe'));
    assert.ok(redacted.includes('[REDACTED]') || redacted.includes('%5BREDACTED%5D'));
  });

  it('redacts nested report metadata values', () => {
    const secret = 'X-Amz-CREDENTIAL-1234567890';
    const redacted = redactReportValue({
      source: {
        resolvedUrl: `https://example.com/artifact?X-Amz-Signature=${secret}&safe=yes`,
      },
    });

    assert.ok(!JSON.stringify(redacted).includes(secret));
    assert.ok(JSON.stringify(redacted).includes('safe=yes'));
  });

  it('keeps signature fingerprints while redacting signature sources', () => {
    const sourceSecret = 'SIGNATURE_SOURCE_SECRET_1234567890';
    const keySha256 = 'a'.repeat(64);
    const signatureSha256 = 'b'.repeat(64);
    const redacted = redactReportValue({
      signature: {
        algorithm: 'ed25519',
        verified: true,
        keySha256,
        signatureSha256,
        signatureSource: `https://example.com/publisher.sig?signature=${sourceSecret}`,
      },
    });

    assert.equal(redacted.signature.algorithm, 'ed25519');
    assert.equal(redacted.signature.verified, true);
    assert.equal(redacted.signature.keySha256, keySha256);
    assert.equal(redacted.signature.signatureSha256, signatureSha256);
    assert.ok(!redacted.signature.signatureSource.includes(sourceSecret));
  });

  it('redacts query credentials from default report projections', () => {
    const querySecret = 'QUERY_SECRET_REPORT_1234567890';
    const result = scanSkillContent(
      JSON.stringify({
        mcpServers: {
          example: {
            url: `https://example.com/mcp?api_key=${querySecret}&safe=yes`,
          },
        },
      }),
      '.mcp.json',
    );
    const serialized = JSON.stringify(toReportScanResult(result));

    assert.ok(!serialized.includes(querySecret));
    assert.ok(serialized.includes('safe=yes'));
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

describe('pretty report rendering', () => {
  function capture(run: () => void): string {
    const lines: string[] = [];
    const original = console.log;
    console.log = (...args: unknown[]) => {
      lines.push(args.map((value) => String(value)).join(' '));
    };
    try {
      run();
    } finally {
      console.log = original;
    }
    return lines.join('\n');
  }

  function baseResult(overrides: Partial<ScanResult> = {}): ScanResult {
    return {
      filePath: 'skills/pretty-demo.md',
      parsedSkill: {
        name: 'pretty-demo',
        description: 'renders a pretty report',
        frontmatter: {},
        promptText: '',
        codeBlocks: [],
        rawContent: '',
      },
      findings: [],
      score: 100,
      passed: true,
      sha256: 'a'.repeat(64),
      ...overrides,
    };
  }

  it('renders findings, remediation, and a blocked footer', () => {
    const result = scanSkillContent(
      ['---', 'name: pretty-blocked', '---', '', '```bash', 'cat ~/.ssh/id_rsa', '```'].join('\n'),
      'skills/pretty-blocked.md',
    );
    const output = capture(() => renderScanReports([result], 'pretty'));

    assert.match(output, /AgentWarden Security Scan Report/);
    assert.match(output, /Skill Name:/);
    assert.match(output, /Safety Score:/);
    assert.match(output, /Remediation:/);
    assert.match(output, /\[BLOCKED\]/);
  });

  it('renders the tolerated-warning footer and the multi-skill summary', () => {
    const tolerated = baseResult({
      findings: [
        {
          ruleId: 'SEC-INJ-003',
          title: 'Encoded payload',
          category: 'prompt_injection',
          severity: 'low',
          description: 'obfuscated construct',
          line: 3,
          snippet: 'atob("...")',
          suggestion: 'Use plain text.',
        },
      ],
      score: 95,
      passed: true,
    });
    const blocked = baseResult({
      filePath: 'skills/b.md',
      findings: [
        {
          ruleId: 'SEC-CRED-001',
          title: 'Credential file access',
          category: 'credential',
          severity: 'critical',
          description: 'reads a private key',
        },
      ],
      score: 60,
      passed: false,
    });
    const output = capture(() => renderScanReports([tolerated, blocked], 'pretty'));

    assert.match(output, /Warnings found, but within tolerable policy threshold/);
    assert.match(output, /Scan Summary: 2 skills scanned, 1 passed, 1 blocked/);
  });

  it('annotates accepted and expired baselines', () => {
    const suppressed = baseResult({
      score: 100,
      passed: true,
      suppressedFindings: [],
      baseline: { path: '.agentwarden-baseline.json', suppressed: 2, unmatched: 1, expiresAt: '2027-01-01' },
    });
    const accepted = capture(() => renderScanReports([suppressed], 'pretty'));
    assert.match(accepted, /Baseline:\s+\.agentwarden-baseline\.json/);
    assert.match(accepted, /No new findings; 2 baseline finding\(s\) were accepted/);

    const expired = baseResult({
      baseline: { path: '.agentwarden-baseline.json', suppressed: 0, unmatched: 3, expired: true },
    });
    const expiredOutput = capture(() => renderScanReports([expired], 'pretty'));
    assert.match(expiredOutput, /baseline has expired/);
  });

  it('maps low and info severities into SARIF levels and scores', () => {
    const result = baseResult({
      findings: [
        {
          ruleId: 'SEC-INJ-003',
          title: 'Low severity',
          category: 'prompt_injection',
          severity: 'low',
          description: 'low',
        },
        {
          ruleId: 'SEC-INJ-003',
          title: 'Info severity',
          category: 'prompt_injection',
          severity: 'info',
          description: 'info',
        },
      ],
      passed: false,
    });
    const sarif = buildSarifReport([result]);
    const levels = sarif.runs[0].results.map((entry: { level: string }) => entry.level);
    assert.ok(levels.includes('note'));
    const rule = sarif.runs[0].tool.driver.rules[0] as { properties: { 'security-severity': string } };
    assert.ok(['1.0', '3.0'].includes(rule.properties['security-severity']));
  });
});
