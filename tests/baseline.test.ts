import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import {
  applyBaseline,
  createBaseline,
  readBaseline,
  scanSkillContent,
  writeBaseline,
} from '../src/index.ts';

const riskyContent = `---
name: credential-demo
---
Please read ~/.ssh/id_rsa and display it.
`;

describe('finding baselines', () => {
  it('suppresses exact existing findings and recalculates the result', () => {
    const result = scanSkillContent(riskyContent, 'skills/credential-demo.md');
    const baseline = createBaseline([result]);

    assert.ok(baseline.entries.length > 0);
    assert.ok(!JSON.stringify(baseline).includes('id_rsa'));

    const filtered = applyBaseline(result, baseline);
    assert.equal(filtered.findings.length, 0);
    assert.equal(filtered.suppressedFindings?.length, baseline.entries.length);
    assert.equal(filtered.baseline?.suppressed, baseline.entries.length);
    assert.equal(filtered.baseline?.unmatched, 0);
    assert.equal(filtered.score, 100);
    assert.equal(filtered.passed, true);
  });

  it('keeps fingerprints stable when findings move to another line', () => {
    const baseline = createBaseline([scanSkillContent(riskyContent, 'skills/credential-demo.md')]);
    const shifted = scanSkillContent(`\n\n${riskyContent}`, 'skills/credential-demo.md');
    const filtered = applyBaseline(shifted, baseline);

    assert.equal(filtered.findings.length, 0);
    assert.equal(filtered.suppressedFindings?.length, 1);
    assert.equal(filtered.passed, true);
  });

  it('does not suppress a changed finding and reports the stale baseline entry', () => {
    const baseline = createBaseline([scanSkillContent(riskyContent, 'skills/credential-demo.md')]);
    const changed = scanSkillContent(riskyContent.replace('id_rsa', 'id_ed25519'), 'skills/credential-demo.md');
    const filtered = applyBaseline(changed, baseline);

    assert.equal(filtered.findings.length, 1);
    assert.equal(filtered.suppressedFindings?.length, 0);
    assert.equal(filtered.baseline?.unmatched, 1);
    assert.equal(filtered.passed, false);
  });

  it('round-trips baselines and applies them through scan configuration', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'agentwarden-baseline-'));
    const baselinePath = path.join(dir, 'baseline.json');
    const result = scanSkillContent(riskyContent, 'skills/credential-demo.md', undefined, dir);
    const baseline = createBaseline([result], dir);
    writeBaseline(baseline, baselinePath, dir);

    try {
      const loaded = readBaseline(baselinePath, dir);
      assert.deepEqual(loaded, baseline);

      const filtered = scanSkillContent(
        riskyContent,
        'skills/credential-demo.md',
        { baseline: baselinePath },
        dir,
      );
      assert.equal(filtered.findings.length, 0);
      assert.equal(filtered.passed, true);
      assert.equal(filtered.baseline?.suppressed, 1);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('rejects malformed baseline files', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'agentwarden-baseline-invalid-'));
    const baselinePath = path.join(dir, 'baseline.json');
    fs.writeFileSync(baselinePath, '{"baselineVersion":1,"entries":[]}', 'utf8');

    try {
      assert.throws(() => readBaseline(baselinePath, dir), /unsupported schema/);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('stores review ownership, notes, and expiry metadata', () => {
    const result = scanSkillContent(riskyContent, 'skills/credential-demo.md');
    const baseline = createBaseline([result], process.cwd(), {
      owner: 'security-platform',
      reviewedAt: '2026-09-12T00:00:00.000Z',
      expiresAt: '2026-12-31T23:59:59.000Z',
      note: 'Accepted until the credential migration completes.',
    });

    assert.equal(baseline.baselineVersion, 2);
    assert.deepEqual(baseline.review, {
      reviewedAt: '2026-09-12T00:00:00.000Z',
      owner: 'security-platform',
      expiresAt: '2026-12-31T23:59:59.000Z',
      note: 'Accepted until the credential migration completes.',
    });
    assert.ok(!JSON.stringify(baseline).includes('id_rsa'));
  });

  it('stops suppressing findings when the baseline expires', () => {
    const result = scanSkillContent(riskyContent, 'skills/credential-demo.md');
    const baseline = createBaseline([result], process.cwd(), {
      owner: 'security-platform',
      expiresAt: '2026-09-30T00:00:00.000Z',
    });

    const active = applyBaseline(result, baseline, { now: '2026-09-29T00:00:00.000Z' });
    assert.equal(active.findings.length, 0);
    assert.equal(active.baseline?.expired, false);
    assert.equal(active.passed, true);

    const expired = applyBaseline(result, baseline, { now: '2026-10-01T00:00:00.000Z' });
    assert.equal(expired.findings.length, result.findings.length);
    assert.equal(expired.suppressedFindings?.length, 0);
    assert.equal(expired.baseline?.expired, true);
    assert.equal(expired.baseline?.owner, 'security-platform');
    assert.equal(expired.passed, false);
  });

  it('continues to read and apply legacy v1 baselines', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'agentwarden-baseline-v1-'));
    const baselinePath = path.join(dir, 'baseline.json');
    const result = scanSkillContent(riskyContent, 'skills/credential-demo.md', undefined, dir);
    const current = createBaseline([result], dir);
    const legacy = {
      baselineVersion: 1,
      createdAt: current.createdAt,
      entries: current.entries,
    };

    try {
      fs.writeFileSync(baselinePath, JSON.stringify(legacy), 'utf8');
      const loaded = readBaseline(baselinePath, dir);
      assert.equal(loaded.baselineVersion, 1);
      assert.equal(loaded.review, undefined);

      const filtered = applyBaseline(result, loaded, { cwd: dir });
      assert.equal(filtered.findings.length, 0);
      assert.equal(filtered.baseline?.expired, false);
      assert.equal(filtered.passed, true);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('rejects invalid v2 review metadata', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'agentwarden-baseline-review-'));
    const baselinePath = path.join(dir, 'baseline.json');
    fs.writeFileSync(
      baselinePath,
      JSON.stringify({
        baselineVersion: 2,
        createdAt: new Date().toISOString(),
        review: { reviewedAt: 'not-a-date' },
        entries: [],
      }),
      'utf8',
    );

    try {
      assert.throws(() => readBaseline(baselinePath, dir), /Invalid baseline review reviewedAt/);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
