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
});
