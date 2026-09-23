import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  createFindingFingerprints,
  normalizeFindingPath,
  scanSkillContent,
} from '../src/index.ts';
import * as path from 'node:path';

describe('finding fingerprints', () => {
  it('keeps duplicate occurrences unique and stable across line shifts', () => {
    const content = [
      '---',
      'name: duplicate-findings',
      '---',
      '```bash',
      'cat ~/.ssh/id_rsa',
      'cat ~/.ssh/id_rsa',
      '```',
    ].join('\n');
    const shiftedContent = `\n\n${content}`;
    const first = scanSkillContent(content, 'skills/duplicate-findings.md');
    const shifted = scanSkillContent(shiftedContent, 'skills/duplicate-findings.md');
    const firstFingerprints = createFindingFingerprints(first.filePath, first.findings);
    const shiftedFingerprints = createFindingFingerprints(shifted.filePath, shifted.findings);

    assert.equal(firstFingerprints.length, 2);
    assert.notEqual(firstFingerprints[0], firstFingerprints[1]);
    assert.deepEqual(firstFingerprints, shiftedFingerprints);
  });

  it('keeps dot-prefixed relative filenames relative to the scan root', () => {
    const absolute = path.resolve(process.cwd(), '..hidden.md');
    assert.equal(normalizeFindingPath(absolute, process.cwd()), '..hidden.md');
  });
});
