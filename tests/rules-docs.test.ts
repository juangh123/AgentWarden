import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { allRules } from '../src/index.ts';

describe('rule catalog documentation', () => {
  it('documents every rule ID and the current rule count', () => {
    const document = fs.readFileSync(path.resolve(process.cwd(), 'docs/rules.md'), 'utf8');

    assert.match(
      document,
      new RegExp(`AgentWarden ships ${allRules.length} static analysis rules`),
    );
    assert.equal(new Set(allRules.map((rule) => rule.id)).size, allRules.length);

    for (const rule of allRules) {
      assert.ok(document.includes(`| \`${rule.id}\` |`), `missing table row for ${rule.id}`);
      assert.ok(
        new RegExp(`^## ${rule.id}$`, 'm').test(document),
        `missing section for ${rule.id}`,
      );
    }
  });
});
