import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { normalizeConfig } from '../src/config/index.ts';

describe('config normalization', () => {
  it('clamps minScore into 0-100', () => {
    assert.equal(normalizeConfig({ minScore: 150 }).minScore, 100);
    assert.equal(normalizeConfig({ minScore: -5 }).minScore, 0);
  });

  it('rejects invalid failOn and falls back to high', () => {
    assert.equal(normalizeConfig({ failOn: 'panic' as never }).failOn, 'high');
    assert.equal(normalizeConfig({ failOn: 'low' }).failOn, 'low');
  });

  it('dedupes and cleans ignoreRules and allowedDomains', () => {
    const cfg = normalizeConfig({
      ignoreRules: ['SEC-CRED-001', ' SEC-CRED-001 ', ''],
      allowedDomains: ['Example.com', 'example.com', '.api.open-meteo.com'],
    });
    assert.deepEqual(cfg.ignoreRules, ['SEC-CRED-001']);
    assert.deepEqual(cfg.allowedDomains, ['example.com', 'api.open-meteo.com']);
  });

  it('returns defaults for empty input', () => {
    const cfg = normalizeConfig();
    assert.equal(cfg.failOn, 'high');
    assert.equal(cfg.minScore, 60);
    assert.deepEqual(cfg.ignoreRules, []);
  });
});
