import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { POLICY_PROFILES, normalizeConfig } from '../src/config/index.ts';

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
      baseline: ' .agentwarden-baseline.json ',
      severityOverrides: {
        'sec-cred-001': 'medium',
        'SEC-INJ-002': 'low',
        invalid: 'panic' as never,
      },
    });
    assert.deepEqual(cfg.ignoreRules, ['SEC-CRED-001']);
    assert.deepEqual(cfg.allowedDomains, ['example.com', 'api.open-meteo.com']);
    assert.equal(cfg.baseline, '.agentwarden-baseline.json');
    assert.deepEqual(cfg.severityOverrides, {
      'SEC-CRED-001': 'medium',
      'SEC-INJ-002': 'low',
    });
  });

  it('returns defaults for empty input', () => {
    const cfg = normalizeConfig();
    assert.equal(cfg.profile, 'legacy');
    assert.equal(cfg.failOn, 'high');
    assert.equal(cfg.minScore, 60);
    assert.deepEqual(cfg.ignoreRules, []);
    assert.deepEqual(cfg.include, []);
    assert.deepEqual(cfg.exclude, []);
  });

  it('applies policy profile defaults and preserves explicit threshold overrides', () => {
    assert.deepEqual(POLICY_PROFILES.legacy, { failOn: 'high', minScore: 60 });
    assert.deepEqual(POLICY_PROFILES.balanced, { failOn: 'high', minScore: 80 });
    assert.deepEqual(POLICY_PROFILES.strict, { failOn: 'medium', minScore: 90 });

    const balanced = normalizeConfig({ profile: 'balanced' });
    assert.equal(balanced.failOn, 'high');
    assert.equal(balanced.minScore, 80);

    const strict = normalizeConfig({ profile: 'strict' });
    assert.equal(strict.failOn, 'medium');
    assert.equal(strict.minScore, 90);

    const overridden = normalizeConfig({
      profile: 'strict',
      failOn: 'critical',
      minScore: 75,
    });
    assert.equal(overridden.profile, 'strict');
    assert.equal(overridden.failOn, 'critical');
    assert.equal(overridden.minScore, 75);
  });

  it('normalizes include and exclude path patterns', () => {
    const cfg = normalizeConfig({
      include: [' skills/** ', 'skills/**', ''],
      exclude: ['skills/private/**', ' skills/private/** '],
    });
    assert.deepEqual(cfg.include, ['skills/**']);
    assert.deepEqual(cfg.exclude, ['skills/private/**']);
  });
});
