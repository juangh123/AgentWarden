import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import {
  ConfigError,
  POLICY_PROFILES,
  loadConfigWithMetadata,
  normalizeConfig,
} from '../src/config/index.ts';

function tempDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'agentwarden-config-'));
}

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

  it('normalizes publisher trust and keeps revocation authoritative', () => {
    const trusted = 'A'.repeat(64);
    const revoked = 'b'.repeat(64);
    const cfg = normalizeConfig({
      publishers: {
        requireSignature: true,
        trustedKeys: [trusted, `sha256:${revoked}`, trusted],
        revokedKeys: [revoked],
      },
    });

    assert.equal(cfg.publishers?.requireSignature, true);
    assert.deepEqual(cfg.publishers?.trustedKeys, [trusted.toLowerCase()]);
    assert.deepEqual(cfg.publishers?.revokedKeys, [revoked]);
  });

  it('fails closed on malformed publisher policy fields', () => {
    assert.throws(
      () =>
        normalizeConfig({
          publishers: { requireSignature: 'yes' as never },
        }),
      (error) => error instanceof ConfigError && error.message.includes('requireSignature'),
    );
    assert.throws(
      () =>
        normalizeConfig({
          publishers: { trustedKeys: ['not-a-fingerprint'] },
        }),
      (error) => error instanceof ConfigError && error.message.includes('trustedKeys'),
    );
  });

  it('loads an explicit config with source metadata', () => {
    const root = tempDir();
    try {
      fs.mkdirSync(path.join(root, 'config'));
      fs.writeFileSync(
        path.join(root, 'config', 'policy.json'),
        JSON.stringify({
          profile: 'strict',
          include: ['skills/**'],
          exclude: ['skills/vendor/**'],
        }),
        'utf8',
      );

      const loaded = loadConfigWithMetadata(root, 'config/policy.json');
      assert.equal(loaded.explicit, true);
      assert.equal(loaded.source, path.join(root, 'config', 'policy.json'));
      assert.deepEqual(loaded.sources, [path.join(root, 'config', 'policy.json')]);
      assert.equal(loaded.config.profile, 'strict');
      assert.equal(loaded.config.failOn, 'medium');
      assert.equal(loaded.config.minScore, 90);
      assert.deepEqual(loaded.config.include, ['skills/**']);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  it('fails closed when an explicit config is missing or malformed', () => {
    const root = tempDir();
    try {
      assert.throws(
        () => loadConfigWithMetadata(root, 'missing.json'),
        (error) => error instanceof ConfigError && error.message.includes('Config file not found'),
      );

      const malformed = path.join(root, 'malformed.json');
      fs.writeFileSync(malformed, '{"profile":', 'utf8');
      assert.throws(
        () => loadConfigWithMetadata(root, 'malformed.json'),
        (error) => error instanceof ConfigError && error.message.includes('Invalid config file'),
      );

      const arrayConfig = path.join(root, 'array.json');
      fs.writeFileSync(arrayConfig, '[]', 'utf8');
      assert.throws(
        () => loadConfigWithMetadata(root, 'array.json'),
        (error) => error instanceof ConfigError && error.message.includes('JSON object'),
      );
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  it('tracks implicit config sources and preserves malformed implicit fallback', () => {
    const root = tempDir();
    try {
      const implicit = path.join(root, '.wardenrc.json');
      fs.writeFileSync(implicit, JSON.stringify({ profile: 'balanced' }), 'utf8');
      const loaded = loadConfigWithMetadata(root);
      assert.equal(loaded.explicit, false);
      assert.equal(loaded.source, implicit);
      assert.deepEqual(loaded.sources, [implicit]);
      assert.equal(loaded.config.profile, 'balanced');
      assert.equal(loaded.config.minScore, 80);

      fs.writeFileSync(implicit, '{"profile":', 'utf8');
      const fallback = loadConfigWithMetadata(root);
      assert.equal(fallback.source, undefined);
      assert.deepEqual(fallback.sources, []);
      assert.equal(fallback.config.profile, 'legacy');
      assert.equal(fallback.config.minScore, 60);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  it('merges extended configs from parent to child with additive policy lists', () => {
    const root = tempDir();
    try {
      fs.mkdirSync(path.join(root, 'config'));
      const base = path.join(root, 'config', 'base.json');
      const child = path.join(root, 'config', 'child.json');
      fs.writeFileSync(
        base,
        JSON.stringify({
          profile: 'strict',
          ignoreRules: ['SEC-INJ-002'],
          allowedDomains: ['example.com'],
          publishers: {
            requireSignature: true,
            trustedKeys: ['a'.repeat(64)],
          },
          include: ['skills/**'],
          severityOverrides: { 'SEC-CRED-003': 'medium' },
        }),
        'utf8',
      );
      fs.writeFileSync(
        child,
        JSON.stringify({
          extends: './base.json',
          exclude: ['skills/vendor/**'],
          publishers: {
            revokedKeys: ['b'.repeat(64)],
          },
          severityOverrides: { 'SEC-INJ-002': 'low' },
        }),
        'utf8',
      );

      const loaded = loadConfigWithMetadata(root, 'config/child.json');
      assert.equal(loaded.source, child);
      assert.deepEqual(loaded.sources, [base, child]);
      assert.equal(loaded.config.profile, 'strict');
      assert.equal(loaded.config.failOn, 'medium');
      assert.equal(loaded.config.minScore, 90);
      assert.deepEqual(loaded.config.ignoreRules, ['SEC-INJ-002']);
      assert.deepEqual(loaded.config.allowedDomains, ['example.com']);
      assert.equal(loaded.config.publishers?.requireSignature, true);
      assert.deepEqual(loaded.config.publishers?.trustedKeys, ['a'.repeat(64)]);
      assert.deepEqual(loaded.config.publishers?.revokedKeys, ['b'.repeat(64)]);
      assert.deepEqual(loaded.config.include, ['skills/**']);
      assert.deepEqual(loaded.config.exclude, ['skills/vendor/**']);
      assert.deepEqual(loaded.config.severityOverrides, {
        'SEC-CRED-003': 'medium',
        'SEC-INJ-002': 'low',
      });
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  it('supports multiple parents, child overrides, and cycle detection', () => {
    const root = tempDir();
    try {
      const first = path.join(root, 'first.json');
      const second = path.join(root, 'second.json');
      const child = path.join(root, 'child.json');
      fs.writeFileSync(first, JSON.stringify({ profile: 'balanced', minScore: 70 }), 'utf8');
      fs.writeFileSync(second, JSON.stringify({ profile: 'strict' }), 'utf8');
      fs.writeFileSync(
        child,
        JSON.stringify({ extends: ['./first.json', './second.json'], minScore: 85 }),
        'utf8',
      );

      const loaded = loadConfigWithMetadata(root, 'child.json');
      assert.deepEqual(loaded.sources, [first, second, child]);
      assert.equal(loaded.config.profile, 'strict');
      assert.equal(loaded.config.failOn, 'medium');
      assert.equal(loaded.config.minScore, 85);

      const cycleA = path.join(root, 'cycle-a.json');
      const cycleB = path.join(root, 'cycle-b.json');
      fs.writeFileSync(cycleA, JSON.stringify({ extends: './cycle-b.json' }), 'utf8');
      fs.writeFileSync(cycleB, JSON.stringify({ extends: './cycle-a.json' }), 'utf8');
      assert.throws(
        () => loadConfigWithMetadata(root, 'cycle-a.json'),
        (error) => error instanceof ConfigError && error.message.includes('Circular config extends chain'),
      );

      const missingParent = path.join(root, 'missing-parent.json');
      fs.writeFileSync(missingParent, JSON.stringify({ extends: './does-not-exist.json' }), 'utf8');
      assert.throws(
        () => loadConfigWithMetadata(root, 'missing-parent.json'),
        (error) => error instanceof ConfigError && error.message.includes('Config file not found'),
      );

      const invalidExtends = path.join(root, 'invalid-extends.json');
      fs.writeFileSync(invalidExtends, JSON.stringify({ extends: 42 }), 'utf8');
      assert.throws(
        () => loadConfigWithMetadata(root, 'invalid-extends.json'),
        (error) => error instanceof ConfigError && error.message.includes('Invalid "extends"'),
      );
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });
});
