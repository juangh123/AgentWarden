import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { diffPolicyConfigs } from '../src/policy/diff.ts';

describe('policy diff', () => {
  it('treats normalized profile defaults as equivalent', () => {
    const diff = diffPolicyConfigs(
      { profile: 'strict' },
      { profile: 'strict', failOn: 'medium', minScore: 90 },
    );

    assert.equal(diff.changed, false);
    assert.deepEqual(diff.changes, []);
  });

  it('reports scalar, list, and severity override changes in stable order', () => {
    const diff = diffPolicyConfigs(
      {
        profile: 'legacy',
        ignoreRules: ['SEC-INJ-002'],
        allowedDomains: ['old.example'],
        include: ['skills/**'],
        severityOverrides: { 'SEC-CRED-003': 'high' },
      },
      {
        profile: 'strict',
        ignoreRules: ['SEC-INJ-003'],
        allowedDomains: ['old.example', 'new.example'],
        exclude: ['vendor/**'],
        severityOverrides: {
          'SEC-CRED-003': 'medium',
          'SEC-MCP-001': 'critical',
        },
      },
    );

    assert.equal(diff.changed, true);
    assert.deepEqual(diff.changes, [
      { field: 'profile', kind: 'changed', before: 'legacy', after: 'strict' },
      { field: 'failOn', kind: 'changed', before: 'high', after: 'medium' },
      { field: 'minScore', kind: 'changed', before: 60, after: 90 },
      { field: 'ignoreRules', key: 'SEC-INJ-002', kind: 'removed', before: 'SEC-INJ-002' },
      { field: 'ignoreRules', key: 'SEC-INJ-003', kind: 'added', after: 'SEC-INJ-003' },
      { field: 'allowedDomains', key: 'new.example', kind: 'added', after: 'new.example' },
      { field: 'include', key: 'skills/**', kind: 'removed', before: 'skills/**' },
      { field: 'exclude', key: 'vendor/**', kind: 'added', after: 'vendor/**' },
      {
        field: 'severityOverrides',
        key: 'SEC-CRED-003',
        kind: 'changed',
        before: 'high',
        after: 'medium',
      },
      {
        field: 'severityOverrides',
        key: 'SEC-MCP-001',
        kind: 'added',
        after: 'critical',
      },
    ]);
  });

  it('reports baseline changes with explicit null values', () => {
    const diff = diffPolicyConfigs(
      {},
      { baseline: '.agentwarden-baseline.json' },
    );

    assert.deepEqual(diff.changes, [
      {
        field: 'baseline',
        kind: 'changed',
        before: null,
        after: '.agentwarden-baseline.json',
      },
    ]);
  });
});
