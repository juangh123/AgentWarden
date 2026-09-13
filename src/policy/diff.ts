import { normalizeConfig, type SkillGuardConfig } from '../config/index.ts';

export type PolicyDiffKind = 'added' | 'removed' | 'changed';

export interface PolicyDiffChange {
  field: string;
  key?: string;
  kind: PolicyDiffKind;
  before?: string | number | boolean | null;
  after?: string | number | boolean | null;
}

export interface PolicyDiff {
  changed: boolean;
  changes: PolicyDiffChange[];
}

function compareScalar(
  changes: PolicyDiffChange[],
  field: string,
  before: string | number | boolean | null | undefined,
  after: string | number | boolean | null | undefined,
): void {
  const normalizedBefore = before ?? null;
  const normalizedAfter = after ?? null;
  if (normalizedBefore !== normalizedAfter) {
    changes.push({
      field,
      kind: 'changed',
      before: normalizedBefore,
      after: normalizedAfter,
    });
  }
}

function compareList(
  changes: PolicyDiffChange[],
  field: string,
  beforeValues: string[],
  afterValues: string[],
): void {
  const before = new Set(beforeValues);
  const after = new Set(afterValues);
  const keys = [...new Set([...before, ...after])].sort();

  for (const key of keys) {
    if (!before.has(key)) {
      changes.push({ field, key, kind: 'added', after: key });
    } else if (!after.has(key)) {
      changes.push({ field, key, kind: 'removed', before: key });
    }
  }
}

function compareSeverityOverrides(
  changes: PolicyDiffChange[],
  beforeValues: Record<string, string>,
  afterValues: Record<string, string>,
): void {
  const keys = [...new Set([...Object.keys(beforeValues), ...Object.keys(afterValues)])].sort();

  for (const key of keys) {
    const before = beforeValues[key];
    const after = afterValues[key];
    if (before === undefined) {
      changes.push({ field: 'severityOverrides', key, kind: 'added', after });
    } else if (after === undefined) {
      changes.push({ field: 'severityOverrides', key, kind: 'removed', before });
    } else if (before !== after) {
      changes.push({ field: 'severityOverrides', key, kind: 'changed', before, after });
    }
  }
}

/** Compare two raw or normalized policy configurations by their effective values. */
export function diffPolicyConfigs(from: SkillGuardConfig, to: SkillGuardConfig): PolicyDiff {
  const before = normalizeConfig(from);
  const after = normalizeConfig(to);
  const changes: PolicyDiffChange[] = [];

  compareScalar(changes, 'profile', before.profile, after.profile);
  compareScalar(changes, 'failOn', before.failOn, after.failOn);
  compareScalar(changes, 'minScore', before.minScore, after.minScore);
  compareScalar(changes, 'baseline', before.baseline, after.baseline);
  compareScalar(
    changes,
    'publishers.requireSignature',
    before.publishers?.requireSignature ?? false,
    after.publishers?.requireSignature ?? false,
  );
  compareList(changes, 'ignoreRules', before.ignoreRules ?? [], after.ignoreRules ?? []);
  compareList(changes, 'allowedDomains', before.allowedDomains ?? [], after.allowedDomains ?? []);
  compareList(
    changes,
    'publishers.trustedKeys',
    before.publishers?.trustedKeys ?? [],
    after.publishers?.trustedKeys ?? [],
  );
  compareList(
    changes,
    'publishers.revokedKeys',
    before.publishers?.revokedKeys ?? [],
    after.publishers?.revokedKeys ?? [],
  );
  compareList(changes, 'include', before.include ?? [], after.include ?? []);
  compareList(changes, 'exclude', before.exclude ?? [], after.exclude ?? []);
  compareSeverityOverrides(
    changes,
    before.severityOverrides ?? {},
    after.severityOverrides ?? {},
  );

  return {
    changed: changes.length > 0,
    changes,
  };
}
