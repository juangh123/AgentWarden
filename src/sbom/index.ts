import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { normalizeConfig, type SkillGuardConfig } from '../config/index.ts';
import {
  readLockfile,
  resolveFromRoot,
  type LockedSkill,
  type LockfileSchema,
} from '../manifest/lockfile.ts';
import { scanSkillContent } from '../scanner/index.ts';
import { inspectInstalledSkillPackage } from '../source/package.ts';
import {
  evaluatePublisherPolicy,
  type PublisherPolicyDecision,
} from '../source/provenance.ts';
import { readPackageVersion } from '../version.ts';

export interface CycloneDxHash {
  alg: 'SHA-256';
  content: string;
}

export interface CycloneDxProperty {
  name: string;
  value: string;
}

export interface CycloneDxExternalReference {
  type: 'distribution';
  url: string;
}

export interface CycloneDxComponent {
  type: 'application' | 'library' | 'file';
  'bom-ref': string;
  name: string;
  version?: string;
  scope?: 'required';
  hashes?: CycloneDxHash[];
  properties?: CycloneDxProperty[];
  externalReferences?: CycloneDxExternalReference[];
  components?: CycloneDxComponent[];
}

export interface CycloneDxDependency {
  ref: string;
  dependsOn?: string[];
}

export interface CycloneDxBom {
  bomFormat: 'CycloneDX';
  specVersion: '1.5';
  serialNumber: string;
  version: 1;
  metadata: {
    tools: {
      components: CycloneDxComponent[];
    };
    component: CycloneDxComponent;
  };
  components: CycloneDxComponent[];
  dependencies: CycloneDxDependency[];
}

export interface SbomEntryInspection {
  name: string;
  source: string;
  integrityPassed: boolean | null;
  observedSha256: string | null;
  packageFileCount: number;
  missingFiles: string[];
  extraFiles: string[];
  modifiedFiles: string[];
  unsafePaths: string[];
  publisherPolicyPassed: boolean;
  publisherPolicyCode: string | null;
  signerKeySha256: string | null;
}

export interface SbomBuildResult {
  bom: CycloneDxBom;
  documentSha256: string;
  passed: boolean;
  componentCount: number;
  packageFileCount: number;
  inspections: SbomEntryInspection[];
}

export interface BuildSbomOptions {
  cwd?: string;
  config?: SkillGuardConfig;
  lockfile?: LockfileSchema;
  inspect?: boolean;
}

const WORKSPACE_REF = 'urn:agentwarden:workspace';
const TOOL_REF = 'urn:agentwarden:tool:agentwarden';

function sha256(value: string | Uint8Array): string {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function canonicalJson(value: unknown): string {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function deterministicUuid(seed: string): string {
  const bytes = Buffer.from(sha256(seed), 'hex');
  bytes[6] = (bytes[6] & 0x0f) | 0x50;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(
    16,
    20,
  )}-${hex.slice(20, 32)}`;
}

function skillReference(entry: LockedSkill): string {
  const version = entry.version || '0.1.0';
  return `pkg:generic/${encodeURIComponent(entry.name)}@${encodeURIComponent(version)}`;
}

function packageFileReference(skillRef: string, filePath: string): string {
  return `urn:agentwarden:file:${sha256(`${skillRef}\0${filePath}`).slice(0, 32)}`;
}

function safeDistributionUrl(value: string | undefined): string | undefined {
  if (!value) return undefined;
  try {
    const url = new URL(value);
    url.username = '';
    url.password = '';
    url.search = '';
    url.hash = '';
    return url.href;
  } catch {
    return undefined;
  }
}

function properties(
  values: Record<string, string | number | boolean | null | undefined>,
): CycloneDxProperty[] {
  return Object.entries(values)
    .filter(([, value]) => value !== undefined && value !== null)
    .map(([name, value]) => ({ name: `agentwarden:${name}`, value: String(value) }));
}

function inspectSingleFile(
  entry: LockedSkill,
  cwd: string,
  config: SkillGuardConfig,
): { integrityPassed: boolean | null; observedSha256: string | null } {
  const resolvedPath = resolveFromRoot(entry.source, cwd);
  if (!fs.existsSync(resolvedPath)) {
    return { integrityPassed: false, observedSha256: null };
  }

  try {
    const observedSha256 = scanSkillContent(
      fs.readFileSync(resolvedPath, 'utf8'),
      resolvedPath,
      { ...config, baseline: undefined },
      cwd,
    ).sha256;
    return {
      integrityPassed: observedSha256 === entry.sha256,
      observedSha256,
    };
  } catch {
    return { integrityPassed: false, observedSha256: null };
  }
}

function inspectEntry(
  entry: LockedSkill,
  cwd: string,
  config: SkillGuardConfig,
  inspect: boolean,
): SbomEntryInspection {
  const publisherDecision = evaluatePublisherPolicy(config.publishers, {
    signatureVerified: entry.signatureVerified,
    signatureKeySha256: entry.signatureKeySha256,
  });

  if (!inspect) {
    return {
      name: entry.name,
      source: entry.source,
      integrityPassed: null,
      observedSha256: null,
      packageFileCount: entry.packageFiles?.length ?? 0,
      missingFiles: [],
      extraFiles: [],
      modifiedFiles: [],
      unsafePaths: [],
      publisherPolicyPassed: publisherDecision.passed,
      publisherPolicyCode: publisherDecision.code ?? null,
      signerKeySha256: publisherDecision.keySha256 ?? entry.signatureKeySha256 ?? null,
    };
  }

  if (
    entry.packageFormat === 'tar.gz' &&
    entry.packageSha256 &&
    entry.packageEntry &&
    entry.packageFiles
  ) {
    const resolvedPath = resolveFromRoot(entry.source, cwd);
    const packageInspection = inspectInstalledSkillPackage(path.dirname(resolvedPath), {
      entryPath: entry.packageEntry,
      sha256: entry.packageSha256,
      manifest: entry.packageFiles,
    });
    return {
      name: entry.name,
      source: entry.source,
      integrityPassed: packageInspection.packageMatch,
      observedSha256: packageInspection.packageSha256 ?? null,
      packageFileCount: packageInspection.files.length,
      missingFiles: packageInspection.missingFiles,
      extraFiles: packageInspection.extraFiles,
      modifiedFiles: packageInspection.modifiedFiles,
      unsafePaths: packageInspection.unsafePaths,
      publisherPolicyPassed: publisherDecision.passed,
      publisherPolicyCode: publisherDecision.code ?? null,
      signerKeySha256: publisherDecision.keySha256 ?? entry.signatureKeySha256 ?? null,
    };
  }

  const singleFile = inspectSingleFile(entry, cwd, config);
  return {
    name: entry.name,
    source: entry.source,
    integrityPassed: singleFile.integrityPassed,
    observedSha256: singleFile.observedSha256,
    packageFileCount: 0,
    missingFiles: singleFile.integrityPassed ? [] : [entry.source],
    extraFiles: [],
    modifiedFiles: singleFile.integrityPassed ? [] : [entry.source],
    unsafePaths: [],
    publisherPolicyPassed: publisherDecision.passed,
    publisherPolicyCode: publisherDecision.code ?? null,
    signerKeySha256: publisherDecision.keySha256 ?? entry.signatureKeySha256 ?? null,
  };
}

function packageComponents(
  entry: LockedSkill,
  skillRef: string,
): { components: CycloneDxComponent[]; references: string[] } {
  const components = (entry.packageFiles ?? [])
    .map((file) => {
      const reference = packageFileReference(skillRef, file.path);
      return {
        component: {
          type: 'file' as const,
          'bom-ref': reference,
          name: file.path,
          hashes: [{ alg: 'SHA-256' as const, content: file.sha256 }],
          properties: properties({
            path: file.path,
            size: file.size,
          }),
        },
        reference,
      };
    })
    .sort((left, right) => left.component.name.localeCompare(right.component.name));

  return {
    components: components.map((item) => item.component),
    references: components.map((item) => item.reference),
  };
}

function skillComponent(
  entry: LockedSkill,
  inspection: SbomEntryInspection,
): { component: CycloneDxComponent; dependencies: string[] } {
  const reference = skillReference(entry);
  const packageFiles = packageComponents(entry, reference);
  const hasPackage =
    entry.packageFormat === 'tar.gz' && Boolean(entry.packageSha256) && Boolean(entry.packageEntry);
  const remoteUrl = safeDistributionUrl(entry.remoteUrl);
  const resolvedUrl = safeDistributionUrl(entry.resolvedUrl);
  const component: CycloneDxComponent = {
    type: 'library',
    'bom-ref': reference,
    name: entry.name,
    version: entry.version || '0.1.0',
    scope: 'required',
    hashes: [
      {
        alg: 'SHA-256',
        content: hasPackage ? entry.packageSha256! : entry.sha256,
      },
    ],
    properties: properties({
      source: entry.source,
      sourceType: entry.sourceType ?? 'local',
      installedAt: entry.installedAt,
      verifiedScore: entry.verifiedScore,
      integrityPassed: inspection.integrityPassed,
      observedSha256: inspection.observedSha256,
      entrySha256: hasPackage ? entry.sha256 : undefined,
      packageFormat: entry.packageFormat,
      packageEntry: entry.packageEntry,
      packageFileCount: inspection.packageFileCount,
      missingFiles: inspection.missingFiles.join(','),
      extraFiles: inspection.extraFiles.join(','),
      modifiedFiles: inspection.modifiedFiles.join(','),
      unsafePaths: inspection.unsafePaths.join(','),
      remoteUrl,
      resolvedUrl,
      downloadSha256: entry.downloadSha256,
      digestVerified: entry.digestVerified,
      signatureAlgorithm: entry.signatureAlgorithm,
      signatureVerified: entry.signatureVerified,
      signatureKeySha256: entry.signatureKeySha256,
      signatureSha256: entry.signatureSha256,
      publisherPolicyPassed: inspection.publisherPolicyPassed,
      publisherPolicyCode: inspection.publisherPolicyCode,
    }),
  };
  if (packageFiles.components.length > 0) component.components = packageFiles.components;
  const distributionUrl = resolvedUrl ?? remoteUrl;
  if (distributionUrl) {
    component.externalReferences = [{ type: 'distribution', url: distributionUrl }];
  }

  return { component, dependencies: packageFiles.references };
}

function sortedEntries(lock: LockfileSchema): LockedSkill[] {
  return Object.keys(lock.skills)
    .sort((left, right) => left.localeCompare(right))
    .map((key) => lock.skills[key]);
}

/**
 * Build a deterministic CycloneDX 1.5 SBOM from AgentWarden's lockfile.
 * The result distinguishes recorded hashes from currently observed integrity.
 */
export function buildCycloneDxSbom(options: BuildSbomOptions = {}): SbomBuildResult {
  const cwd = options.cwd ?? process.cwd();
  const lock = options.lockfile ?? readLockfile(cwd);
  const config = normalizeConfig(options.config);
  const inspect = options.inspect !== false;
  const version = readPackageVersion();
  const entries = sortedEntries(lock);
  const inspections = entries.map((entry) => inspectEntry(entry, cwd, config, inspect));
  const inspectionByName = new Map(inspections.map((inspection) => [inspection.name, inspection]));
  const components: CycloneDxComponent[] = [];
  const dependencies: CycloneDxDependency[] = [];
  const skillReferences: string[] = [];

  for (const entry of entries) {
    const inspection = inspectionByName.get(entry.name)!;
    const skill = skillComponent(entry, inspection);
    components.push(skill.component);
    skillReferences.push(skill.component['bom-ref']);
    dependencies.push({
      ref: skill.component['bom-ref'],
      ...(skill.dependencies.length > 0 ? { dependsOn: skill.dependencies } : {}),
    });
  }

  dependencies.unshift({ ref: WORKSPACE_REF, dependsOn: skillReferences });
  const seed = JSON.stringify({
    lockfileVersion: lock.lockfileVersion,
    skills: entries,
    publishers: config.publishers,
    version,
  });
  const bom: CycloneDxBom = {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    serialNumber: `urn:uuid:${deterministicUuid(seed)}`,
    version: 1,
    metadata: {
      tools: {
        components: [
          {
            type: 'application',
            'bom-ref': TOOL_REF,
            name: 'agentwarden',
            version,
            scope: 'required',
          },
        ],
      },
      component: {
        type: 'application',
        'bom-ref': WORKSPACE_REF,
        name: 'agentwarden-lockfile',
        version,
        scope: 'required',
      },
    },
    components,
    dependencies,
  };

  const passed = inspections.every(
    (inspection) =>
      inspection.integrityPassed !== false && inspection.publisherPolicyPassed,
  );
  return {
    bom,
    documentSha256: sha256(canonicalJson(bom)),
    passed,
    componentCount: components.length,
    packageFileCount: inspections.reduce(
      (total, inspection) => total + inspection.packageFileCount,
      0,
    ),
    inspections,
  };
}
