import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { toRelativePosix, updateLockfileSkill } from '../src/manifest/lockfile.ts';
import { extractSkillPackage, writeSkillPackage } from '../src/source/package.ts';
import { createTarGz } from './helpers/tar.ts';
import { buildCycloneDxSbom } from '../src/sbom/index.ts';
import { scanSkillContent } from '../src/scanner/index.ts';
import { createSignatureProof } from '../src/source/proof.ts';
import { verifyPayloadSignature } from '../src/source/signature.ts';

function tempDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'agentwarden-sbom-'));
}

describe('CycloneDX SBOM export', () => {
  it('builds a deterministic CycloneDX 1.5 document with provenance properties', async () => {
    const cwd = tempDir();
    try {
      const source = 'signed-skill.md';
      const content = [
        '---',
        'name: signed-skill',
        'version: 1.2.3',
        '---',
        '# Signed skill',
        '',
      ].join('\n');
      fs.writeFileSync(path.join(cwd, source), content, 'utf8');
      const scan = scanSkillContent(content, source);
      const payload = Buffer.from(content, 'utf8');
      const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
      const signature = crypto.sign(null, payload, privateKey);
      const verification = await verifyPayloadSignature(payload, {
        publicKey: `base64:${publicKey.export({ type: 'spki', format: 'der' }).toString('base64')}`,
        signature: `base64:${signature.toString('base64')}`,
      });
      const keySha256 = verification.publicKeySha256;
      const proof = createSignatureProof(verification, payload, cwd);
      updateLockfileSkill(
        {
          name: 'signed-skill',
          version: '1.2.3',
          source,
          sha256: scan.sha256,
          installedAt: '2026-09-13T00:00:00.000Z',
          verifiedScore: 100,
          sourceType: 'remote',
          remoteUrl: 'https://user:secret@publisher.example/signed-skill.md?token=private',
          resolvedUrl: 'https://cdn.example/signed-skill.md?signature=private#fragment',
          downloadSha256: 'b'.repeat(64),
          digestVerified: true,
          signatureAlgorithm: 'ed25519',
          signatureVerified: true,
          signatureKeySha256: keySha256,
          signatureSha256: verification.signatureSha256,
          signatureProof: proof,
        },
        cwd,
      );

      const first = buildCycloneDxSbom({
        cwd,
        config: {
          publishers: {
            requireSignature: true,
            trustedKeys: [keySha256],
          },
        },
      });
      const second = buildCycloneDxSbom({
        cwd,
        config: {
          publishers: {
            requireSignature: true,
            trustedKeys: [keySha256],
          },
        },
      });

      assert.equal(first.passed, true);
      assert.equal(first.componentCount, 1);
      assert.equal(first.bom.bomFormat, 'CycloneDX');
      assert.equal(first.bom.specVersion, '1.5');
      assert.match(first.bom.serialNumber, /^urn:uuid:[0-9a-f-]{36}$/);
      assert.deepEqual(first.bom, second.bom);
      assert.equal(first.documentSha256, second.documentSha256);

      const component = first.bom.components[0];
      assert.equal(component.name, 'signed-skill');
      assert.equal(component.version, '1.2.3');
      assert.equal(component.hashes?.[0].alg, 'SHA-256');
      assert.equal(component.hashes?.[0].content, scan.sha256);
      assert.equal(
        component.properties?.find((property) => property.name === 'agentwarden:signatureKeySha256')
          ?.value,
        keySha256,
      );
      assert.equal(
        component.properties?.find((property) => property.name === 'agentwarden:remoteUrl')?.value,
        'https://publisher.example/signed-skill.md',
      );
      assert.equal(
        component.externalReferences?.[0].url,
        'https://cdn.example/signed-skill.md',
      );
      assert.equal(
        component.properties?.find(
          (property) => property.name === 'agentwarden:publisherPolicyPassed',
        )?.value,
        'true',
      );
      assert.deepEqual(first.bom.dependencies[0].dependsOn, [component['bom-ref']]);
    } finally {
      fs.rmSync(cwd, { recursive: true, force: true });
    }
  });

  it('reports content and publisher policy failures in the document and result', () => {
    const cwd = tempDir();
    try {
      const source = 'unsigned-skill.md';
      const content = '---\nname: unsigned-skill\nversion: 1.0.0\n---\n# Unsigned\n';
      fs.writeFileSync(path.join(cwd, source), content, 'utf8');
      const scan = scanSkillContent(content, source);
      updateLockfileSkill(
        {
          name: 'unsigned-skill',
          version: '1.0.0',
          source,
          sha256: scan.sha256,
          installedAt: '2026-09-13T00:00:00.000Z',
          verifiedScore: 100,
          sourceType: 'local',
        },
        cwd,
      );

      fs.appendFileSync(path.join(cwd, source), 'tampered\n');
      const result = buildCycloneDxSbom({
        cwd,
        config: { publishers: { requireSignature: true } },
      });

      assert.equal(result.passed, false);
      assert.equal(result.inspections[0].integrityPassed, false);
      assert.equal(result.inspections[0].publisherPolicyPassed, false);
      assert.equal(result.inspections[0].publisherPolicyCode, 'SIGNATURE_REQUIRED');
      assert.equal(
        result.bom.components[0].properties?.find(
          (property) => property.name === 'agentwarden:integrityPassed',
        )?.value,
        'false',
      );
    } finally {
      fs.rmSync(cwd, { recursive: true, force: true });
    }
  });
});

describe('SBOM package and skip-inspection paths', () => {
  it('inspects an installed package and exports its per-file components', () => {
    const cwd = tempDir();
    try {
      const content = '---\nname: packaged-skill\nversion: 2.0.0\n---\n# Packaged\n';
      const archive = createTarGz([
        { path: 'SKILL.md', content },
        { path: 'scripts/run.sh', content: 'echo hi\n' },
      ]);
      const skillPackage = extractSkillPackage(archive);
      const destination = path.join(cwd, '.agentwarden', 'skills', 'packaged-skill');
      writeSkillPackage(skillPackage, destination);

      updateLockfileSkill(
        {
          name: 'packaged-skill',
          version: '2.0.0',
          source: toRelativePosix(path.join(destination, 'SKILL.md'), cwd),
          sha256: crypto.createHash('sha256').update(content.replace(/\r\n/g, '\n')).digest('hex'),
          installedAt: '2026-10-11T00:00:00.000Z',
          verifiedScore: 100,
          sourceType: 'local',
          packageFormat: 'tar.gz',
          packageSha256: skillPackage.sha256,
          packageEntry: skillPackage.entryPath,
          packageFiles: skillPackage.manifest,
        },
        cwd,
      );

      const result = buildCycloneDxSbom({ cwd, inspect: true });

      assert.equal(result.passed, true);
      assert.equal(result.inspections[0].integrityPassed, true);
      assert.equal(result.inspections[0].packageFileCount, 2);
      assert.equal(result.inspections[0].missingFiles.length, 0);
      assert.equal(result.componentCount, 1);
      assert.equal(
        result.bom.components[0].properties?.find(
          (property) => property.name === 'agentwarden:packageFileCount',
        )?.value,
        '2',
      );
      // Package files are exported as content-addressed dependency references.
      const skillDependency = result.bom.dependencies.find((entry) => entry.dependsOn.length === 2);
      assert.ok(skillDependency, 'expected the skill to depend on its two package files');
      assert.ok(
        skillDependency.dependsOn.every((reference) => reference.startsWith('urn:agentwarden:file:')),
        'expected content-addressed file references',
      );
      assert.match(result.documentSha256, /^[a-f0-9]{64}$/);
    } finally {
      fs.rmSync(cwd, { recursive: true, force: true });
    }
  });

  it('skips on-disk inspection when asked and reports null integrity', () => {
    const cwd = tempDir();
    try {
      const source = 'uninspected.md';
      const content = '---\nname: uninspected\nversion: 1.0.0\n---\n# Uninspected\n';
      fs.writeFileSync(path.join(cwd, source), content, 'utf8');
      const scan = scanSkillContent(content, source);
      updateLockfileSkill(
        {
          name: 'uninspected',
          version: '1.0.0',
          source,
          sha256: scan.sha256,
          installedAt: '2026-10-11T00:00:00.000Z',
          verifiedScore: 100,
          sourceType: 'local',
        },
        cwd,
      );

      const result = buildCycloneDxSbom({ cwd, inspect: false });

      assert.equal(result.inspections[0].integrityPassed, null);
      assert.equal(result.inspections[0].observedSha256, null);
      assert.equal(result.inspections[0].missingFiles.length, 0);
    } finally {
      fs.rmSync(cwd, { recursive: true, force: true });
    }
  });
});
