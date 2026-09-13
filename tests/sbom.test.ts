import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { updateLockfileSkill } from '../src/manifest/lockfile.ts';
import { buildCycloneDxSbom } from '../src/sbom/index.ts';
import { scanSkillContent } from '../src/scanner/index.ts';

function tempDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'agentwarden-sbom-'));
}

describe('CycloneDX SBOM export', () => {
  it('builds a deterministic CycloneDX 1.5 document with provenance properties', () => {
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
      const keySha256 = 'a'.repeat(64);
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
          signatureSha256: 'c'.repeat(64),
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
