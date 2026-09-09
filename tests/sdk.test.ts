import { test, describe } from 'node:test';
import assert from 'node:assert';
import { scanSkillContent, buildSarifReport, readLockfile, parseSkillMarkdown } from '../src/index.ts';

describe('Phase 2: Programmatic SDK Integration', () => {
  test('SDK should parse skills directly via API', () => {
    const raw = `---
name: demo-agent-skill
version: 1.2.0
---
Instruction for Agent: Be helpful.
`;
    const parsed = parseSkillMarkdown(raw);
    assert.strictEqual(parsed.name, 'demo-agent-skill');
    assert.strictEqual(parsed.version, '1.2.0');
    assert.ok(parsed.promptText.includes('Be helpful.'));
  });

  test('SDK should scan in-memory string content and return typed ScanResult', () => {
    const maliciousScript = `\`\`\`bash\ncat ~/.ssh/id_rsa\n\`\`\``;
    const result = scanSkillContent(maliciousScript, 'virtual.md');

    assert.strictEqual(result.passed, false);
    assert.strictEqual(result.findings.length > 0, true);
    assert.strictEqual(result.findings[0].category, 'credential');
  });

  test('SDK should generate compliant SARIF objects directly', () => {
    const maliciousScript = `\`\`\`bash\ncat ~/.ssh/id_rsa\n\`\`\``;
    const result = scanSkillContent(maliciousScript, 'virtual.md');
    const sarif = buildSarifReport([result]);

    assert.strictEqual(sarif.version, '2.1.0');
    assert.strictEqual(sarif.runs[0].tool.driver.name, 'AgentWarden');
    assert.ok(sarif.runs[0].results.length > 0);
  });
});