import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { discoverSkillFiles, scanSkillFile, scanSkillPaths } from '../src/index.ts';

function tempDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'agentwarden-discovery-'));
}

function writeFile(root: string, relativePath: string, content: string): void {
  const target = path.join(root, relativePath);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, content, 'utf8');
}

describe('skill and MCP discovery', () => {
  it('discovers Markdown skills and common MCP configs without scanning unrelated JSON', () => {
    const root = tempDir();
    try {
      writeFile(root, 'SKILL.md', '# Safe skill\n');
      writeFile(root, '.mcp.json', JSON.stringify({ mcpServers: {} }));
      writeFile(root, '.cursor/mcp.json', JSON.stringify({ mcpServers: {} }));
      writeFile(root, '.vscode/mcp.json', JSON.stringify({ servers: {} }));
      writeFile(root, 'configs/tool.json', JSON.stringify({ name: 'not-an-mcp-config' }));
      writeFile(root, 'package.json', JSON.stringify({ scripts: { test: 'node test.js' } }));
      writeFile(root, '.private/config.json', JSON.stringify({ mcpServers: {} }));
      writeFile(root, 'notes.txt', 'not a skill');

      const files = discoverSkillFiles(root)
        .map((file) => path.relative(root, file).replace(/\\/g, '/'))
        .sort();

      assert.deepEqual(files, ['.cursor/mcp.json', '.mcp.json', '.vscode/mcp.json', 'SKILL.md']);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  it('scans discovered MCP configurations through the SDK path API', () => {
    const root = tempDir();
    try {
      writeFile(
        root,
        '.mcp.json',
        JSON.stringify({
          mcpServers: {
            unsafe: {
              command: 'npx',
              args: ['unpinned-mcp-tool'],
            },
          },
        }),
      );

      const results = scanSkillPaths(root);
      assert.equal(results.length, 1);
      assert.equal(results[0].parsedSkill.kind, 'mcp');
      assert.ok(results[0].findings.some((finding) => finding.ruleId === 'SEC-MCP-001'));
      assert.equal(results[0].passed, false);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  it('flags malformed MCP JSON instead of silently treating it as safe', () => {
    const root = tempDir();
    try {
      const configPath = path.join(root, '.mcp.json');
      fs.writeFileSync(configPath, '{"mcpServers": {', 'utf8');

      const result = scanSkillFile(configPath);
      assert.equal(result.parsedSkill.kind, 'mcp');
      assert.ok(result.parsedSkill.parseError);
      assert.ok(result.findings.some((finding) => finding.ruleId === 'SEC-MCP-003'));
      assert.equal(result.passed, false);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });
});
