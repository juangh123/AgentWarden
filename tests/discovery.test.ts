import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import {
  discoverSkillFiles,
  filterSkillFiles,
  scanSkillFile,
  scanSkillPaths,
} from '../src/index.ts';

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
      writeFile(root, '.copilot/mcp-config.json', JSON.stringify({ mcpServers: {} }));
      writeFile(root, '.codeium/windsurf/mcp_config.json', JSON.stringify({ mcpServers: {} }));
      writeFile(root, '.roo/mcp.json', JSON.stringify({ mcpServers: {} }));
      writeFile(root, '.cline/mcp.json', JSON.stringify({ mcpServers: {} }));
      writeFile(root, '.continue/mcpServers/local.json', JSON.stringify({ mcpServers: {} }));
      writeFile(root, '.zed/settings.json', JSON.stringify({ context_servers: {} }));
      writeFile(root, '.gemini/settings.json', JSON.stringify({ mcpServers: {} }));
      writeFile(
        root,
        '.devcontainer/devcontainer.json',
        JSON.stringify({ customizations: { vscode: { mcp: { servers: {} } } } }),
      );
      writeFile(root, 'configs/tool.json', JSON.stringify({ name: 'not-an-mcp-config' }));
      writeFile(root, 'package.json', JSON.stringify({ scripts: { test: 'node test.js' } }));
      writeFile(root, '.private/config.json', JSON.stringify({ mcpServers: {} }));
      writeFile(root, 'notes.txt', 'not a skill');

      const files = discoverSkillFiles(root)
        .map((file) => path.relative(root, file).replace(/\\/g, '/'))
        .sort();

      assert.deepEqual(files, [
        '.cline/mcp.json',
        '.codeium/windsurf/mcp_config.json',
        '.continue/mcpServers/local.json',
        '.copilot/mcp-config.json',
        '.cursor/mcp.json',
        '.devcontainer/devcontainer.json',
        '.gemini/settings.json',
        '.mcp.json',
        '.roo/mcp.json',
        '.vscode/mcp.json',
        '.zed/settings.json',
        'SKILL.md',
      ]);
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

  it('scans Zed and Dev Container MCP entries discovered from client configs', () => {
    const root = tempDir();
    try {
      writeFile(
        root,
        '.zed/settings.json',
        JSON.stringify({
          context_servers: {
            unsafeZedServer: {
              command: 'npx',
              args: ['unpinned-zed-tool'],
            },
          },
        }),
      );
      writeFile(
        root,
        '.devcontainer/devcontainer.json',
        JSON.stringify({
          customizations: {
            vscode: {
              mcp: {
                servers: {
                  unsafeDevContainerServer: {
                    command: 'npx',
                    args: ['unpinned-devcontainer-tool'],
                  },
                },
              },
            },
          },
        }),
      );

      const results = scanSkillPaths(root);

      assert.deepEqual(
        results.map((result) => path.relative(root, result.filePath).replace(/\\/g, '/')),
        ['.devcontainer/devcontainer.json', '.zed/settings.json'],
      );
      assert.ok(results.every((result) => result.parsedSkill.kind === 'mcp'));
      assert.ok(results.every((result) => result.findings.some((finding) => finding.ruleId === 'SEC-MCP-001')));
      assert.ok(results.every((result) => !result.passed));
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

  it('applies include and exclude globs to directory discovery and SDK scans', () => {
    const root = tempDir();
    try {
      writeFile(root, 'skills/public/SKILL.md', '# Public skill\n');
      writeFile(root, 'skills/private/SKILL.md', '# Private skill\n');
      writeFile(root, 'skills/README.txt', 'not scanned');
      writeFile(root, 'outside/SKILL.md', '# Outside skill\n');

      const files = discoverSkillFiles(root, root, {
        include: ['skills/**/*.md'],
        exclude: ['skills/private/**'],
      }).map((file) => path.relative(root, file).replace(/\\/g, '/'));

      assert.deepEqual(files, ['skills/public/SKILL.md']);

      const results = scanSkillPaths(
        root,
        {
          include: ['skills/**/*.md'],
          exclude: ['skills/private/**'],
        },
        root,
      );
      assert.deepEqual(
        results.map((result) => path.relative(root, result.filePath).replace(/\\/g, '/')),
        ['skills/public/SKILL.md'],
      );

      const explicitFile = path.join(root, 'skills', 'private', 'SKILL.md');
      assert.deepEqual(
        discoverSkillFiles(explicitFile, root, {
          include: ['never/**'],
          exclude: ['**'],
        }),
        [explicitFile],
      );

      writeFile(root, 'skills/public/mcp.json', JSON.stringify({ mcpServers: {} }));
      writeFile(root, 'skills/public/notes.json', JSON.stringify({ notes: true }));
      const filtered = filterSkillFiles(
        [
          path.join(root, 'skills', 'public', 'SKILL.md'),
          path.join(root, 'skills', 'private', 'SKILL.md'),
          path.join(root, 'skills', 'public', 'mcp.json'),
          path.join(root, 'skills', 'public', 'notes.json'),
        ],
        root,
        {
          include: ['skills/**'],
          exclude: ['skills/private/**'],
        },
      )
        .map((file) => path.relative(root, file).replace(/\\/g, '/'))
        .sort();

      assert.deepEqual(filtered, ['skills/public/SKILL.md', 'skills/public/mcp.json'].sort());
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });
});
