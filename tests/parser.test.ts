import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { parseSkillMarkdown } from '../src/parser/skillParser.ts';

describe('skillParser', () => {
  it('extracts frontmatter fields', () => {
    const parsed = parseSkillMarkdown('---\nname: demo\nversion: 2.1.0\ndescription: Hello\n---\nbody');
    assert.equal(parsed.name, 'demo');
    assert.equal(parsed.version, '2.1.0');
    assert.equal(parsed.description, 'Hello');
  });

  it('extracts code blocks with accurate 1-based line numbers and languages', () => {
    const content = [
      '---',
      'name: demo',
      '---',
      '',
      '```bash',
      'echo hi',
      'echo bye',
      '```',
      '',
      '```js',
      'x = 1',
      '```',
    ].join('\n');
    const parsed = parseSkillMarkdown(content);
    assert.equal(parsed.codeBlocks.length, 2);
    assert.equal(parsed.codeBlocks[0].language, 'bash');
    assert.equal(parsed.codeBlocks[0].code, 'echo hi\necho bye');
    // Opening fence is line 5, first content line must be line 6.
    assert.equal(parsed.codeBlocks[0].startLine, 5);
    assert.equal(parsed.codeBlocks[1].startLine, 10);
  });

  it('defaults name/version when missing', () => {
    const parsed = parseSkillMarkdown('# Title only');
    assert.equal(parsed.name, 'Unnamed-Skill');
    assert.equal(parsed.version, '0.1.0');
  });

  it('supports nested mcp.servers configurations', () => {
    const parsed = parseSkillMarkdown(JSON.stringify({
      mcp: {
        servers: {
          weather: {
            command: 'node',
            args: ['weather.js'],
          },
        },
      },
    }));

    assert.equal(parsed.kind, 'mcp');
    assert.equal(parsed.mcpServers?.length, 1);
    assert.equal(parsed.mcpServers?.[0].name, 'weather');
    assert.equal(parsed.parseError, undefined);
  });

  it('supports Zed context_servers configurations', () => {
    const parsed = parseSkillMarkdown(JSON.stringify({
      context_servers: {
        local: {
          command: 'node',
          args: ['server.js'],
        },
      },
    }), '.zed/settings.json');

    assert.equal(parsed.kind, 'mcp');
    assert.equal(parsed.mcpServers?.length, 1);
    assert.equal(parsed.mcpServers?.[0].name, 'local');
    assert.equal(parsed.parseError, undefined);
  });

  it('supports VS Code Dev Container MCP configurations', () => {
    const parsed = parseSkillMarkdown(JSON.stringify({
      customizations: {
        vscode: {
          mcp: {
            servers: {
              playwright: {
                command: 'npx',
                args: ['-y', '@microsoft/mcp-server-playwright'],
              },
            },
          },
        },
      },
    }), '.devcontainer/devcontainer.json');

    assert.equal(parsed.kind, 'mcp');
    assert.equal(parsed.mcpServers?.length, 1);
    assert.equal(parsed.mcpServers?.[0].name, 'playwright');
    assert.equal(parsed.parseError, undefined);
  });

  it('fails closed when a known MCP config file has no server map', () => {
    const parsed = parseSkillMarkdown('{}', '.mcp.json');

    assert.equal(parsed.kind, 'mcp');
    assert.ok(parsed.parseError);
    assert.equal(parsed.mcpServers?.length, 0);
  });

  it('treats an invalid declared server map as malformed MCP JSON', () => {
    const parsed = parseSkillMarkdown('{"servers":[]}', 'settings.json');

    assert.equal(parsed.kind, 'mcp');
    assert.ok(parsed.parseError);
    assert.equal(parsed.mcpServers?.length, 0);
  });
});
