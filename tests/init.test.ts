import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import {
  INIT_CONFIG_PATH,
  INIT_WORKFLOW_PATH,
  InitError,
  buildInitWorkflow,
  initializeAgentWarden,
  loadConfig,
} from '../src/index.ts';

function tempDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'agentwarden-init-'));
}

describe('project initialization', () => {
  it('creates an auto-discovered policy and GitHub Actions workflow', () => {
    const cwd = tempDir();
    try {
      const result = initializeAgentWarden(cwd);

      assert.deepEqual(
        [...result.created].sort(),
        [INIT_CONFIG_PATH, INIT_WORKFLOW_PATH].sort(),
      );
      assert.deepEqual(result.overwritten, []);

      const policy = JSON.parse(
        fs.readFileSync(path.join(cwd, INIT_CONFIG_PATH), 'utf8'),
      ) as { profile: string; failOn: string; minScore: number };
      assert.equal(policy.profile, 'balanced');
      assert.equal(policy.failOn, 'high');
      assert.equal(policy.minScore, 80);
      assert.equal(loadConfig(cwd).profile, 'balanced');

      const workflow = fs.readFileSync(path.join(cwd, INIT_WORKFLOW_PATH), 'utf8');
      assert.match(workflow, /uses: juangh123\/AgentWarden@v\d+\.\d+\.\d+/);
      assert.match(workflow, /config: \.agentwarden\/policy\.json/);
      assert.match(workflow, /hashFiles\('agentwarden\.sarif'\)/);
      assert.match(
        buildInitWorkflow('example/warden@0123456789abcdef'),
        /uses: example\/warden@0123456789abcdef/,
      );
    } finally {
      fs.rmSync(cwd, { recursive: true, force: true });
    }
  });

  it('requires force before overwriting and supports workflow-free setup', () => {
    const cwd = tempDir();
    try {
      initializeAgentWarden(cwd, { profile: 'strict', workflow: false });
      assert.equal(fs.existsSync(path.join(cwd, INIT_CONFIG_PATH)), true);
      assert.equal(fs.existsSync(path.join(cwd, INIT_WORKFLOW_PATH)), false);
      assert.equal(loadConfig(cwd).profile, 'strict');

      assert.throws(
        () => initializeAgentWarden(cwd, { workflow: false }),
        (error) => error instanceof InitError && /Refusing to overwrite/.test(error.message),
      );

      const result = initializeAgentWarden(cwd, {
        profile: 'legacy',
        workflow: false,
        force: true,
      });
      assert.deepEqual(result.created, []);
      assert.deepEqual(result.overwritten, [INIT_CONFIG_PATH]);
      assert.equal(result.workflowPath, null);
      assert.equal(loadConfig(cwd).profile, 'legacy');
    } finally {
      fs.rmSync(cwd, { recursive: true, force: true });
    }
  });
});
