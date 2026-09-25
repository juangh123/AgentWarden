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
      assert.match(workflow, /policy-guard: \$\{\{ github\.event_name == 'pull_request' \}\}/);
      assert.match(workflow, /policy-guard-base: \$\{\{ github\.event\.pull_request\.base\.sha \}\}/);
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

  it('previews changes without writing files when dryRun is set', () => {
    const cwd = tempDir();
    try {
      const preview = initializeAgentWarden(cwd, { dryRun: true });
      assert.equal(preview.dryRun, true);
      assert.deepEqual(
        [...preview.created].sort(),
        [INIT_CONFIG_PATH, INIT_WORKFLOW_PATH].sort(),
      );
      assert.equal(fs.existsSync(path.join(cwd, INIT_CONFIG_PATH)), false);
      assert.equal(fs.existsSync(path.join(cwd, INIT_WORKFLOW_PATH)), false);

      initializeAgentWarden(cwd, { profile: 'strict' });

      const existing = initializeAgentWarden(cwd, { dryRun: true, force: true });
      assert.deepEqual(existing.created, []);
      assert.deepEqual(
        [...existing.overwritten].sort(),
        [INIT_CONFIG_PATH, INIT_WORKFLOW_PATH].sort(),
      );
      assert.equal(loadConfig(cwd).profile, 'strict');
    } finally {
      fs.rmSync(cwd, { recursive: true, force: true });
    }
  });

  it('supports a custom workflow path and action ref', () => {
    const cwd = tempDir();
    try {
      const workflowPath = '.github/workflows/security.yml';
      const result = initializeAgentWarden(cwd, {
        workflowPath,
        actionRef: 'example/warden@v0',
      });

      assert.equal(result.workflowPath, workflowPath);
      assert.deepEqual(result.created, [INIT_CONFIG_PATH, workflowPath]);
      assert.match(
        fs.readFileSync(path.join(cwd, workflowPath), 'utf8'),
        /uses: example\/warden@v0/,
      );
      assert.equal(fs.existsSync(path.join(cwd, INIT_WORKFLOW_PATH)), false);

      assert.throws(
        () => initializeAgentWarden(cwd, { workflowPath: '../escape.yml', force: true }),
        (error) => error instanceof InitError && /inside the repository/.test(error.message),
      );
      assert.throws(
        () => initializeAgentWarden(cwd, { workflowPath: 'C:\\tmp\\escape.yml', force: true }),
        (error) => error instanceof InitError && /inside the repository/.test(error.message),
      );
      assert.throws(
        () =>
          initializeAgentWarden(cwd, {
            workflowPath: '.github/workflows/security.txt',
            force: true,
          }),
        (error) => error instanceof InitError && /\.yml or \.yaml/.test(error.message),
      );
      assert.throws(
        () => initializeAgentWarden(cwd, { workflowPath: INIT_CONFIG_PATH, force: true }),
        (error) => error instanceof InitError && /\.yml or \.yaml/.test(error.message),
      );
    } finally {
      fs.rmSync(cwd, { recursive: true, force: true });
    }
  });
});
