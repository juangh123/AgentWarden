import * as fs from 'node:fs';
import * as path from 'node:path';
import { POLICY_PROFILES, type PolicyProfileName } from '../config/index.ts';
import { readPackageVersion } from '../version.ts';
import { writeFileAtomic } from '../utils/atomicWrite.ts';

export const INIT_CONFIG_PATH = '.agentwarden/policy.json';
export const INIT_WORKFLOW_PATH = '.github/workflows/agentwarden.yml';

export interface InitializeOptions {
  profile?: PolicyProfileName | undefined;
  workflow?: boolean | undefined;
  force?: boolean | undefined;
  actionRef?: string | undefined;
  workflowPath?: string | undefined;
  dryRun?: boolean | undefined;
}

export interface InitializeResult {
  profile: PolicyProfileName;
  configPath: string;
  workflowPath: string | null;
  dryRun: boolean;
  created: string[];
  overwritten: string[];
}

export class InitError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'InitError';
  }
}

/**
 * Normalize a custom workflow path and keep it inside the repository so init
 * never writes outside the project it was pointed at.
 */
function normalizeWorkflowPath(input: string): string {
  const trimmed = input.trim();
  if (!trimmed) {
    throw new InitError('Invalid --workflow-path "" (expected a repository-relative path)');
  }

  const normalized = path.posix.normalize(trimmed.replace(/\\/g, '/'));
  const escapesRepository =
    path.posix.isAbsolute(normalized) ||
    /^[A-Za-z]:/.test(normalized) ||
    normalized === '..' ||
    normalized.startsWith('../');
  if (escapesRepository) {
    throw new InitError(
      `Invalid --workflow-path "${input}" (expected a path inside the repository)`,
    );
  }
  if (!/\.(ya?ml)$/i.test(normalized)) {
    throw new InitError(`Invalid --workflow-path "${input}" (expected a .yml or .yaml file)`);
  }
  return normalized;
}

export function buildInitPolicy(profile: PolicyProfileName): string {
  const defaults = POLICY_PROFILES[profile];
  if (!defaults) {
    throw new InitError(`Invalid profile "${profile}" (expected legacy|balanced|strict)`);
  }

  return `${JSON.stringify(
    {
      profile,
      failOn: defaults.failOn,
      minScore: defaults.minScore,
    },
    null,
    2,
  )}\n`;
}

export function buildInitWorkflow(actionRef?: string): string {
  const ref = actionRef?.trim() || `juangh123/AgentWarden@v${readPackageVersion()}`;

  return [
    'name: AgentWarden Security Gate',
    '',
    'on:',
    '  pull_request:',
    '  push:',
    '    branches: [main]',
    '',
    'permissions:',
    '  contents: read',
    '  security-events: write',
    '',
    'jobs:',
    '  agentwarden:',
    '    runs-on: ubuntu-latest',
    '    steps:',
    '      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7',
    '        with:',
    '          fetch-depth: 0',
    '',
    '      - name: Scan agent assets',
    `        uses: ${ref}`,
    '        with:',
    '          path: .',
    `          config: ${INIT_CONFIG_PATH}`,
    "          policy-guard: ${{ github.event_name == 'pull_request' }}",
    '          policy-guard-base: ${{ github.event.pull_request.base.sha }}',
    '          sarif: agentwarden.sarif',
    '',
    '      - name: Upload SARIF',
    "        if: always() && hashFiles('agentwarden.sarif') != ''",
    '        uses: github/codeql-action/upload-sarif@24c54180a607b1449ed407dd24f251e4e9147c8d # v4',
    '        with:',
    '          sarif_file: agentwarden.sarif',
    '',
  ].join('\n');
}

export function initializeAgentWarden(
  cwd: string = process.cwd(),
  options: InitializeOptions = {},
): InitializeResult {
  const profile = options.profile ?? 'balanced';
  if (!Object.hasOwn(POLICY_PROFILES, profile)) {
    throw new InitError(`Invalid profile "${profile}" (expected legacy|balanced|strict)`);
  }

  const workflowPath =
    options.workflow === false
      ? null
      : normalizeWorkflowPath(options.workflowPath ?? INIT_WORKFLOW_PATH);

  const dryRun = Boolean(options.dryRun);
  const targets = [
    {
      path: path.resolve(cwd, INIT_CONFIG_PATH),
      displayPath: INIT_CONFIG_PATH,
      content: buildInitPolicy(profile),
    },
    ...(workflowPath === null
      ? []
      : [
          {
            path: path.resolve(cwd, workflowPath),
            displayPath: workflowPath,
            content: buildInitWorkflow(options.actionRef),
          },
        ]),
  ];

  const existing = targets.filter((target) => fs.existsSync(target.path));
  if (existing.length > 0 && !options.force) {
    throw new InitError(
      `Refusing to overwrite existing file(s): ${existing
        .map((target) => target.displayPath)
        .join(', ')}. Run with --force to replace them.`,
    );
  }

  const created: string[] = [];
  const overwritten: string[] = [];
  for (const target of targets) {
    if (fs.existsSync(target.path)) {
      overwritten.push(target.displayPath);
    } else {
      created.push(target.displayPath);
    }
    if (!dryRun) writeFileAtomic(target.path, target.content);
  }

  return {
    profile,
    configPath: INIT_CONFIG_PATH,
    workflowPath,
    dryRun,
    created,
    overwritten,
  };
}
