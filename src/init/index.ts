import * as fs from 'node:fs';
import * as path from 'node:path';
import { POLICY_PROFILES, type PolicyProfileName } from '../config/index.ts';
import { readPackageVersion } from '../version.ts';
import { writeFileAtomic } from '../utils/atomicWrite.ts';

export const INIT_CONFIG_PATH = '.agentwarden/policy.json';
export const INIT_WORKFLOW_PATH = '.github/workflows/agentwarden.yml';

export interface InitializeOptions {
  profile?: PolicyProfileName;
  workflow?: boolean;
  force?: boolean;
  actionRef?: string;
}

export interface InitializeResult {
  profile: PolicyProfileName;
  configPath: string;
  workflowPath: string | null;
  created: string[];
  overwritten: string[];
}

export class InitError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'InitError';
  }
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
    '      - uses: actions/checkout@v7',
    '        with:',
    '          fetch-depth: 0',
    '',
    '      - name: Scan agent assets',
    `        uses: ${ref}`,
    '        with:',
    '          path: .',
    `          config: ${INIT_CONFIG_PATH}`,
    '          sarif: agentwarden.sarif',
    '',
    '      - name: Upload SARIF',
    "        if: always() && hashFiles('agentwarden.sarif') != ''",
    '        uses: github/codeql-action/upload-sarif@v3',
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

  const configAbsolutePath = path.resolve(cwd, INIT_CONFIG_PATH);
  const workflowAbsolutePath = path.resolve(cwd, INIT_WORKFLOW_PATH);
  const targets = [
    {
      path: configAbsolutePath,
      displayPath: INIT_CONFIG_PATH,
      content: buildInitPolicy(profile),
    },
    ...(options.workflow === false
      ? []
      : [
          {
            path: workflowAbsolutePath,
            displayPath: INIT_WORKFLOW_PATH,
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
    writeFileAtomic(target.path, target.content);
  }

  return {
    profile,
    configPath: INIT_CONFIG_PATH,
    workflowPath: options.workflow === false ? null : INIT_WORKFLOW_PATH,
    created,
    overwritten,
  };
}
