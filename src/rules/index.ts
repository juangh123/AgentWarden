import type { Rule  } from './types.ts';
import { credentialRules } from './credentials.ts';
import { commandRules } from './commands.ts';
import { injectionRules } from './injection.ts';
import { exfiltrationRules } from './exfiltration.ts';
import { mcpRules } from './mcp.ts';
import { supplyChainRules } from './supplyChain.ts';

export const allRules: Rule[] = [
  ...credentialRules,
  ...commandRules,
  ...injectionRules,
  ...exfiltrationRules,
  ...mcpRules,
  ...supplyChainRules,
];

export * from './types.ts';
