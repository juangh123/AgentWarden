import type { Rule  } from './types.ts';
import { credentialRules } from './credentials.ts';
import { commandRules } from './commands.ts';
import { injectionRules } from './injection.ts';
import { exfiltrationRules } from './exfiltration.ts';

export const allRules: Rule[] = [
  ...credentialRules,
  ...commandRules,
  ...injectionRules,
  ...exfiltrationRules,
];

export * from './types.ts';
