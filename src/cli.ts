#!/usr/bin/env node
import { chalk } from './reporter/chalk.ts';
import { SkillPackageError } from './source/package.ts';
import { EXIT_FAIL, usageError } from './cli/args.ts';
import { main } from './cli/main.ts';

try {
  await main();
} catch (err) {
  // A refused install destination is a usage/path problem, not a security
  // finding: report it with the documented usage exit code.
  if (
    err instanceof SkillPackageError &&
    (err.code === 'DESTINATION_NOT_EMPTY' ||
      err.code === 'DESTINATION_NOT_MANAGED' ||
      err.code === 'DESTINATION_UNSAFE')
  ) {
    usageError(err.message);
  }
  console.error(chalk.red(`Fatal: ${err instanceof Error ? err.message : String(err)}`));
  process.exit(EXIT_FAIL);
}
