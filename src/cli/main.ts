import * as fs from 'node:fs';
import * as path from 'node:path';
import { chalk, setColorEnabled } from '../reporter/chalk.ts';
import { parseArgs, EXIT_USAGE, VERSION, validateCommandOptions, resolveFormat, usageError } from './args.ts';

export async function main(): Promise<void> {
  const { positionals, options, errors } = parseArgs(process.argv.slice(2));

  if (options['no-color']) setColorEnabled(false);

  if (options.cwd !== undefined) {
    const dir = path.resolve(process.cwd(), String(options.cwd));
    if (!fs.existsSync(dir) || !fs.statSync(dir).isDirectory()) {
      console.error(chalk.red(`Error: --cwd directory not found at ${dir}`));
      process.exit(EXIT_USAGE);
    }
    process.chdir(dir);
  }

  if (errors.length > 0) {
    for (const error of errors) console.error(chalk.red(`Error: ${error}`));
    console.error(`Run ${chalk.yellow('"agentwarden help"')} for usage.`);
    process.exit(EXIT_USAGE);
  }

  if (options.version) {
    console.log(`agentwarden v${VERSION}`);
    return;
  }

  const command = positionals[0];
  if (!command || command === 'help' || command === '--help' || command === '-h' || options.help) {
    const { printHelp } = await import('./help.ts');
    printHelp();
    return;
  }

  validateCommandOptions(command, options);

  if (command === 'init') {
    if (positionals.length > 1) {
      usageError('init does not accept positional paths');
    }
    const { cmdInit, resolveInitFormat } = await import('./commands/misc.ts');
    cmdInit(options, resolveInitFormat(options));
    return;
  }

  if (command === 'scan') {
    const targets = positionals.slice(1);
    if (targets.length === 0) usageError(`Missing file or directory path to scan. Usage: agentwarden scan <path> [--format pretty|json|sarif]`);
    const [{ scanTargets }, { buildConfig }] = await Promise.all([
      import('./commands/scan.ts'),
      import('./config.ts'),
    ]);
    scanTargets(targets, buildConfig(options), resolveFormat(options), options);
    return;
  }

  if (command === 'install') {
    const target = positionals[1];
    if (!target) usageError(`Missing skill path to install. Usage: agentwarden install <path/to/SKILL.md|https://url> --sha256 <digest>`);
    const { cmdInstall } = await import('./commands/install.ts');
    await cmdInstall(target, options, resolveFormat(options));
    return;
  }

  if (command === 'verify') {
    const target = positionals[1];
    if (!target) usageError(`Missing skill path to verify. Usage: agentwarden verify <path/to/SKILL.md>`);
    const [{ cmdVerify }, { buildConfig }] = await Promise.all([
      import('./commands/verify.ts'),
      import('./config.ts'),
    ]);
    cmdVerify(target, buildConfig(options), resolveFormat(options));
    return;
  }

  if (command === 'audit') {
    const [{ cmdAudit }, { buildConfig }] = await Promise.all([
      import('./commands/audit.ts'),
      import('./config.ts'),
    ]);
    cmdAudit(options, buildConfig(options), resolveFormat(options));
    return;
  }

  if (command === 'sbom') {
    if (positionals.length > 1) {
      usageError('sbom does not accept positional paths');
    }
    const { cmdSbom } = await import('./commands/misc.ts');
    cmdSbom(options);
    return;
  }

  if (command === 'rules') {
    const [{ cmdRules }, { buildConfig }] = await Promise.all([
      import('./commands/misc.ts'),
      import('./config.ts'),
    ]);
    cmdRules(buildConfig(options), resolveFormat(options));
    return;
  }

  if (command === 'policy') {
    const subcommand = positionals[1];
    if (subcommand === 'guard') {
      const baseRef = positionals[2];
      if (!baseRef) {
        usageError('Missing base ref. Usage: agentwarden policy guard <base-ref> [--config <file>]');
      }
      if (positionals.length > 3) {
        usageError('policy guard accepts exactly one base ref');
      }
      const { cmdPolicyGuard } = await import('./commands/policy.ts');
      cmdPolicyGuard(baseRef, options, resolveFormat(options));
      return;
    }
    if (subcommand === 'diff') {
      const from = positionals[2];
      const to = positionals[3];
      if (!from || !to) {
        usageError('Missing policy comparison inputs. Usage: agentwarden policy diff <from> <to>');
      }
      if (positionals.length > 4) {
        usageError('policy diff accepts exactly two comparison inputs');
      }
      const { cmdPolicyDiff } = await import('./commands/policy.ts');
      cmdPolicyDiff(from, to, options, resolveFormat(options));
      return;
    }
    if (subcommand !== undefined) {
      usageError(`Unknown policy subcommand: "${subcommand}"`);
    }
    const [{ cmdPolicy }, { buildConfigDetails }] = await Promise.all([
      import('./commands/policy.ts'),
      import('./config.ts'),
    ]);
    cmdPolicy(buildConfigDetails(options), resolveFormat(options));
    return;
  }

  if (command === 'list') {
    const [{ cmdList }, { readLockfile }] = await Promise.all([
      import('./commands/misc.ts'),
      import('../manifest/lockfile.ts'),
    ]);
    cmdList(readLockfile(), resolveFormat(options));
    return;
  }

  if (command === 'uninstall') {
    const name = positionals[1];
    if (!name) usageError(`Missing skill name to uninstall. Usage: agentwarden uninstall <name>`);
    const { cmdUninstall } = await import('./commands/misc.ts');
    cmdUninstall(name, resolveFormat(options));
    return;
  }

  if (command === 'baseline') {
    const { cmdBaselineStatus, cmdBaselineMaintenance, cmdBaseline } = await import(
      './commands/baseline.ts'
    );
    const subcommand = positionals[1];
    if (subcommand === 'status') {
      const targets = positionals.length > 2 ? positionals.slice(2) : ['.'];
      cmdBaselineStatus(targets, options, resolveFormat(options));
      return;
    }
    if (subcommand === 'prune' || subcommand === 'update') {
      const targets = positionals.length > 2 ? positionals.slice(2) : ['.'];
      cmdBaselineMaintenance(subcommand, targets, options, resolveFormat(options));
      return;
    }
    const targets = subcommand === 'create' ? positionals.slice(2) : positionals.slice(1);
    cmdBaseline(targets.length > 0 ? targets : ['.'], options, resolveFormat(options));
    return;
  }

  if (command === 'version') {
    console.log(`agentwarden v${VERSION}`);
    return;
  }

  usageError(`Unknown command: "${command}"`);
}

