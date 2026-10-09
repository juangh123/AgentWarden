import { chalk } from '../reporter/chalk.ts';
import { VERSION } from './args.ts';

export function printHelp(): void {
  console.log(`
${chalk.bold.cyan('🛡️  AgentWarden')} v${VERSION} - Zero-Dependency Security Warden & Integrity Manager for Agent Skills

${chalk.bold('USAGE:')}
  agentwarden <command> [options] [paths...]
  warden <command> [options] [paths...]

${chalk.bold('COMMANDS:')}
  ${chalk.green('scan <file|dir>...')}    Audit skill markdown files or directories of skills
  ${chalk.green('install <file|archive|https://url>')} Pre-scan, then securely record fingerprint to skills.lock
  ${chalk.green('verify <file>')}        Verify a single skill file against skills.lock fingerprint
  ${chalk.green('audit')}                Audit all installed skills in skills.lock against local tampering
  ${chalk.green('sbom')}                 Generate a CycloneDX 1.5 SBOM from skills.lock
  ${chalk.green('rules')}                List active security rules and effective severity
  ${chalk.green('init')}                 Create a policy file and GitHub Actions security gate
  ${chalk.green('policy [diff <from> <to>]')} Show effective policy or compare two policies
  ${chalk.green('policy guard <base-ref>')} Fail when the current policy differs from a base ref
  ${chalk.green('list')}                 List skills recorded in skills.lock
  ${chalk.green('uninstall <name>')}     Remove a skill entry from skills.lock
  ${chalk.green('baseline [create|status|prune|update] [path...]')} Manage accepted findings
  ${chalk.green('help')}                 Show this help manual

${chalk.bold('OPTIONS:')}
  ${chalk.yellow('-f, --force')}            Bypass install warning, replace a non-empty --output, or apply baseline writes
  ${chalk.yellow('--format <type>')}        Report format: pretty (default), json, sarif
  ${chalk.yellow('--json')}                 Shorthand for --format json
  ${chalk.yellow('--sarif')}                Shorthand for --format sarif
  ${chalk.yellow('--profile <name>')}       Policy preset: legacy|balanced|strict (scan default: legacy; init default: balanced)
  ${chalk.yellow('--config <file>')}        Load an explicit JSON configuration file
  ${chalk.yellow('--fail-on <sev>')}        Fail threshold: critical|high|medium|low|info (default: high)
  ${chalk.yellow('--min-score <n>')}        Minimum safety score 0-100 (default: 60)
  ${chalk.yellow('--ignore-rule <id>')}     Skip a rule id (repeatable)
  ${chalk.yellow('--severity-override <rule=sev>')} Override a rule severity (repeatable)
  ${chalk.yellow('--include <glob>')}       Limit directory scans to matching paths (repeatable)
  ${chalk.yellow('--exclude <glob>')}       Exclude matching paths from directory scans (repeatable)
  ${chalk.yellow('--changed')}              Scan only files changed from the detected Git base
  ${chalk.yellow('--changed-from <ref>')}   Scan only files changed since a Git ref
  ${chalk.yellow('--fail-on-diff')}         Exit 1 when policy diff detects changes
  ${chalk.yellow('--baseline <file>')}      Suppress exact findings recorded in a baseline
  ${chalk.yellow('--output <file>')}        Baseline, package, or SBOM output path
  ${chalk.yellow('--replace-directory')}    Allow install to replace a directory AgentWarden did not create
  ${chalk.yellow('--sha256 <digest>')}      Required SHA-256 pin for remote installs
  ${chalk.yellow('--signature <ref>')}      Detached Ed25519 signature file, URL, base64:, or hex:
  ${chalk.yellow('--public-key <ref>')}     Trusted Ed25519 public key file or inline pem:/base64:
  ${chalk.yellow('--allow-http')}           Allow HTTP remote installs (trusted local testing only)
  ${chalk.yellow('--owner <name>')}         Baseline review owner or team
  ${chalk.yellow('--expires-in <days>')}    Expire a new baseline after 1-3650 days
  ${chalk.yellow('--expires-at <date>')}    Explicit baseline expiry date
  ${chalk.yellow('--note <text>')}          Baseline review note
  ${chalk.yellow('--expiring-within <days>')} Warn when a baseline expires within N days (default: 30)
  ${chalk.yellow('--fail-on-expiring')}      Exit 1 when a baseline is nearing expiry
  ${chalk.yellow('--fail-on-unmatched')}     Exit 1 when baseline entries no longer match
  ${chalk.yellow('--dry-run')}               Preview baseline prune/update or init output without writing
  ${chalk.yellow('--no-workflow')}           Skip GitHub Actions workflow generation during init
  ${chalk.yellow('--workflow-path <file>')}  Write the init workflow to a custom repository path
  ${chalk.yellow('--action-ref <ref>')}      Action ref for the generated init workflow (default: pinned version)
  ${chalk.yellow('-C, --cwd <dir>')}        Run as if started from <dir>
  ${chalk.yellow('--no-color')}             Disable ANSI colors (also honors NO_COLOR env)
  ${chalk.yellow('--no-redact')}            Include raw snippets and file content in reports
  ${chalk.yellow('-v, --version')}          Show version

${chalk.bold('EXIT CODES:')}
  0 = clean  1 = security failure  2 = usage / file error
`);
}

