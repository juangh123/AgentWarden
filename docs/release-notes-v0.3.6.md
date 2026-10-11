# AgentWarden v0.3.6

AgentWarden v0.3.6 is a detection-coverage and fail-closed release. It closes a
case where a realistic dropper skill scored 100/100, stops silent policy
downgrades, and removes a destructive install path.

## Security Highlights

- Detection coverage no longer depends on English-only, pipe-only patterns. The
  rules now recognise Chinese, Japanese, and Korean instruction-override
  phrasing, the two-step "download a script to a file, then execute it" chain
  (`curl -o`, `wget -O`, `Invoke-WebRequest -OutFile` followed by
  `chmod`/execution), upload calls in higher-level languages
  (`requests`/`httpx`/`urlopen`/`fetch`/`Invoke-RestMethod`) and sensitive
  system paths such as `/etc/passwd`, `/etc/shadow`, `/proc/self/environ`,
  `~/.npmrc` and `~/.docker/config.json`. A sample that previously produced
  zero findings and a 100/100 score now fails with four findings.
- Config fields are validated strictly. A wrongly typed or misspelled
  `profile`, `failOn`, `minScore`, `ignoreRules`, `severityOverrides`,
  `include`, `exclude`, or `baseline` now fails with exit code `2` instead of
  silently falling back to a looser default.
- `install --output <dir> --force` no longer deletes a directory AgentWarden did
  not create. Replacing a foreign directory requires the explicit
  `--replace-directory` flag, the entries to be removed are printed first, and
  the directory swap is committed together with the `skills.lock` write so a
  failed lockfile update restores the previous directory.
- Reading an installed package is bounded by file count, total bytes, and
  depth, and uses a file descriptor with an `fstat` identity check to close a
  check-then-read race.
- Reports withhold code fence bodies, strip ANSI/OSC control characters, remove
  URL fragments, and redact camelCase secret assignments such as
  `dbPassword = "..."`.
- Skills saved with a UTF-8 BOM or without frontmatter no longer lose their
  metadata or write an absolute path into `skills.lock`; lockfile validation
  rejects skill names containing path separators or control characters.
- `SEC-EXFIL-001` honors the `allowedDomains` allowlist, and `install`,
  `verify`, `audit`, and `policy` warn when `requireSignature` is enabled
  without `trustedKeys`, because that configuration pins no publisher identity.

## Workflow and Supply Chain

- The GitHub Action no longer sends an implicit `--profile balanced`, which
  silently downgraded a stricter policy committed in the repository config.
- Published composite-Action steps are pinned to commit SHAs, with the source
  tag recorded in a trailing comment, and the release workflow grants least
  privilege per job, keeps no persisted git credentials while running
  third-party installs, and pins the npm version it installs.
- The floating Action tag is now the minor series (`v0.3`). A 0.x project should
  not advertise `@v0`, because that would deliver breaking changes to anyone
  pinning it.
- `init` generates a workflow whose third-party actions are SHA-pinned and whose
  SARIF upload step uses `github/codeql-action` v4.

## Correctness and Reporting

- MCP findings report the real source line instead of a synthesized offset, and
  repeated reports of the same rule on one line are collapsed instead of
  deducting score twice.
- Ordering in lockfiles, baselines, CycloneDX documents, discovery results, and
  reports uses a locale-independent comparator, so artifacts are stable across
  machines.
- Unsupported options now fail with exit code `2` instead of being silently
  ignored, an empty scan scope exits `2` rather than `1`, and report paths set
  the exit code instead of calling `process.exit()` so output cannot be
  truncated.
- Baselines are read once per unchanged file and discovery globs are compiled
  once, removing repeated I/O and regex compilation in multi-file scans.
- The 2 598-line CLI entry point is split into focused modules under
  `src/cli/` (argument parsing, config resolution, shared helpers, help text,
  command dispatch, and one module per command group). `src/cli.ts` is now a
  22-line entry point, and the CLI contract tests plus the 140-check end-to-end
  suite pass unchanged.
- `noUncheckedIndexedAccess` is enabled, so unchecked array and
  index-signature access is a compile error; every affected site now carries an
  explicit guard or a provably in-range assertion.

## Install Today

```bash
npx --yes agentwarden-cli@0.3.6 scan ./skills
```

Or install globally:

```bash
npm install --global agentwarden-cli@0.3.6
agentwarden scan ./skills
```

## GitHub Action

```yaml
- uses: juangh123/AgentWarden@v0.3.6
  with:
    path: .
    config: .agentwarden/policy.json
    policy-guard: 'true'
    policy-guard-base: ${{ github.event.pull_request.base.sha }}
```

## Verification

The release workflow runs type checking, 181 unit tests (including a new CLI
contract suite covering exit codes and JSON/SARIF output), 140 end-to-end
checks, package installation tests, and the installed-artifact MVP acceptance
gate before publishing the checksummed tarball. Main CI covers package
installation on Linux, macOS, and Windows.

AgentWarden remains a static gate. It does not execute scanned assets and does
not guarantee that they are safe. Static rules will miss novel techniques and
will flag legitimate content; use least privilege, isolation, network controls,
publisher policy, and human review for high-risk tools.
