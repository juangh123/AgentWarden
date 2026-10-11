# Changelog

All notable changes to AgentWarden are documented here. The project follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and uses semantic
versioning.

## [0.3.6] - 2026-10-10

### Fixed

- Closed a detection gap where a realistic dropper skill produced zero
  findings and a 100/100 score. Rules now recognise CJK (Chinese, Japanese,
  Korean) instruction-override phrasing, the non-pipe "download to a file then
  execute it" chain (`curl -o`, `wget -O`, `Invoke-WebRequest -OutFile`
  followed by `chmod`/execution), generic upload helpers
  (`requests`/`httpx`/`urlopen`/`fetch`/`Invoke-RestMethod`) and sensitive
  system paths such as `/etc/passwd`, `/etc/shadow`, `/proc/self/environ`,
  `~/.npmrc` and `~/.docker/config.json`.
- Config fields are now validated strictly. A wrongly typed or misspelled
  `profile`, `failOn`, `minScore`, `ignoreRules`, `severityOverrides`,
  `include`, `exclude` or `baseline` raises `ConfigError` and exits with code
  `2` instead of silently falling back to a looser default, so a typo can no
  longer leave a gate quietly downgraded.
- A skill file with a UTF-8 BOM or without frontmatter no longer loses its
  metadata, and no longer writes an absolute path into `skills.lock`. The
  fallback name is a relative, machine-independent slug.
- `install --output <dir> --force` no longer deletes a non-empty directory that
  AgentWarden did not create. Replacing a foreign directory now requires the
  new explicit `--replace-directory` flag, the entries to be removed are
  printed first, and the directory swap is committed together with the
  `skills.lock` write so a failed lockfile update restores the previous
  directory instead of leaving data destroyed.
- The default report withholds code fence bodies (`[REDACTED CODE]`), strips
  ANSI/OSC control characters, removes URL fragments, and redacts camelCase
  secret assignments such as `dbPassword = "…"`.
- MCP findings report the real source line instead of a synthesized offset, and
  repeated reports of the same rule on one line are collapsed instead of
  deducting score twice.
- The GitHub Action no longer sends an implicit `--profile balanced`, which
  silently downgraded a stricter policy committed in the repository config.

### Security

- `SEC-EXFIL-001` now honors the `allowedDomains` allowlist, matching the
  documented behaviour of the other network rules.
- `install`, `verify`, `audit`, and `policy` warn on stderr once per run when
  `publishers.requireSignature` is enabled but `publishers.trustedKeys` is
  empty, because that configuration accepts any valid signature and pins no
  publisher identity. The warning never writes to stdout, so `--json` and
  `--sarif` output stay machine-readable.
- Lockfile validation rejects skill names containing path separators or
  control characters.
- Reading an installed package is bounded by file count, total bytes and
  depth, and uses a file descriptor with an `fstat` identity check to close a
  check-then-read race that a concurrent writer could exploit.
- The release workflow now grants least privilege per job (`verify` only
  reads), keeps no persisted git credentials while running third-party
  installs, pins the npm version it installs, and floats the minor tag
  (`v0.3`) instead of `v0`, which for a 0.x project would have delivered
  breaking changes to anyone pinning `@v0`.
- Every third-party GitHub Action reference is pinned to a full commit SHA
  (resolved from its release tag and recorded in a trailing comment), in the
  composite Action, both workflows, and the workflow that `init` generates.
  The generated SARIF upload step moves to `github/codeql-action` v4, whose
  `upload-sarif` action still accepts the same `sarif_file` input.

### Changed

- `verify` honours `--format`/`--json` instead of silently printing the pretty
  report. It now emits a machine-readable verdict with `verified`, `key`,
  `score`, `expectedSha256`, `actualSha256`, publisher-policy status, and a
  failure `reason` covering tampered content, tampered packages, invalid
  package metadata, publisher policy, and unregistered skills.
- Ordering in lockfiles, baselines, CycloneDX documents, discovery results and
  reports uses a locale-independent comparator, so generated artifacts are
  stable across machines and locales.
- `tsconfig.json` enables `noUnusedLocals`, `noUnusedParameters`,
  `noImplicitOverride`, `noFallthroughCasesInSwitch`,
  `noUncheckedIndexedAccess` and `exactOptionalPropertyTypes`; the dead
  `parseConfigFile` helper, an unused `EXIT_OK` constant, a redundant import,
  and an unused `options` parameter were removed to satisfy them. Unchecked
  index access is now a compile error: object lookups gained explicit guards,
  and only provably in-range lockstep array reads use assertions. Under
  `exactOptionalPropertyTypes`, input option bags document that they accept an
  explicit `undefined`, while serialized records (baseline entries, findings,
  scan results, package entry metadata) omit absent fields instead of writing
  `undefined` into them.
- Duplicated logic the audit flagged is now shared: `runGit` and the
  filesystem `canonicalPath` live in `src/utils/git.ts`, and every plain
  SHA-256 digest goes through `src/utils/hash.ts`. The normalising content
  hashes stay separate because their BOM and line-ending rules differ by
  design, and the string-normalising helper in `proof.ts` is renamed
  `normalizeRecordPath` so it can no longer be confused with the filesystem
  one.
- Aborting a risky install now sets the exit code and returns instead of
  calling `process.exit()`, so the scan report printed immediately before the
  abort cannot be truncated. `scan`, `audit`, `rules`, `policy diff`,
  `policy guard` and `baseline status` already did this.
- Added `tests/cli.test.ts`: the CLI entry point now has direct unit coverage
  for exit codes (0/1/2), JSON and SARIF output validity, unsupported-option
  rejection, strict config failures, multi-file report completeness and
  determinism, and the unpinned-publisher warning. This closes the largest
  remaining gap from the audit, where ~2 200 lines of CLI code were only
  exercised by the end-to-end smoke script.
- `FORCE_COLOR` is honored as an explicit override instead of disabling color.
- Scanning an empty scope now exits with code `2` (usage/file error) rather
  than `1`, which is reserved for security failures.
- Commands reject options that do not apply to them (for example
  `scan --output`, `audit --sarif`, `scan --fail-on-diff`) with exit code `2`
  instead of silently ignoring them.
- Baselines are read once per unchanged file during a scan, and discovery
  globs are compiled once, removing repeated I/O and regex compilation in
  multi-file scans.
- The 2 598-line `src/cli.ts` entry point is split into focused modules under
  `src/cli/`: `args.ts`, `config.ts`, `shared.ts`, `help.ts`, `main.ts` (command
  dispatch) and one module per command group under `src/cli/commands/`.
  `src/cli.ts` is now a 22-line entry point. Behaviour is unchanged: the CLI
  contract tests and the 140-check end-to-end suite pass unmodified.

### Notes

- `release/agentwarden-cli-0.3.6.tgz` replaces the previous artifact, matching
  the repository convention of carrying only the current release tarball;
  earlier versions remain available on npm and in GitHub Releases.

## [0.3.5] - 2026-09-30

### Changed

- The release workflow now verifies and publishes the tarball committed in
  the repository instead of repacking a fresh one on the runner, so the
  checksum published to npm and GitHub Release always matches the recorded
  artifact. `npm run test:release` runs that verification, including a
  clean install and full CLI lifecycle check of the committed tarball.
- Added `.gitattributes` so text files check out with LF endings on every
  platform, which stops Windows checkouts from packing different tarball
  bytes than the Linux release runner.

### Security

- Publisher provenance is now re-verified from a content-addressed
  `signatureProof` and matching local attestation instead of trusting
  self-reported signature booleans.
- Lockfile reads now fail closed on unsupported schemas, unsafe skill keys or
  paths, duplicate package entries, malformed provenance, invalid timestamps,
  and out-of-range scores. Hash casing and portable package paths are
  normalized before comparison.
- Signature attestations are read through a file descriptor with regular-file
  and 20 MiB limits, and changes during the read are rejected.
- Malformed implicitly discovered policy files now fail closed instead of
  silently falling back to the legacy profile.
- URL credentials, sensitive query parameters, fragments, and signed download
  URLs are removed from install output, lockfile metadata, `list --json`, and
  SBOM distributions.
- Explicit non-empty package output directories require `--force`, and
  baseline files are written through an atomic same-directory replacement.

## [0.3.4] - 2026-09-27

### Added

- Added `agentwarden policy guard <base-ref>` and the GitHub Action
  `policy-guard` input. They fail when a pull request weakens the effective
  policy that was approved on the base branch, closing the gap where an unsafe
  Skill and a matching rule exclusion could land in the same commit.
- The policy guard also compares configured finding baselines, including
  additions, removals, expiry changes, and entry metadata changes. Review-only
  baseline updates therefore need the same separate approval path as policy
  changes.
- The Action now passes every policy-affecting workflow input into the policy
  guard, so `ignore-rules`, severity thresholds, scan scope, severity
  overrides, and baseline inputs cannot silently weaken the approved policy.
- Added a complete downstream GitHub Action integration example and CI smoke
  coverage that scans it with the same strict policy it uses in its workflow.
- CI now verifies the integration example through both the local Action source
  and the published `juangh123/AgentWarden@v0.3.3` tag.

### Changed

- Newly initialized workflows and the downstream Action example enable the
  policy guard for pull requests by default; the direct Action input remains
  opt-in so existing push and pull-request workflows keep their current
  behavior.
- The MVP packaging gate now validates the local publish target against an
  isolated mock registry, keeping the check repeatable after a version is
  already published.

### Security

- Policy and finding-baseline changes can no longer ride along with a feature
  pull request to weaken the gate that evaluates that same pull request.

## [0.3.3] - 2026-09-24

### Added

- Added `SEC-MCP-004` to flag insecure remote MCP endpoints, and expanded
  `SEC-MCP-002` to cover hardcoded credentials in remote server headers.
- Expanded MCP configuration discovery to recognize common Cursor, VS Code,
  Copilot, Windsurf, Cline, Roo Code, Continue, Zed, Gemini, Qwen, and Dev
  Container locations, including `mcp.servers`, `context_servers`, and
  `customizations.vscode.mcp.servers` container shapes, plus Claude Code user
  and project scopes in `~/.claude.json`.
- Added `npm run test:mvp` to package the release tarball, write
  `release/SHA256SUMS`, install the artifact into a clean consumer, and verify
  the full user-facing CLI lifecycle through the installed package.

### Changed

- Hardened MCP parsing and detection against reserved server names, absolute
  command paths, scoped or tagged packages, malformed discovered configs, and
  remote transport fields.
- Made atomic replacement restore the previous file if a Windows replacement
  fails, corrected supply-chain finding line numbers, and aligned SARIF schema
  and artifact URI encoding with the specification.
- CI and the release workflow now enforce the MVP packaging gate. Releases
  publish the exact tarball that passed verification and attach the tarball and
  checksum to the GitHub Release.

## [0.3.2] - 2026-09-14

### Added

- Added `agentwarden init` to generate an auto-discovered policy and a GitHub
  Actions SARIF security gate without hand-writing workflow configuration.
- Added documentation drift checks that keep the rule catalog aligned with the
  implemented rule IDs and count.
- Added `agentwarden init --dry-run` to preview the files init would create or
  replace without writing to disk.
- Added `agentwarden init --workflow-path <file>` for a custom workflow location
  and `agentwarden init --action-ref <ref>` to choose the generated Action ref.
- Added `npm run test:git-install` with a matching CI job, so a regression in the
  git-sourced install path fails the build instead of shipping silently.

### Fixed

- Git-sourced installs such as `npm install github:juangh123/AgentWarden#<sha>`
  now build `dist/` through the `prepare` lifecycle, so the published `bin`
  entries resolve instead of pointing at a missing file.

## [0.3.1] - 2026-09-14

### Added

- SARIF results now carry stable partial fingerprints shared with baselines, so
  GitHub Code Scanning can retain finding identity when line numbers move.
- SARIF rules now include GitHub security severity, category/security tags, and
  remediation links to the complete rule catalog.
- Added `docs/rules.md` with detection scope and remediation guidance for all
  current rules.
- Exported the shared finding fingerprint helpers through the programmatic SDK.

### Changed

- Baselines and SARIF now derive finding identity from the same normalized
  path, rule, category, severity, and snippet implementation.
- The GitHub Action now runs the checked-in TypeScript source with Node type
  stripping instead of installing dependencies and building on every job.

## [0.3.0] - 2026-09-13

### Added

- CycloneDX 1.5 SBOM export with package manifests, hashes, remote sources, and
  publisher provenance.
- SHA-256 pinned remote Skill installation with atomic writes.
- Safe multi-file `.tar.gz` / `.tgz` extraction and whole-package integrity
  verification.
- Ed25519 detached signature verification and trusted/revoked publisher policy.
- Stable finding baselines with owners, notes, expiry status, and maintenance
  commands.
- Git changed-file scanning for pull request and incremental CI gates.
- Policy profiles, policy diffs, rule governance, JSON, SARIF, and redaction.
- GitHub Action, package installation smoke test, cross-platform CI, and release
  automation.
- User examples, GitHub Action guide, community templates, security policy, and
  cold-start release material.

### Changed

- npm package name is `agentwarden-cli` because the unrelated `agentwarden`
  name is already occupied.
- CLI version and help output now use the AgentWarden brand. The `skillguard`
  binary remains as a compatibility alias.

### Security

- Scanner reports, JSON, and SARIF redact credentials and sensitive content by
  default.
- Publisher policy can require signatures and reject revoked keys.
- Package publishing excludes the repository `skills.lock`.

[Unreleased]: https://github.com/juangh123/AgentWarden/compare/v0.3.6...HEAD
[0.3.6]: https://github.com/juangh123/AgentWarden/releases/tag/v0.3.6
[0.3.5]: https://github.com/juangh123/AgentWarden/releases/tag/v0.3.5
[0.3.4]: https://github.com/juangh123/AgentWarden/releases/tag/v0.3.4
[0.3.3]: https://github.com/juangh123/AgentWarden/releases/tag/v0.3.3
[0.3.2]: https://github.com/juangh123/AgentWarden/releases/tag/v0.3.2
[0.3.1]: https://github.com/juangh123/AgentWarden/releases/tag/v0.3.1
[0.3.0]: https://github.com/juangh123/AgentWarden/releases/tag/v0.3.0
