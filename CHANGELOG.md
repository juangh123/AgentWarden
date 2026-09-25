# Changelog

All notable changes to AgentWarden are documented here. The project follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and uses semantic
versioning.

## [Unreleased]

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

[Unreleased]: https://github.com/juangh123/AgentWarden/compare/v0.3.3...HEAD
[0.3.3]: https://github.com/juangh123/AgentWarden/releases/tag/v0.3.3
[0.3.2]: https://github.com/juangh123/AgentWarden/releases/tag/v0.3.2
[0.3.1]: https://github.com/juangh123/AgentWarden/releases/tag/v0.3.1
[0.3.0]: https://github.com/juangh123/AgentWarden/releases/tag/v0.3.0
