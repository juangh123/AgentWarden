# Changelog

All notable changes to AgentWarden are documented here. The project follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and uses semantic
versioning.

## [Unreleased]

### Added

- Expanded MCP configuration discovery to recognize common Cursor, VS Code,
  Copilot, Windsurf, Cline, Roo Code, Continue, Zed, Gemini, Qwen, and Dev
  Container locations, including `mcp.servers`, `context_servers`, and
  `customizations.vscode.mcp.servers` container shapes.
- Added `npm run test:mvp` to package the release tarball, write
  `release/SHA256SUMS`, install the artifact into a clean consumer, and verify
  the full user-facing CLI lifecycle through the installed package.

### Changed

- CI and the release workflow now enforce the MVP packaging gate. Releases
  publish the exact tarball that passed verification and attach the tarball and
  checksum to the GitHub Release.
- Published the first npm bootstrap release as `agentwarden-cli@0.3.2` and
  configured the GitHub Actions Trusted Publisher for subsequent tagged
  releases.
- Published the GitHub Action as `AgentWarden Security Gate` on GitHub
  Marketplace under the `Security` category.

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

[Unreleased]: https://github.com/juangh123/AgentWarden/compare/v0.3.2...HEAD
[0.3.2]: https://github.com/juangh123/AgentWarden/releases/tag/v0.3.2
[0.3.1]: https://github.com/juangh123/AgentWarden/releases/tag/v0.3.1
[0.3.0]: https://github.com/juangh123/AgentWarden/releases/tag/v0.3.0
