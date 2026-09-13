# Changelog

All notable changes to AgentWarden are documented here. The project follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and uses semantic
versioning.

## [Unreleased]

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

[Unreleased]: https://github.com/juangh123/AgentWarden/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/juangh123/AgentWarden/releases/tag/v0.3.0
