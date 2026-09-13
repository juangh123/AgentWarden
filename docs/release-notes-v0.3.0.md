# AgentWarden v0.3.0

AgentWarden v0.3.0 is the first release focused on turning the scanner into an
installable supply-chain gate for AI Agent Skills, Tools, and MCP
configurations.

## Install

```bash
npx agentwarden-cli scan ./skills
npm install --global agentwarden-cli
```

The npm package is `agentwarden-cli`. Installed binaries are `agentwarden-cli`,
`agentwarden`, `warden`, and the compatibility alias `skillguard`.

## Highlights

- Static detection for prompt injection, credential access, destructive or
  obfuscated commands, and data exfiltration patterns.
- `skills.lock` integrity records for single-file and multi-file Skill packages.
- SHA-256 pinned remote installation with HTTPS-by-default transport.
- Ed25519 publisher signatures, trusted key allowlists, and revoked key blocks.
- Stable finding baselines with owners, expiry, and maintenance workflows.
- Incremental Git scanning and policy profiles for pull request gates.
- CycloneDX 1.5 SBOM export with package and provenance metadata.
- Redacted console, JSON, and SARIF reports for CI and GitHub Code Scanning.
- GitHub Action with baseline, changed-file, policy, and SARIF support.

## Upgrade Notes

- Use `agentwarden-cli` for npm installation and `npx`.
- `skillguard` remains available as a command alias for existing scripts.
- Node.js 22.6 or newer is required.
- The published package intentionally excludes the repository's root
  `skills.lock`.

## Security Scope

AgentWarden performs static analysis and provenance checks. It cannot prove that
an asset is safe. Use least privilege, isolated execution, signature policy,
human review, and runtime controls for high-risk agent tools.

## Verification

The release workflow runs type checking, unit tests, end-to-end smoke tests, and
package installation tests on Linux, macOS, and Windows before publishing.
