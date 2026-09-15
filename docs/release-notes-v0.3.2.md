# AgentWarden v0.3.2

AgentWarden v0.3.2 makes project initialization easier to review, fixes
git-sourced installs, and is the first version published as
`agentwarden-cli` on npm.

## Highlights

- `agentwarden init --dry-run` previews the files init would create or replace
  without writing to disk, and `--json` reports the same plan for scripts.
- `agentwarden init --workflow-path <file>` writes the generated workflow to a
  custom repository path, and `--action-ref <ref>` chooses the `uses:` ref:
  `@v0.3.2`, the floating `@v0`, or a pinned commit SHA.
- Fixed git-sourced installs. `npm install github:juangh123/AgentWarden#<sha>`
  now builds `dist/` through the `prepare` lifecycle hook, so `agentwarden`,
  `warden`, and `agentwarden-cli` resolve instead of pointing at a missing file.
- Added `npm run test:git-install` with a matching CI job, so the git-sourced
  install path cannot regress silently.

## Install Today

```bash
npm install --global agentwarden-cli
warden init --dry-run

# Git fallback:
npm install --global "github:juangh123/AgentWarden#v0.3.2"
warden init --dry-run
```

## GitHub Action

```yaml
- uses: juangh123/AgentWarden@v0.3.2
  with:
    path: skills/
    profile: strict
```

The Action runs directly from the tagged repository checkout and can be used
independently of the npm package.

## npm Status

The package is published as `agentwarden-cli@0.3.2`:

```bash
npx --yes agentwarden-cli --version
```

This bootstrap release has no npm provenance. The GitHub Actions Trusted
Publisher is now configured for `release.yml` in `juangh123/AgentWarden`, so
subsequent tagged versions will be published through OIDC with provenance.

## Security Scope

AgentWarden performs static analysis and provenance checks. It cannot prove that
an asset is safe. Use least privilege, isolated execution, signature policy,
human review, and runtime controls for high-risk agent tools.

## Verification

The release workflow runs type checking, unit tests, end-to-end smoke tests,
package installation tests, and the full installed-artifact MVP acceptance
gate before publishing. Main CI additionally covers the git-sourced install
path and package smoke tests on Linux, macOS, and Windows.
