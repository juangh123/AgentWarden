# AgentWarden v0.3.2

AgentWarden v0.3.2 makes project initialization easier to review and makes
git-sourced installs work while the npm package is still unpublished.

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

The Action runs from the tagged repository checkout and does not require the
`agentwarden-cli` npm package to be published.

## npm Status

The npm package name remains `agentwarden-cli`. First publication is still
pending npm authentication or Trusted Publisher configuration. When those
credentials are available, rerun the v0.3.2 Release workflow; the tag and
package version already match.

## Security Scope

AgentWarden performs static analysis and provenance checks. It cannot prove that
an asset is safe. Use least privilege, isolated execution, signature policy,
human review, and runtime controls for high-risk agent tools.

## Verification

The release workflow runs type checking, unit tests, end-to-end smoke tests, and
package installation tests before publishing. Main CI additionally covers the
git-sourced install path and package smoke tests on Linux, macOS, and Windows.