# AgentWarden v0.3.1

AgentWarden v0.3.1 improves finding identity in GitHub Code Scanning and makes
the GitHub Action independent of npm package publication.

## Highlights

- Baselines and SARIF now share one line-stable finding fingerprint, so moving a
  finding to another line keeps its identity in GitHub Code Scanning.
- SARIF rules now include GitHub `security-severity`, remediation links, and
  category/security tags.
- Added a complete
  [rule catalog](https://github.com/juangh123/AgentWarden/blob/v0.3.1/docs/rules.md)
  with detection scope and remediation guidance.
- The GitHub Action now runs the checked-in TypeScript source directly on Node
  22.6 or newer. It no longer installs dependencies or builds the project on
  every workflow run.

## GitHub Action

```yaml
- uses: juangh123/AgentWarden@v0.3.1
  with:
    path: skills/
    profile: strict
```

The Action works from the tagged repository checkout and does not require the
`agentwarden-cli` npm package to be published.

## npm Status

The npm package name remains `agentwarden-cli`. First publication is still
pending npm authentication or Trusted Publisher configuration. When those
credentials are available, rerun the v0.3.1 Release workflow; the tag and
package version already match.

## Security Scope

AgentWarden performs static analysis and provenance checks. It cannot prove that
an asset is safe. Use least privilege, isolated execution, signature policy,
human review, and runtime controls for high-risk agent tools.

## Verification

The release workflow runs type checking, unit tests, end-to-end smoke tests, and
package installation tests before publishing. Cross-platform package smoke tests
run in the main CI workflow on Linux, macOS, and Windows.
