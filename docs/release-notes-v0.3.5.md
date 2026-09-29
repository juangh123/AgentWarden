# AgentWarden v0.3.5

AgentWarden v0.3.5 is a security release for the CLI, lockfile, publisher
provenance, and report-redaction paths.

## Security Highlights

- Publisher signatures are re-verified from `signatureProof` and a
  content-addressed local attestation. Legacy self-reported
  `signatureVerified` booleans are no longer trusted.
- Lockfile parsing now validates the schema, skill keys, relative paths,
  timestamps, scores, remote metadata, package manifests, and provenance
  records before use. Unsafe or malformed files fail closed.
- Hash casing and portable paths are normalized consistently, so valid
  uppercase SHA-256 values and Windows path separators no longer cause false
  integrity mismatches.
- Signature attestations are read through a file descriptor with a regular
  file check, a 20 MiB cap, and truncation or growth detection.
- Sensitive URL credentials, query parameters, fragments, and signed download
  URLs are redacted from install output, lockfiles, `list --json`, and SBOM
  distribution metadata.
- Malformed implicitly discovered policy files now fail closed instead of
  silently falling back to the legacy profile.
- Package installations reject unsafe replacement of non-empty explicit output
  directories unless `--force` is provided. Baseline writes use atomic file
  replacement.

## Install Today

```bash
npx --yes agentwarden-cli@0.3.5 scan ./skills
```

Or install globally:

```bash
npm install --global agentwarden-cli@0.3.5
agentwarden scan ./skills
```

## GitHub Action

```yaml
- uses: juangh123/AgentWarden@v0.3.5
  with:
    path: .
    config: .agentwarden/policy.json
    policy-guard: 'true'
    policy-guard-base: ${{ github.event.pull_request.base.sha }}
```

## Verification

The release workflow runs type checking, 150 unit tests, 138 end-to-end checks,
package installation tests, and the installed-artifact MVP acceptance gate
before publishing the checksummed tarball. Main CI covers package installation
on Linux, macOS, and Windows.

AgentWarden remains a static gate. It does not execute scanned assets and does
not guarantee that they are safe. Use least privilege, isolation, network
controls, publisher policy, and human review for high-risk tools.
