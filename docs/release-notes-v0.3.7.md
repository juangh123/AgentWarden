# AgentWarden v0.3.7

AgentWarden v0.3.7 is a startup-performance and release-assurance update. It
does not change scanner rules, policy defaults, lockfile formats or public
command semantics.

## Highlights

- CLI command modules are loaded only when their command is selected. On the
  Windows reference environment, stable local medians moved to roughly 95 ms
  for `--version`, 97 ms for `--help`, and 137 ms for the malicious fixture
  scan.
- The cold-start benchmark can repeat network samples with independent npm
  caches. A scheduled workflow records three fresh-cache samples per run.
- CI now tests the exact minimum runtime, Node.js 22.6.0, and audits both
  high-severity advisories and npm registry signatures on Node 24.
- CodeQL analyzes the JavaScript/TypeScript source with the
  `security-extended` query pack.
- `npm run verify:local` provides one reusable pre-release health gate, and
  manual npm publishing now runs that gate before artifact verification.

## Verification

```bash
npm run verify:local
npm run bench:cold-start:network:repeat
npm run test:release
```

The local health gate covers type checking, 245 tests, 140 end-to-end checks,
package installation, dependency audit and registry signatures. The release
gate verifies the committed tarball, `SHA256SUMS`, clean installation and the
full CLI lifecycle.

## Upgrade

```bash
npx --yes agentwarden-cli@0.3.7 --version
npm install --global agentwarden-cli@0.3.7
```

In GitHub Actions:

```yaml
- uses: juangh123/AgentWarden@v0.3.7
```

This is a static gate, not a sandbox or a guarantee that an asset is safe.
