# Contributing

Thanks for helping improve AgentWarden.

## Development Setup

Requirements:

- Node.js 22.6 or newer
- npm 10 or newer

```bash
npm ci
npm run typecheck
npm test
npm run smoke
npm run test:package
npm run test:mvp
npm run test:git-install
```

`npm run test:package` builds the project, creates an npm tarball, installs it
into a temporary consumer, and verifies the published command aliases, scan
exit codes, and SBOM output.

`npm run test:mvp` creates the release tarball and checksum, installs it into a
clean consumer, and walks the complete packaged CLI surface from `init` through
scan, SARIF, install, verify, audit, SBOM, rules, baseline, and uninstall.

`npm run test:git-install` clones this repository into a temporary directory and
installs it as a git dependency, which fails if the `prepare` build hook stops
producing `dist/` for git-sourced installs.

## Change Scope

- Keep changes focused on one behavior or maintenance concern.
- Preserve the zero-runtime-dependency design.
- Update tests and docs with behavior changes.
- Do not add a dependency when the Node.js standard library is sufficient.
- Never weaken redaction, integrity, signature, or publisher policy checks
  without an explicit security rationale.

## Tests

Add focused tests for scanner rules, parsers, policy handling, provenance, and
exit-code behavior. A change is not complete until all of these pass:

```bash
npm run typecheck
npm test
npm run smoke
npm run test:package
npm run test:mvp
npm run test:git-install
```

## Pull Requests

A pull request should include:

- The problem and user-visible impact
- The chosen approach and rejected alternatives when relevant
- Test evidence
- Documentation changes
- Security or compatibility notes

Keep commit subjects in imperative form, for example:

```text
feat: add trusted publisher policy
fix: reject unsafe archive paths
docs: explain SARIF upload
```

## Security Reports

Do not report vulnerabilities in a public issue. Follow [SECURITY.md](SECURITY.md).
