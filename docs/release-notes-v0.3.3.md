# AgentWarden v0.3.3

AgentWarden v0.3.3 expands MCP configuration discovery and closes several
fail-open paths found while hardening the scanner. It is the first tagged
release published through GitHub Actions Trusted Publisher with npm provenance.

## Highlights

- Discover common MCP configuration files used by Cursor, VS Code, GitHub
  Copilot, Windsurf, Cline, Roo Code, Continue, Zed, Gemini, Qwen, and Dev
  Containers.
- Scan Claude Code user and project scopes in `~/.claude.json`, including
  `mcpServers` and `projects.*.mcpServers`.
- Added `SEC-MCP-004` for insecure remote MCP endpoints, including plain HTTP,
  invalid URLs, and credentials embedded in URLs.
- Expanded `SEC-MCP-002` to detect hardcoded credentials in remote server
  headers.
- Hardened package and command inspection against reserved server names,
  absolute-path shell commands, downloaders, scoped packages, floating tags,
  and malformed discovered configurations.
- Corrected Windows atomic replacement behavior, supply-chain finding line
  numbers, SARIF schema output, and artifact URI encoding.

## Install Today

```bash
npx --yes agentwarden-cli@0.3.3 scan ./skills
```

Or install globally:

```bash
npm install --global agentwarden-cli@0.3.3
agentwarden scan ./skills
```

The first bootstrap release, `agentwarden-cli@0.3.2`, did not have npm
provenance. The v0.3.3 artifact is published from `release.yml` through GitHub
OIDC and includes a signed provenance attestation.

## GitHub Action

```yaml
- uses: juangh123/AgentWarden@v0.3.3
  with:
    path: skills/
    profile: strict
```

The floating `v0` Action tag is updated to the same verified commit after the
release is published.

## Verification

The release workflow runs type checking, unit tests, end-to-end smoke tests,
package installation tests, and the installed-artifact MVP acceptance gate
before publishing the checksummed tarball. Main CI covers package installation
on Linux, macOS, and Windows.

AgentWarden remains a static gate. It does not execute scanned assets and does
not guarantee that they are safe. Use least privilege, isolation, network
controls, publisher policy, and human review for high-risk tools.
