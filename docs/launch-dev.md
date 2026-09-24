# Agent Skills and MCP Configs Need a Security Gate

> Internal publication note: review every claim and command before publishing.
> Dev.to requires disclosure when AI-assisted content is published. Keep an
> accurate disclosure such as: "AI was used for drafting and editing; the
> maintainer reviewed and verified the technical content."

AI agents are gaining access to real capabilities: reading files, running
commands, calling APIs, connecting to MCP servers, and combining those tools
under natural-language instructions.

At the same time, Agent Skills are still installed like documentation. In many
projects, a skill is a Markdown file copied into a directory or referenced by a
URL. That file can also contain executable scripts, credential access patterns,
network requests, and instructions designed to override the agent.

Skills and MCP configurations are becoming dependencies, but they often do not
get the basic protections we expect from dependencies:

- no lockfile recording exactly what was installed;
- no stable content digest for detecting later changes;
- no verification of the publisher;
- no CI gate to stop a high-risk configuration before merge.

AgentWarden is a static security gate for those assets. It is not a sandbox and
does not promise that an agent is safe at runtime. It scans, locks, and verifies
Agent Skills, tools, and MCP configurations before they reach an agent.

## Reproduce the problem in one minute

AgentWarden requires Node.js 22.6 or later and has zero runtime dependencies.
You can run the published CLI without installing it globally:

```bash
mkdir agentwarden-demo
cd agentwarden-demo

curl -fsSLO https://raw.githubusercontent.com/juangh123/AgentWarden/v0.3.3/examples/safe-skill.md
npx --yes agentwarden-cli@0.3.3 scan safe-skill.md

curl -fsSLO https://raw.githubusercontent.com/juangh123/AgentWarden/v0.3.3/examples/malicious-skill.md
npx --yes agentwarden-cli@0.3.3 scan malicious-skill.md
```

The safe sample exits with code `0`. The intentionally unsafe sample matches
credential, command, prompt-injection, or data-exfiltration rules and exits with
code `1`.

The exit code matters because it turns the same check into a CI gate:

- `0`: scan passed;
- `1`: risk found, integrity mismatch, or policy failure;
- `2`: invalid command, path, or configuration.

## What it scans

The current rules cover:

- credential and secret exposure, including sensitive local paths, privileged
  environment variables, API tokens, and embedded private keys;
- dangerous commands, including destructive operations, download-and-execute
  patterns, `eval`, and encoded execution chains;
- prompt injection and jailbreak patterns;
- data exfiltration and reverse-connection attempts;
- risky MCP configurations, including raw shell execution, unpinned server
  packages, and plaintext secrets in `env`;
- supply-chain patterns such as executing a remote script without a digest or
  using a lookalike download domain.

Directory scans discover Markdown skills and common MCP configuration formats.
You can narrow the scope with include and exclude globs:

```bash
npx --yes agentwarden-cli@0.3.3 scan . \
  --profile strict \
  --include "skills/**" \
  --exclude "skills/vendor/**"
```

Reports are redacted by default so a security scan does not leak the credentials
it was looking for.

## Lock the reviewed bytes

A one-time scan only tells you that the current content did not match a rule. It
does not prove that the file stayed unchanged.

AgentWarden stores reviewed skills in `skills.lock`, including the SHA-256
digest, package manifest, remote source, and publisher provenance. It is similar
in spirit to a package lockfile:

```bash
npx --yes agentwarden-cli@0.3.3 install ./skills/weather.md
npx --yes agentwarden-cli@0.3.3 verify .agentwarden/skills/weather.md
npx --yes agentwarden-cli@0.3.3 audit
npx --yes agentwarden-cli@0.3.3 sbom --output agentwarden.cdx.json
```

`verify` checks the installed content against the lockfile. `audit` checks
integrity and applies the current security policy. `sbom` exports the lockfile as
a CycloneDX 1.5 document.

Remote installation requires a publisher-provided SHA-256:

```bash
npx --yes agentwarden-cli@0.3.3 install \
  https://publisher.example/skills/weather.md \
  --sha256 <64-char-sha256>
```

If the digest does not match, or the downloaded content fails policy, the
command exits non-zero and does not silently record the artifact.

For publisher provenance, the CLI also supports a detached Ed25519 signature:

```bash
npx --yes agentwarden-cli@0.3.3 install \
  https://publisher.example/skills/weather.md \
  --sha256 <64-char-sha256> \
  --signature https://publisher.example/skills/weather.md.sig \
  --public-key ./trusted-publisher.pem
```

SHA-256 answers whether the bytes changed. An Ed25519 signature answers who
published them. They solve different problems.

## Put the gate in CI

To generate a policy file and a GitHub Actions workflow:

```bash
npx --yes agentwarden-cli@0.3.3 init --profile strict
```

The Action is also available from GitHub Marketplace:

```yaml
permissions:
  contents: read
  security-events: write

steps:
  - uses: actions/checkout@v7

  - uses: juangh123/AgentWarden@v0.3.3
    with:
      path: skills/
      profile: strict
      config: .agentwarden/policy.json
```

It emits SARIF for GitHub Code Scanning. Larger repositories can use changed-file
scans for pull requests. Existing findings can be accepted through a fingerprint
baseline with an owner and an expiration date, so temporary exceptions do not
become permanent.

## Limits matter

AgentWarden is a static gate, not a sandbox, antivirus product, or runtime policy
engine.

It can miss new attack patterns. It can produce false positives. Static rules do
not replace least privilege, isolation, network controls, code review, and human
judgment.

The most useful feedback is reproducible:

- MCP configuration formats that are not discovered or parsed correctly;
- realistic false positives;
- rule bypasses;
- CI workflow integration gaps;
- installation or cross-platform problems.

## Links

- GitHub: https://github.com/juangh123/AgentWarden
- npm: https://www.npmjs.com/package/agentwarden-cli
- GitHub Marketplace:
  https://github.com/marketplace/actions/agentwarden-security-gate
- Discussions:
  https://github.com/juangh123/AgentWarden/discussions

If you maintain Agent Skills, MCP servers, or an internal agent toolchain, I am
more interested in your current install and review workflow than in a star.
Concrete workflow gaps are what should shape the next release.

## Publication checklist

- Suggested tags: `ai`, `security`, `opensource`, `devops`.
- Alternative tag if available: `mcp`.
- Cover image: `docs/assets/dev-cover.png`.
- Use the first paragraph as the article description.
- Add the required AI-assisted content disclosure and confirm the maintainer
  reviewed the technical claims.
- Do not request likes, follows, or reposts.
