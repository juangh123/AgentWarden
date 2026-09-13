# Security Policy

## Supported Versions

Security fixes are provided for the latest published `0.x` release. Users should
upgrade to the newest `agentwarden-cli` version before reporting an issue that
may already be fixed.

## Reporting a Vulnerability

Do not open a public issue for a suspected vulnerability. Use GitHub Security
Advisories:

https://github.com/juangh123/AgentWarden/security/advisories/new

Include:

- Affected version or commit
- A minimal reproduction
- Expected and observed behavior
- Security impact and likely attack path
- Any suggested mitigation

Do not include live credentials, private keys, customer data, or other secrets.
Replace sensitive values with clearly marked test data.

## Response Expectations

The maintainers aim to acknowledge a report within three business days and
provide an initial assessment within seven business days. Timelines may vary
with severity, reproducibility, and maintainer availability.

## Scope

In scope:

- Scanner rule bypasses with a concrete security impact
- Path traversal, archive extraction, or remote source handling flaws
- Lockfile integrity, signature, or publisher policy bypasses
- Redaction failures that expose secrets in JSON, SARIF, or terminal output
- CI, release, or package publishing security issues

Out of scope:

- False positives without a bypass or security impact
- Findings in third-party skills that AgentWarden correctly reports
- Social engineering, spam, or denial-of-service reports without a project-specific flaw

AgentWarden performs static analysis and provenance checks. It cannot prove that
an asset is safe, and it must not be used as the only control for high-risk
execution.
