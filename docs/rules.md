# Security Rule Catalog

AgentWarden ships 18 static analysis rules across credential access, destructive
commands, prompt injection, data exfiltration, MCP configuration, and supply
chain risk. Use `agentwarden rules --json` for the effective severity after
policy overrides.

| Rule | Category | Default severity |
| :--- | :--- | :--- |
| `SEC-CRED-001` | Credential | Critical |
| `SEC-CRED-002` | Credential | Critical |
| `SEC-CRED-003` | Credential | High |
| `SEC-CRED-004` | Credential | Critical |
| `SEC-CMD-001` | Destructive command | Critical |
| `SEC-CMD-002` | Destructive command | High |
| `SEC-CMD-003` | Destructive command | High |
| `SEC-INJ-001` | Prompt injection | Critical |
| `SEC-INJ-002` | Prompt injection | High |
| `SEC-INJ-003` | Prompt injection | Medium |
| `SEC-EXFIL-001` | Exfiltration | Critical |
| `SEC-EXFIL-002` | Exfiltration | High |
| `SEC-MCP-003` | MCP misconfiguration | High |
| `SEC-MCP-001` | MCP misconfiguration | Critical |
| `SEC-MCP-002` | MCP misconfiguration | High |
| `SEC-MCP-004` | MCP misconfiguration | High |
| `SEC-SUPPLY-001` | Supply chain | High |
| `SEC-SUPPLY-002` | Supply chain | Medium |

## SEC-CRED-001

**Sensitive Credential File Access**

Detects code or instructions that access SSH keys, AWS credentials, GPG material,
Kubernetes configuration, or `.env` files.

**Remediation:** Remove direct credential path access and inject narrowly scoped
secret values through an approved runtime secret store.

## SEC-CRED-002

**Direct API Key / Secret Environment Variable Extraction**

Detects direct reads or exports of high-privilege environment variables such as
`OPENAI_API_KEY`, `AWS_SECRET_ACCESS_KEY`, or `GITHUB_TOKEN`.

**Remediation:** Keep credentials outside prompts and logs. Use the smallest
possible runtime permission and never echo the secret value.

## SEC-CRED-003

**Hardcoded API Tokens / Secret Keys**

Detects realistic-looking provider tokens, cloud access keys, JWTs, and payment
API keys embedded in Skill content.

**Remediation:** Revoke the exposed credential, replace it with a placeholder,
and load the real value from a secret manager.

## SEC-CRED-004

**Embedded Private Key Material**

Detects complete SSH, RSA, EC, DSA, encrypted, or PGP private key blocks.

**Remediation:** Revoke and rotate the key, remove all private key material, and
reference keys through a protected runtime identity.

## SEC-CMD-001

**Destructive Filesystem Operation**

Detects catastrophic deletion, formatting, or permission changes against root,
home, or broad wildcard paths.

**Remediation:** Remove unconstrained recursive deletion and require explicit,
scoped paths with preflight checks.

## SEC-CMD-002

**Arbitrary Remote Code Execution / Dynamic Piped Download**

Detects `curl | sh`, `wget | bash`, and similar unverified download-and-execute
flows.

**Remediation:** Pin an immutable version and integrity hash, download it first,
and verify it before execution.

## SEC-CMD-003

**Eval / Decode-and-Execute Chains**

Detects dynamic `eval`, base64 or hex decoding piped into interpreters, and
similar obfuscated execution patterns.

**Remediation:** Replace dynamic evaluation with explicit code paths and review
the decoded payload as plain text.

## SEC-INJ-001

**Prompt Injection / Instruction Override**

Detects attempts to ignore previous instructions, bypass system policy, or claim
new authority.

**Remediation:** Remove adversarial override language and keep instructions
scoped to the declared task.

## SEC-INJ-002

**Jailbreak Lexicon / Unauthorized Mode Override**

Detects known jailbreak phrases and requests to enter unrestricted or
policy-free modes.

**Remediation:** Replace mode-override language with explicit, reviewable task
constraints.

## SEC-INJ-003

**Encoded / Obfuscated Payload Markers**

Detects `base64`, `atob`, `String.fromCharCode`, and other encoding helpers that
may hide instructions or executable payloads.

**Remediation:** Store behavior in plain text and document the purpose of any
remaining encoding operation.

## SEC-EXFIL-001

**Suspicious Data Exfiltration / Reverse Shell**

Detects sensitive data posted to unknown endpoints, raw-IP callbacks, and reverse
shell constructs.

**Remediation:** Remove the outbound flow, pin approved destinations, and require
explicit user consent before transmitting data.

## SEC-EXFIL-002

**Known Data-Sink Endpoint or Local File Upload**

Detects webhook collectors, request-bin services, interactsh endpoints, and
uploads of local files with `curl -d @`.

**Remediation:** Use an approved destination and never upload local files or
credentials to an unverified collector.

## SEC-MCP-003

**Malformed or Incomplete MCP Configuration**

Detects invalid JSON and server files that do not define a supported MCP server
map.

**Remediation:** Fix JSON syntax and define servers under `mcpServers`, `servers`,
`mcp.servers`, `context_servers`, `customizations.vscode.mcp.servers`, or
Claude Code `projects.*.mcpServers`.

## SEC-MCP-001

**MCP Server Dangerous Command Invocation**

Detects raw shell interpreters, downloaders, and unpinned `npx` or `uvx` server
launches.

**Remediation:** Use a trusted binary wrapper or pin the exact package version
and integrity source.

## SEC-MCP-002

**MCP Server Hardcoded Plaintext Secrets**

Detects credentials committed directly inside an MCP server `env` or `headers`
object.

**Remediation:** Keep secret values out of repository configuration and inject
them through the runtime environment or a secret manager.

## SEC-MCP-004

**Insecure Remote MCP Endpoint**

Detects remote MCP servers that use HTTP, malformed URLs, or credentials
embedded directly in the endpoint URL.

**Remediation:** Use a valid HTTPS endpoint and keep credentials in runtime
environment variables or a secret manager.

## SEC-SUPPLY-001

**Suspicious / Untrusted Remote Script Installation**

Detects unverified remote installation instructions that bypass checksum or
source pinning.

**Remediation:** Pin an immutable commit or release and verify a published
checksum or signature before use.

## SEC-SUPPLY-002

**Typosquatting or Untrusted Domain Tooling Source**

Detects lookalike domains that imitate official package registries or source
hosts.

**Remediation:** Replace the URL with the official HTTPS endpoint and validate
the organization ownership before downloading.

## Suppressions and Policy

Use `ignoreRules`, `severityOverrides`, and auditable baselines only after
review. Prefer fixing the underlying behavior. Every suppression should have an
owner, rationale, and expiry where possible.
