# AgentWarden v0.3.4

AgentWarden v0.3.4 closes the policy-rewrite gap reported by an external
reviewer. A pull request can no longer add a risky Skill or MCP configuration
while weakening the same policy that evaluates it.

## Highlights

- Added `agentwarden policy guard <base-ref>` to compare the effective
  workspace policy with the approved policy on a base Git ref.
- Added the optional GitHub Action inputs `policy-guard` and
  `policy-guard-base`; newly initialized workflows and the downstream Action
  example enable the guard for pull requests.
- The guard reads inherited policy chains and compares every effective value,
  including profiles, failure thresholds, scan scope, ignored rules, severity
  overrides, and configured finding baselines.
- Policy-affecting Action inputs are included in the comparison, so workflow
  inputs cannot silently weaken the approved policy.
- Baseline additions, removals, expiry changes, review metadata changes, and
  entry changes are guarded as policy changes. Reordering entries remains a
  no-op.
- Added a complete downstream GitHub Action example with `CODEOWNERS`
  guidance and CI coverage through both the local Action source and the
  published `v0.3.3` tag.

## Install Today

```bash
npx --yes agentwarden-cli@0.3.4 scan ./skills
```

Or install globally:

```bash
npm install --global agentwarden-cli@0.3.4
agentwarden scan ./skills
```

## GitHub Action

```yaml
- uses: juangh123/AgentWarden@v0.3.4
  with:
    path: .
    config: .agentwarden/policy.json
    policy-guard: 'true'
    policy-guard-base: ${{ github.event.pull_request.base.sha }}
```

The direct Action input remains opt-in for compatibility. `agentwarden init`
and the downstream example enable it for pull requests by default. Use
`CODEOWNERS` to require a separate review for policy, baseline, and workflow
changes.

## Verification

The release workflow runs type checking, 132 unit tests, 127 end-to-end checks,
package installation tests, and the installed-artifact MVP acceptance gate
before publishing the checksummed tarball. Main CI covers package
installation on Linux, macOS, and Windows.

AgentWarden remains a static gate. It does not execute scanned assets and does
not guarantee that they are safe. Use least privilege, isolation, network
controls, publisher policy, and human review for high-risk tools.
