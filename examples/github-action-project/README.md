# GitHub Action integration example

This directory is a minimal downstream repository for the AgentWarden GitHub
Action. It contains:

- `skills/release-notes/SKILL.md`: a reviewed skill with no blocking findings.
- `.agentwarden/policy.json`: the strict policy used by both local scans and CI.
- `.github/workflows/agentwarden.yml`: the pull request and main-branch gate.

Run the same policy locally:

```bash
npx --yes agentwarden-cli@0.3.3 scan . \
  --config .agentwarden/policy.json \
  --json
```

The command exits `0` with a `100/100` score. The repository CI also runs this
directory through the local Action, so the example cannot drift into an
unverified configuration.

For a downstream repository, copy the workflow and policy files, then replace
the example skill with the skills that repository actually reviews and locks.
