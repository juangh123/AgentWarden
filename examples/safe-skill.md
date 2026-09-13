---
name: release-notes-helper
description: Format release notes from user-provided text.
version: 1.0.0
---

# Release Notes Helper

Turn a list of user-provided changes into concise release notes.

## Input

The caller provides an array of change descriptions and an optional version number.

## Output

Return Markdown containing:

- A short summary
- Grouped features, fixes, and maintenance items
- A version heading when a version is supplied

## Constraints

- Operate only on the supplied text.
- Keep unknown details unchanged instead of inventing facts.
- Do not access files, environment variables, credentials, or network endpoints.
