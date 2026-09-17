# Security Policy

Praxis is a security tool, so we take vulnerabilities seriously.

## Reporting a vulnerability

Please **do not** open a public issue for security vulnerabilities.

Instead, report privately via GitHub's
[private vulnerability reporting](https://github.com/praxisgaurdrails/praxis-lite/security/advisories/new)
or email the maintainers. We'll acknowledge your report as quickly as we can and keep you
updated on the fix.

## Scope & boundaries

Praxis Lite governs actions that **route through it** (via the MCP filesystem server). It
is a strong guardrail on that path — not an OS-wide, kernel-level filter. It cannot
intercept file access performed by an application through a channel Praxis never sees.

Credential stores (`~/.ssh`, `~/.aws`, keychains, `.env`) and root/irreversible actions
are refused unconditionally, regardless of caller. Destructive deletes are staged to a
recoverable trash — but always keep your own backups.
