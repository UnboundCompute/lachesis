# Security Policy

## Reporting a vulnerability

Please do not report security vulnerabilities through public GitHub issues, discussions, or pull requests.

Lachesis is a program-analysis tool. It parses untrusted source code and builds a graph from it, so bugs in that path are treated as security issues. That includes things like a crafted input tree that causes resource exhaustion, path traversal during ingestion, or code execution inside a frontend.

If you think you have found a security vulnerability, report it privately using one of these:

- GitHub Private Vulnerability Reporting. Go to the Security tab, then Report a vulnerability. This is the preferred route because it keeps everything in one place.
- Email riyandhiman14@gmail.com with the subject line `SECURITY: Lachesis`.

Please include:

- A description of the vulnerability and its impact.
- Steps to reproduce it, ideally with a minimal input or codebase snippet.
- The affected component, whether that is the Lachesis builder, a specific frontend, `kuzu_store`, or `nav` and the MCP server, plus the version or commit.
- A suggested fix, if you have one.

## What to expect

- An acknowledgement within a few days of your report.
- An initial assessment and severity triage, and a private channel to work through it together.
- Credit in the release notes or advisory once the issue is fixed, unless you would rather stay anonymous.

Please give a reasonable window to investigate and ship a fix before any public disclosure. This is a small and early project, so there is no formal SLA, but reports are taken seriously and handled promptly.

## Scope

In scope:

- The graph builder and the language frontends, meaning anything that parses or analyzes input source.
- The Kùzu store writer and the `nav` navigation and MCP server.

Out of scope:

- Vulnerabilities in third-party dependencies. Report those upstream. Do tell us if Lachesis uses one of them in an unsafe way, though.
- Findings that need an already-privileged local attacker who gains no additional privilege.
- The content of the graphs Lachesis produces about your code. That is your data, not an Lachesis vulnerability.

## Supported versions

Lachesis is pre-1.0 and moves fast. Security fixes land on the latest `main`. If you need stability, pin a commit, and upgrade to pick up fixes.
