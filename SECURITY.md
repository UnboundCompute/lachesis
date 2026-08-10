# Security Policy

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues, discussions, or pull requests.**

Arachne is a program-analysis tool that parses untrusted source code and builds a graph from it. Bugs in that path (e.g. a crafted input tree that causes resource exhaustion, path traversal during ingestion, or code execution in a frontend) are treated as security issues.

If you believe you have found a security vulnerability, report it privately using **one** of:

- **GitHub Private Vulnerability Reporting** — go to the **Security** tab → **Report a vulnerability** (preferred; keeps everything in one place).
- **Email** — riyandhiman14@gmail.com with subject line `SECURITY: Arachne`.

Please include:

- A description of the vulnerability and its impact.
- Steps to reproduce (a minimal input / codebase snippet if possible).
- The affected component (`Arachne` builder, a specific frontend, `kuzu_store`, or `nav`/MCP) and version/commit.
- Any suggested remediation, if you have one.

## What to expect

- **Acknowledgement** within a few days of your report.
- An initial assessment and severity triage, and a private channel to coordinate.
- Credit in the release notes / advisory once the issue is fixed, unless you prefer to remain anonymous.

Please give a reasonable window to investigate and release a fix before any public disclosure. As a small/early project there is no formal SLA, but reports are taken seriously and handled promptly.

## Scope

In scope:

- The graph-builder and language frontends (parsing/analysing input source).
- The Kùzu store writer and the `nav` navigation / MCP server.

Out of scope:

- Vulnerabilities in third-party dependencies (report those upstream; do tell us if Arachne uses them in an unsafe way).
- Findings that require a already-privileged local attacker with no additional privilege gain.
- The *content* of graphs Arachne produces about *your* code — that is your data, not an Arachne vulnerability.

## Supported versions

Arachne is pre-1.0 and moves fast. Security fixes are applied to the latest `main`. Pin a commit if you need stability, and upgrade to pick up fixes.
