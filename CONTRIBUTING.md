# Contributing to Arachne

Thanks for your interest in Arachne. Contributions — bug reports, fixes, new language frontends, and docs — are welcome.

## Ground rules

- **Be respectful.** Assume good faith; keep discussion technical.
- **One logical change per pull request.** Small, reviewable PRs land faster.
- **Keep commits revertible and auditable.** Clear messages; each commit should build.

## Getting started

1. Fork the repo and create a branch off `main`.
2. Make your change with tests where it makes sense.
3. Run the parity/checks suite before opening a PR:
   ```
   python3 -m pytest Arachne/frontends/checks.py
   ```
   The graph must stay at **byte-identical parity between the JSON and Kùzu backends** for the navigation/MCP tools — the checks suite enforces this. If your change touches the store or nav layer, make sure that test still passes.
4. Open a pull request describing *what* changed and *why*, and how you verified it.

## What makes a good contribution

- **New language frontends** are the highest-value area — a frontend emits the layered graph (syntax → symbols → calls → dataflow overlays) for a language/ecosystem. Follow an existing frontend under `Arachne/frontends/` as the template, and include the dataflow tier (`VALUE_FLOWS_TO`, `POINTS_TO`, `TAINT_FLOWS_TO`, `ALIASES`) — that tier is the point of Arachne, not an optional extra.
- **Store / nav improvements** — indexing for the warm-query paths, memory/latency wins, better reachability or guard reasoning.
- **Bug fixes with a regression test** that fails before and passes after.

Please open an issue to discuss larger or architectural changes before you write a lot of code, so we can agree on the approach.

## Reporting bugs

Open a GitHub issue with: what you did, what you expected, what happened, and a minimal reproducer (a small input tree is ideal). For **security** issues, do **not** open a public issue — follow [`SECURITY.md`](./SECURITY.md).

## Coding style

- Match the style of the surrounding code — naming, structure, and comment density.
- Prefer clarity over cleverness. Program analysis is subtle; readable code is safer.
- No new hard dependencies without discussion. `pyarrow` and `kuzu` are optional at runtime and guarded — keep it that way.

## Licensing and the DCO

Arachne is licensed under the **GNU Affero General Public License v3.0** (see [`LICENSE`](./LICENSE)). By contributing, you agree that your contributions are licensed under the same AGPL-3.0 terms.

### Developer Certificate of Origin

We use the [Developer Certificate of Origin](https://developercertificate.org/) (DCO). It is a lightweight statement that you wrote the patch or otherwise have the right to submit it under the project's license. To certify it, sign off each commit:

```
git commit -s -m "your message"
```

which adds a line:

```
Signed-off-by: Your Name <your.email@example.com>
```

Use your real name and a valid email. Unsigned commits may be asked to sign off before merge.

### A note on commercial licensing

Arachne is offered under the AGPL, and it may also be offered under a separate **commercial license** for users who cannot comply with the AGPL's network-copyleft terms. To keep that option open for the project, substantial contributions may be asked to agree to a Contributor License Agreement (CLA) in addition to the DCO. If and when that applies to your PR, a maintainer will let you know and point you to the CLA before merge — for typical bug fixes and small improvements, the DCO sign-off above is all that's needed.

## Questions

Open a GitHub issue or start a discussion. Thanks for helping make Arachne better.
