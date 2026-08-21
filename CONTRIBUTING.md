# Contributing to Lachesis

Thanks for your interest in Lachesis. Contributions are welcome, whether that is a bug report, a fix, a new language frontend, or docs.

## Ground rules

- Be respectful. Assume good faith and keep the discussion technical.
- One logical change per pull request. Small, reviewable PRs land faster.
- Keep commits revertible and auditable. Write clear messages, and make sure each commit builds.

## Getting started

1. Fork the repo and create a branch off `main`.
2. Install it. Python 3.10 or newer is required, because the embedded Kuzu store is
   the graph store. The TypeScript frontend shells out to the real compiler, so it
   also needs the npm dev dependency:
   ```
   python -m pip install -e ".[dev]"
   npm ci
   ```
   A built distribution carries its own copy of the compiler instead, fetched by
   `tools/vendor_typescript.py`; a checkout does not need that and prefers its own
   `node_modules`, so the TypeScript version you develop against is the one
   `package.json` pins. See [`RELEASING.md`](./RELEASING.md).
3. Make your change, with tests where it makes sense.
4. Run the local parity gate before you open a PR:
   ```
   make check
   ```
   The graph has to stay at byte-identical parity between the JSON and Kùzu backends for the navigation and MCP tools, and the checks suite enforces that. If your change touches the store or the nav layer, make sure that test still passes.

   The end-to-end tests analyze the fixture corpus at
   `lachesis/frontends/typescript/fixtures/project/`. It is deliberately small — a
   dozen files — and it exercises the same code paths as a production codebase
   (public parameter to repository lookup, a guarded/unguarded sibling pair, a
   dynamic-code frontier, a route registration) without the same scale. Point
   `LACHESIS_CORPUS` at a larger TypeScript tree to re-run the same tests against it;
   the assertions that pin the fixture's exact file and function sets step aside
   automatically, and the structural ones still run.
5. Open a pull request that says what changed, why, and how you verified it.

## What makes a good contribution

- New language frontends are the highest-value area. A frontend emits the layered graph for a language or ecosystem, going from syntax to symbols to calls to dataflow overlays. Follow an existing frontend under `lachesis/frontends/` as your template, and include the dataflow tier: `DEFINES`, `VALUE_FLOWS_TO`, `READS_FROM`, `WRITES_TO`, `ALIASES`, and `allocation` nodes. That tier is the whole point of Lachesis, not an optional extra. `POINTS_TO`, `TAINT_FLOWS_TO` and the rest of the derived set are overlay-owned and rejected from a frontend snapshot by the validator (`FRONTEND_FORBIDDEN_EDGE_KINDS` in `lachesis/core/schema.py`): emit the allocation sites and the value flow, and the overlays derive the heap and the taint from them.
- Store and nav improvements, like indexing for the warm-query paths, memory or latency wins, or better reachability and guard reasoning.
- Bug fixes with a regression test that fails before your change and passes after.

If you are planning something large or architectural, please open an issue to talk it through before you write a lot of code, so we can agree on the approach.

## Reporting bugs

Open a GitHub issue with what you did, what you expected, what actually happened, and a minimal reproducer. A small input tree is ideal. For security issues, do not open a public issue. Follow [`SECURITY.md`](./SECURITY.md) instead.

## Coding style

- Match the style of the code around you, including naming, structure, and comment density.
- Prefer clarity over cleverness. Program analysis is subtle, and readable code is safer.
- No new runtime dependencies without discussion. `kuzu` and `pyarrow` are the only two, and everything else is standard library. Keep it that way.

## Licensing and the DCO

Lachesis is licensed under the GNU Affero General Public License v3.0. See [`LICENSE`](./LICENSE). By contributing, you agree that your contributions are licensed under those same AGPL-3.0 terms.

### Developer Certificate of Origin

We use the [Developer Certificate of Origin](https://developercertificate.org/), or DCO. It is a lightweight statement that you wrote the patch, or otherwise have the right to submit it under the project's license. To certify it, sign off each commit:

```
git commit -s -m "your message"
```

That adds a line like:

```
Signed-off-by: Your Name <your.email@example.com>
```

Use your real name and a valid email. If a commit is not signed off, you may be asked to sign it off before it can merge.

### A note on commercial licensing

Lachesis is offered under the AGPL, and it may also be offered under a separate commercial license for people who cannot comply with the AGPL's network-copyleft terms. To keep that option open for the project, substantial contributions may be asked to agree to a Contributor License Agreement (CLA) on top of the DCO. If that ends up applying to your PR, a maintainer will tell you and point you to the CLA before anything merges. For typical bug fixes and small improvements, the DCO sign-off above is all you need.

## Questions

Open a GitHub issue or start a discussion. Thanks for helping make Lachesis better.
