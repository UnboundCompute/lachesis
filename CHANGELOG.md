# Changelog

All notable changes to Lachesis are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

Lachesis is pre-1.0. Until 1.0 the graph schema, the query surface and the MCP tool set
may change between minor versions; those changes are called out here explicitly rather
than left for you to discover.

## Unreleased

- Documented reliable MCP startup configurations for installed and source
  checkouts, including interpreter, graph-path, and stderr troubleshooting.
- Use `python -m pip` in user and contributor install commands so dependencies
  land in the interpreter that launches Lachesis and its MCP server.
- `lachesis doctor` now returns a failure status when it cannot inventory the
  requested source tree, so automation cannot mistake an incomplete check for
  a healthy install.
- CI now installs the matrix package with `python -m pip`, guaranteeing each
  Python job tests the interpreter it configured.
- The CI package-verification job now has the same 20-minute timeout as the
  release artifact gate, preventing a packaging hang from running indefinitely.
- Cache deletion now fails closed and reports filesystem errors instead of
  claiming an index was removed when the operating system rejected the delete.
- `cache clear --all` now deletes only recognized Lachesis entries and preserves
  unrelated files under a user-configured cache directory.
- Stale index cleanup now propagates permission and filesystem errors while
  remaining idempotent when a partial directory has already disappeared.
- Added a `make check` developer gate for the frontend parity suite; CI and release
  instructions now use the same command developers can run locally.
- Require `lachesis cache clear --all` before deleting every cached graph; targeted
  project clears remain unchanged.
- All installed Lachesis console modules now support consistent `--version` and
  MCP exposes explicit `--help`/`--version` handling instead of treating flags as
  graph paths.
- Pin the Lachesis self-test's Marketplace Action reference to the reviewed v1.0.0
  release commit for reproducible CI.
- Bound Kùzu and PyArrow runtime dependencies to the compatibility window exercised
  by CI and the release suite; future major/minor upgrades now require an explicit
  compatibility update.
- Added a dry-run-first `lachesis cache prune` command for reclaiming abandoned or
  old graph indexes without deleting anything until `--apply` is supplied.
- Aligned `lachesis doctor` with the published Python 3.10 and Node 20 support floors.

- Added the MCP capability surface from the graph-bughunt backlog, including bounded
  scans, wrapper evidence, guard dominance, counterexamples, invariant traces,
  representation comparisons, and boundary crossings.
- Added explicit prerequisite responses for numeric range, object lifecycle, and
  error-path capabilities that are not yet emitted by the graph.
- Added clean-install release verification guidance.
- The clean-wheel gate now starts the user-facing `lachesis mcp <source>` command,
  completes its indexing handoff, and verifies the MCP initialize/tools handshake;
  packaging CI therefore covers the same startup path used by the UI.
- The product CLI now rejects zero and negative frontend timeouts consistently across
  `scan`, `index`, and `mcp`, instead of passing an invalid safety bound into a build.
- Implicit graph-cache freshness now includes output-affecting frontend environment
  settings, so changing token/proof emission, C flags, or compile-command inputs cannot
  reuse a graph built under different semantics.
- Source discovery now ignores file symlinks that resolve outside the requested project,
  preventing accidental traversal of external or generated trees while preserving
  symlinks within the project.
- Optional concept-search and Kùzu recovery hints now use `python -m pip`, keeping
  installs attached to the interpreter that runs Lachesis.
- Concurrent product CLI builds now serialize per cache entry and recheck freshness
  after acquiring the lock, preventing two callers from deleting or writing the same
  graph simultaneously.
- Frontend timeouts now terminate the whole compiler process group on POSIX runners,
  preventing a timed-out child compiler from lingering and retaining memory.
- Comprehension source paths now preserve hidden and parent components while removing
  only explicit `./` prefixes, keeping navigation locations exact.
- Component-boundary queries now use the same lossless path normalization, so hidden
  directory names are not stripped before matching.
- Git-backed comprehension history lookups now have a 30-second bound and return a
  diagnostic instead of waiting indefinitely on a damaged or very large worktree.
- Packaging CI and release verification now install the sdist in an isolated environment
  and exercise its console scripts and vendored TypeScript payload, matching the wheel gate.
- Clean wheel and sdist verifiers now disable pip prompts and bound package download waits,
  so unattended release checks fail rather than hanging on an unavailable index.
- The top-level quickstart now leads with the product `lachesis scan`/`lachesis mcp`
  workflow, while retaining the explicit graph commands for artifact-oriented users.

## [0.1.0] — unreleased

First public release: `python -m pip install lachesis-cpg`.

### Added

- **A single install step.** The distribution carries the TypeScript compiler, so
  installing the package is enough to analyse a TypeScript project — no `npm install`,
  no network access at analysis time. Only the compiler API and its default library
  declarations are included, under the Apache 2.0 licence recorded in `NOTICE`.
  `tools/vendor_typescript.py` pins the version and verifies the download against the
  registry's own hash.
- **Console scripts**: `lachesis-analyze`, `lachesis-query`, `lachesis-mcp`,
  `lachesis-plan`.
- `tools/verify_wheel.sh`, which drives a built wheel from a clean virtualenv outside
  the repository, and `RELEASING.md`, which is the checklist around it.

### Changed

- **The package is one top-level name, `lachesis`.** It previously installed `Lachesis`,
  `nav` and `planner` at top level; the latter two are ordinary English words and
  claiming them globally would shadow a module in any project that has its own. Imports
  are now `lachesis.nav` and `lachesis.planner`. Nothing a user types on the command
  line changed. This is the reason the rename happened before the first release rather
  than after: once published, the import path is public API.

### Fixed

- The TypeScript frontend's dependency-source analysis is off by default (it is what
  bounds memory on a real dependency tree), but the test covering it still assumed the
  older always-on behaviour. Both the default and the opt-in
  (`LACHESIS_INCLUDE_DEP_TYPES=1`) are now pinned by tests.
- Analysing a tree that contains a Lachesis install no longer walks the vendored
  TypeScript compiler as if it were the project's own source.
