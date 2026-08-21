# Changelog

All notable changes to Lachesis are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

Lachesis is pre-1.0. Until 1.0 the graph schema, the query surface and the MCP tool set
may change between minor versions; those changes are called out here explicitly rather
than left for you to discover.

## Unreleased

- Added the MCP capability surface from the graph-bughunt backlog, including bounded
  scans, wrapper evidence, guard dominance, counterexamples, invariant traces,
  representation comparisons, and boundary crossings.
- Added explicit prerequisite responses for numeric range, object lifecycle, and
  error-path capabilities that are not yet emitted by the graph.
- Added clean-install release verification guidance.

## [0.1.0] — unreleased

First public release: `pip install lachesis-cpg`.

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
