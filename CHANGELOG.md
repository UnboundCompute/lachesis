# Changelog

All notable changes to Lachesis are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

Lachesis is pre-1.0. Until 1.0 the graph schema, the query surface and the MCP tool set
may change between minor versions; those changes are called out here explicitly rather
than left for you to discover.

## [0.5.1]

Explorer-bundle comprehension release. The graph-first 2.0 Explorer bundle already
carried nodes, edges, value paths and the security envelope, but nothing that let a
reader who does not know the repository *start reading* it. This release adds that
comprehension layer, projected entirely from the same loaded store the rest of the
export uses, so every id it emits resolves to a real node it also includes. Version
and metadata only otherwise: no engine, schema-store, or query behavior changes, and
schema 1.0 bundle output is byte-for-byte unchanged.

### Added

- **Comprehension-first 2.0 Explorer bundle.** `graph.entrypoints` are derived from
  the entrypoint-anchoring recognitions (route / callback / exported-entry), each
  gated to a node with a real file and line so it is actually openable. For each
  entry, `paths.requests` renders a guided walk down the real `CALLS` chain out of
  the handler — every consecutive hop pair is a genuine edge, with stable hop ids,
  edge labels, and explicit `source_node`/`sink_node` endpoints. Every featured node
  carries real source (`end_line`, dotted `module`, `qualified_name`, and a bounded,
  highlighted `source_window`), edges are promoted to first-class objects (stable id,
  canonical kind plus a relation alias, confidence, dynamic flag, limitations),
  `graph.modules` partition every file-bearing node by its file so no node lands in
  two modules, and `graph.coverage` states included vs indexed node counts exactly.
  `meta` gains `description` and `generated_at`. The projection degrades to a bare
  graph on any failure, so the security bundle always stands.
- **`trace --description TEXT`** records a one-line projection description in bundle
  `meta` (2.0).
- **`meta.loc`/`meta.lines`** are now populated from the loaded graph's files (a
  cached read shared with the source windows, no extra pass), kept distinct from
  `indexed_nodes`; an unreadable file contributes 0 rather than a guess.

### Fixed

- Snippet lookup and entrypoint enrichment silently degraded because the bundle
  builder called a context accessor that did not exist; corrected so real snippets
  and the comprehension surface populate.

## [0.5.0]

Scale-and-lifetime release. Two engine capabilities headline it: the build now
federates independent shards so a large multi-language tree is analyzed within a
bounded memory envelope, and a native temporal pipeline confirms C object-lifetime
bugs (double-free, use-after-free) end to end rather than leaving them out of the
taxonomy. Pre-1.0: the candidate surface, the graph schema and the query projection
widen here; older candidate output remains readable.

### Added

- **Federated sharding.** Independent shard stores are federated by cross-shard USR
  linking, so value flow, callers and callees resolve across shard boundaries. The
  cross-shard value-flow composition runs in Pass 2/3 across all four languages
  (C, Python, JavaScript, TypeScript), reverse resolution recovers federated
  callers, and shards build in parallel by default. Cross-shard nodes and edges are
  de-duplicated on COPY so the store reports true, not double-counted, totals.
- **Native temporal lifetime pipeline (C).** A separate native path —
  `native/clang_frontend` (C lifecycle events) → the Rust `lifetime_kernel`
  typestate matcher → the temporal-obligation census — surfaces object-lifetime
  families (double-free, use-after-free and their kin) that the sink taxonomy alone
  cannot name. Double-free and use-after-free are confirmed end to end on the
  lifetime fixtures, with no false positive on the clean control. Confirmed
  temporal leads carry `file:line` (decl id resolved to source location).
- **Scan from a URL.** `lachesis` accepts a git URL as the scan source and clones
  it before building, so a one-shot scan needs no prior checkout.
- **Graph-first Explorer bundle export and proof CLI.** Export a graph-first
  Explorer bundle with validated trace artifacts and explicit source-link
  templates, for offline review of a scan.
- **Object-integrity reflection family** in the taxonomy, and type-keyed sink
  models made sound by stamping the receiver type in Python and TypeScript so a
  model keyed to a type binds only on that type.
- **Guard adjudication substrate.** The C frontend emits loop and switch body
  regions and classifies guard dominance by surfacing branch substrate to the
  census; the validation-call guard recognizer fires on real call graphs and is
  surfaced in the explain capsule.

### Fixed

- **Lifetime-kernel precision.** Closed the aggregate-copy struct double-free;
  made cap truncation per-function instead of a graph-wide veto; stopped
  return-may-null origins from seeding a spurious leak; stopped flagging the clean
  realloc idiom as leak/dangling-use; and unlinked leading declarations from the
  synthetic exit so a leading-decl no longer bypasses the exit check.
- **Bounded-memory Linux scale.** Pass 3 shards by weakly-connected component and
  the native semantic serialize streams, so peak RSS is bounded on a large tree;
  the enrich shard split streams rather than buffering the whole input.
- **Native family reporting is honest.** Unvalidated native families are reported
  as PARTIAL leads, and native temporal findings that resolve to a non-C file are
  dropped rather than surfaced against the wrong language.
- **Graph wire robustness.** Lone surrogates are scrubbed instead of aborting the
  build.

### Known limitations

- **Temporal confirmation is C-only.** The confirmed lifetime families run through
  the native clang/Rust pipeline; the other languages carry the sink taxonomy but
  not the temporal-obligation census.
- **One open lifetime false positive.** An object that is both freed and used after
  free can be spuriously reported leaked at function exit; this is a
  `lifetime_kernel` state-machine issue and is tracked, not yet closed.

## [0.4.2]

Packaging fix. The Atropos catalog — the data every catalog-keyed judgement reads,
including which calls are allocations and releases — was never bundled into the
distribution. `ATROPOS_ROOT` defaulted to a sibling checkout that an installed wheel
or the Docker image does not have beside it, so every catalog table read empty: the
reader still parsed and navigated code, but the lifetime matcher saw nothing marked
freed and reported no double-free or use-after-free. The catalog now ships inside the
distribution (`lachesis/_atropos_catalog/`, staged by `tools/vendor_atropos.py` before
a release build), and both catalog resolvers fall back to it. An explicit `$ATROPOS_ROOT`
or a real sibling checkout still wins, so a source checkout is unchanged; a standalone
wheel is now self-contained. No engine changes from 0.4.1.

## [0.4.1]

Packaging fix. The `lachesis-mcp` console script was removed in favor of the
`lachesis mcp` subcommand, but the Docker image entrypoint and the MCP registry
launcher (`server.json`) still invoked the old name, so the published container
failed to start and the registry entry pointed at a missing command. Both now
call `lachesis mcp`. No engine changes from 0.4.0.

## [0.4.0]

Engine-correctness release. The Rust matcher and flow substrate now report what
they actually did, the binder attaches a wider class of sinks, and three real
CVE sinks that the reader previously dropped now surface as leads. Pre-1.0: the
candidate surface widens here; older candidate output remains readable.

### Added

- **Receiver-access, DOM-write, and computed-write sinks.** New JS/TS catalog
  models name shapes the reader could not previously express: `.match` /
  `.search` (Receiver) and `.test` / `.exec` (Argument[0]) as ReDoS leads over a
  tainted subject, `.innerHTML` / `.outerHTML` assignment as markup-injection,
  and computed property write as prototype-pollution. All are low-confidence,
  type-less models — they name the shape and leave adjudication to the reader.
- **Property-write binding.** The binder scans property-write and
  computed-property-write nodes into synthetic call sites, so `el.innerHTML =
  tainted` and `obj[key] = value` become bindable targets for their models.

### Fixed

- **Generic method models bind across differing receivers.** A type-less
  method-only model no longer bails out `ambiguous` when its method appears on
  call sites with differing receiver identities; the ambiguity guard now fires
  only for models that pin a receiver identity (package or type). A generic
  model binds every matching call site and lets each attachment stand as a lead.
  This unlocks receiver-access sinks through the existing constructors — a
  subject-tainted `.match` ReDoS lead now surfaces at its real call site instead
  of vanishing at bind.
- **Honest completion and timeout.** `converged` / `timed_out` are reported from
  the kernel's own convergence state rather than inferred by the Python driver.
- **Presence observations retained.** Presence-family sinks keep their
  constant-argument observations instead of discarding them, so a lead whose
  only evidence is a literal argument carries that evidence into adjudication.
- **Local prefix alias composition.** The matcher's `canonical()` composes local
  prefix aliases before comparing value identities, so an argument renamed
  through a local binding still unifies with its origin across a call seam.

### Known limitations

- **Computed-write candidates are locationless.** Prototype-pollution leads from
  `obj[key] = value` are enumerated but do not yet carry `file` / `line`, so they
  are present in the census but not addressable by source location. Call-site
  sinks are unaffected. Location surfacing for synthetic writes is deferred.
- **ReDoS coverage is asymmetric.** `.match` / `.search` / `.test` / `.exec` are
  modeled; `.replace` and `.split` are not yet, so a catastrophic pattern used
  only through those two methods is not flagged.

## [0.3.1]

Packaging release: Linux arm64 (aarch64) now gets a real prebuilt wheel.

### Added

- **`manylinux_2_28_aarch64` wheel.** The release matrix now builds on a native
  arm64 Linux runner (`ubuntu-24.04-arm`), so `pip install lachesis-cpg` on Linux
  arm64 — including Docker containers on Apple Silicon — resolves a prebuilt wheel
  carrying the native clang frontend and lifetime kernel. Previously Linux arm64
  had no wheel and fell back to the sdist, which installs without the native C
  frontend and cannot build C graphs. x86_64 Linux, arm64 macOS, and Windows
  wheels are unchanged.

## [0.3.0]

This release introduces a source-rooted semantic flow analysis and a lifetime/typestate
candidate layer on top of the existing sink-reachability model. Pre-1.0: the graph schema
and candidate surface grow here; older candidate output remains readable.

### Added

- **Semantic flow graph (Pass 3).** A new source-rooted pass builds a frontend-neutral
  semantic flow graph for every supported language: per-function fragments joined at
  call/return seams, carrying object identities, symbolic generations, guard proofs, and
  source provenance. It replaces the legacy per-function skeletons as the object-mode
  production path and is scheduled from a source-rooted coverage worklist.
- **Lifetime and typestate candidate families.** The candidate census now surfaces
  temporal leads alongside sink reachability: cross-seam double-free, use-after-free and
  unchecked use, uninitialized-pointer use, realloc-invalidated (dangling) pointers,
  returned stack-local escapes, unchecked nullable-return dereference, allocation/copy
  size mismatch, loop-bounded unbounded copy, and multiplicative allocation overflow.
- **Catalog-driven detection.** Lifecycle allocation/release/use nodes, sink facts, and
  the default matcher registry are derived from the Atropos catalog, so detection coverage
  tracks the catalog rather than hard-coded rules. Lifecycle transitions are routed through
  catalog evaluators.
- **Interprocedural cross-seam matching.** The matcher advances loose ordered patterns
  along branch-compatible paths across call seams — rebasing pointer slots, stitching
  callback seams, and preserving field aliases and object identity across returns — so
  free-here / use-there patterns are matchable.
- **Adjudicable evidence.** Pass 3 lifecycle evidence and structured semantic witness
  traces are exposed through the navigation and MCP surface, and the taint witness path is
  surfaced so each lead can be traced source-to-sink. MCP tool descriptions now document
  read-only status, parameters, and usage.

### Changed

- **One `lead` vocabulary across every surface.** The CLI, library, and MCP now speak a
  single `lead` result noun; engine selection and engine labels are internal details.
  `lachesis.scan()` / `lachesis scan` default to the whole-taxonomy hunt, with `all`,
  `guard-diff`, and `flow` as explicit lenses. `scan --lens all` returns one ranked,
  deduplicated `LeadSet` across the registry and native-flow producers; MCP `scan`,
  `candidates`, and warm `leads` page with offsets and structured recoverable errors.
- **A five-name library API.** `import lachesis` exposes exactly `scan`, `Analysis`,
  `LeadSet`, `Deadline`, and `AnalysisError`; bare `lachesis <path>` routes to `scan`.
- `query` and `plan` are parsed subcommands with their own help; shell completion, color
  control, verbose native status, and `doctor` kernel checks are available day to day.
- The removed Python analysis fallbacks are no longer reachable from the query, taint, or
  flow surfaces; the native binary sidecars are the runtime contract.
- Object mode produces the semantic flow graph as its production path; legacy skeletons are
  retired from object mode.
- Coverage accounting is call/return aware and source-rooted, and reusable semantic
  fragments are cached with deterministic fingerprints across pass runs.

### Packaging

- **Cross-platform wheels.** The native kernel and clang frontend load through
  `ctypes`/`subprocess`, not as CPython extensions, so each release ships one
  `py3-none-<platform>` wheel per platform (Linux `x86_64`, macOS `x86_64`/`arm64`,
  Windows `amd64`) that serves every supported interpreter. `setup.py` sets the tag;
  `cibuildwheel` builds the native binaries per platform and repairs each wheel.
- **Tag-driven PyPI publishing.** Pushing a `vX.Y.Z` tag builds and verifies the wheels
  and sdist and publishes them through Trusted Publishing (OIDC, no stored token). The
  run refuses to build unless the tag matches the version and has a changelog entry, and
  refuses to publish any platform-agnostic wheel.
- **Native-kernel install gate.** `lachesis doctor` verifies the bundled kernel loads and
  matches the package version; the wheel verifier and the release build both run it, so a
  wheel that ships a stale or missing kernel fails in CI rather than at a user's first scan.

### Fixed

- Deterministic fragment cache fingerprints and fail-safe unions on incompatible caches.
- A size guard must compare magnitude, not merely name a variable.
- The C frontend slices AST snippets by byte offset rather than code point.
- Tolerate unreadable legacy graph properties instead of failing the load.
- Queries materialize the dataflow tier from the native binary sidecar only; the removed
  in-process Python enrichment fallback is no longer reachable from any query surface, so
  a batch export (for example the GitHub Action's SARIF run) no longer risks exhausting
  memory re-enriching a large graph in the query process.

## [0.2.0]

Packaged the reader on PyPI: the graph builder, navigation and dataflow tools, the
candidate registry, and the MCP server. Superseded by 0.3.0, which lands the source-rooted
semantic flow analysis and lifetime/typestate candidates described above.

## [0.1.7]

### Added

- **Architecture comprehension.** Function-level community detection groups the
  call graph into cohesive modules, each labelled by its highest-degree member,
  and an architecture report renders the map. New `lachesis communities` and
  `lachesis report` subcommands, and matching `communities` and
  `architecture_map` MCP tools.
- **Container distribution.** The MCP server ships as a multi-arch image at
  `ghcr.io/unboundcompute/lachesis` (linux/amd64 and linux/arm64), so a client
  can run it with no Python, Node, or clang on the host. Published on every
  release tag.
- **One-click install.** README install buttons for Cursor and VS Code that
  register the server through `uvx` with no prior install step.

## [0.1.6]

### Fixed

- Match the GitHub organization's exact casing in the MCP registry identity:
  `server.json` and the README `mcp-name` marker now read
  `io.github.UnboundCompute/lachesis`. The registry authorizes org namespaces
  case-sensitively against the `repository_owner` claim, so the lowercase form
  in 0.1.5 could not be published. No code or API changes.

## [0.1.5]

### Added

- Registry metadata for the official MCP registry: a repo-root `server.json`
  (`io.github.unboundcompute/lachesis`) describing the `lachesis-cpg` PyPI package
  and its stdio transport, plus the `mcp-name` ownership marker in the README that
  the registry checks against the published package. No code or API changes.

## [0.1.4]

### Added

- `build_graph` MCP tool: build a graph from a source directory and attach it in one
  call, so the server is zero-config — start `lachesis-mcp` with no graph path and the
  agent provisions its own graph on demand. Content-addressed (an unchanged tree is
  served from cache; `refresh: true` forces a rebuild) and toolchain-aware (a missing
  `node`/`clang` returns an actionable error instead of crashing).

## [0.1.3]

- Release the merged `main` workflow and documentation corrections.

## [0.1.2]

- Release the production-readiness and release-reference fixes from `main`.

- Documented the Python 3.10–3.12 release-tested window so installation guidance does
  not imply unverified newer interpreters are supported.
- The clean wheel verifier now covers the complete six-script console surface, including
  `lachesis-candidates` and version responses, matching the sdist gate.
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
- Use the reviewed `v1` Action and engine release tags in workflow references.
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
- The quickstart now uses the working source-checkout install while the first PyPI
  release is unpublished, and labels `lachesis-cpg` as the tagged-release path.
- Checkout, contributor, and release instructions now use `npm ci` with the committed
  lockfile, preventing setup from silently rewriting the TypeScript dependency graph.

## [0.1.1]

- Normalize source distribution metadata so repeated release builds produce identical
  sdist bytes, matching the wheel reproducibility gate.
- Expand wheel verification to cover every declared console script and its version path.

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
