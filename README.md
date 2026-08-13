# Lachesis

A compiler-precise code property graph (CPG) with an embedded columnar graph store and a navigation layer built for security reasoning over source code.

Lachesis parses a codebase into a layered graph. It captures syntax, symbols, calls, and a full dataflow tier (value-flow, points-to, taint, and aliasing). It then writes that graph to an embedded [Kùzu](https://kuzudb.com/) database and hands it to tools and LLM agents through a navigation API and an MCP server.

It exists to do one thing well: let a program, or an agent, ask precise questions about how data and control move through real source code. Things like who calls this function, what reaches this sink, which sibling function guards this input, and what flows into here. And it answers them with compiler-level fidelity instead of regex or heuristic matching.

## Why Lachesis exists

Most code-graph tools stop at symbols and references. That is the SCIP and LSIF layer, and it is useful, but it can only tell you where a name is used. It cannot tell you how a value moves.

Lachesis's whole point is the dataflow tier, because those are the edges that actually matter when you are reasoning about security:

- `VALUE_FLOWS_TO` for value and def-use flow
- `POINTS_TO` for points-to and pointer analysis
- `TAINT_FLOWS_TO` for taint propagation from a source to a sink
- `ALIASES` for aliasing relationships
- `CALLS`, `MAY_INVOKE`, and `INVOKES` for resolved and possible call edges

A symbol index cannot give you any of these. They are what let a downstream tool reason about reachability, guard coverage, and tainted flows, rather than just "where does this name appear."

## Quick start

```bash
pip install lachesis-cpg
```

That is the whole installation. Python 3.10 or newer is required. The only runtime
dependencies are `kuzu` and `pyarrow`, which back the embedded columnar store the graph
lives in; the builder, the navigation layer and the MCP server are otherwise pure
standard library.

There is no second step for TypeScript. The TypeScript frontend analyses with the real
compiler API rather than a reimplementation of it, so a copy of the compiler ships
inside the distribution and is used automatically — no Node package to install, no
network access at analysis time. Node itself does need to be on your PATH for the
TypeScript frontend to run. Analysing C additionally needs `clang`; without it, C files
are simply not analysed and every other language still is.

Then build a graph and ask it questions:

```bash
lachesis-analyze path/to/your/source graph.kuzu   # parse a tree into a layered graph
lachesis-query graph.kuzu overview                # what's in it
lachesis-query graph.kuzu function handleRequest  # a budgeted slice of one function
lachesis-mcp graph.kuzu                           # serve the nav tools over MCP (stdio)
```

`graph.kuzu` is a directory: an embedded Kùzu database plus the store manifest. It
is the graph, and every tool reads it directly. `lachesis-mcp` speaks MCP over
stdio, so point an MCP-capable client at `lachesis-mcp /abs/path/to/graph.kuzu` and
the navigation tools show up as tools.

### Installing from a clone

Working on Lachesis itself, or running from source:

```bash
git clone https://github.com/UnboundCompute/lachesis && cd lachesis
python -m pip install --upgrade pip   # editable installs need pip >= 21.3
pip install -e ".[dev]"               # builder, nav layer, MCP server, test deps
npm install                           # the TypeScript compiler the TS frontend loads
```

A checkout does need `npm install`, because the vendored compiler is a build-time
artifact and is not kept in version control. A checkout prefers its own `node_modules`
copy anyway, so the TypeScript version you develop against is the one your `package.json`
pins. See [`RELEASING.md`](./RELEASING.md) for how it gets into a distribution.

The build writes the core tier. The dataflow tier is `f(core graph, languages,
capabilities)` — pure and deterministic — so it is rebuilt on the first query and
cached in a sibling `graph.kuzu.enriched` directory keyed to the core's content hash.
Answers are identical either way; the work moves off every build and onto one first
query per graph. `lachesis-analyze --enrich` folds it in at build time instead.

### Parallel builds for monorepos

`lachesis-analyze --parallel-packages` splits a workspace by package (every
directory holding a `package.json` outside `node_modules`, deepest one wins) and
builds the packages in a process pool. `--max-workers N` caps the pool; it
defaults to the number of packages or the core count, whichever is smaller.

It is opt-in because it is a real semantic change, not just a scheduling one.
Each package becomes its own compiler program, so types resolve across that
package's files rather than across the whole tree. On the two-package workspace
fixture in this repo, the per-package build recovers 647 of the whole-repo
build's 650 edges, with an identical node set and zero invented edges. The three
it misses are cross-program: two macro expansions into `lib.es5.d.ts` and one
value flow across the package boundary. Edges whose far endpoint lands in a
different unit are dropped rather than guessed at, and the count is always
printed:

```
Dropped 0 cross-package edges (parallel build)
```

Wall time here is floored by the largest single package, so this does not scale
linearly with worker count: a workspace whose weight sits in one big package
gains almost nothing. `--parallel-packages` cannot be combined with
`--incremental`, whose manifest keys bundles by frontend rather than by package.

## Languages

Three frontends ship in the repo. Each one is backed by a real compiler or by the
language's own parser, never by a regex or a heuristic grammar.

| language | frontend | engine | extensions |
|---|---|---|---|
| TypeScript, JavaScript | `typescript-compiler-api` | the TypeScript compiler API, with the type checker | `.ts` `.tsx` `.mts` `.cts` `.js` `.jsx` |
| C | `clang-c` | `clang -Xclang -ast-dump=json` | `.c` `.h` |
| Python | `cpython-ast` | CPython's own `ast` and `symtable`, standard library only | `.py` `.pyi` |

A frontend declares what it actually knows in its snapshot manifest, and the
validator holds it to that. Two honest limits worth stating up front: the Python
frontend has no type checker, so it reports `types: none` and resolves attribute
calls lexically rather than by type; and the C frontend reads a single translation
unit at a time, so it does not follow a call through a function pointer table it
never sees.

Mixed-language trees are one graph, not three. `run_project` picks a frontend per
file by extension, composes the snapshots into a single node and edge set, and
runs the same overlays over the result, so a Python caller and a TypeScript callee
sit in one store and the same navigation tools answer over both.

## See it work

Before you point it at your own code, watch the dataflow tier catch something on
a project that ships in the repo. [`examples/README.md`](./examples/README.md) is
a five-minute walkthrough: build a graph from the bundled fixture, then watch
Lachesis tell two sibling functions apart because one authorizes a database
lookup and the other reaches the identical call with no check. That is the kind
of question a symbol index cannot answer, and it is the whole reason the dataflow
tier exists.

## How it fits together

```
  source tree
      |
      v
  Lachesis (builder)      language frontends parse each ecosystem and emit
      |                  syntax + symbols + calls + dataflow overlays
      |  layered graph
      v
  kuzu_store             bulk COPY-FROM staged Parquet writer into an
      |                  embedded columnar graph DB (typed node/rel tables)
      v
  nav (+ MCP)            graph_store, reachability, hubs, guards, call_roles,
                         siblings, flow, symbol_index, and an MCP server
```

### `lachesis/`, the graph builder

- `pipeline.py` orchestrates project partitioning and the per-frontend runs.
- `frontends/` holds the language frontends. Each one is parser or compiler backed and emits the graph.
- `core/`, `types.py`, `ecosystems/`, `projections/`, and `reasoning/` are the graph core, the node and edge types, ecosystem handling, projections, and the analysis overlays.
- `kuzu_store.py` is the bulk writer. It stages the graph to Parquet and copies it into a Kùzu database using typed hot-relation tables plus a cold generic edge table. The [`KUZU_STORE_SPEC.md`](./KUZU_STORE_SPEC.md) has the full layout.
- `cli/` holds the command-line entry points for build, analyze, and export.

### `lachesis/nav/`, navigation and MCP

- `graph_store.py` loads a graph from either JSON or a Kùzu directory. It auto-detects which one it is looking at and gives you one API over both.
- `kuzu_index.py` is the Kùzu-backed graph index.
- `reachability.py`, `hubs.py`, `guards.py`, `call_roles.py`, `siblings.py`, `flow.py`, and `symbol_index.py` are the reasoning primitives.
- `mcp_server.py` exposes the navigation tools over MCP, so an LLM agent can drive the graph directly.

## Benchmarks

All numbers below come from one public, reproducible target: the TypeScript
packages in the [`vercel/ai`](https://github.com/vercel/ai) monorepo (`ai@7.0.55`),
built with the TypeScript frontend on an Apple M4 (16 GB), single process, Python
3.9, Kùzu 0.11.3. Clone the repo and point the analyzer at any package's `src`
directory to reproduce them.

### Build throughput

Lachesis builds the full layered graph, including the dataflow tier, at roughly
one thousand source lines per second, or ten to eleven thousand graph elements
(nodes plus edges) per second, and it stays near-linear as the input grows.

| Package (`packages/<name>/src`) | TS LOC | Nodes | Edges | Build time | Serialized graph |
|---|---:|---:|---:|---:|---:|
| `anthropic` | 30,577 | 133,903 | 227,662 | 31.9 s | 265 MB |
| `openai` | 44,890 | 210,164 | 361,406 | 49.6 s | 422 MB |
| `ai` | 164,607 | 504,246 | 920,708 | 140.9 s | 1.0 GB |

```bash
python -m lachesis.cli.analyze path/to/vercel-ai/packages/ai/src ai.kuzu
```

These build times and sizes were measured when the builder also wrote the whole
graph out as indented JSON, which it no longer does, and when it folded in the
dataflow tier on every build, which is now `--enrich`. The last column is that JSON
dump, kept here because it is the most direct measure of how much graph each
package produces. Both columns are therefore an upper bound on what the command
above costs today. The current numbers are not published here yet; they will be
once they have been re-measured on this same public target.

### Storage and open time

The store is columnar and easy on RAM, which is the property that lets a
half-million-node graph open in under a second. On the `ai` graph above (504,246
nodes / 920,708 edges), against the one-big-JSON representation the builder used to
emit, loading each through the navigation layer:

| | One-big-JSON | Kùzu store | change |
|---|---:|---:|---|
| On-disk size | 1.0 GB | 368 MB | 63% smaller |
| Open time (load into nav) | 11.1 s | 0.58 s | about 19x faster |
| Load peak RSS | 3511 MB | 362 MB | 90% smaller |
| Warm query (hubs top-10) | about 1 ms | about 4 ms | parity |

That store was built with `--prune`, which drops the pure-lexical `token` and
`source-span` nodes. Pruning is lossless for every navigation tool (source excerpts
are read from the file by offset, not from those nodes) but it does drop real T0
graph content, so it is opt-in and the default store keeps everything.

The [`KUZU_STORE_SPEC.md`](./KUZU_STORE_SPEC.md) covers the on-disk layout, the
incremental unit key, and the trade-offs we measured. The short version: columnar
scans give up a little warm-query latency in exchange for a large win on RAM and
startup time. A test suite enforces that the store answers every navigation and MCP
tool identically to the same graph held whole in memory.

## Documentation

- [`examples/README.md`](./examples/README.md) is the five-minute walkthrough:
  build a graph and read a guard differential and a taint path out of it.
- [`docs/graph-model.md`](./docs/graph-model.md) is the reference for what the
  graph contains: the node kinds, the edge kinds, and the tiers, generated from
  the canonical contract.
- [`docs/queries.md`](./docs/queries.md) is the reference for asking the graph
  questions, both the `lachesis-query` command line and the `lachesis-mcp` tools.
- [`KUZU_STORE_SPEC.md`](./KUZU_STORE_SPEC.md) covers the embedded columnar store:
  the on-disk layout, the incremental unit key, and the trade-offs measured.

## Status

Lachesis is early and moving fast. The graph model, the Kùzu store, and the navigation and MCP layer all work today, and they are covered by a parity test suite in `lachesis/frontends/checks.py`.

There are known rough edges, and they live in the issue tracker. Two worth calling out: a tail-recursive control-flow walk can hit Python's recursion limit on very deep functions, and whole-repo multi-package builds currently need per-package compilation to stay inside a single Node process's heap.

## License

Lachesis is licensed under the GNU Affero General Public License v3.0 (AGPL-3.0). See [`LICENSE`](./LICENSE).

The short version: you are free to use, study, modify, and share it, including commercially. But if you run a modified version as a network service, you have to make your modified source available to the people using that service. That is the deal that keeps Lachesis and its improvements open.

If the AGPL does not fit your use case, say you want to embed Lachesis in a closed-source product, a separate commercial license may be available. See [`CONTRIBUTING.md`](./CONTRIBUTING.md) for how licensing and contributions are handled, or open an issue to start the conversation.

## Security

If you find a vulnerability, please do not open a public issue. See [`SECURITY.md`](./SECURITY.md) for how to report it privately.
