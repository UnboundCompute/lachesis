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
git clone https://github.com/UnboundCompute/lachesis && cd lachesis

python -m pip install --upgrade pip   # editable installs need pip >= 21.3
pip install -e .          # the graph builder, the nav layer and the MCP server
npm install               # the TypeScript compiler the TS frontend loads
```

The base install has **no Python dependencies** — the builder, the JSON store, the
navigation layer and the MCP server are pure standard library. The embedded Kùzu
store is opt-in and needs Python 3.10+:

```bash
pip install -e ".[kuzu]"  # adds kuzu + pyarrow for the columnar store
```

Then build a graph and ask it questions:

```bash
lachesis-analyze path/to/your/source graph.json   # parse a tree into a layered graph
lachesis-query graph.json overview                # what's in it
lachesis-query graph.json function handleRequest  # a budgeted slice of one function
lachesis-mcp graph.json                           # serve the nav tools over MCP (stdio)
```

`lachesis-analyze` dual-writes by default: `graph.json` plus a sibling `graph.kuzu`
directory when the `[kuzu]` extra is installed. Pass `--no-kuzu` for JSON only.
`lachesis-mcp` speaks MCP over stdio, so point an MCP-capable client at
`lachesis-mcp /abs/path/to/graph.json` and the navigation tools show up as tools.

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

### `Lachesis/`, the graph builder

- `pipeline.py` orchestrates project partitioning and the per-frontend runs.
- `frontends/` holds the language frontends. Each one is parser or compiler backed and emits the graph.
- `core/`, `types.py`, `ecosystems/`, `projections/`, and `reasoning/` are the graph core, the node and edge types, ecosystem handling, projections, and the analysis overlays.
- `kuzu_store.py` is the bulk writer. It stages the graph to Parquet and copies it into a Kùzu database using typed hot-relation tables plus a cold generic edge table. The [`KUZU_STORE_SPEC.md`](./KUZU_STORE_SPEC.md) has the full layout.
- `cli/` holds the command-line entry points for build, analyze, and export.

### `nav/`, navigation and MCP

- `graph_store.py` loads a graph from either JSON or a Kùzu directory. It auto-detects which one it is looking at and gives you one API over both.
- `kuzu_index.py` is the Kùzu-backed graph index.
- `reachability.py`, `hubs.py`, `guards.py`, `call_roles.py`, `siblings.py`, `flow.py`, and `symbol_index.py` are the reasoning primitives.
- `mcp_server.py` exposes the navigation tools over MCP, so an LLM agent can drive the graph directly.

## Storage: JSON or Kùzu

Lachesis dual-writes by default. You get a JSON graph, which is portable and diff-friendly, and a sibling `.kuzu` directory, which is columnar and easy on RAM. The navigation layer figures out which one to load and behaves the same over either backend. The two are kept at byte-identical parity across the navigation and MCP tools, and there is a test suite that enforces that.

The Kùzu backend is the one you want at scale. On a real whole-package graph of roughly 500K nodes and 926K edges, here is how the two compare:

| | JSON | Kùzu | change |
|---|---:|---:|---|
| On-disk size | 1.0 GB | 368 MB | 63% smaller |
| Load-time peak RSS | 3394 MB | 357 MB | 90% smaller |
| Open time | about 10 s | about 0.5 s | roughly 20x faster |

The [`KUZU_STORE_SPEC.md`](./KUZU_STORE_SPEC.md) covers the on-disk layout, the incremental unit key, and the trade-offs we measured. The short version: columnar scans give up a little warm-query latency in exchange for a large win on RAM and startup time.

## Status

Lachesis is early and moving fast. The graph model, the Kùzu store, and the navigation and MCP layer all work today, and they are covered by a parity test suite in `Lachesis/frontends/checks.py`.

There are known rough edges, and they live in the issue tracker. Two worth calling out: a tail-recursive control-flow walk can hit Python's recursion limit on very deep functions, and whole-repo multi-package builds currently need per-package compilation to stay inside a single Node process's heap.

## License

Lachesis is licensed under the GNU Affero General Public License v3.0 (AGPL-3.0). See [`LICENSE`](./LICENSE).

The short version: you are free to use, study, modify, and share it, including commercially. But if you run a modified version as a network service, you have to make your modified source available to the people using that service. That is the deal that keeps Lachesis and its improvements open.

If the AGPL does not fit your use case, say you want to embed Lachesis in a closed-source product, a separate commercial license may be available. See [`CONTRIBUTING.md`](./CONTRIBUTING.md) for how licensing and contributions are handled, or open an issue to start the conversation.

## Security

If you find a vulnerability, please do not open a public issue. See [`SECURITY.md`](./SECURITY.md) for how to report it privately.
