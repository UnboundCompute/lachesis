# Arachne

**A compiler-precise code property graph (CPG) with an embedded columnar graph store and a navigation/MCP layer for security reasoning over source.**

Arachne parses a codebase into a layered graph — syntax, symbols, calls, and a full **dataflow tier** (value-flow, points-to, taint, aliasing) — then persists it to an embedded [Kùzu](https://kuzudb.com/) graph database and exposes it to tools and LLM agents through a navigation API and an MCP server.

It is built for one job: let a program (or an agent) ask precise, cross-file questions about how data and control move through real source code — *who calls this, what reaches this sink, which sibling guards this input, what flows into here* — with compiler-level fidelity rather than regex or heuristic matching.

---

## Why Arachne

Most code-graph tools stop at symbols and references (the SCIP/LSIF layer). Arachne's differentiator is the **dataflow tier** — the edges that actually matter for security reasoning:

- `VALUE_FLOWS_TO` — value/def-use flow
- `POINTS_TO` — points-to / pointer analysis
- `TAINT_FLOWS_TO` — taint propagation source → sink
- `ALIASES` — aliasing relationships
- `CALLS` / `MAY_INVOKE` / `INVOKES` — resolved and possible call edges

These are the relationships a symbol index cannot give you, and they are what let downstream tools reason about reachability, guard coverage, and tainted flows instead of just "where is this name used."

---

## Architecture

```
  source tree
      │
      ▼
┌─────────────┐   language frontends (per-ecosystem parsers/compilers)
│   Arachne   │   → syntax + symbols + calls + dataflow overlays
│  (builder)  │
└─────────────┘
      │  layered graph (L)
      ▼
┌─────────────┐   bulk COPY-FROM staged Parquet writer
│  kuzu_store │   → embedded columnar graph DB (typed node/rel tables)
└─────────────┘
      │
      ▼
┌─────────────┐   graph_store · reachability · hubs · guards ·
│     nav     │   call_roles · siblings · flow · symbol_index
│  (+ MCP)    │   → navigation API + MCP server for agents
└─────────────┘
```

### `Arachne/` — the graph builder
- `pipeline.py` — orchestrates project partitioning and per-frontend runs.
- `frontends/` — language frontends that emit the graph (compiler/parser-backed).
- `core/`, `types.py`, `ecosystems/`, `projections/`, `reasoning/` — graph core, node/edge types, ecosystem handling, projections, and analysis overlays.
- `kuzu_store.py` — bulk writer that stages the graph to Parquet and `COPY`s it into a Kùzu DB (typed hot-relation tables + a cold generic edge table). See [`KUZU_STORE_SPEC.md`](./KUZU_STORE_SPEC.md).
- `cli/` — command-line entry points (build / analyze / export).

### `nav/` — navigation + MCP
- `graph_store.py` — loads a graph from JSON or a Kùzu directory (auto-detected); one API over both backends.
- `kuzu_index.py` — Kùzu-backed graph index.
- `reachability.py`, `hubs.py`, `guards.py`, `call_roles.py`, `siblings.py`, `flow.py`, `symbol_index.py` — the reasoning primitives.
- `mcp_server.py` — exposes the navigation tools over MCP so an LLM agent can drive the graph.

---

## Storage: JSON or Kùzu

Arachne dual-writes by default: a JSON graph (portable, diff-friendly) and a sibling `.kuzu` directory (columnar, low-RAM). The navigation layer auto-detects which to load and behaves identically over either backend — the two are kept at **byte-identical parity** across the navigation/MCP tools.

The Kùzu backend is the one you want at scale. On a real whole-package graph (~500K nodes / ~926K edges):

| | JSON | Kùzu | |
|---|---:|---:|---|
| On-disk size | 1.0 GB | 368 MB | −63% |
| Load-time peak RSS | 3394 MB | 357 MB | **−90%** |
| Open time | ~10 s | ~0.5 s | **~20×** |

See [`KUZU_STORE_SPEC.md`](./KUZU_STORE_SPEC.md) for the on-disk layout, the incremental unit key, and the measured trade-offs (columnar scans trade some warm-query latency for the large RAM/startup win).

---

## Status

Arachne is early and evolving. The graph model, the Kùzu store, and the navigation/MCP layer work and are covered by a parity test suite (`Arachne/frontends/checks.py`). Known rough edges are tracked in the issue tracker — notably a tail-recursive control-flow walk that can hit Python's recursion limit on very deep functions, and whole-repo multi-package builds that currently need per-package compilation to stay within a single Node process's heap.

---

## License

Arachne is licensed under the **GNU Affero General Public License v3.0** (AGPL-3.0). See [`LICENSE`](./LICENSE).

In short: you are free to use, study, modify, and share it, including commercially — but **if you run a modified version as a network service, you must make your modified source available to its users.** This keeps Arachne and its improvements open.

If the AGPL does not fit your use case (for example, you want to embed Arachne in a closed-source product or service), a separate commercial license may be available — see [`CONTRIBUTING.md`](./CONTRIBUTING.md) for how licensing and contributions are handled, or open an issue to start the conversation.

---

## Security

Found a vulnerability? Please **do not** open a public issue — see [`SECURITY.md`](./SECURITY.md) for private reporting.
