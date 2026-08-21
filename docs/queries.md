# Querying the graph

Once a graph is built there are three ways to ask it questions: `lachesis-query`,
the verdict-free `lachesis-candidates` worklist command, and the `lachesis-mcp`
server that exposes both kinds of reasoning to an LLM agent. This page is the
reference for them. For a hands-on run of the most
important ones, follow [`examples/README.md`](../examples/README.md).

Both surfaces read the same canonical graph and speak in terms of the
[graph model](./graph-model.md): node kinds, edge kinds, and tiers.

## The `lachesis-query` command line

```
lachesis-query [--budget-tokens N] [--format json|text] <graph> <command> [args]
```

`<graph>` is a store directory built by `lachesis-analyze`. Two global flags apply
to every command:

- `--format json` (default) emits the full result dict. `--format text` emits a
  compact human-readable digest. The flag goes before the graph path.
- `--budget-tokens N` (default 12000) caps the size of the reasoning slice a
  command returns, so a query against a huge function stays bounded. Results carry
  a `truncated` flag when the budget clipped them.

Every command emits a self-contained reasoning slice: the records it returns
carry their own location, owner chain, and source excerpts, so a consumer that
reads one slice does not have to hold the whole graph.

| Command | Arguments | What it answers |
|---|---|---|
| `overview` | none | Project summary: languages, node and edge counts, how many source-to-sink security paths were recovered, and how many of them are guard differentials. The place to start. |
| `find-entity` | `name` `[--kind K] [--file F]` | Resolve a name to its canonical node id(s). Reports `exact`, `ambiguous`, or `not-found`. Filter by `--kind` (for example `function`, `method`, `sink`) or `--file`. The name must be exact, not a substring. |
| `locate` | `node_id` | Locate a node by id: its kind, label, location, and owner chain. |
| `expand` | `node_id` `[--depth N]` | Expand the neighborhood around a node out to `--depth` (default 1). |
| `function` | `focus` `[--file F]` | A budgeted slice of one function: its parameters, outgoing calls and resolved targets, body, and effects. `focus` is a function name; use `--file` to disambiguate. |
| `call` | `node_id` | The detail of one call site: callee, arguments, resolution confidence. |
| `value-history` | `node_id` | The def-use history of a value: the versions it passes through and the transitions between them. Large, and budget-clipped. |
| `security-path` | `node_id` | The full source-to-sink path for a `taint-reach` node: each hop with its `TAINT_FLOWS_TO` transition and source excerpt, plus the guard verdict that rides along the path. |
| `handler-security` | `focus` `[--file F]` | The security verdict for a handler: `GUARDED` or `UNGUARDED`, the guard signal and confidence, its security paths, and any `differential_siblings` (a guarded twin that reaches the same sink). `focus` is a function name. |
| `unresolved` | `[node_id]` | Unresolved references and indirect-dispatch slots, either graph-wide or scoped to a node. |

The two commands that carry the dataflow story are `handler-security` and
`security-path`. In the worked example, `handler-security getInvoice` returns
`GUARDED` while the sibling `handler-security getDocument` returns `UNGUARDED`
with `differential_siblings: ["getInvoice"]`, and `security-path` on the unguarded
taint-reach node prints the four-hop path from the public parameter to the
`findById` sink.

## The `lachesis-mcp` server

```
lachesis-mcp [graph.kuzu | source-dir] [overlay.json] [profile]
```

The server speaks MCP over stdio as `nav-reasoning`. It loads the graph once at
startup, then every tool call hits the in-memory copy, so each call is cheap
relative to the neighborhood it touches.

**Zero-config is the default.** You do not have to build a graph first or pass any
path. Start the server with no argument and the client config stays path-free:

```json
{
  "mcpServers": {
    "lachesis": { "command": "lachesis-mcp" }
  }
}
```

The agent then builds its own graph on demand with the `build_graph` tool — point
it at a repo path and it compiles, caches, and attaches the graph in one call. The
build is content-addressed, so an unchanged tree is served instantly from cache and
`refresh: true` forces a rebuild. (Startup with a source directory as the argument,
or none at all, does the same build-or-reuse for the working tree.) Toolchain: Python
needs nothing beyond the package; TypeScript/JavaScript builds need `node` on `PATH`
and C builds need `clang` — a missing one comes back as an actionable error, not a
crash.

**Or point it at a prebuilt graph.** When you already have a `graph.kuzu`, pass its
absolute path and the server serves that graph directly:

```json
{
  "mcpServers": {
    "lachesis": {
      "command": "lachesis-mcp",
      "args": ["/abs/path/to/graph.kuzu"]
    }
  }
}
```

Use an absolute executable and graph path in a deployed client. For a wheel or
editable install, the simplest form is the console script from that same
environment:

```json
{
  "mcpServers": {
    "lachesis": {
      "command": "/absolute/path/to/venv/bin/lachesis-mcp",
      "args": ["/absolute/path/to/graph.kuzu"]
    }
  }
}
```

When launching directly from a source checkout, install the checkout into the
interpreter selected by the client and make the checkout importable:

```bash
cd /absolute/path/to/arachne
python3.11 -m pip install -e ".[dev]"
```

```json
{
  "mcpServers": {
    "lachesis": {
      "command": "/absolute/path/to/python3.11",
      "args": ["-m", "lachesis.nav.mcp_server", "/absolute/path/to/graph.kuzu"],
      "env": {"PYTHONPATH": "/absolute/path/to/arachne"}
    }
  }
}
```

If startup fails with `ModuleNotFoundError: No module named 'lachesis'`, the
client is using a different interpreter or working directory. Check the exact
interpreter with:

```bash
/absolute/path/to/python3.11 -c 'import lachesis; print(lachesis.__file__)'
```

Always pass a graph path. With no graph argument the server treats the current
working directory as source and starts indexing it, which can look like a
hung MCP launch on a large repository. Startup diagnostics are written to
stderr; stdout is reserved for MCP JSON-RPC messages.

Every tool except `load_graph` accepts an optional `format` argument, `text`
(compact, the default) or `json` (the full result dict). The list-shaped tools
also page their text rendering so a call against a function with hundreds of
callers stays bounded; the JSON result is always complete.

The tools group by what they are for.

### Orientation: where do I start on an unfamiliar graph

| Tool | What it does |
|---|---|
| `hubs` | The subsystem's spine: the highest-degree functions over the union call graph (direct calls plus indirect dispatch), ranked by fan-in plus fan-out, each with file:line and entry-point flags. Language-agnostic cold start: find what a subsystem is built around, then traverse. |
| `guards_top` | The functions that look most guard-shaped, ranked by derived guard signal, with no name knowledge needed. A security-hunting entry point. |
| `search` | Resolve a function, method, type, or file name to its node id(s) with file:line. Fuzzy by default, with paging and a real match total, and it de-prioritizes test symbols. Use once you know a name. |

### Navigation: move around the call graph

| Tool | What it does |
|---|---|
| `callers` | Who calls this symbol, direct plus indirect dispatch, external stubs filtered. Each row tagged with how the call reaches it. Set `direct_only` for resolved declaration-to-declaration calls only. |
| `callees` | What this symbol calls, in-repo only, same tagging. An indirect row that is unresolved marks a real indirection whose target is not pinned. |
| `read_body` | Read a function or method's real source, by name or node id. Returns the exact source span with file and line range, capped at `max_chars` with a truncated flag. |
| `open_file` | The file-level graph for one repo-relative path: imports, declarations, intra-file calls, and cross-file jump stubs. |
| `open_folder` | The folder-level graph under a path prefix: folder to file to declarations. |

### Dataflow: follow the values

| Tool | What it does |
|---|---|
| `flow` | The forward value-flow cone from a value or symbol: everything it reaches over `VALUE_FLOWS_TO` and `POINTS_TO`, bridging aliases through the heap. |
| `sources_of` | The reverse cone: which values can feed a given sink. |
| `reaches` | Does a source reach a sink through value flow? Returns the labeled witness path, or a negative answer. Arguments may be node ids or names. |
| `points_to` | The heap objects a value points to. |
| `aliases` | The values that alias a given one by sharing a heap object, the destructuring or alias set. |

### Security: the guard and differential reasoning

| Tool | What it does |
|---|---|
| `guards` | The derived guard profile of a function: a score, a class (`guard`, `validate`, or `passthrough`), and the raw condition, short-circuit, and throw counts behind it. |
| `call_roles` | Type a function's outgoing calls by derived security role (`verify`, `sanitize`, `authz`, `validate`, or `none`). These are security roles, not AST structural roles. |
| `siblings` | The peer differential: form a symbol's cross-module family, classify each member guarded or unguarded with guard transitivity, and flag the unguarded outlier against the peer guard it lacks. This is the negative-space move that surfaces the missing check. |
| `scan` | Run the cached guard-differential constructor over graph entrypoints. Returns ranked investigation capsules plus a census of scanned/skipped entrypoints, suppressed questions, and truncated closures. Use `entrypoints`, `min_rank`, and paging `limit`/`offset` to bound a request. Results are questions, not safety verdicts. |
| `wrapper_model` | Infer allocator, deallocator, I/O, and validator wrapper roles from resolved callee evidence without mutating the registry. |
| `guard_dominance` | Check a bounded entry→effect call path for recognized guards and report dominant, skippable, or undecided evidence. |
| `counterexample` | Find a bounded source→sink call path that avoids a named validator; truncation is reported explicitly. |
| `invariant_trace` | Trace graph-evidenced producers, mutators, checkers, and consumers around a value or field. |
| `representation_roundtrip` | Compare two functions/paths for call, control, dispatch, and side-effect shape differences. |
| `cross_boundary_paths` | Rank calls, values, callbacks, and lifecycle crossings between two components by transition rarity. |
| `range_analysis` | Reports the numeric-model frontier; full range reasoning is not silently approximated. |
| `object_lifecycle` | Reports the lifecycle-constructor frontier; full state machines wait for free/deref facts. |
| `error_path_summary` | Reports the exit/release-analysis frontier; complete transfer summaries wait for free/deref facts. |

### Candidate worklists: point the judge at every obligation

| Tool | What it does |
|---|---|
| `candidates` | Enumerate and rank obligation sites selected by exact Atropos attachments. Filter by `domain`, `constructor`, or `language`; page with the opaque `cursor`. The v1 constructor is `memory.copy.capacity`. |
| `candidate_detail` | Return one complete candidate capsule by `candidate_id`, including observations, bounded inferences, graph handles, rank reasons, and the suggested drill-in move. |
| `candidate_census` | Return counts and explicit coverage frontiers without candidate rows. This distinguishes zero candidates from missing models or analysis capability. |
| `taint` | Bind Atropos source/sink/summary facts and report witnessed source-to-sink flows. This is flow evidence; it is separate from obligation enumeration. |

Candidate tools deliberately do not run a safety check. A constant size, a
self-bounded API, a nearby condition, or an unwitnessed input path may lower rank,
but never removes an observable site. Atropos owns the exact symbol/access-path
facts; Lachesis maps those facts to constructors, enumerates, derives bounded
evidence, and ranks. The LLM remains the judge.

The same registry is available for batch use:

```bash
lachesis-candidates graph.kuzu --constructor memory.copy.capacity --limit 40
lachesis-candidates graph.kuzu --constructor memory.copy.capacity --census
lachesis-candidates graph.kuzu --candidate-id obl_...
```

This batch command emits JSON and binds against the core symbol index. It does not
build value flow or judge safety; the AI calls `sources_of`, `reaches`, `read_body`,
and other graph tools for the candidates it chooses to investigate.

### Session control

| Tool | What it does |
|---|---|
| `load_graph` | Switch the active graph the whole server reasons over, mid-session and with no restart. Takes a graph path and an optional overlay and profile. |

The `siblings`, `guards`, and `call_roles` tools are the interactive counterpart
of the `handler-security` command: they are how an agent rediscovers, one hop at
a time, the same guarded-versus-unguarded differential the command reports in one
shot.
