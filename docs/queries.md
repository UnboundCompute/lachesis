# Querying the graph

Once a graph is built there are two ways to ask it questions: the `lachesis-query`
command line, and the `lachesis-mcp` server that exposes the same reasoning to an
LLM agent. This page is the reference for both. For a hands-on run of the most
important ones, follow [`examples/README.md`](../examples/README.md).

Both surfaces read the same canonical graph and speak in terms of the
[graph model](./graph-model.md): node kinds, edge kinds, and tiers.

## The `lachesis-query` command line

```
lachesis-query [--budget-tokens N] [--format json|text] <graph> <command> [args]
```

`<graph>` is the canonical JSON graph (or a `.kuzu` directory; the loader
auto-detects). Two global flags apply to every command:

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
lachesis-mcp <graph.json> [overlay.json] [profile]
```

The server speaks MCP over stdio as `nav-reasoning`. It loads the graph once at
startup, then every tool call hits the in-memory copy, so each call is cheap
relative to the neighborhood it touches. Point an MCP-capable client at it with a
config entry like:

```json
{
  "mcpServers": {
    "lachesis": {
      "command": "lachesis-mcp",
      "args": ["/abs/path/to/graph.json"]
    }
  }
}
```

Every tool except `load_graph` accepts an optional `format` argument, `text`
(compact, the default) or `json` (the full result dict). The list-shaped tools
also page their text rendering so a call against a function with hundreds of
callers stays bounded; the JSON result is always complete.

The seventeen tools group by what they are for.

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

### Session control

| Tool | What it does |
|---|---|
| `load_graph` | Switch the active graph the whole server reasons over, mid-session and with no restart. Takes a graph path and an optional overlay and profile. |

The `siblings`, `guards`, and `call_roles` tools are the interactive counterpart
of the `handler-security` command: they are how an agent rediscovers, one hop at
a time, the same guarded-versus-unguarded differential the command reports in one
shot.
