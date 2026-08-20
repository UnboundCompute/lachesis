# Lachesis

**A compiler-precise code graph you can ask questions about: how data moves, who calls what, what reaches a sink. C, Python, and TypeScript, all in one graph.**

[![Lachesis](https://img.shields.io/badge/security-Lachesis-8250df)](https://github.com/UnboundCompute/lachesis-action)

> Scan your own repo with this on every PR: the [Lachesis Security Scan Action](https://github.com/UnboundCompute/lachesis-action) traces untrusted input to sinks and reports guard differentials straight into GitHub code scanning.

Lachesis parses a codebase with real compilers, not regexes, and turns it into a graph you can navigate. Syntax, symbols, calls, and the part that matters most: a full dataflow layer of value-flow, points-to, taint, and aliasing. That graph lives in an embedded columnar database and answers questions through a small navigation API and an MCP server, so a person or an LLM agent can reason about real source with compiler-level fidelity.

```bash
git clone https://github.com/UnboundCompute/lachesis && cd lachesis
pip install -e ".[dev]" && npm install       # build from source (details below)
lachesis-analyze ./my-project graph.kuzu     # parse a tree into a graph
lachesis-mcp graph.kuzu                       # hand it to your agent over MCP
```

---

## Why it exists

Most code-graph tools stop at symbols and references, the SCIP/LSIF layer. That tells you *where a name appears*. It cannot tell you *how a value moves*.

That gap is exactly where the interesting questions live. Does this request parameter reach that SQL call? Which of these two near-identical functions checks its input before the lookup, and which one doesn't? What can flow into this buffer? A symbol index shrugs at all of these.

Lachesis is built around the answer. Its dataflow edges (`VALUE_FLOWS_TO`, `POINTS_TO`, `TAINT_FLOWS_TO`, `ALIASES`, alongside resolved and possible call edges) are what let a tool reason about reachability, guard coverage, and tainted flow instead of pattern-matching text and hoping.

And because it parses with the language's own compiler, it doesn't lose a caller to a rename, an alias, or an import indirection. It answers from the parse, not the spelling.

---

## See it work

Two sibling functions reach the same database call. One checks the caller's tenant first; the other doesn't. A symbol index sees both call `findById` and stops there — Lachesis tells them apart by following the value.

Build the bundled fixture and ask for an overview:

```bash
lachesis-analyze lachesis/frontends/typescript/fixtures/project example.kuzu
lachesis-query --format text example.kuzu overview
```

```
# overview
Project: layered-project:de19e2325b09731683b9
Languages: javascript, typescript
Canonical graph: 3307 nodes / 6078 edges
Security paths: 6
Guard differentials: 1
```

One **guard differential**: a pair of siblings reaching the same sink where one authorizes and one does not. Ask about the unguarded one:

```bash
lachesis-query --format text example.kuzu handler-security getDocument
```

```
"status": "UNGUARDED",
"guard_signal": null,
"differential_siblings": [ "getInvoice" ]
```

`getDocument` reaches `findById` with no check — and the record names its guarded twin, `getInvoice`, directly. That cross-reference is the finding: a fact that lives in *how the value moves*, not *where the name appears*. Full five-minute walkthrough in [`examples/`](./examples/README.md).

---

## What you can ask

Once a graph is built, these are the moves, from the command line or as MCP tools an agent drives directly:

| You want to know | The move |
|---|---|
| What is this subsystem built around? | `hubs`, the highest-degree functions (no name knowledge needed) |
| Where is this symbol? | `search` |
| Who calls this? What does it call? | `callers`, `callees` (direct and indirect dispatch) |
| Show me the actual source | `read_body`, exact bytes by offset |
| What's in this file or folder? | `open_file`, `open_folder` |
| Where does this value go? What feeds this sink? | `flow`, `sources_of` |
| Does this source reach that sink? | `reaches`, a labeled witness path or an honest "no" |
| What does this pointer point to? What aliases it? | `points_to`, `aliases` |
| Where does untrusted input actually reach a dangerous sink? | `taint`, source→sink witnesses folded from the Atropos catalog onto this graph's own nodes |
| Which safety-obligation sites should I inspect first? | `candidates`, ranked and exhaustive over bound facts across the whole sink taxonomy, with no safety verdict |
| The full evidence for one site, or coverage across every family | `candidate_detail` (the neutral evidence capsule), `candidate_census` (constructor metadata, exhaustive counts, and the analysis frontier) |
| Which code implements a behavior when I do not know its symbol name? | `concept_search` (optional local model, installed and downloaded separately) |

Every answer carries a confidence and an origin. An `exact` edge is resolved; a `conservative` one is a deliberate over-approximation the tool tells you about rather than hiding. You read the results as evidence, not as verdicts, which is the honest way to reason about a large codebase you didn't write.

---

## Languages

Three frontends, each backed by a real compiler or the language's own parser, never a heuristic grammar.

| Language | Engine | Extensions |
|---|---|---|
| TypeScript / JavaScript | the TypeScript compiler API, with the type checker | `.ts` `.tsx` `.mts` `.cts` `.js` `.jsx` |
| Python | CPython's own `ast` + `symtable` (standard library only) | `.py` `.pyi` |
| C | Clang, via its AST dump | `.c` `.h` |

A mixed tree is **one graph, not three**. Lachesis picks a frontend per file, composes the results into a single node and edge set, and runs the same analysis over all of it, so a Python caller and a TypeScript callee sit in the same store and the same tools answer over both.

Two honest limits, stated up front: Python has no type checker, so it resolves attribute calls lexically and says so (`types: none`); C reads one translation unit at a time, so it won't follow a call through a function-pointer table it never sees. Each frontend declares what it actually knows, and a validator holds it to that claim.

---

## How it's built

Lachesis writes the graph in two tiers, and the split is the whole performance story.

**The build writes the core tier**: syntax, symbols, and calls. That's the fast part, and it's all most navigation needs.

**The dataflow tier is a pure function of the core graph**, so it isn't written at build time. The first query that actually needs value-flow folds in just the *cone* around its seed (the slice of dataflow that question touches) and caches it beside the store. Nothing pays for a whole-graph dataflow pass it never asked about. Ask a second question and the relevant cone is already there; ask about a fresh corner and only that corner gets folded.

The result: builds stay lean, the graph opens in well under a second, and the expensive analysis happens lazily, per question, only where you look. Want it all up front anyway, say for a batch job? `lachesis-analyze --enrich` folds the full tier in at build time.

```
  source tree
      |
      v
  frontends        real compilers parse each language into
      |            syntax, symbols, calls  (the core tier)
      v
  kuzu store       staged Parquet, bulk-copied into an embedded
      |            columnar graph DB: typed, compact, fast to open
      v
  nav  (+ MCP)     hubs, search, callers/callees, read_body,
                   flow, reaches, sources_of, points_to, aliases,
                   candidates, taint, folding the dataflow cone
                   it needs, on demand
```

`graph.kuzu` is a directory: the embedded database plus a manifest. That *is* the graph. Every tool reads it directly, and `lachesis-mcp` serves the same tools over stdio for any MCP-capable client.

---

## Performance, briefly

The store is columnar, which is what lets a graph with well over a million nodes open in under a second on a laptop, holding only a few hundred megabytes of RAM to do it. A pruned store of a large Python codebase (Django: 1.6M nodes / 2.6M edges) lands around 500 MB on disk, opens fast, and stays cheap to keep resident, because columnar scans read only the columns a query touches.

Lossless `--prune` drops pure-lexical nodes (source is read from files by offset, not stored twice), roughly halving the store. The on-disk layout and the compression work live in [`docs/KUZU_STORE_SPEC.md`](./docs/KUZU_STORE_SPEC.md) and [`docs/STORE_COMPRESSION_SPEC.md`](./docs/STORE_COMPRESSION_SPEC.md).

For reproducible large-codebase measurements, use the direct-package commands and
record the results in [`docs/PERFORMANCE.md`](./docs/PERFORMANCE.md). The ledger tracks
frontend build, enrichment, Kùzu materialization, node/edge counts, and peak memory so
an optimization can be checked for both speed and graph completeness.

The main engine-only command is:

```bash
LACHESIS_C_JOBS=1 LACHESIS_EMIT_TOKENS=0 LACHESIS_EMIT_PROOFS=0 \
  python3.11 -m lachesis.frontends.c.build_graph \
  /path/to/large-c-tree /tmp/lachesis-frontends
```

For a core-only store on a large mixed-language tree, stream frontend shards directly
into Kùzu to keep the parent process from composing one giant graph:

```bash
lachesis-analyze /path/to/project /tmp/project.kuzu \
  --stream-shards /tmp/project-shards --prune
```

For large CI runners, bound Kùzu's cache explicitly so materialization cannot claim
the host's entire available RAM. The value is bytes; 1 GiB is a good starting point
for Linux/net-sized workloads:

```bash
LACHESIS_KUZU_BUFFER_POOL_SIZE=1073741824 \
  lachesis-analyze /path/to/project /tmp/project.kuzu \
  --stream-shards /tmp/project-shards --prune
```

`--stream-shards` is currently incompatible with `--enrich`; dataflow partition
streaming is the next integration step. The resulting store is explicitly marked
core-only, so `GraphStore`/the GitHub Action builds the dataflow tier on its first
security query rather than silently skipping enrichment. Additive derived records are
cached in a compact internal `<store>.dataflow.pb` sidecar; JSON is reserved for
user-facing output. A full `.enriched` Kùzu cache remains the fallback for overlays
that mutate core records.

The GitHub Action's SARIF step sets `LACHESIS_QUERY_EPHEMERAL_ENRICH=1`: its batch
security query uses the derived tier only for that process and avoids writing a second
graph-sized cache. Local query commands keep persistent enriched-cache behavior.

The streamed path defaults to a 1 GiB Kùzu buffer pool. For very large subsystems
such as Linux `fs`, raise it when the runner has room (the tested fs run used 2 GiB):

```bash
LACHESIS_KUZU_BUFFER_POOL_SIZE=2147483648 \
  lachesis-analyze /path/to/linux/fs /tmp/fs.kuzu \
  --stream-shards /tmp/fs-shards --prune --timeout 900
```

Disk-backed query/materialization scans use up to eight Kùzu execution threads by
default. Override this for a constrained runner with `LACHESIS_KUZU_QUERY_THREADS=2`
(or another positive integer); this changes read parallelism, not graph facts.

Use a clean output directory and monitor the process on very large trees. The command
builds the complete C graph directly; the token/proof switches remove only lexical
facts that `--prune` discards later.

---

## Install from source

Lachesis installs from a clone — that's the supported path for now (a published wheel comes with the first release):

```bash
git clone https://github.com/UnboundCompute/lachesis && cd lachesis
python -m pip install --upgrade pip     # editable installs need pip >= 21.3
pip install -e ".[dev]"                 # builder, nav, MCP server, tests
npm install                             # the TypeScript compiler the TS frontend loads
```

Runtime dependencies are just `kuzu` and `pyarrow`; everything else is standard library. The `npm install` step vendors the TypeScript compiler the TS frontend loads — it's a build artifact, not checked in, so a fresh checkout needs it. Node must be on your PATH for the TS frontend; C additionally needs `clang`, and without it C files are simply skipped while every other language still builds.

Semantic `concept_search` is deliberately separate from the core install. Neither its
FastEmbed runtime nor its model weights ship in the Lachesis wheel, and a search never
downloads them implicitly. Opt in and download the local model explicitly:

```bash
pip install -e ".[concept-search]"       # optional ONNX embedding runtime
lachesis concept-model download          # model weights in the user cache
lachesis concept-model status            # inspect without downloading
```

The default is the small local `BAAI/bge-small-en-v1.5` model. Search uses a global
lexical/structural pass and embeds only a small source-rich shortlist; those vectors
are cached separately by graph fingerprint and model ID. Set
`LACHESIS_CONCEPT_CACHE` to choose where both the downloaded model and derived indexes
live, outside the installed package.

---

## Where to go next

- **[`examples/`](./examples/README.md)**: a five-minute walkthrough. Build a graph from the bundled fixture, then watch Lachesis tell two sibling functions apart because one authorizes a database lookup and the other reaches the identical call with no check. The kind of thing a symbol index can't do.
- **[`docs/graph-model.md`](./docs/graph-model.md)**: the reference for what's in the graph, its node kinds, edge kinds, and tiers.
- **[`docs/queries.md`](./docs/queries.md)**: every way to ask a question, both `lachesis-query` and the MCP tools.
- **[`docs/`](./docs/)**: the deeper material, including the store spec, the lazy dataflow tier, frontend scaling, and design notes.

---

## Where this is heading

Lachesis has one north star: be the precise, complete, and honest structural substrate an LLM reasons over when the codebase is far larger than any context window. The division of labor is deliberate. **The graph owns "don't miss":** every caller, every callee, every source-to-sink path, with each fact carrying where it came from and how sure it is. **The LLM owns "don't false-positive":** is this check a real authorization, is this actually a bug, is this a shape nobody has a name for yet.

The shape that falls out of that is a type checker for security questions. A type checker earns its keep by proving the *absence* of an error on every run, locally and offline. Point the same idea at reachability and the question becomes: can attacker-controlled input reach this dangerous sink? The answer Lachesis is built to give is either a labeled witness path or a bounded "no" that names exactly what it could not see. Not another list of findings to triage, but a way to make a question go away.

So the direction is depth before breadth: completeness, types, and clean entry and sink identification on C, Python, and TypeScript matter more right now than a fourth language that only half works.

## Roadmap

Near-term, roughly in order:

- [ ] **Monorepo-scale builds.** Very large TypeScript trees can exceed the compiler's own internal limits when analyzed as a single program. `--parallel-packages` compiles each package on its own, and making that the smooth default for big repos is active work.
- [ ] **Bounded security signal.** The guard-analysis tools currently need a whole-graph pass, so they are switched off rather than let a query stall on a large graph. Reworking the guard signal to fold the same per-seed, on-demand cone the dataflow tools already use brings them back without the cost.
- [ ] **Entry and sink identification.** Mechanical, honest identification of where untrusted input enters and where it lands, so "can input reach this sink" has well-defined endpoints.
- [ ] **The reachability query, first-class.** "Can attacker input reach this sink" as a single call that returns a witness path or a bounded no, across file, package, and language boundaries.
- [ ] **Deeper types and framework models.** More precise call resolution and mechanical framework identification, still stopping short of encoding a security verdict.

The longer charter, and the reasoning behind this split, lives in [`docs/DIRECTION.md`](./docs/DIRECTION.md).

## Status

Lachesis is early and moving fast. The graph model, the store, and the navigation and MCP layer all work today and are held to a parity test suite that checks the columnar store answers every tool identically to the same graph held whole in memory.

Rough edges live in the issue tracker. The schema and tool set may still shift before 1.0; the [`CHANGELOG`](./CHANGELOG.md) calls out changes explicitly rather than leaving them to be discovered.

## License

AGPL-3.0. See [`LICENSE`](./LICENSE). You're free to use, study, modify, and share it, commercially included; run a modified version as a network service and you make your modified source available to its users. If that doesn't fit, say embedding in a closed product, a separate commercial license may be available. See [`CONTRIBUTING.md`](./CONTRIBUTING.md) or open an issue.

## Security

Found a vulnerability? Please don't open a public issue; see [`SECURITY.md`](./SECURITY.md) for private reporting.
