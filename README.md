<!-- mcp-name: io.github.UnboundCompute/lachesis -->

# Lachesis

**A compiler-precise code graph you can ask questions about: how data moves, who calls what, what reaches a sink. C, Python, and TypeScript, all in one graph.**

[![PyPI](https://img.shields.io/pypi/v/lachesis-cpg)](https://pypi.org/project/lachesis-cpg/)
[![Python](https://img.shields.io/pypi/pyversions/lachesis-cpg)](https://pypi.org/project/lachesis-cpg/)
[![CI](https://github.com/UnboundCompute/lachesis/actions/workflows/ci.yml/badge.svg)](https://github.com/UnboundCompute/lachesis/actions/workflows/ci.yml)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue)](./LICENSE)
[![MCP](https://img.shields.io/badge/MCP-server-1f6feb)](https://modelcontextprotocol.io)
[![Docker](https://img.shields.io/badge/ghcr.io-lachesis-2496ED?logo=docker&logoColor=white)](https://github.com/UnboundCompute/lachesis/pkgs/container/lachesis)
[![Glama](https://glama.ai/mcp/servers/UnboundCompute/lachesis/badges/score.svg)](https://glama.ai/mcp/servers/UnboundCompute/lachesis)
[![Security Scan](https://img.shields.io/badge/security-Lachesis-8250df)](https://github.com/UnboundCompute/lachesis-action)

> Scan your own repo on every PR: the [Lachesis Security Scan Action](https://github.com/UnboundCompute/lachesis-action) traces untrusted input to sinks and reports guard differentials straight into GitHub code scanning.

## Watch it work

<video src="https://raw.githubusercontent.com/UnboundCompute/lachesis/main/docs/media/lachesis-demo.mp4" poster="https://raw.githubusercontent.com/UnboundCompute/lachesis/main/docs/media/lachesis-demo-poster.png" controls muted loop playsinline width="100%"></video>

[![Lachesis flags SQL injection on a live pull request](docs/media/lachesis-demo-poster.png)](https://github.com/UnboundCompute/lachesis-action-demo/pull/5)

A 55-second walkthrough: a Flask control plane where three handlers reach the same SQL sink unguarded while two sibling handlers authorize first. Lachesis follows the value, flags the three, and names their guarded twins — [**see it live on the pull request →**](https://github.com/UnboundCompute/lachesis-action-demo/pull/5)

Lachesis parses a codebase with real compilers, not regexes, and turns it into a graph you can navigate. Syntax, symbols, calls, and the part that matters most: a full dataflow layer of value-flow, points-to, taint, and aliasing. That graph lives in an embedded columnar database and answers questions through a small navigation API and an MCP server, so a person or an LLM agent can reason about real source with compiler-level fidelity.

A symbol index (LSP, ctags, SCIP) tells you *where a name appears*. Lachesis is built to tell you *how a value moves* — which is where the questions that matter live: does this request parameter reach that SQL call, which of these two near-identical functions checks its input first, what can flow into this buffer.

## Install

```bash
python -m pip install lachesis-cpg
```

The release-tested Python window is 3.10–3.12 (the CI matrix); use a newer interpreter
only after verifying it against the Lachesis/Kùzu dependency set. Python analysis needs
nothing beyond the package; TypeScript/JavaScript builds need `node` on `PATH` and C
builds need `clang` — a missing one comes back as an actionable error, not a crash.

To work from a clone instead (the contributor workflow), see
[Install from source](#install-from-source).

## Quickstart

```bash
lachesis scan ./my-project                   # build/cache the graph and report findings
lachesis mcp ./my-project                    # hand the same codebase to your agent over MCP
```

The lower-level artifact commands remain available when you need to name and move a graph
explicitly, now as subcommands of the one `lachesis` entrypoint: `lachesis build` builds a
store, `lachesis query` reads it, and `lachesis mcp` serves it. (The old `lachesis-analyze`
/ `lachesis-query` / `lachesis-mcp` scripts still work and print a one-line hint to the new
verb — `lachesis-analyze` is `lachesis build`, the graph builder.)

## MCP

Use the `lachesis-mcp` executable from the same environment that built the graph. You can
hand it an absolute `graph.kuzu` path, but you do not have to: start it with no argument
and the agent builds its own graph on demand with the `build_graph` tool — point it at a
repo path and it compiles, caches, and attaches the graph in one call (an unchanged tree is
served from cache; `refresh: true` forces a rebuild). That makes the server zero-config.

**One click** (uses `uvx`, no install step):

[![Add lachesis to Cursor](https://cursor.com/deeplink/mcp-install-dark.svg)](https://cursor.com/install-mcp?name=lachesis&config=eyJjb21tYW5kIjoidXZ4IiwiYXJncyI6WyItLWZyb20iLCJsYWNoZXNpcy1jcGciLCJsYWNoZXNpcy1tY3AiXX0=)
&nbsp;
[![Install in VS Code](https://img.shields.io/badge/VS_Code-Install_Lachesis-0098FF?logo=visualstudiocode&logoColor=white)](https://insiders.vscode.dev/redirect/mcp/install?name=lachesis&config=%7B%22command%22%3A%22uvx%22%2C%22args%22%3A%5B%22--from%22%2C%22lachesis-cpg%22%2C%22lachesis-mcp%22%5D%7D)

Or configure any client by hand. Drop one of these into your MCP client's config
(Claude Desktop, Cursor, Claude Code). If the package is already installed in the environment:

```json
{
  "mcpServers": {
    "lachesis": { "command": "lachesis-mcp" }
  }
}
```

Or with no install step at all, letting `uvx` fetch it on first run:

```json
{
  "mcpServers": {
    "lachesis": { "command": "uvx", "args": ["--from", "lachesis-cpg", "lachesis-mcp"] }
  }
}
```

Or run it as a container — no Python, Node, or clang on the host, all three
frontends inside the image:

```json
{
  "mcpServers": {
    "lachesis": {
      "command": "docker",
      "args": ["run", "--rm", "-i", "-v", "/path/to/your/project:/src",
               "ghcr.io/unboundcompute/lachesis:edge"]
    }
  }
}
```

Mount your project (here `/src`) and point `build_graph` at it. In VS Code you
can use `${workspaceFolder}` for the mount source. The image is published for
linux/amd64 and linux/arm64; `:edge` tracks `main` and each release also
publishes an `:x.y.z` tag.

Source-checkout and interpreter troubleshooting examples are in
[`docs/queries.md`](./docs/queries.md#the-lachesis-mcp-server).

## See it work

Two sibling functions reach the same database call. One checks the caller's tenant first; the other doesn't. A symbol index sees both call `findById` and stops there — Lachesis tells them apart by following the value.

```bash
lachesis build lachesis/frontends/typescript/fixtures/project example.kuzu
lachesis query --format text example.kuzu handler-security getDocument
```

```
"status": "UNGUARDED",
"guard_signal": null,
"differential_siblings": [ "getInvoice" ]
```

`getDocument` reaches `findById` with no check — and the record names its guarded twin, `getInvoice`, directly. That finding lives in *how the value moves*, not *where the name appears*. Full walkthrough in [`examples/`](./examples/README.md).

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
| Which entrypoints can reach sensitive effects without a recognized guard? | `scan`, the cached guard-differential queue with census/frontier counts (questions, not verdicts) |
| What wrappers, guards, invariants, and boundaries are visible? | `wrapper_model`, `guard_dominance`, `counterexample`, `invariant_trace`, `cross_boundary_paths` |
| Which path representations differ? | `representation_roundtrip`, structural comparison with no generated behavior verdict |
| Which safety-obligation sites should I inspect first? | `candidates`, ranked and exhaustive over bound facts across the whole sink taxonomy, with no safety verdict |
| The full evidence for one site, or coverage across every family | `candidate_detail` (the neutral evidence capsule), `candidate_census` (constructor metadata, exhaustive counts, and the analysis frontier) |
| Which code implements a behavior when I do not know its symbol name? | `concept_search` (optional local model, installed and downloaded separately) |

Every answer carries a confidence and an origin. An `exact` edge is resolved; a `conservative` one is a deliberate over-approximation the tool tells you about rather than hiding. You read the results as evidence, not as verdicts.

## Languages

Three frontends, each backed by a real compiler or the language's own parser, never a heuristic grammar.

| Language | Engine | Extensions |
|---|---|---|
| TypeScript / JavaScript | the TypeScript compiler API, with the type checker | `.ts` `.tsx` `.mts` `.cts` `.js` `.jsx` |
| Python | CPython's own `ast` + `symtable` (standard library only) | `.py` `.pyi` |
| C | Clang, via its AST dump | `.c` `.h` |

A mixed tree is **one graph, not three**. Lachesis picks a frontend per file, composes the results into a single node and edge set, and runs the same analysis over all of it, so a Python caller and a TypeScript callee sit in the same store and the same tools answer over both.

Two honest limits, stated up front: Python has no type checker, so it resolves attribute calls lexically and says so (`types: none`); C reads one translation unit at a time, so it won't follow a call through a function-pointer table it never sees. Each frontend declares what it actually knows, and a validator holds it to that claim.

## How it's built

Lachesis writes the graph in two tiers. **The build writes the core tier**: syntax,
symbols, and calls — the fast part, and all most navigation needs. **The dataflow tier is
a pure function of the core graph**, so it isn't written at build time. The first query
that actually needs value-flow folds in just the *cone* around its seed and caches it
beside the store; nothing pays for a whole-graph dataflow pass it never asked about. Want
it all up front anyway, say for a batch job? `lachesis-analyze --enrich` folds the full
tier in at build time.

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
                   scan, candidates, taint, folding the dataflow cone
                   it needs, on demand
```

`graph.kuzu` is a directory: the embedded database plus a manifest. That *is* the graph.
Every tool reads it directly, and `lachesis-mcp` serves the same tools over stdio for any
MCP-capable client. The graph model is documented in
[`docs/graph-model.md`](./docs/graph-model.md); large-build and CI tuning lives in
[`docs/scaling.md`](./docs/scaling.md).

## Pass 3 cold-path audit (developers)

Pass 3 is the object-identity and semantic-matching flow over an existing CPG store. This
is a cold-path benchmark: use a fresh Python process and `LACHESIS_LIFETIME_WORKERS=1`;
do not compare a warm in-process run with Pass 1 or Pass 2.

Build or rebuild the graph first. The graph writer automatically publishes the compact
structural sidecar that Pass 3 consumes:

```bash
cd /Users/riyandhiman/project/unboundcompute/arachne

SOURCE=/Users/riyandhiman/project/unboundcompute/cve-proof/src/libxml2
GRAPH=/tmp/codex-pass3-audit-20260825/libxml2-clean/pass2.kuzu

lachesis-analyze "$SOURCE" "$GRAPH"
# From a source checkout, use this equivalent command:
# python3 -m lachesis.cli.analyze "$SOURCE" "$GRAPH"
```

Run the complete cold Pass 3 flow with the five-minute safety stop and maximum RSS
measurement (macOS):

```bash
cd /Users/riyandhiman/project/unboundcompute/arachne

LACHESIS_LIFETIME_WORKERS=1 /usr/bin/time -l timeout 300 python3 - <<'PY'
from lachesis.nav.graph_store import GraphStore
from lachesis.flow.pipeline import run_pass

graph = "/tmp/codex-pass3-audit-20260825/libxml2-clean/pass2.kuzu"
store = GraphStore.load(graph)
result = run_pass(store, lang="c", lifetime_engine="object")

print("leads", len(result["leads"]))
print("timings", result["timings"])
PY
```

The timeout rule is `max(5 minutes, max(Pass 1, Pass 2) + 1 minute)`. The current Pass 1
and Pass 2 baselines are about 99.1s and 147.2s, so the active hard stop is 300s. On
Linux, replace `/usr/bin/time -l` with `/usr/bin/time -v`.

The expected sidecar is next to the store:

```text
/tmp/codex-pass3-audit-20260825/libxml2-clean/pass2.kuzu.pass3.substrate.pb
```

If it is absent, rebuild the store so the writer can create it. The large semantic JSON
snapshot is intentionally excluded from the cold path. Enable it only when explicitly
testing snapshot reuse:

```bash
LACHESIS_PASS3_SNAPSHOT=1 ...the same Pass 3 command...
```

Run the small deterministic parity fixture separately:

```bash
python3 -m lachesis.flow.match \
  --graph /tmp/codex-pass3-audit-20260825/example/pass2n.kuzu \
  --workers 1
```

The current reference result is `468 leads over 201 skeletons`. The latest full cold
libxml2 result is approximately 110.9s wall time, 85.9s internal Pass 3 time, and
6.74 GiB peak RSS; measurements vary with the machine and graph cache state.

## Install from source

Lachesis also installs from a clone — the workflow for contributors and for building the
TypeScript frontend from checked-out sources:

```bash
git clone https://github.com/UnboundCompute/lachesis && cd lachesis
python -m pip install --upgrade pip     # editable installs need pip >= 21.3
python -m pip install -e ".[dev]"       # builder, nav, MCP server, tests
npm ci                                   # install the locked TypeScript compiler dependency
```

After installing the checkout dependencies, run the same frontend parity gate used by CI
with `make check` (or `make PYTHON=python3.11 check` when selecting an interpreter).

Runtime dependencies are just `kuzu` and `pyarrow`; everything else is standard library.
The `npm ci` step installs the locked TypeScript compiler the TS frontend loads — it's a
build artifact, not checked in, so a fresh checkout needs it. Node 20+ must be on your PATH
for the TS frontend (CI verifies Node 20; the GitHub Action runs Node 22); C additionally
needs `clang`, and without it C files are simply skipped while every other language still
builds.

Semantic `concept_search` is optional and separate: neither its FastEmbed runtime nor its
weights ship in the wheel, and a search never downloads them implicitly. Opt in with
`pip install -e ".[concept-search]"`, then `lachesis concept-model download` (small local
`BAAI/bge-small-en-v1.5`; set `LACHESIS_CONCEPT_CACHE` to relocate the model and indexes).

## Where to go next

- **[`examples/`](./examples/README.md)**: a five-minute walkthrough — build a graph from the bundled fixture, then watch Lachesis tell two sibling functions apart because one authorizes a database lookup and the other reaches the identical call with no check.
- **[`docs/graph-model.md`](./docs/graph-model.md)**: what's in the graph — node kinds, edge kinds, and tiers.
- **[`docs/queries.md`](./docs/queries.md)**: every way to ask a question, both `lachesis-query` and the MCP tools.
- **[`docs/scaling.md`](./docs/scaling.md)**: large-build, monorepo, and CI-runner tuning; managing the local graph cache.
- **[`docs/`](./docs/)**: the deeper material, including the store spec and the lazy dataflow tier.

## Roadmap

Recently shipped:

- [x] **Zero-config MCP.** `lachesis-mcp` starts with no graph path; the `build_graph` tool compiles, caches, and attaches a graph on demand.
- [x] **PyPI distribution.** `python -m pip install lachesis-cpg`, with the TypeScript compiler vendored so a TS build needs no `npm`.

Near-term, roughly in order:

- [ ] **Monorepo-scale builds.** Very large TypeScript trees can exceed the compiler's own internal limits when analyzed as a single program. `--parallel-packages` compiles each package on its own; making that the smooth default for big repos is active work.
- [ ] **Bounded security signal.** The guard-analysis tools currently need a whole-graph pass, so they are switched off rather than let a query stall on a large graph. Reworking the guard signal to fold the same per-seed, on-demand cone the dataflow tools already use brings them back without the cost.
- [ ] **Entry and sink identification.** Mechanical, honest identification of where untrusted input enters and where it lands, so "can input reach this sink" has well-defined endpoints.
- [ ] **The reachability query, first-class.** "Can attacker input reach this sink" as a single call that returns a witness path or a bounded no, across file, package, and language boundaries.
- [ ] **Deeper types and framework models.** More precise call resolution and mechanical framework identification, still stopping short of encoding a security verdict.

## Status

Lachesis is early and moving fast. The graph model, the store, and the navigation and MCP
layer all work today and are held to a parity test suite that checks the columnar store
answers every tool identically to the same graph held whole in memory. The schema and tool
set may still shift before 1.0; the [`CHANGELOG`](./CHANGELOG.md) calls out changes
explicitly rather than leaving them to be discovered.

## License

AGPL-3.0. See [`LICENSE`](./LICENSE). You're free to use, study, modify, and share it, commercially included; run a modified version as a network service and you make your modified source available to its users. If that doesn't fit, say embedding in a closed product, a separate commercial license may be available. See [`CONTRIBUTING.md`](./CONTRIBUTING.md) or open an issue.

## Security

Found a vulnerability? Please don't open a public issue; see [`SECURITY.md`](./SECURITY.md) for private reporting.
