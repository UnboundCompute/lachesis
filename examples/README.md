# Examples: a five-minute walkthrough

This runs Lachesis end to end against a tiny TypeScript project that ships in the
repo, so you can see real output before you point it at your own code. Nothing
here is invented. Every command and every block below is the actual output of a
fresh build of the bundled fixture, and the node IDs are content-addressed, so
the ones you see when you run it will match the ones printed here.

The whole point of the walkthrough is one question that a symbol index cannot
answer: two sibling functions reach the same database call, one checks
authorization first and the other does not, and Lachesis tells them apart by
following the data, not by matching a name.

## Runnable scripts

The narrative below is the security-path story; the `.py` scripts beside this file
are the library surface, one per operation, each a few `lachesis.Analysis` calls
you can read and re-run (they double as CI smoke tests):

| script | operation | CLI equivalent |
| --- | --- | --- |
| `build_graph.py` | build a graph from source, open it warm | `lachesis build` |
| `enrich_graph.py` | warm the dataflow + bind sidecars | `lachesis enrich` |
| `analyze_leads.py` | run the flow pass, filter the held leads | `lachesis analyze` |
| `find_candidates.py` | enumerate obligations across the whole taxonomy | `lachesis candidates` |
| `explain_candidate.py` | the whole adjudication chain in one call | `lachesis explain` |

Each takes `--help`. Every operation is available on all three surfaces — the
library method, the `lachesis` subcommand, and the matching MCP tool.

## The code under analysis

The fixture lives at `lachesis/frontends/typescript/fixtures/project`. Three of
its files carry the story.

One attacker-reachable entry point takes a public request and lifts an identifier
off its body, then hands that identifier to two different service calls
(`http/webhook.ts`):

```ts
export function handleWebhook(req: WebhookRequest): number {
  const rawId = req.body.id;
  const id = normalizeId(rawId);
  const document = getDocument(id);   // unguarded path
  const invoice = getInvoice(id);     // guarded path
  remember(id, document !== undefined);
  return (document ? 1 : 0) + (invoice ? 1 : 0);
}
```

The guarded sibling consults the caller's tenant before it returns the record
(`resources/invoice-service.ts`):

```ts
export function getInvoice(invoiceId: string): StoreRecord | undefined {
  const tenant = principalKey();
  const record = findById(invoiceId);
  if (record && record.tenant === tenant) {
    return record;
  }
  return undefined;
}
```

The unguarded sibling reaches the identical `findById` sink with no such check
(`resources/document-service.ts`):

```ts
export function getDocument(documentId: string): StoreRecord | undefined {
  return findById(documentId);
}
```

Both call `findById`. Both are reachable from the same public request. Only one
of them authorizes. Everything below is Lachesis recovering that fact from the
graph.

## Step 1: build the graph

Assuming you have installed the package (see the [Quick start](../README.md#quick-start)
in the top-level README), build a graph from the fixture. The output is a store
directory holding the embedded database and its manifest.

```bash
python3 -m lachesis.cli.analyze \
  lachesis/frontends/typescript/fixtures/project \
  /tmp/example.kuzu
```

```
Composed 1 frontends into 3026 nodes and 5158 edges: /tmp/example.kuzu
Tier: core-only (nav rebuilds the dataflow tier on first use)
Frontends: typescript-compiler-api
Node kinds: allocation=9, argument=31, ... token=1034, value=209, variable=48, write=26
```

The store holds the core tier. The dataflow tier on top of it (taint, control flow,
points-to, routes) is a pure function of the core graph plus the store manifest, so
the build leaves it out and the first query rebuilds it and caches it in a sibling
`/tmp/example.kuzu.enriched` directory. Every command below therefore answers exactly
as it would from an eagerly enriched store; the first one just pays for the tier once.
Pass `--enrich` (or set `LACHESIS_ENRICH_AT_BUILD=1`) to fold it in at build time
instead, which prints `3307 nodes and 6078 edges` and node kinds including `sink=3`,
`source=4`, `taint-reach=6`.

This moves the cost, it does not remove it: enrichment is a whole-graph in-memory
operation either way.

The `lachesis build` and `lachesis query` subcommands are the installed-package
equivalents of these module invocations. The `python3 -m` form works straight from
a clone.

## Step 2: get your bearings

```bash
python3 -m lachesis.cli.query --format text /tmp/example.kuzu overview
```

```
# overview

Project: layered-project:de19e2325b09731683b9
Languages: javascript, typescript
Canonical graph: 3307 nodes / 6078 edges
Security paths: 6
Guard differentials: 1
```

The two lines that matter are the last two. Six source-to-sink security paths
were recovered, and one of them is a guard differential: a pair of siblings that
reach the same sink where one authorizes and one does not.

## Step 3: the guard differential

Ask about the guarded handler first. The `--format text` flag prints a readable
digest; the underlying records are full JSON.

```bash
python3 -m lachesis.cli.query --format text /tmp/example.kuzu handler-security getInvoice
```

```
# handler-security
Focus: [function] getInvoice <...:function:e2c456e52d68a7fcb148> at resources/invoice-service.ts:5

Summary:
{
  "path_count": 3,
  "guard_verdicts": [
    {
      "handler_label": "getInvoice",
      "line": 5,
      "sink_names": [ "findById" ],
      "status": "GUARDED",
      "guard_signal": "resolved-authz-call",
      "confidence": "high",
      "witnesses": [ "...:body:32b7dfb9e628bd324fa8" ],
      "differential_siblings": []
    }
  ]
}
```

`status` is `GUARDED` and `guard_signal` is `resolved-authz-call`. The witness is
the `principalKey()` call that establishes the tenant before `findById` runs. Now
the sibling:

```bash
python3 -m lachesis.cli.query --format text /tmp/example.kuzu handler-security getDocument
```

```
# handler-security
Focus: [function] getDocument <...:function:90410a76b2ad16107ba6> at resources/document-service.ts:7

Summary:
{
  "path_count": 3,
  "guard_verdicts": [
    {
      "handler_label": "getDocument",
      "line": 7,
      "sink_names": [ "findById" ],
      "status": "UNGUARDED",
      "guard_signal": null,
      "confidence": "conservative",
      "witnesses": [],
      "differential_siblings": [ "getInvoice" ]
    }
  ]
}
```

Same sink, `findById`. Opposite verdict. And the record names its guarded twin
directly: `differential_siblings: ["getInvoice"]`. That cross-reference is the
finding. A tool that stops at symbols and references can tell you both functions
call `findById`. It cannot tell you that one of them checks the tenant first and
the other skips it, because that fact lives in how the value moves, not in where
the name appears.

## Step 4: follow the tainted value to the sink

The unguarded path from Step 3 has an ID you can drill into. Pull the full
source-to-sink chain:

```bash
python3 -m lachesis.cli.query --format text /tmp/example.kuzu \
  security-path v2:core:taint-propagation:taint-reach:4607b639d02e2fdf14d9
```

```
# security-path
Focus: [taint-reach] public parameter:documentId → database:findById(documentId) <...:taint-reach:4607b639d02e2fdf14d9>

Summary:
{
  "step_count": 4,
  "guard": {
    "handler_label": "getDocument",
    "status": "UNGUARDED",
    "differential_siblings": [ "getInvoice" ]
  }
}

## path (4)
- documentId            [parameter,  resources/document-service.ts:7]  position 0
- documentId            [value,      resources/document-service.ts:8]  position 1  (TAINT_FLOWS_TO)
- documentId            [argument,   resources/document-service.ts:8]  position 2  (TAINT_FLOWS_TO)
- findById(documentId)  [call-value, resources/document-service.ts:8]  position 3  (TAINT_FLOWS_TO)
```

Four hops, each carrying a `TAINT_FLOWS_TO` transition with its own source
excerpt: the public parameter `documentId` becomes a value, becomes a call
argument, reaches the `findById` sink. The guard verdict rides along inside the
path, so a consumer that only ever looks at this one record still learns that the
flow is unguarded and that a guarded sibling exists.

## Step 5: drive it from an agent over MCP

Everything above is also available to an LLM agent through the MCP server. Point
an MCP-capable client at the graph:

```bash
lachesis mcp /tmp/example.kuzu
```

The server speaks MCP over stdio and registers the navigation tools (`search`,
`callers`, `callees`, `reaches`, `guards_top`, `flow`, and the rest). For a
client that reads a JSON config, the entry looks like this:

```json
{
  "mcpServers": {
    "lachesis": {
      "command": "lachesis",
      "args": ["mcp", "/tmp/example.kuzu"]
    }
  }
}
```

Once it is wired up the agent can ask the same questions you asked on the command
line, one graph hop at a time, without loading the whole project into its context.

## Now point it at your own code

Swap the fixture path for a real TypeScript tree and run the same commands:

```bash
python3 -m lachesis.cli.analyze path/to/your/source graph.kuzu
python3 -m lachesis.cli.query --format text graph.kuzu overview
```

See [`KUZU_STORE_SPEC.md`](../docs/KUZU_STORE_SPEC.md) for what the columnar store buys
you on a large graph, and how it is laid out on disk.
