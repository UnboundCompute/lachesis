# LLM reasoning exposure

`ReasoningQuery` is the programmatic interface over the canonical project graph.
It returns JSON-ready, evidence-backed slices; it never reparses source or changes
canonical facts.

```python
from lachesis.pipeline import run_project
from lachesis.reasoning import ReasoningQuery

graph, snapshots = run_project("path/to/source")
query = ReasoningQuery(graph)
overview = query.overview()
matches = query.find_entity("getDocument", kind="function")
function = query.function_slice(matches["matches"][0]["id"])
```

The default budget is approximately 12,000 tokens using deterministic serialized
characters divided by four. When lower-priority records do not fit, the result
contains an `expand` continuation handle pointing at the first omitted node.

The JSON-first CLI reads the canonical project JSON written by
`lachesis/cli/analyze.py`:

```sh
python3 lachesis/cli/query.py graph.json overview
python3 lachesis/cli/query.py graph.json function getDocument --file document-service.ts
python3 lachesis/cli/query.py graph.json security-path NODE_ID
python3 lachesis/cli/query.py graph.json --budget-tokens 6000 unresolved
python3 lachesis/cli/query.py graph.json --format text call NODE_ID
```

Names are never guessed. A non-unique function name returns typed candidates;
subsequent queries use the stable node ID.

## Exposure model

- `manifest.json` is the compact project entry card.
- `project.capabilities` reports effective canonical capabilities after overlays;
  `project.frontend_capabilities` retains each compiler's raw declaration.
- T0–T4 artifacts are progressive semantic views.
- `node_index.json` locates every canonical node in those artifacts.
- `ReasoningQuery` calculates focused function, value, call, security, and
  unresolved-frontier slices from canonical facts.
- Source excerpts come from compiler-emitted `source-span` proof nodes.

The current interface is intentionally in-process Python plus CLI. An HTTP or MCP
surface can wrap the same query class later without changing graph semantics.

## Lightweight investigation loop

`InvestigationAgent` adds a bounded LLM loop without an agent framework. Each
model turn chooses one validated reasoning query or a terminal outcome. Python
rejects unknown IDs, repeated actions, and confirmed findings whose evidence was
not observed in a previous slice.

The default is eight model calls with a 2,500-token budget for each graph slice.
Agent slices are capped at 3,000 tokens so state plus observation stays inside a
typical model context envelope; larger standalone reasoning queries remain
available. Provider absence is reported as `LLM_UNAVAILABLE`; it does not fall
back to an unstructured or fabricated investigation.

### Bring your own provider

Lachesis ships no LLM client and depends on no provider SDK. `InvestigationAgent`
takes any object satisfying a two-method duck type, so you wire it to whatever you
already use:

```python
async def complete(request) -> Response
```

- `request` is an `AgentRequest` — `task` (str), `context` (dict), `schema`
  (optional JSON Schema for the expected reply), `max_items` (int). Pass your own
  `request_factory=` to `InvestigationAgent` if your provider wants a different
  request object; the agent only constructs it, it never inspects it.
- The returned object needs `.data` — the parsed reply as a `dict` matching
  `schema`; anything else ends the loop as `LLM_UNAVAILABLE`, or as
  `BUDGET_EXHAUSTED_WITH_LEADS` if `.status == "budget"`. It also reads `.status`
  and `.usage` (a dict), both recorded per step in the investigation output.

That is the entire contract. A minimal adapter:

```python
class MyProvider:
    async def complete(self, request):
        reply = await my_client.json_call(
            prompt=request.task, context=request.context, schema=request.schema)
        return SimpleNamespace(data=reply, status="ok", usage={})

from lachesis.reasoning import InvestigationAgent, ReasoningQuery

agent = InvestigationAgent(ReasoningQuery(graph), MyProvider(), max_steps=8)
investigation = await agent.run(focus_id=None)
```

`lachesis/frontends/checks.py` drives the agent with a scripted stub of exactly this
shape, so the contract is exercised by the test suite on every run — no provider
required.
