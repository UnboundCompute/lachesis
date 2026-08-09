# LLM reasoning exposure

`ReasoningQuery` is the programmatic interface over the canonical project graph.
It returns JSON-ready, evidence-backed slices; it never reparses source or changes
canonical facts.

```python
from Arachne.pipeline import run_project
from Arachne.reasoning import ReasoningQuery

graph, snapshots = run_project("src")
query = ReasoningQuery(graph)
overview = query.overview()
matches = query.find_entity("getDocument", kind="function")
function = query.function_slice(matches["matches"][0]["id"])
```

The default budget is approximately 12,000 tokens using deterministic serialized
characters divided by four. When lower-priority records do not fit, the result
contains an `expand` continuation handle pointing at the first omitted node.

The JSON-first CLI reads the canonical project JSON written by
`Arachne/cli/analyze.py`:

```sh
python3 Arachne/cli/query.py graph.json overview
python3 Arachne/cli/query.py graph.json function getDocument --file document-service.ts
python3 Arachne/cli/query.py graph.json security-path NODE_ID
python3 Arachne/cli/query.py graph.json --budget-tokens 6000 unresolved
python3 Arachne/cli/query.py graph.json --format text call NODE_ID
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
