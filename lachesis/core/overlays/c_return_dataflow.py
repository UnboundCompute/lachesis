"""Flow a C function's returned value into each callsite's result.

The C frontend records, per function, which expressions are returned
(``value -RETURNS_VALUE-> function``) and, per callsite, which function it
invokes (``call -INVOKES-> function``). It does not, however, connect the two:
the value a function returns has no value-flow edge to the call node that
receives it. So a value computed inside a function -- an untrusted-input source,
say, that a thin wrapper obtains and returns -- dies at the wrapper's ``return``,
and every caller sees an unrelated, untainted call result. curl is full of these
wrappers (its own ``getenv``/``recv``/``strdup`` shims), which is why an
in-wrapper source never reaches a caller-side sink.

This overlay supplies the missing edge, in the enrich flow, without touching the
base build: for each function, one additive ``VALUE_FLOWS_TO`` from every
returned value to every call node that invokes it. The edge is not a taint
heuristic -- the call result *is* the returned value -- so it is a plain
value-flow completion, the interprocedural sibling of the intraprocedural
:class:`CCallResultDataflow`. It composes with that overlay: the returned value
reaches the call node here, and ``CCallResultDataflow`` carries the call node on
into the variable the caller assigns.

It is context-insensitive by construction: a function returning a tainted value
on one path taints the result at every callsite, a sound over-approximation
appropriate to a taint *finder*. Only ``INVOKES`` (a resolved direct call) is
used, not ``MAY_INVOKE`` (a function-pointer candidate), so the edge is never
placed on a call whose target is merely possible.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any

from ..composition import GraphDelta

FLOW_KIND = "VALUE_FLOWS_TO"


class CReturnToCallsite:
    """Additive overlay: a function's returned value -> each callsite result."""

    overlay_id = "c-return-to-callsite"

    def applies(self, graph: dict, index: Any = None) -> bool:
        kinds = {e.get("kind") for e in graph.get("edges", ())}
        return "RETURNS_VALUE" in kinds and "INVOKES" in kinds

    def enrich(self, graph: dict, index: Any = None) -> GraphDelta:
        returns_by_fn: dict[str, list] = defaultdict(list)
        calls_by_fn: dict[str, list] = defaultdict(list)
        existing: set = set()
        for edge in graph.get("edges", ()):
            kind = edge.get("kind")
            if kind == "RETURNS_VALUE":
                returns_by_fn[edge["target"]].append(edge["source"])
            elif kind == "INVOKES":
                calls_by_fn[edge["target"]].append(edge["source"])
            elif kind == FLOW_KIND:
                existing.add((edge["source"], edge["target"]))

        edges = []
        seen: set = set()
        for function_id, returned in returns_by_fn.items():
            callsites = calls_by_fn.get(function_id)
            if not callsites:
                continue
            for value_id in returned:
                for call_id in callsites:
                    key = (value_id, call_id)
                    if key in seen or key in existing or value_id == call_id:
                        continue
                    seen.add(key)
                    edges.append({
                        "kind": FLOW_KIND,
                        "source": value_id, "target": call_id,
                        "properties": {
                            "fact_origin": "core-inference",
                            "confidence": "high",
                            "evidence_ids": [value_id, call_id],
                            "inference": "c-return-to-callsite",
                        },
                    })
        return GraphDelta(self.overlay_id, [], edges)
