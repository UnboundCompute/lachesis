"""Materialize intraprocedural field-sensitive reaching-def edges over the C CPG.

The C frontend records AST structure (``AST_CHILD``), reference resolution
(``REFERS_TO``) and a basic-block-level control flow (``CFG_NEXT``), but it does
not record which *definition* of a value reaches which *use* at field precision.
Value-flow overlays approximate this field-INsensitively; this overlay adds the
field-sensitive relation directly.

For each function it synthesizes a per-expression micro-CFG from the AST, runs a
forward gen/kill fixpoint, and filters def->use pairs through the access-path
exact-match algebra (a write to ``p->payload`` reaches a read of ``p->payload``
but not a read of ``p->hdr``). It emits one additive ``REACHING_DEF`` edge per
surviving def->use pair. The reader lives in :mod:`lachesis.nav.dataflow`; this
overlay is a thin build-time driver over it.

It is a **separate, additive pass**: it reads only pre-existing compiler facts and
contributes only ``REACHING_DEF`` edges, so every other overlay's time and space
are unchanged (the registry measures each overlay independently). Because the pass
is per-function independent and its cost is dominated by the number of functions,
an optional ``functions`` filter scopes it to a subset (e.g. the call-graph
neighbourhood of known sinks), which is the practical build-time lever — the
full-graph pass is a one-time build cost, not a per-query one.

Process-parallelism was measured and deliberately *not* adopted: the per-function
work is small (tens of ms), so wall time is dominated by moving the per-function
result edges back across the process boundary and deduping them in the parent,
neither of which parallelizes; an 8-worker fork pool measured ~1.1x on a full
graph, not worth the cross-platform fork/spawn fragility. Scope with ``functions``
instead, or accept the one-time serial cost.
"""
from __future__ import annotations

from typing import Any, Iterable, List, Optional, Tuple

from ..composition import GraphDelta
from ..query import GraphIndex

RD_KIND = "REACHING_DEF"


class _OverlayIndex:
    """Adapt a build-time :class:`GraphIndex` to the reader's Substrate contract.

    Substrate needs ``edges_of_kind``/``nodes_of_kind``/``nodes_owned_by`` (all
    present on GraphIndex) plus ``_node(nid)`` (node dict by id), which GraphIndex
    exposes as ``nodes.get``. This wrapper supplies the last one and delegates.
    """

    def __init__(self, index: GraphIndex) -> None:
        self._idx = index

    def _node(self, nid: str):
        return self._idx.nodes.get(nid)

    def edges_of_kind(self, *kinds: str):
        return self._idx.edges_of_kind(*kinds)

    def nodes_of_kind(self, *kinds: str):
        return self._idx.nodes_of_kind(*kinds)

    def nodes_owned_by(self, owner_id: str, *kinds: str):
        return self._idx.nodes_owned_by(owner_id, *kinds)


class CReachingDef:
    """Additive overlay: field-sensitive intraprocedural def->use edges.

    ``functions`` optionally scopes the pass to a subset of function ids; ``None``
    processes every function that owns an expression (the full pass).
    """

    overlay_id = "c-reaching-def"

    def __init__(self, functions: Optional[Iterable[str]] = None) -> None:
        self._functions = set(functions) if functions is not None else None

    def applies(self, graph: dict, index: Any = None) -> bool:
        kinds = {e.get("kind") for e in graph.get("edges", ())}
        # needs AST to synthesize the micro-CFG and CFG_NEXT for block order
        return "AST_CHILD" in kinds and "CFG_NEXT" in kinds

    @staticmethod
    def _edge(def_id: str, use_id: str) -> dict:
        return {
            "kind": RD_KIND,
            "source": def_id, "target": use_id,
            "properties": {
                "fact_origin": "core-inference",
                "confidence": "high",
                "evidence_ids": [def_id, use_id],
                "inference": "c-reaching-def",
            },
        }

    def _collect(self, pairs: Iterable[Tuple[str, str]], seen: set) -> List[dict]:
        out: List[dict] = []
        for def_id, use_id in pairs:
            if def_id == use_id:
                continue
            key = (def_id, use_id)
            if key in seen:
                continue
            seen.add(key)
            out.append(self._edge(def_id, use_id))
        return out

    def enrich(self, graph: dict, index: Any = None) -> GraphDelta:
        # local imports: the reader is only needed when the overlay actually runs
        from lachesis.nav.dataflow.substrate import Substrate
        from lachesis.nav.dataflow.reaching_def import ReachingDef

        index = GraphIndex(graph) if index is None else index
        sub = Substrate(_OverlayIndex(index)).load()

        if self._functions is not None:
            targets = list(self._functions)
        else:
            targets = list(sub.functions())

        edges: List[dict] = []
        seen: set = set()

        rd = ReachingDef(sub)
        for fn in targets:
            try:
                result = rd.run_function(fn)
            except Exception:
                # a single malformed function must not abort the whole pass
                continue
            edges.extend(self._collect(result["edges"], seen))
        return GraphDelta(self.overlay_id, [], edges)
