#!/usr/bin/env python3
"""Fix 1 — transitive value reachability, queryable on demand.

The canonical taint overlay materializes almost nothing end-to-end (`TAINT_REACHES`
= 4): it only propagates from graph-declared `source`/`sink` role nodes, so any
value that isn't pre-tagged has no reach answer. But the *substrate* it walks is
fully present — `VALUE_FLOWS_TO` (67k), `POINTS_TO` (19k), the alias/heap edges —
and `Lachesis/core/overlays/taint.py` already encodes the correct traversal
(context-sensitive worklist with `context-parameter`/`context-return` push-pop for
interprocedural transitivity, per-source budget, predecessor witnesses).

This module is that same worklist, made **seedable from any node** and returning
the **labeled witness path** rather than materializing a global overlay. It powers
three moves:

  * `flow(seed)`        — everything a value reaches (its forward cone), path-shaped
  * `reaches(src,sink)` — the witness path from src to sink, or the negative answer
  * `sources_of(sink)`  — reverse cone: which values feed a sink

**Alias bridging** is the key gain over the base overlay: two values alias when they
both `POINTS_TO` the same heap-object, so we walk `POINTS_TO` forward (value→heap)
*and* its reverse (heap→sibling value). That crosses `const {url} = options` — the
exact destructuring shape where the taint overlay gives up — as an explicit
`alias-via-heap` hop in the returned path.

  python3 nav/reachability.py graph.kuzu --from <value-id>
  python3 nav/reachability.py graph.kuzu --reaches <src-id> <sink-id>
  python3 nav/reachability.py graph.kuzu --sources-of <sink-id>
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict, deque
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from Lachesis.core.overlays.taint import FLOW_EDGE_KINDS
from nav.graph_store import GraphStore

# Same fail-open valve as taint.py, but per *query* (one seed) instead of per source.
MAX_STATES = 200_000
# POINTS_TO is directional (value -> heap-object -> heap-location). Aliasing lives in
# the reverse hop: from a shared heap-object back to a sibling value. We synthesize
# that reverse edge so two destructured/aliased values connect through their heap.
_ALIAS_KIND = "POINTS_TO"


def _synth_alias_edge(heap_id: str, value_id: str, base: dict) -> dict:
    """A reverse POINTS_TO hop (heap-object -> aliasing value), labeled as such."""
    props = base.get("properties") or {}
    return {
        "source": heap_id, "target": value_id, "kind": _ALIAS_KIND,
        "properties": {
            "reason": "alias-via-heap",
            "confidence": props.get("confidence"),
            "fact_origin": props.get("fact_origin"),
        },
    }


class Reachability:
    """Forward/reverse value-flow closure with a labeled witness, built once."""

    def __init__(self, store: GraphStore) -> None:
        self.store = store
        self.index = store.index
        # adjacency entries: node_id -> [(target, edge_dict, reason, context_id)]
        self._fwd: dict[str, list] | None = None
        self._rev: dict[str, list] | None = None

    # -- adjacency (built once, both directions) ----------------------------

    def _build(self) -> None:
        fwd: dict[str, list] = defaultdict(list)
        rev: dict[str, list] = defaultdict(list)
        for edge in self.index.flow_edges(FLOW_EDGE_KINDS):
                kind = self.index.semantic_edge_kind(edge)
                src, tgt = edge.get("source"), edge.get("target")
                if src is None or tgt is None:
                    continue
                props = edge.get("properties") or {}
                reason = props.get("reason")
                context_id = props.get("context_id")
                fwd[src].append((tgt, edge, reason, context_id))
                # reverse graph: the flow edge, walked backwards, is the reverse
                # direction with its context push/pop inverted so sources_of stays
                # interprocedurally sound.
                rev_reason = ({"context-parameter": "context-return",
                               "context-return": "context-parameter"}
                              .get(reason, reason))
                rev[tgt].append((src, edge, rev_reason, context_id))
                # alias bridge: a POINTS_TO edge also lets the heap-object reach the
                # value in forward traversal (heap -> sibling value), so aliasing
                # values connect. Symmetric on the reverse graph.
                if kind == _ALIAS_KIND:
                    alias = _synth_alias_edge(tgt, src, edge)
                    fwd[tgt].append((src, alias, "alias-via-heap", None))
                    rev[src].append((tgt, alias, "alias-via-heap", None))
        self._fwd, self._rev = fwd, rev

    def _adj(self, reverse: bool) -> dict[str, list]:
        if self._fwd is None:
            self._build()
        return self._rev if reverse else self._fwd

    # -- core worklist -------------------------------------------------------

    def _walk(self, seed_id: str, reverse: bool, budget: int):
        """Context-sensitive BFS from a seed. Returns (reached, predecessor, truncated).

        `reached`: value_id -> first state that reached it.
        `predecessor`: state -> (prev_state, edge_dict) witness map.
        Mirrors taint.py's push/pop so interprocedural hops stay balanced."""
        adjacency = self._adj(reverse)
        initial = (seed_id, ())
        queue = deque([initial])
        seen = {initial}
        predecessor: dict = {}
        reached: dict[str, tuple] = {}
        truncated = False
        while queue:
            if len(seen) > budget:
                truncated = True
                break
            state = queue.popleft()
            current, contexts = state
            if current not in reached:
                reached[current] = state
            for target, edge, reason, context_id in adjacency.get(current, []):
                next_contexts = contexts
                if reason == "context-parameter":
                    if not context_id or len(contexts) >= 12:
                        continue
                    next_contexts = (*contexts, context_id)
                elif reason == "context-return":
                    if not context_id or not contexts or contexts[-1] != context_id:
                        continue
                    next_contexts = contexts[:-1]
                nstate = (target, next_contexts)
                if nstate not in seen:
                    seen.add(nstate)
                    predecessor[nstate] = (state, edge)
                    queue.append(nstate)
        return reached, predecessor, truncated

    @staticmethod
    def _witness(state, predecessor, initial):
        """Walk the predecessor chain back to `initial`; return (node_ids, edges)."""
        node_ids = [state[0]]
        edges: list[dict] = []
        cursor = state
        while cursor != initial and cursor in predecessor:
            prev, edge = predecessor[cursor]
            edges.append(edge)
            node_ids.append(prev[0])
            cursor = prev
        if cursor != initial:
            return None, None
        node_ids.reverse()
        edges.reverse()
        return node_ids, edges

    # -- public moves --------------------------------------------------------

    def flow(self, seed_id: str, budget: int = MAX_STATES, limit: int = 200) -> dict:
        """The forward cone of a value: every node it flows to, path-shaped.

        Edges are the predecessor spanning tree (one witness hop per reached node),
        so the result reads as the flow graph rooted at the seed."""
        reached, predecessor, truncated = self._walk(seed_id, False, budget)
        return self._cone_shape(seed_id, reached, predecessor, truncated,
                                limit, direction="forward")

    def sources_of(self, sink_id: str, budget: int = MAX_STATES, limit: int = 200) -> dict:
        """The reverse cone of a sink: every value that can feed it, path-shaped."""
        reached, predecessor, truncated = self._walk(sink_id, True, budget)
        return self._cone_shape(sink_id, reached, predecessor, truncated,
                                limit, direction="reverse")

    def reaches(self, src_id: str, sink_id: str, budget: int = MAX_STATES) -> dict:
        """The single witness path src -> sink, or a negative answer, path-shaped."""
        reached, predecessor, truncated = self._walk(src_id, False, budget)
        initial = (src_id, ())
        sink_state = reached.get(sink_id)
        if sink_state is None:
            return self.store.path_shape([], [], manifest={
                "move": "reaches", "src": src_id, "sink": sink_id,
                "reachable": False, "truncated": truncated,
                "note": "no value-flow path found under the flow/alias edges",
            })
        node_ids, edges = self._witness(sink_state, predecessor, initial)
        if node_ids is None:
            node_ids, edges = [src_id, sink_id], []
        return self.store.path_shape(node_ids, edges, manifest={
            "move": "reaches", "src": src_id, "sink": sink_id,
            "reachable": True, "hops": len(edges), "truncated": truncated,
        })

    def _cone_shape(self, seed_id, reached, predecessor, truncated,
                    limit, direction) -> dict:
        initial = (seed_id, ())
        node_ids: list[str] = [seed_id]
        edges: list[dict] = []
        seen = {seed_id}
        # deterministic order, seed first, then reached nodes by id
        for value_id in sorted(reached):
            if value_id == seed_id or value_id in seen:
                continue
            if len(node_ids) >= limit:
                break
            seen.add(value_id)
            node_ids.append(value_id)
            _, hop = self._witness(reached[value_id], predecessor, initial)
            if hop:
                edges.append(hop[-1])  # the last hop into this node (its parent edge)
        return self.store.path_shape(node_ids, edges, manifest={
            "move": "flow" if direction == "forward" else "sources_of",
            "seed": seed_id, "direction": direction,
            "reached": len(reached), "shown": len(node_ids),
            "truncated": truncated,
        })


def _seed_from(store: GraphStore, token: str) -> str | None:
    """Accept a raw node id or a name that resolves to one."""
    if store.node(token):
        return token
    hits = store.resolve(token)
    return hits[0]["node_id"] if hits else None


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Fix 1 — transitive value reachability")
    p.add_argument("graph")
    p.add_argument("--overlay", help="override sidecar overlay path")
    p.add_argument("--from", dest="frm", metavar="ID|NAME",
                   help="forward flow cone from a value")
    p.add_argument("--sources-of", metavar="ID|NAME",
                   help="reverse cone: what feeds this sink")
    p.add_argument("--reaches", nargs=2, metavar=("SRC", "SINK"),
                   help="witness path from SRC to SINK")
    p.add_argument("--budget", type=int, default=MAX_STATES)
    p.add_argument("--limit", type=int, default=200)
    return p


def main(argv: list[str]) -> int:
    args = _parser().parse_args(argv)
    store = GraphStore.load(args.graph, overlay_path=args.overlay)
    r = Reachability(store)
    if args.frm:
        seed = _seed_from(store, args.frm)
        if not seed:
            print(f"no node for {args.frm!r}", file=sys.stderr); return 2
        print(json.dumps(r.flow(seed, args.budget, args.limit), indent=2, ensure_ascii=False))
        return 0
    if args.sources_of:
        seed = _seed_from(store, args.sources_of)
        if not seed:
            print(f"no node for {args.sources_of!r}", file=sys.stderr); return 2
        print(json.dumps(r.sources_of(seed, args.budget, args.limit), indent=2, ensure_ascii=False))
        return 0
    if args.reaches:
        src = _seed_from(store, args.reaches[0])
        sink = _seed_from(store, args.reaches[1])
        if not src or not sink:
            print("could not resolve src/sink", file=sys.stderr); return 2
        print(json.dumps(r.reaches(src, sink, args.budget), indent=2, ensure_ascii=False))
        return 0
    print("need --from, --reaches, or --sources-of", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
