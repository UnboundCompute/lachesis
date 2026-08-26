"""Sequential registry for language-neutral canonical graph overlays."""
from __future__ import annotations

import time
from collections import defaultdict
from typing import Callable, Optional, Protocol, Tuple

from ..composition import GraphAccumulator, GraphDelta
from ..contract import ContractError
from ..query import GraphIndex


#: Told the overlay id, its wall time, and the size of the delta it contributed.
OverlayObserver = Callable[[str, float, int, int], None]
DeltaSink = Callable[[list[dict], list[dict]], None]


class _MinimalOverlayIndex:
    """Node membership plus bounded outgoing edges for a single small overlay."""

    def __init__(self, graph: dict, seed_sources) -> None:
        self.nodes = {node["id"]: node for node in graph.get("nodes", ())}
        sources = set(seed_sources)
        self.outgoing = defaultdict(list)
        if sources:
            for edge in graph.get("edges", ()):
                if edge.get("source") in sources:
                    self.outgoing[edge["source"]].append(edge)

    def absorb(self, nodes, edges, *, assume_fresh: bool = False) -> None:
        for node in nodes:
            self.nodes[node["id"]] = node
        for edge in edges:
            self.outgoing[edge["source"]].append(edge)


class CanonicalOverlay(Protocol):
    overlay_id: str

    def applies(self, graph: dict, index: "GraphIndex | None" = None) -> bool: ...

    def enrich(self, graph: dict, index: "GraphIndex | None" = None) -> GraphDelta: ...


class OverlayRegistry:
    """Apply independently registered core analyses in dependency order."""

    def __init__(self) -> None:
        self._overlays: list[CanonicalOverlay] = []

    def register(self, overlay: CanonicalOverlay) -> None:
        if any(item.overlay_id == overlay.overlay_id for item in self._overlays):
            raise ContractError(f"canonical overlay already registered: {overlay.overlay_id}")
        self._overlays.append(overlay)

    @property
    def overlays(self) -> Tuple[CanonicalOverlay, ...]:
        return tuple(self._overlays)

    def enrich(
        self, graph: dict, observer: Optional[OverlayObserver] = None,
        delta_sink: Optional[DeltaSink] = None,
    ) -> dict:
        """Fold every applicable overlay's facts into one graph.

        The accumulator is what makes this affordable. Recomposing the whole graph after
        each overlay charges every later overlay for every earlier overlay's output, and
        the overlays that contribute least pay the most, since the bill tracks the size
        of the accumulated graph rather than the size of the contribution.

        It is created lazily so that a registry where nothing applies hands back the
        caller's own graph rather than a re-sorted copy of it, and so that the first
        overlay to apply still sees the graph exactly as it arrived.

        ``observer`` is how the fold is measured. It is a permanent seam rather than
        something a profiler monkeypatches, because the per-overlay cost is the number
        this file exists to keep honest, and a patch that reaches inside a loop breaks
        the first time the loop is rewritten.
        """
        current = graph
        accumulator = None
        # Overlay predicates and folds only need kind and adjacency lookups. Defer
        # navigation-only label/file/owner buckets so enrichment does not allocate
        # three additional references for every node in a large graph.
        minimal_factory = None
        if len(self._overlays) == 1:
            minimal_factory = getattr(self._overlays[0], "minimal_index", None)
        index = (minimal_factory(graph) if minimal_factory is not None
                 else GraphIndex(graph, compact=True))
        for overlay in self._overlays:
            if not overlay.applies(current, index):
                continue
            started = time.perf_counter()
            delta = overlay.enrich(current, index)
            if accumulator is None:
                accumulator = GraphAccumulator(
                    graph["nodes"], graph["edges"],
                    shared_nodes=index.nodes,
                    shared_edges=graph["edges"],
                    seed_edge_lookup=lambda source: index.outgoing.get(source, ()),
                )
                # The accumulator has copied the seed sequences and now owns the
                # canonical records.  Do not keep the original graph container alive
                # through every later overlay and the final global sort; on large
                # graphs that otherwise retains a redundant graph-sized pair of lists.
                graph = None
            fresh_nodes, fresh_edges = accumulator.apply(delta)
            if delta_sink is not None:
                # Emit only records that survived accumulator deduplication.  A
                # sidecar writer can retain these deltas and release the full
                # enriched graph immediately after the fold.
                delta_sink(fresh_nodes, fresh_edges)
            index.absorb(fresh_nodes, fresh_edges, assume_fresh=True)
            # Overlay predicates and indexes are order-independent.  Defer the
            # global node/edge sort until the fold is complete; sorting the full
            # graph after every small overlay is a large, avoidable cost.
            current = accumulator.view(sorted_output=False)
            if observer is not None:
                observer(
                    overlay.overlay_id, time.perf_counter() - started,
                    len(delta.nodes), len(delta.edges),
                )
        if accumulator is None:
            return current
        # The compact index only supports delta production; release its node and
        # adjacency references before the accumulator performs the final full-graph
        # sort and returns the enriched view.
        del index
        return accumulator.result()
