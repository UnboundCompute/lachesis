"""Sequential registry for language-neutral canonical graph overlays."""
from __future__ import annotations

import time
from typing import Callable, Optional, Protocol, Tuple

from ..composition import GraphAccumulator, GraphDelta
from ..contract import ContractError
from ..query import GraphIndex


#: Told the overlay id, its wall time, and the size of the delta it contributed.
OverlayObserver = Callable[[str, float, int, int], None]


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

    def enrich(self, graph: dict, observer: Optional[OverlayObserver] = None) -> dict:
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
        index = GraphIndex(graph, compact=True)
        for overlay in self._overlays:
            if not overlay.applies(current, index):
                continue
            started = time.perf_counter()
            delta = overlay.enrich(current, index)
            if accumulator is None:
                accumulator = GraphAccumulator(graph["nodes"], graph["edges"])
            index.absorb(*accumulator.apply(delta))
            # Overlay predicates and indexes are order-independent.  Defer the
            # global node/edge sort until the fold is complete; sorting the full
            # graph after every small overlay is a large, avoidable cost.
            current = accumulator.view(sorted_output=False)
            if observer is not None:
                observer(
                    overlay.overlay_id, time.perf_counter() - started,
                    len(delta.nodes), len(delta.edges),
                )
        return accumulator.result() if accumulator is not None else current
