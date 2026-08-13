"""Sequential registry for language-neutral canonical graph overlays."""
from __future__ import annotations

from typing import Protocol, Tuple

from ..composition import GraphAccumulator, GraphDelta
from ..contract import ContractError


class CanonicalOverlay(Protocol):
    overlay_id: str

    def applies(self, graph: dict) -> bool: ...

    def enrich(self, graph: dict) -> GraphDelta: ...


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

    def enrich(self, graph: dict) -> dict:
        """Fold every applicable overlay's facts into one graph.

        The accumulator is what makes this affordable. Recomposing the whole graph after
        each overlay charges every later overlay for every earlier overlay's output, and
        the overlays that contribute least pay the most, since the bill tracks the size
        of the accumulated graph rather than the size of the contribution.

        It is created lazily so that a registry where nothing applies hands back the
        caller's own graph rather than a re-sorted copy of it, and so that the first
        overlay to apply still sees the graph exactly as it arrived.
        """
        current = graph
        accumulator = None
        for overlay in self._overlays:
            if not overlay.applies(current):
                continue
            delta = overlay.enrich(current)
            if accumulator is None:
                accumulator = GraphAccumulator(graph["nodes"], graph["edges"])
            accumulator.apply(delta)
            current = accumulator.view()
        return current

