"""Sequential registry for language-neutral canonical graph overlays."""
from __future__ import annotations

from typing import Protocol, Tuple

from ..composition import GraphDelta, compose
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
        current = graph
        for overlay in self._overlays:
            if not overlay.applies(current):
                continue
            delta = overlay.enrich(current)
            current = compose((
                GraphDelta("canonical-input", current["nodes"], current["edges"]),
                delta,
            ))
        return current

