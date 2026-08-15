"""Which optional analysis capabilities the observable graph actually backs.

The coverage frontier must not claim a capability is missing when the graph
already carries the edges that implement it, nor claim one is present when
nothing computed it. So presence is derived from the graph itself -- the raw
edge kinds a frontend emitted -- plus whatever the enumerator reports it
computed. The manifest then stays honest as frontends grow: once the C frontend
emits VALUE_FLOWS_TO, value-flow leaves every family's missing list with no edit
here.
"""
from __future__ import annotations

from collections.abc import Iterable

# The graph edge kind that witnesses each raw-fact capability. A capability with
# no entry here is a *computed inference* (object-size, dominance), not a raw
# graph fact: it counts as present only when an enumerator says it computed it.
_CAPABILITY_EDGE = {
    "value-flow": "VALUE_FLOWS_TO",
    "points-to": "POINTS_TO",
}


def present_capabilities(graph: dict, computed: Iterable[str] = ()) -> set[str]:
    """The optional capabilities the graph observably backs: raw-fact ones proven
    by an edge kind being present, plus any the enumerator reports it computed."""
    edge_kinds = {edge.get("kind") for edge in graph.get("edges", ())}
    present = {cap for cap, kind in _CAPABILITY_EDGE.items() if kind in edge_kinds}
    present.update(computed)
    return present


def absent_optional_capabilities(graph: dict, optional_capabilities: Iterable[str],
                                 computed: Iterable[str] = ()) -> list[str]:
    """The subset of a family's optional capabilities the graph does NOT back,
    in the metadata's declared order. This is the frontier's honest missing list."""
    present = present_capabilities(graph, computed)
    return [cap for cap in optional_capabilities if cap not in present]
