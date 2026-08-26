"""Compiler-native, language-pluggable canonical code graph."""

from .pipeline import (
    combine_graphs,
    run_project,
    snapshot_graph,
    source_inventory,
)
from .kuzu_store import write_kuzu_graph
from .types import CodeGraph, GraphEdge, GraphNode

__all__ = [
    "Analysis",
    "CodeGraph",
    "Deadline",
    "GraphEdge",
    "GraphNode",
    "LeadSet",
    "combine_graphs",
    "run_project",
    "snapshot_graph",
    "source_inventory",
    "write_kuzu_graph",
]

# The warm session lives in `lachesis.session`, which pulls in the heavy `nav.graph_store`
# and `flow.pipeline` trees. Export the three names lazily (PEP 562) so `import lachesis`
# -- which the frontends and the graph builder pay for on every invocation -- stays cheap
# and only imports the session when a caller actually reaches for it.
_LAZY = {"Analysis": "session", "LeadSet": "session", "Deadline": "session"}


def __getattr__(name):
    module = _LAZY.get(name)
    if module is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    import importlib

    return getattr(importlib.import_module(f".{module}", __name__), name)


def __dir__():
    return sorted(__all__)
