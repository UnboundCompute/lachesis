"""The small, first-class Python front door to native Lachesis analysis."""

__all__ = ["scan", "Analysis", "LeadSet", "Deadline", "AnalysisError", "__version__"]

# The warm session lives in `lachesis.session`, which pulls in the heavy `nav.graph_store`
# and `flow.pipeline` trees. Export the three names lazily (PEP 562) so `import lachesis`
# -- which the frontends and the graph builder pay for on every invocation -- stays cheap
# and only imports the session when a caller actually reaches for it.
_LAZY = {
    "scan": "session",
    "Analysis": "session",
    "LeadSet": "session",
    "Deadline": "session",
    "AnalysisError": "session",
}
_MOVED = {
    "CodeGraph", "GraphNode", "GraphEdge", "combine_graphs", "run_project",
    "snapshot_graph", "source_inventory", "write_kuzu_graph",
}


def __getattr__(name):
    if name == "__version__":
        # Match what the CLI's --version reports (see cache._version): read it from
        # installed package metadata rather than hard-coding it here, so the library
        # attribute can never drift from pyproject's version. Resolved lazily on first
        # access to keep `import lachesis` free of the importlib.metadata cost.
        try:
            from importlib.metadata import version
            return version("lachesis-cpg")
        except Exception:  # noqa: BLE001 - metadata is absent in a source checkout
            return "0+unknown"
    if name in _MOVED:
        raise AttributeError(
            f"{name} moved to lachesis.graph.{name}; import it from there")
    module = _LAZY.get(name)
    if module is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    import importlib

    return getattr(importlib.import_module(f".{module}", __name__), name)


def __dir__():
    return sorted(__all__)
