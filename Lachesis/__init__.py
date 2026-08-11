"""Compiler-native, language-pluggable canonical code graph."""

from .pipeline import (
    combine_graphs,
    run_project,
    semantic_snapshot_graph,
    snapshot_graph,
    source_inventory,
    write_project_graph,
)
from .types import CodeGraph, GraphEdge, GraphNode

__all__ = [
    "CodeGraph",
    "GraphEdge",
    "GraphNode",
    "combine_graphs",
    "run_project",
    "semantic_snapshot_graph",
    "snapshot_graph",
    "source_inventory",
    "write_project_graph",
]
