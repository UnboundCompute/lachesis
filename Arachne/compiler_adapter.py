"""Compose compiler snapshots and run language-neutral canonical overlays."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from .core.contract import ContractError as FrontendError, FrontendSnapshot
from .core.runner import run_frontend
from .frontends.registry import FrontendRegistry, default_registry
from .types import CodeGraph, FileInfo, GraphEdge, GraphNode


def snapshot_graph(snapshot: FrontendSnapshot) -> CodeGraph:
    """Convert one validated frontend snapshot without changing its facts."""
    nodes: List[GraphNode] = []
    for source in snapshot.nodes:
        properties = dict(source.get("properties", {}))
        properties.update({
            "frontend_id": snapshot.frontend_id,
            "frontend_tier": source.get("tier"),
        })
        nodes.append({
            "id": source["id"], "kind": source["kind"],
            "label": source.get("label", source["id"]), "properties": properties,
        })
    edges: List[GraphEdge] = []
    for source in snapshot.edges:
        properties = dict(source.get("properties", {}))
        properties.update({
            "frontend_id": snapshot.frontend_id,
            "source_tier": source.get("source_tier"),
            "relationship_class": source.get("relationship_class"),
        })
        edges.append({
            "kind": source["kind"], "source": source["source"],
            "target": source["target"], "properties": properties,
        })
    return {"nodes": nodes, "edges": edges}


def combine_graphs(graphs: Iterable[CodeGraph]) -> CodeGraph:
    """Union canonical graphs while rejecting conflicting stable identities."""
    nodes: Dict[str, GraphNode] = {}
    edges: List[GraphEdge] = []
    edge_keys = set()
    for graph in graphs:
        for node in graph["nodes"]:
            existing = nodes.get(node["id"])
            if existing and existing != node:
                raise FrontendError(f"frontends emitted conflicting node id {node['id']}")
            nodes[node["id"]] = node
        for edge in graph["edges"]:
            key = (
                edge["kind"], edge["source"], edge["target"],
                json.dumps(edge.get("properties", {}), sort_keys=True),
            )
            if key not in edge_keys:
                edge_keys.add(key)
                edges.append(edge)
    known = set(nodes)
    dangling = [
        edge for edge in edges
        if edge["source"] not in known or edge["target"] not in known
    ]
    if dangling:
        first = dangling[0]
        raise FrontendError(
            f"combined graph has {len(dangling)} dangling edges; first is "
            f"{first['source']} -> {first['target']}"
        )
    return {
        "nodes": sorted(nodes.values(), key=lambda item: item["id"]),
        "edges": sorted(edges, key=lambda item: (
            item["kind"], item["source"], item["target"],
        )),
    }


def source_inventory(source_dir: str) -> List[str]:
    ignored = {".git", "node_modules", "graph_out", "dist", "build"}
    result = []
    for root, directories, files in os.walk(os.path.abspath(source_dir)):
        directories[:] = sorted(name for name in directories if name not in ignored)
        result.extend(os.path.join(root, name) for name in sorted(files))
    return result


def _combined_capabilities(snapshots: Sequence[FrontendSnapshot]) -> dict[str, str]:
    rank = {"none": 0, "partial": 1, "complete": 2}
    names = {name for snapshot in snapshots for name in snapshot.capabilities}
    return {
        name: max(
            (snapshot.capability(name) for snapshot in snapshots),
            key=lambda level: rank[level],
        )
        for name in names
    }


def _enrich_graph(graph: CodeGraph, snapshots: Sequence[FrontendSnapshot]) -> CodeGraph:
    from .core.overlays import (
        default_model_overlay_registry,
        default_overlay_registry,
        default_security_overlay_registry,
    )
    from .core.query import GraphIndex
    from .ecosystems import default_ecosystem_registry

    graph = default_overlay_registry().enrich(graph)
    index = GraphIndex(graph)
    graph = default_ecosystem_registry().enrich(
        graph,
        index.package_inventory(),
        {language for snapshot in snapshots for language in snapshot.languages},
        _combined_capabilities(snapshots),
    )
    graph = default_model_overlay_registry().enrich(graph)
    return default_security_overlay_registry().enrich(graph)


def run_project_frontends(
    source_dir: str,
    output_root: Optional[str] = None,
    registry: Optional[FrontendRegistry] = None,
    timeout_seconds: int = 300,
) -> Tuple[CodeGraph, List[FrontendSnapshot]]:
    """Run every needed frontend and enrich their canonical facts directly."""
    source_dir = os.path.abspath(source_dir)
    registry = registry or default_registry()
    groups = registry.partition(source_inventory(source_dir))
    snapshots = []
    for frontend_id in sorted(groups):
        frontend = registry.get(frontend_id)
        frontend_output = (
            os.path.join(os.path.abspath(output_root), frontend_id)
            if output_root else None
        )
        snapshots.append(run_frontend(
            frontend, source_dir, frontend_output, timeout_seconds,
        ))
    if not snapshots:
        supported = sorted({
            extension for item in registry.frontends for extension in item.extensions
        })
        raise FrontendError(
            f"no registered frontend supports files below {source_dir}; "
            f"supported extensions: {', '.join(supported)}"
        )
    graph = combine_graphs(snapshot_graph(snapshot) for snapshot in snapshots)
    return _enrich_graph(graph, snapshots), snapshots


def analyze_typescript_with_compiler(
    source_dir: str, output_root: Optional[str] = None,
) -> Tuple[List[FileInfo], CodeGraph, FrontendSnapshot]:
    """Compatibility entrypoint backed by the finished canonical graph."""
    graph, snapshots = run_project_frontends(source_dir, output_root)
    snapshot = next((
        item for item in snapshots if item.frontend_id == "typescript-compiler-api"
    ), None)
    if snapshot is None:
        raise FrontendError(f"no TypeScript/JavaScript frontend selected for {source_dir}")
    from .compatibility.projector import graph_file_infos
    return graph_file_infos(graph), graph, snapshot


def snapshot_file_infos(snapshot: FrontendSnapshot) -> List[FileInfo]:
    """Deprecated direct-fact projection; primary compatibility uses final graphs."""
    from .compatibility.projector import graph_file_infos
    return graph_file_infos(snapshot_graph(snapshot))


def semantic_snapshot_graph(snapshot: FrontendSnapshot) -> CodeGraph:
    """Enrich one already-loaded snapshot without a FileInfo round trip."""
    return _enrich_graph(snapshot_graph(snapshot), [snapshot])


def write_project_graph(
    graph: CodeGraph, snapshots: Sequence[FrontendSnapshot], output_path: str,
) -> str:
    """Persist a composed graph with its frontend/capability inventory."""
    output = Path(output_path).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "manifest": {
            "version": 2,
            "frontends": [{
                "frontend_id": item.frontend_id,
                "languages": list(item.languages),
                "capabilities": item.capabilities,
                "node_count": len(item.nodes), "edge_count": len(item.edges),
                "diagnostic_count": item.manifest.get("diagnostic_count", 0),
            } for item in snapshots],
            "node_count": len(graph["nodes"]), "edge_count": len(graph["edges"]),
        },
        "nodes": graph["nodes"], "edges": graph["edges"],
    }
    output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return str(output)
