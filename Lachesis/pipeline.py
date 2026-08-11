"""Build one canonical project graph through registered compiler frontends."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from .core.contract import ContractError as FrontendError, FrontendSnapshot
from .core.runner import run_frontend
from .core.snapshot import load_snapshot
from .frontends.registry import FrontendRegistry, default_registry
from .types import CodeGraph, GraphEdge, GraphNode


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


def source_inventory(source_dir: str, include_tests: bool = False) -> List[str]:
    """Discover source files. Test/spec files are excluded by default — they are not
    attack surface and production code does not import them, so dropping them at
    discovery (before compile) is safe for type resolution and shrinks the graph. The
    test predicate is the single source of truth in ``nav.symbol_index`` (imported
    lazily to avoid an import cycle), so build-time exclusion can never drift from any
    query-time notion of "is a test"."""
    ignored = {".git", "node_modules", "graph_out", "dist", "build"}
    is_test = None
    if not include_tests:
        from nav.symbol_index import is_test_path as is_test
    result = []
    for root, directories, files in os.walk(os.path.abspath(source_dir)):
        directories[:] = sorted(name for name in directories if name not in ignored)
        for name in sorted(files):
            path = os.path.join(root, name)
            if is_test is not None and is_test(path):
                continue
            result.append(path)
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


def enrich_graph(
    graph: CodeGraph, languages: Iterable[str], capabilities: Dict[str, str],
) -> CodeGraph:
    """Fold the four overlay registries over a core graph to produce the dataflow tier.

    Pure and deterministic: ``enriched = f(core_graph, languages, capabilities)``. The
    package inventory the ecosystem registry needs is derived from the graph, so those
    two values are the *only* inputs beyond the graph itself — which is exactly why
    this can run at load time from a core-only store, given a manifest.
    """
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
        graph, index.package_inventory(), set(languages), capabilities,
    )
    graph = default_model_overlay_registry().enrich(graph)
    return default_security_overlay_registry().enrich(graph)


def _enrich_graph(graph: CodeGraph, snapshots: Sequence[FrontendSnapshot]) -> CodeGraph:
    return enrich_graph(
        graph,
        {language for snapshot in snapshots for language in snapshot.languages},
        _combined_capabilities(snapshots),
    )


def run_project(
    source_dir: str,
    output_root: Optional[str] = None,
    registry: Optional[FrontendRegistry] = None,
    timeout_seconds: int = 300,
    include_tests: bool = False,
    *,
    enrich: bool = True,
) -> Tuple[CodeGraph, List[FrontendSnapshot]]:
    """Run selected frontends and enrich their canonical facts directly.

    Discovery (``source_inventory``) drops test files by default; the filtered
    per-frontend file list is handed to each frontend as its explicit root set, so a
    frontend that re-walks the tree cannot re-introduce the tests we excluded.

    ``enrich=False`` returns the compact core graph (T0-T3) without the overlay
    dataflow tier, which the nav layer can rebuild on demand from a store manifest.
    The default stays ``True`` so every library caller is unaffected."""
    source_dir = os.path.abspath(source_dir)
    registry = registry or default_registry()
    groups = registry.partition(source_inventory(source_dir, include_tests=include_tests))
    snapshots = []
    for frontend_id in sorted(groups):
        frontend = registry.get(frontend_id)
        frontend_output = (
            os.path.join(os.path.abspath(output_root), frontend_id)
            if output_root else None
        )
        snapshots.append(run_frontend(
            frontend, source_dir, frontend_output, timeout_seconds,
            roots=groups[frontend_id],
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
    return (_enrich_graph(graph, snapshots) if enrich else graph), snapshots


def _file_digest(path: str) -> str:
    """SHA-256 of a source file's bytes — the incremental change key. Self-contained
    (not tied to how any frontend stamps its own content_hash) so the manifest is
    internally consistent regardless of frontend behavior."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _group_digests(files: Iterable[str], source_dir: str) -> Dict[str, str]:
    """Digest each file in a frontend's group, keyed by path relative to
    ``source_dir`` so the manifest is portable across checkout locations."""
    return {os.path.relpath(path, source_dir): _file_digest(path)
            for path in sorted(files)}


def _load_manifest(manifest_path: Optional[str]) -> Dict[str, dict]:
    if not manifest_path or not os.path.isfile(manifest_path):
        return {}
    try:
        payload = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}  # a corrupt/partial manifest just forces a full recompile
    frontends = payload.get("frontends") if isinstance(payload, dict) else None
    return frontends if isinstance(frontends, dict) else {}


def _write_manifest(manifest_path: str, frontends: Dict[str, dict]) -> None:
    output = Path(manifest_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps({"version": 1, "frontends": frontends}, indent=2) + "\n",
        encoding="utf-8",
    )


def default_manifest_path(output_root: str) -> str:
    """The incremental manifest lives beside the per-frontend bundles."""
    return os.path.join(os.path.abspath(output_root), "incremental_manifest.json")


def run_project_incremental(
    source_dir: str,
    output_root: str,
    registry: Optional[FrontendRegistry] = None,
    timeout_seconds: int = 300,
    include_tests: bool = False,
    manifest_path: Optional[str] = None,
    *,
    enrich: bool = True,
) -> Tuple[CodeGraph, List[FrontendSnapshot]]:
    """Like ``run_project`` but reuse a frontend's prior on-disk bundle when none of
    its source files changed, recompiling only the frontends that did.

    The compose + enrich tail is shared verbatim with ``run_project``, so the result
    is identical to a full run: a reused snapshot is exactly the bytes a recompile of
    unchanged files would produce, and ``combine_graphs``/``_enrich_graph`` are
    deterministic over the same snapshot set. ``output_root`` is required — the reused
    bundles and the change manifest both live under it."""
    source_dir = os.path.abspath(source_dir)
    output_root = os.path.abspath(output_root)
    registry = registry or default_registry()
    manifest_path = manifest_path or default_manifest_path(output_root)
    groups = registry.partition(source_inventory(source_dir, include_tests=include_tests))
    prior = _load_manifest(manifest_path)

    snapshots: List[FrontendSnapshot] = []
    manifest: Dict[str, dict] = {}
    for frontend_id in sorted(groups):
        frontend_output = os.path.join(output_root, frontend_id)
        digests = _group_digests(groups[frontend_id], source_dir)
        prior_entry = prior.get(frontend_id) or {}
        can_reuse = (
            prior_entry.get("files") == digests
            and Path(frontend_output, "manifest.json").is_file()
        )
        if can_reuse:
            snapshots.append(load_snapshot(frontend_output))
        else:
            frontend = registry.get(frontend_id)
            snapshots.append(run_frontend(
                frontend, source_dir, frontend_output, timeout_seconds,
                roots=groups[frontend_id],
            ))
        manifest[frontend_id] = {"bundle_dir": frontend_output, "files": digests}

    if not snapshots:
        supported = sorted({
            extension for item in registry.frontends for extension in item.extensions
        })
        raise FrontendError(
            f"no registered frontend supports files below {source_dir}; "
            f"supported extensions: {', '.join(supported)}"
        )
    graph = combine_graphs(snapshot_graph(snapshot) for snapshot in snapshots)
    result = _enrich_graph(graph, snapshots) if enrich else graph
    _write_manifest(manifest_path, manifest)
    return result, snapshots


def semantic_snapshot_graph(snapshot: FrontendSnapshot) -> CodeGraph:
    """Enrich one already-loaded snapshot without a FileInfo round trip."""
    return _enrich_graph(snapshot_graph(snapshot), [snapshot])
