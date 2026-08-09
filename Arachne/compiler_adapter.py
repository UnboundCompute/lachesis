"""Compose language compiler snapshots into one canonical Arachne graph.

This is the integration seam between language-specific compiler processes and
language-neutral graph overlays/querying. It deliberately preserves frontend
node IDs and direct facts: semantic overlays may add nodes and relationships,
but do not need to understand TypeScript or Clang AST object models.
"""
from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from .frontend import (
    FrontendError, FrontendRegistry, FrontendSnapshot, default_registry,
    run_frontend,
)
from .types import CodeGraph, GraphEdge, GraphNode
from .types import FileInfo


def snapshot_graph(snapshot: FrontendSnapshot) -> CodeGraph:
    """Convert the interchange snapshot without discarding tier/provenance."""
    nodes: List[GraphNode] = []
    for source in snapshot.nodes:
        properties = dict(source.get("properties", {}))
        properties.update({
            "frontend_id": snapshot.frontend_id,
            "frontend_tier": source.get("tier"),
        })
        nodes.append({
            "id": source["id"],
            "kind": source.get("kind", "unknown"),
            "label": source.get("label", source["id"]),
            "properties": properties,
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
            "kind": source.get("kind", "RELATED_TO"),
            "source": source["source"],
            "target": source["target"],
            "properties": properties,
        })
    return {"nodes": nodes, "edges": edges}


def combine_graphs(graphs: Iterable[CodeGraph]) -> CodeGraph:
    """Union frontend graphs while rejecting conflicting stable identities."""
    nodes: Dict[str, GraphNode] = {}
    edges: List[GraphEdge] = []
    edge_keys = set()
    for graph in graphs:
        for node in graph["nodes"]:
            existing = nodes.get(node["id"])
            if existing and existing != node:
                raise FrontendError(
                    f"frontends emitted conflicting node id {node['id']}"
                )
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
        "edges": sorted(
            edges,
            key=lambda item: (item["kind"], item["source"], item["target"]),
        ),
    }


def merge_overlay_graph(base: CodeGraph, overlay: CodeGraph) -> CodeGraph:
    """Merge Arachne semantics into compiler identities without duplicating code."""
    nodes = {node["id"]: {
        **node, "properties": dict(node.get("properties", {})),
    } for node in base["nodes"]}
    for node in overlay["nodes"]:
        existing = nodes.get(node["id"])
        if not existing:
            nodes[node["id"]] = node
            continue
        compatible_kinds = (
            {existing["kind"], node["kind"]} <= {"call", "construct"}
            or {existing["kind"], node["kind"]} <= {
                "function", "method", "constructor",
            }
        )
        if existing["kind"] != node["kind"] and not compatible_kinds:
            raise FrontendError(
                f"overlay changes {node['id']} from {existing['kind']} to {node['kind']}"
            )
        if existing["kind"] != node["kind"]:
            existing["properties"]["overlay_kind"] = node["kind"]
        existing["properties"].update(node.get("properties", {}))
    return combine_graphs((
        {"nodes": list(nodes.values()), "edges": base["edges"]},
        {"nodes": list(nodes.values()), "edges": overlay["edges"]},
    ))


def _empty_file_info(path: str, text: str, file_id: str) -> FileInfo:
    absolute = os.path.abspath(path)
    path_hash = hashlib.sha256(absolute.encode("utf-8")).hexdigest()
    info = {key: [] for key in FileInfo.__annotations__}
    info.update({
        "file_id": file_id, "path": absolute, "path_hash": path_hash,
        "content_hash": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "lines": text.count("\n") + (1 if text and not text.endswith("\n") else 0),
        "bytes": len(text.encode("utf-8")), "text": text,
    })
    return info  # type: ignore[return-value]


def snapshot_file_infos(snapshot: FrontendSnapshot) -> List[FileInfo]:
    """Adapt compiler discovery facts to the existing semantic overlay input.

    This transitional adapter is intentionally TypeScript-capable first. C is
    already available in the canonical graph, while C-specific security
    overlays can be added without changing the frontend contract.
    """
    if "typescript" not in snapshot.languages and "javascript" not in snapshot.languages:
        raise FrontendError(
            f"FileInfo compatibility overlays are not implemented for {snapshot.languages}"
        )
    nodes = snapshot.nodes_by_id
    file_nodes = {
        node["id"]: node for node in snapshot.nodes
        if node["kind"] == "file"
        and node.get("properties", {}).get("provenance") == "application"
    }
    by_absolute = {
        os.path.abspath(node["properties"]["absolute_file"]): node
        for node in file_nodes.values()
    }
    infos = {}
    for absolute, file_node in by_absolute.items():
        text = Path(absolute).read_text(encoding="utf-8")
        infos[absolute] = _empty_file_info(absolute, text, file_node["id"])

    for node in snapshot.nodes:
        properties = node.get("properties", {})
        absolute = properties.get("absolute_file")
        if not absolute or os.path.abspath(absolute) not in infos:
            continue
        info = infos[os.path.abspath(absolute)]
        if node["kind"] in {"function", "method", "constructor"}:
            info["functions"].append({
                "id": node["id"], "name": node["label"],
                "form": properties.get("form", node["kind"]),
                "start_line": properties["start_line"],
                "end_line": properties["end_line"],
                "start_offset": properties["start_offset"],
                "end_offset": properties["end_offset"],
                "body_start_offset": properties.get("body_start_offset", properties["start_offset"]),
                "parameters_start_offset": properties.get("parameters_start_offset"),
                "parameters_end_offset": properties.get("parameters_end_offset"),
                "owner_function_id": properties.get("owner_id")
                    if str(properties.get("owner_id", "")).startswith(("function:", "method:")) else None,
                "owner_type_id": properties.get("owner_id")
                    if str(properties.get("owner_id", "")).startswith(("class:", "interface:")) else None,
                "exported": bool(properties.get("exported")),
                "async": bool(properties.get("async")),
                "signature": properties.get("signature"),
                "scope_id": properties.get("scope_id"),
                "captures": list(properties.get("capture_symbol_ids", [])),
            })
        elif node["kind"] in {"class", "interface", "type", "enum"}:
            info["types"].append({
                "id": node["id"], "kind": node["kind"], "name": node["label"],
                "start_line": properties["start_line"], "end_line": properties["end_line"],
                "start_offset": properties["start_offset"], "end_offset": properties["end_offset"],
                "exported": bool(properties.get("exported")),
                "extends": properties.get("extends", []),
                "implements": properties.get("implements", []),
            })
        elif node["kind"] == "scope":
            info["scopes"].append({
                "id": node["id"],
                "kind": properties.get("scope_kind", node["label"]),
                "start_line": properties["start_line"],
                "end_line": properties["end_line"],
                "parent_scope_id": properties.get("parent_scope_id"),
                "owner_function_id": properties.get("owner_function_id"),
                "start_offset": properties["start_offset"],
                "end_offset": properties["end_offset"],
            })
        elif node["kind"] == "symbol" and properties.get("symbol_kind") != "property":
            info["symbols"].append({
                "id": node["id"], "name": properties["symbol_name"],
                "kind": properties["symbol_kind"],
                "line": properties["start_line"],
                "scope_id": properties["scope_id"],
                "declaration_id": properties.get("declaration_id"),
                "start_offset": properties["start_offset"],
                "duplicate_of": properties.get("duplicate_of"),
                "shadows": properties.get("shadows"),
                "owner_function_id": properties.get("owner_function_id"),
                "declared_type": properties.get("declared_type"),
                **({"position": properties["parameter_position"]}
                   if properties.get("parameter_position") is not None else {}),
            })
        elif node["kind"] in {"call", "construct"}:
            start = properties["start_offset"]
            end = properties["end_offset"]
            text = info["text"]
            open_paren = text.find("(", start, end)
            close_paren = text.rfind(")", start, end)
            target = nodes.get(properties.get("primary_target_id"))
            target_properties = target.get("properties", {}) if target else {}
            target_file = target_properties.get("absolute_file")
            target_local = target_file and os.path.abspath(target_file) in infos
            resolution = properties.get("resolution", "unresolved")
            if target_local:
                resolution = "same-file" if os.path.abspath(target_file) == info["path"] else "imported"
            elif target:
                resolution = "external"
            call = {
                "id": node["id"], "callee": properties.get("callee", node["label"]),
                "form": properties.get("form", "constructor" if node["kind"] == "construct" else "call"),
                "line": properties["start_line"], "start_offset": start, "end_offset": end,
                "arguments_start_offset": open_paren if open_paren >= 0 else None,
                "arguments_end_offset": close_paren if close_paren >= 0 else None,
                "caller_function_id": properties.get("owner_function_id"),
                "scope_id": properties.get("scope_id"),
                "resolution": resolution,
                "declaration_symbol_id": target["id"] if target else None,
                "declaration_file": target_file,
                "declaration_file_hash": hashlib.sha256(os.path.abspath(target_file).encode("utf-8")).hexdigest()
                    if target_file else None,
                "declaration_line": target_properties.get("start_line"),
                "declaration_end_line": target_properties.get("end_line"),
                "method_name": properties.get("method_name"),
                "receiver_expression": properties.get("receiver_expression"),
                "computed_key_expression": properties.get("computed_key_expression"),
                "return_type": {"kind": "compiler", "type": properties.get("type")},
            }
            info["function_calls"].append(call)
        elif node["kind"] == "token":
            owners = [
                function for function in info["functions"]
                if function["start_offset"] <= properties["start_offset"] <= function["end_offset"]
            ]
            owner = min(owners, key=lambda item: item["end_offset"] - item["start_offset"], default=None)
            if owner:
                info["tokens"].append({
                    "id": node["id"], "kind": properties.get("token_kind", "token"),
                    "value": node["label"], "start_offset": properties["start_offset"],
                    "end_offset": properties["end_offset"], "start_line": properties["start_line"],
                    "end_line": properties["end_line"], "function_id": owner["id"],
                })

    for edge in snapshot.edges:
        if edge["source"] not in file_nodes:
            continue
        source_path = os.path.abspath(file_nodes[edge["source"]]["properties"]["absolute_file"])
        info = infos[source_path]
        properties = edge.get("properties", {})
        target = nodes.get(edge["target"], {})
        if edge["kind"] == "DEPENDS_ON":
            info["imports"].append({
                "source": properties.get("specifier", target.get("label", "")),
                "symbols": properties.get("symbols", ""),
                "form": properties.get("form", "unknown"),
                "source_kind": properties.get("source_kind", "package"),
                "import_kind": properties.get("import_kind", "type" if properties.get("type_only") else "value"),
                "resolved_path": properties.get("resolved_path"),
                "bindings": properties.get("bindings", []),
            })
        elif edge["kind"] == "EXPORTS":
            name = properties.get("name", target.get("label"))
            if name and name not in info["exports"]:
                info["exports"].append(name)
                info["export_details"].append({
                    "symbols": name, "names": [name], "form": "declaration",
                    "export_kind": "value", "source": None, "source_kind": None,
                    "resolved_path": None,
                })
        elif edge["kind"] == "RE_EXPORTS":
            names = properties.get("names", [])
            info["exports"].extend(name for name in names if name not in info["exports"])
            info["export_details"].append({
                "symbols": properties.get("symbols", "*"), "names": names,
                "form": properties.get("form", "star"),
                "export_kind": properties.get("export_kind", "value"),
                "source": properties.get("specifier"),
                "source_kind": properties.get("source_kind"),
                "resolved_path": properties.get("resolved_path"),
            })

    from .body_analysis import analyze_body_structure
    from .operation_analysis import analyze_operations
    from .variable_analysis import analyze_variable_flow
    for info in infos.values():
        info["functions"].sort(key=lambda item: (item["start_offset"], item["end_offset"]))
        info["function_calls"].sort(key=lambda item: (item["start_offset"], item["end_offset"]))
        info["scopes"].sort(key=lambda item: (item["start_offset"], -item["end_offset"]))
        info["symbols"].sort(key=lambda item: (item["start_offset"], item["name"]))
        analyze_variable_flow(info)
        # Statements/expressions are still produced by the compatibility body
        # adapter until operation/control overlays consume canonical AST kinds.
        analyze_body_structure(info)
        analyze_operations(info)
    return sorted(infos.values(), key=lambda item: item["path"])


def analyze_typescript_with_compiler(
    source_dir: str, output_root: Optional[str] = None,
) -> Tuple[List[FileInfo], CodeGraph, FrontendSnapshot]:
    """Run compiler discovery, existing semantic overlays, then merge graphs."""
    registry = default_registry()
    frontend = registry.get("typescript-compiler-api")
    output = os.path.join(output_root, frontend.frontend_id) if output_root else None
    snapshot = run_frontend(frontend, source_dir, output)
    infos = snapshot_file_infos(snapshot)
    from .file_reader import FILE_MAP, run_semantic_overlays
    from .graph import build_graph
    FILE_MAP.clear()
    for info in infos:
        FILE_MAP[info["path_hash"]] = info
    run_semantic_overlays(infos)
    overlay = build_graph(infos)
    merged = merge_overlay_graph(snapshot_graph(snapshot), overlay)
    return infos, merged, snapshot


def source_inventory(source_dir: str) -> List[str]:
    ignored = {".git", "node_modules", "graph_out", "dist", "build"}
    result = []
    for root, directories, files in os.walk(os.path.abspath(source_dir)):
        directories[:] = sorted(name for name in directories if name not in ignored)
        result.extend(os.path.join(root, name) for name in sorted(files))
    return result


def run_project_frontends(
    source_dir: str,
    output_root: Optional[str] = None,
    registry: Optional[FrontendRegistry] = None,
    timeout_seconds: int = 300,
) -> Tuple[CodeGraph, List[FrontendSnapshot]]:
    """Run every needed language plugin once and compose their direct facts."""
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
        supported = sorted({extension for item in registry.frontends for extension in item.extensions})
        raise FrontendError(
            f"no registered frontend supports files below {source_dir}; "
            f"supported extensions: {', '.join(supported)}"
        )
    return combine_graphs(snapshot_graph(item) for item in snapshots), snapshots


def write_project_graph(
    graph: CodeGraph, snapshots: Sequence[FrontendSnapshot], output_path: str,
) -> str:
    """Persist the composed graph with its frontend/capability inventory."""
    output = Path(output_path).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "manifest": {
            "version": 1,
            "frontends": [
                {
                    "frontend_id": item.frontend_id,
                    "languages": list(item.languages),
                    "capabilities": item.capabilities,
                    "node_count": len(item.nodes),
                    "edge_count": len(item.edges),
                    "diagnostic_count": item.manifest.get("diagnostic_count", 0),
                }
                for item in snapshots
            ],
            "node_count": len(graph["nodes"]),
            "edge_count": len(graph["edges"]),
        },
        "nodes": graph["nodes"],
        "edges": graph["edges"],
    }
    output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return str(output)
