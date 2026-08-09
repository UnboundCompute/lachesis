"""Project the finished canonical graph into the historical ``FileInfo`` view.

This module is intentionally one-way. Compatibility records never feed graph
construction and no source text is parsed to rediscover semantic facts.
"""
from __future__ import annotations

import hashlib
from collections import defaultdict, deque
from pathlib import Path
from typing import Iterable

from ..core.query import GraphIndex
from ..types import FileInfo


VALUE_FLOW_KINDS = frozenset({
    "VALUE_FLOWS_TO", "READS_FROM", "WRITES_TO", "PROPERTY_READ",
    "PHI_INPUT", "BRANCH_READS_FROM", "BRANCH_PREVIOUS",
    "WRITES_HEAP", "READS_HEAP", "DYNAMIC_INPUT",
})
CFG_KINDS = frozenset({
    "CFG_NEXT", "TRUE_BRANCH", "FALSE_BRANCH", "LOOP_BACK", "SWITCH_CASE",
    "EXCEPTION_BRANCH", "RUNS_FINALLY", "MERGES_AT",
})
ASYNC_KINDS = frozenset({
    "REGISTERS_CALLBACK", "HANDLED_BY", "ASYNC_CONTINUES_AT", "SCHEDULES",
    "EMITS_EVENT",
})


def _empty(path: str, file_id: str, content_hash: str | None) -> FileInfo:
    text = Path(path).read_text(encoding="utf-8")
    info = {key: [] for key in FileInfo.__annotations__}
    info.update({
        "file_id": file_id,
        "path": str(Path(path).resolve()),
        "path_hash": hashlib.sha256(str(Path(path).resolve()).encode()).hexdigest(),
        "content_hash": content_hash or hashlib.sha256(text.encode()).hexdigest(),
        "lines": len(text.splitlines()),
        "bytes": len(text.encode()),
        "text": text,
    })
    info["source_lines"] = [
        {"id": f"{file_id}:line:{line}", "line": line, "text": value}
        for line, value in enumerate(text.splitlines(), 1)
    ]
    return info  # type: ignore[return-value]


def graph_file_infos(
    graph: dict, requested_paths: Iterable[str] | None = None,
) -> list[FileInfo]:
    """Return compatibility records derived only from final graph facts."""
    index = GraphIndex(graph)
    files = {
        node["id"]: node for node in index.nodes_of_kind("file")
        if node.get("properties", {}).get("provenance") == "application"
        and node.get("properties", {}).get("absolute_file")
    }
    requested = {
        str(Path(path).resolve()) for path in (requested_paths or ())
    }
    infos: dict[str, FileInfo] = {}
    file_id_by_path = {}
    for file_id, node in files.items():
        path = str(Path(node["properties"]["absolute_file"]).resolve())
        if requested and path not in requested:
            continue
        infos[file_id] = _empty(path, file_id, node["properties"].get("content_hash"))
        file_id_by_path[path] = file_id

    owner_cache: dict[str, str | None] = {}
    resolving: set[str] = set()
    ownership_keys = (
        "owner_function_id", "function_id", "caller_function_id", "callsite_id",
        "site_id", "body_id", "value_id", "source_value_id", "sink_value_id",
        "symbol_id", "target_id", "cfg_node_id", "behavior_id", "file_id",
    )

    def owner_file(node_id: str | None) -> str | None:
        if not node_id:
            return None
        if node_id in owner_cache:
            return owner_cache[node_id]
        if node_id in resolving:
            return None
        resolving.add(node_id)
        node = index.nodes.get(node_id, {})
        properties = node.get("properties", {})
        absolute = properties.get("absolute_file")
        result = file_id_by_path.get(str(Path(absolute).resolve())) if absolute else None
        if not result:
            for key in ownership_keys:
                candidate = properties.get(key)
                if candidate == node_id:
                    continue
                result = owner_file(candidate)
                if result:
                    break
        if not result:
            for evidence_id in properties.get("evidence_ids", []):
                if evidence_id == node_id:
                    continue
                result = owner_file(evidence_id)
                if result:
                    break
        if not result:
            for edge in index.outgoing.get(node_id, []):
                if index.semantic_edge_kind(edge) in {"EVIDENCED_BY", "DYNAMIC_BEHAVIOR_AT"}:
                    result = owner_file(edge["target"])
                    if result:
                        break
        resolving.discard(node_id)
        owner_cache[node_id] = result
        return result

    function_cfg: dict[str, dict[str, str]] = defaultdict(dict)
    for node in index.nodes_of_kind("cfg-entry", "cfg-exit"):
        function_id = node.get("properties", {}).get("function_id")
        if function_id:
            function_cfg[function_id][node["kind"]] = node["id"]

    ast_parent: dict[str, str] = {}
    for edge in graph.get("edges", []):
        if index.semantic_edge_kind(edge) == "AST_CHILD":
            ast_parent[edge["target"]] = edge["source"]

    for node in graph.get("nodes", []):
        file_id = owner_file(node["id"])
        if file_id not in infos:
            continue
        info = infos[file_id]
        p = node.get("properties", {})
        kind = node.get("kind")
        line = p.get("start_line") or p.get("line")
        if kind in {"function", "method", "constructor"}:
            cfg = function_cfg.get(node["id"], {})
            info["functions"].append({
                "id": node["id"], "name": node["label"],
                "form": p.get("form", kind), "start_line": p.get("start_line"),
                "end_line": p.get("end_line"), "start_offset": p.get("start_offset"),
                "end_offset": p.get("end_offset"), "body_start_offset": p.get("body_start_offset"),
                "parameters_start_offset": p.get("parameters_start_offset"),
                "parameters_end_offset": p.get("parameters_end_offset"),
                "owner_function_id": p.get("owner_id") if index.nodes.get(
                    p.get("owner_id"), {},
                ).get("kind") in {"function", "method", "constructor"} else None,
                "owner_type_id": p.get("owner_id") if index.nodes.get(
                    p.get("owner_id"), {},
                ).get("kind") in {"class", "interface", "type"} else None,
                "scope_id": p.get("scope_id"), "async": bool(p.get("async")),
                "exported": any(
                    index.semantic_edge_kind(edge) == "EXPORTS"
                    for edge in index.incoming.get(node["id"], [])
                ),
                "captures": list(p.get("capture_symbol_ids", [])),
                "cfg_entry_id": cfg.get("cfg-entry"), "cfg_exit_id": cfg.get("cfg-exit"),
            })
        elif kind in {"class", "interface", "type", "enum", "record"}:
            extension = p.get("frontend_extensions", {}).get("typescript", {})
            heritage = extension.get("heritage", [])
            info["types"].append({
                "id": node["id"], "kind": kind, "name": node["label"],
                "start_line": p.get("start_line"), "end_line": p.get("end_line"),
                "start_offset": p.get("start_offset"), "end_offset": p.get("end_offset"),
                "extends": [item["type"] for item in heritage if item.get("relationship") == "extends"],
                "implements": [item["type"] for item in heritage if item.get("relationship") == "implements"],
                "members": list(p.get("members", [])),
            })
        elif kind == "scope":
            info["scopes"].append({
                "id": node["id"], "kind": p.get("scope_kind", node["label"]),
                "start_line": p.get("start_line"), "end_line": p.get("end_line"),
                "start_offset": p.get("start_offset"), "end_offset": p.get("end_offset"),
                "parent_scope_id": p.get("parent_scope_id"),
                "owner_function_id": p.get("owner_function_id"),
            })
        elif kind == "symbol":
            info["symbols"].append({
                "id": node["id"], "name": p.get("symbol_name", node["label"]),
                "kind": p.get("symbol_kind", "symbol"), "line": line,
                "scope_id": p.get("scope_id"), "declaration_id": p.get("declaration_id"),
                "start_offset": p.get("start_offset"), "duplicate_of": p.get("duplicate_of"),
                "shadows": p.get("shadows"), "owner_function_id": p.get("owner_function_id"),
                "declared_type": p.get("declared_type") or p.get("type"),
                "position": p.get("parameter_position"),
            })
        elif kind == "property-path":
            info["properties"].append({
                "id": node["id"], "name": node["label"], "path": p.get("path"),
                "base_symbol_id": p.get("base_value_id"), "dynamic": p.get("dynamic"),
                "line": line, "owner_function_id": p.get("owner_function_id"),
            })
        elif kind == "definition":
            info["definitions"].append({
                "id": node["id"], "symbol_id": p.get("target_symbol_id") or p.get("target_id"),
                "target_id": p.get("target_id"), "version": p.get("version", 0),
                "kind": p.get("definition_kind", "definition"), "origin": p.get("origin", "unknown"),
                "line": line, "offset": p.get("start_offset"), "end_offset": p.get("end_offset"),
                "expression_start": p.get("value_start_offset"),
                "expression_end": p.get("value_end_offset"),
                "previous_definition_id": p.get("previous_definition_id"),
                "function_id": p.get("owner_function_id"),
            })
        elif kind == "read":
            direct = next(iter(index.incoming.get(node["id"], [])), None)
            info["reads"].append({
                "id": node["id"], "name": node["label"],
                "symbol_id": p.get("target_symbol_id") or p.get("target_id"),
                "target_id": p.get("target_id"), "definition_id": p.get("definition_id")
                    or (direct and direct.get("source")),
                "line": line, "offset": p.get("start_offset"),
                "end_offset": p.get("end_offset"), "function_id": p.get("owner_function_id"),
            })
        elif kind == "argument":
            info["arguments"].append({
                "id": node["id"], "call_id": p.get("callsite_id"),
                "position": p.get("position"), "expression": node["label"], "line": line,
                "start_offset": p.get("start_offset"), "end_offset": p.get("end_offset"),
            })
        elif kind == "return-value":
            info["returns"].append({
                "id": node["id"], "function_id": p.get("owner_function_id"),
                "expression": node["label"], "kind": p.get("return_kind", "return"),
                "origin": p.get("origin"), "line": line,
                "start_offset": p.get("start_offset"), "end_offset": p.get("end_offset"),
            })
        elif kind == "statement":
            info["statements"].append({
                "id": node["id"], "text": node["label"],
                "kind": p.get("control_kind") or p.get("syntax_kind", "statement"),
                "function_id": p.get("owner_function_id") or file_id,
                "start_line": p.get("start_line"), "end_line": p.get("end_line"),
                "start_offset": p.get("start_offset"), "end_offset": p.get("end_offset"),
                "parent_statement_id": ast_parent.get(node["id"]),
            })
        elif kind in {"expression", "identifier", "call", "construct"}:
            info["expressions"].append({
                "id": node["id"], "compiler_node_id": node["id"], "text": node["label"],
                "kind": kind, "operator": p.get("operator"),
                "function_id": p.get("owner_function_id"),
                "start_line": p.get("start_line"), "end_line": p.get("end_line"),
                "start_offset": p.get("start_offset"), "end_offset": p.get("end_offset"),
            })
            if p.get("operator") or kind in {"call", "construct"}:
                info["operations"].append({
                    "id": node["id"], "expression_id": node["id"],
                    "kind": "call" if kind == "call" else "object-construction"
                        if kind == "construct" else "operation",
                    "operator": p.get("operator"), "text": node["label"],
                    "function_id": p.get("owner_function_id"), "line": line,
                    "start_offset": p.get("start_offset"), "end_offset": p.get("end_offset"),
                })
        elif kind in {"call", "construct"}:
            pass

        if kind in {"call", "construct"}:
            targets = [
                index.nodes[edge["target"]] for edge in index.outgoing.get(node["id"], [])
                if edge.get("kind") in {"INVOKES", "MAY_INVOKE"}
                and edge["target"] in index.nodes
            ]
            primary = index.nodes.get(p.get("primary_target_id")) or (targets[0] if targets else None)
            primary_properties = primary.get("properties", {}) if primary else {}
            primary_file = owner_file(primary["id"]) if primary else None
            target_ids = list(dict.fromkeys(target["id"] for target in targets))
            info["function_calls"].append({
                "id": node["id"], "callee": p.get("callee", node["label"]),
                "form": p.get("form", kind), "line": line,
                "start_offset": p.get("start_offset"), "end_offset": p.get("end_offset"),
                "caller_function_id": p.get("owner_function_id"), "scope_id": p.get("scope_id"),
                "resolution": "same-file" if primary_file == file_id else
                    "imported" if primary_file in infos else
                    "external" if primary else "unresolved",
                "declaration_symbol_id": primary and primary["id"],
                "declaration_file": primary_properties.get("absolute_file"),
                "declaration_line": primary_properties.get("start_line"),
                "declaration_end_line": primary_properties.get("end_line"),
                "method_name": p.get("method_name"),
                "receiver_expression": p.get("receiver_expression"),
                "receiver_call_id": p.get("receiver_call_id"),
                "computed_key_expression": p.get("computed_key_expression"),
                "compiler_value_id": p.get("value_id"),
                "return_value_id": p.get("value_id"),
                "dispatch_target_ids": target_ids,
                "dispatch_status": "exact" if len(target_ids) == 1 else
                    "polymorphic" if target_ids else "unresolved",
                "receiver": {
                    "expression": p.get("receiver_expression"),
                    "symbol_id": p.get("receiver_symbol_id"),
                    "definition_id": p.get("receiver_value_id"),
                    "type": p.get("receiver_type_facts", {}).get("text"),
                    "kind": "compiler", "evidence": "compiler", "confidence": "high",
                } if p.get("receiver_value_id") else None,
            })
        elif kind in {"cfg-entry", "cfg-condition", "cfg-merge", "cfg-exit", "cfg-block"}:
            info["cfg_nodes"].append({
                "id": node["id"], "kind": kind, "label": node["label"],
                "function_id": p.get("function_id"), "line": line,
            })
        elif kind == "unreachable-region":
            info["unreachable"].append({
                "id": node["id"], "statement_id": p.get("body_id"),
                "function_id": p.get("function_id"), "line": line,
            })
        elif kind == "phi":
            info["phi_nodes"].append({
                "id": node["id"], "symbol_id": p.get("target_id"),
                "cfg_node_id": p.get("cfg_node_id"), "function_id": p.get("function_id"),
                "line": line, "incoming_definition_ids": p.get("incoming_definition_ids", []),
            })
        elif kind == "heap-object":
            info["heap_objects"].append({"id": node["id"], "kind": p.get("allocation_kind"), **p})
        elif kind == "heap-location":
            info["heap_locations"].append({"id": node["id"], **p})
        elif kind == "call-context":
            bindings = [
                binding for binding in index.nodes_of_kind("context-parameter")
                if binding.get("properties", {}).get("context_id") == node["id"]
            ]
            info["call_contexts"].append({
                "id": node["id"], "call_id": p.get("callsite_id"),
                "callee_function_id": p.get("callee_function_id"),
                "caller_function_id": p.get("caller_function_id"),
                "parameter_bindings": [{
                    "id": binding["id"],
                    **binding.get("properties", {}),
                    "points_to": [
                        edge["target"] for edge in index.outgoing.get(binding["id"], [])
                        if edge.get("kind") == "POINTS_TO"
                    ],
                } for binding in bindings],
            })
        elif kind == "source":
            value = index.nodes.get(p.get("value_id"), {})
            info["taint_sources"].append({
                "id": node["id"], "kind": p.get("source_kind"), "label": node["label"],
                "value_id": p.get("value_id"), "line": value.get("properties", {}).get("start_line"),
            })
        elif kind == "taint-reach":
            sink = index.nodes.get(p.get("sink_id"), {})
            info["taint_reaches"].append({
                "id": node["id"], "source_id": p.get("source_id"),
                "sink_id": p.get("sink_id"), "value_id": p.get("sink_value_id"),
                "witness_ids": p.get("witness_ids", []),
                "callsite_id": sink.get("properties", {}).get("callsite_id"),
            })
        elif kind == "function-effect":
            if p.get("effect_kind") == "runtime-call":
                info["runtime_models"].append({"id": node["id"], **p})
            else:
                info["effect_summaries"].append({
                    "id": node["id"], "function_id": p.get("function_id"),
                    "returns": "unknown", "effects": [{"kind": p.get("effect_kind"), **p}],
                })
        elif kind == "async-event":
            info["async_nodes"].append({"id": node["id"], "kind": p.get("event_kind"), "label": node["label"], **p})
        elif kind == "dynamic-behavior":
            info["dynamic_behaviors"].append({
                "id": node["id"], "compiler_node_id": node["id"],
                "kind": p.get("behavior_kind"), "line": line,
                "offset": p.get("start_offset"), "expression": p.get("expression", node["label"]),
                "entity_id": p.get("site_id"), "function_id": p.get("owner_function_id"),
                "properties": p,
            })
        elif kind == "type-parameter":
            info["type_parameters"].append({"id": node["id"], "name": node["label"], **p})
        elif kind == "type-refinement":
            info["type_refinements"].append({"id": node["id"], "kind": p.get("refinement_kind"), **p})
        elif kind == "generic-substitution":
            info["generic_substitutions"].append({"id": node["id"], **p})
        elif kind == "module-initializer":
            info["module_initializers"].append({"id": node["id"], **p})
        elif kind == "singleton":
            info["singletons"].append({"id": node["id"], **p})
        elif kind == "module-state":
            info["module_state"].append({"id": node["id"], **p})
        elif kind == "static-initializer":
            info["static_initializers"].append({"id": node["id"], **p})
        elif kind == "import-cycle":
            info["import_cycles"].append({"id": node["id"], **p})
        elif kind in {"route", "boundary"}:
            info["wiring_boundaries"].append({
                "id": node["id"], "kind": kind,
                "key": p.get("path") or p.get("boundary_kind"),
                "target_function_id": p.get("handler_id"),
                "line": line, **p,
            })
        elif kind == "token":
            info["tokens"].append({
                "id": node["id"], "kind": p.get("token_kind"), "value": node["label"],
                "start_offset": p.get("start_offset"), "end_offset": p.get("end_offset"),
                "start_line": p.get("start_line"), "end_line": p.get("end_line"),
                "function_id": p.get("owner_function_id"),
            })

    for edge in graph.get("edges", []):
        kind = index.semantic_edge_kind(edge)
        file_id = owner_file(edge["source"]) or owner_file(edge["target"])
        if file_id not in infos:
            continue
        info = infos[file_id]
        record = {
            "kind": kind, "source": edge["source"], "target": edge["target"],
            "properties": edge.get("properties", {}),
        }
        if edge["source"] in infos and kind == "DEPENDS_ON":
            target = index.nodes.get(edge["target"], {})
            properties = edge.get("properties", {})
            info["imports"].append({
                "source": properties.get("specifier", target.get("label", "")),
                "symbols": properties.get("symbols", ""),
                "form": properties.get("form", "unknown"),
                "source_kind": properties.get("source_kind", "package"),
                "import_kind": properties.get("import_kind", "type" if properties.get("type_only") else "value"),
                "resolved_path": properties.get("resolved_path")
                    or target.get("properties", {}).get("absolute_file"),
                "bindings": properties.get("bindings", []),
            })
        if edge["source"] in infos and kind == "EXPORTS":
            target = index.nodes.get(edge["target"], {})
            properties = edge.get("properties", {})
            name = properties.get("name") or target.get("label")
            if name and name not in info["exports"]:
                info["exports"].append(name)
                info["export_details"].append({
                    "symbols": name, "names": [name], "form": "declaration",
                    "export_kind": properties.get("export_kind", "value"),
                    "source": None, "source_kind": None, "resolved_path": None,
                })
        if edge["source"] in infos and kind == "RE_EXPORTS":
            properties = edge.get("properties", {})
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
        if kind in VALUE_FLOW_KINDS:
            info["data_flows"].append(record)
        if kind in {"ALIASES", "ALIASES_VALUE"}:
            info["aliases"].append(record)
        if kind == "AST_CHILD":
            info["expression_links"].append({
                "parent": edge["source"], "child": edge["target"],
                **edge.get("properties", {}),
            })
        if kind in CFG_KINDS:
            info["cfg_edges"].append(record)
        if kind in {"PHI_INPUT", "BRANCH_READS_FROM", "BRANCH_PREVIOUS"}:
            info["branch_flows"].append(record)
        if kind == "POINTS_TO":
            info["points_to"].append({"source": edge["source"], "target": edge["target"]})
        if kind in {"WRITES_HEAP", "READS_HEAP"}:
            info["heap_accesses"].append(record)
        if kind == "APPLIES_EFFECT":
            info["applied_effects"].append(record)
        if kind == "TAINT_FLOWS_TO":
            info["taint_flows"].append(record)
        if kind in ASYNC_KINDS:
            info["async_edges"].append(record)
        if kind in {"OVERRIDES", "IMPLEMENTS_MEMBER", "IMPLEMENTED_BY"}:
            info["dispatch_relations"].append(record)
        if kind == "MAY_INVOKE":
            target = index.nodes.get(edge["target"], {})
            info["dispatch_candidates"].append({
                "id": f"candidate:{edge['source']}:{edge['target']}",
                "call_id": edge["source"], "target_id": edge["target"],
                "target_name": target.get("label", edge["target"]),
                "target_file": target.get("properties", {}).get("absolute_file"),
                "target_line": target.get("properties", {}).get("start_line"),
                "kind": edge.get("properties", {}).get("reason", "candidate"),
            })
        if kind == "STRUCTURALLY_COMPATIBLE_WITH":
            info["type_compatibilities"].append({
                "id": f"compatibility:{edge['source']}:{edge['target']}",
                "source_type_id": edge["source"], "target_type_id": edge["target"],
                "matched_members": edge.get("properties", {}).get("matched_members", []),
                "kind": "structural",
            })
        if kind == "OVERLOAD_OF":
            source = index.nodes.get(edge["source"], {})
            info["overloads"].append({
                "id": f"overload:{edge['source']}", "compiler_node_id": edge["source"],
                "name": source.get("label"),
                "line": source.get("properties", {}).get("start_line"),
                "signature": source.get("properties", {}).get("signature"),
                "implementation_id": edge["target"],
            })

    for info in infos.values():
        for owner_id in {statement["function_id"] for statement in info["statements"]}:
            owned = sorted(
                (statement for statement in info["statements"] if statement["function_id"] == owner_id),
                key=lambda item: (item.get("start_offset") or 0, item["id"]),
            )
            for position, statement in enumerate(owned):
                statement["position"] = position
        info["functions"].sort(key=lambda item: (item.get("start_offset") or 0, item["id"]))
        info["function_calls"].sort(key=lambda item: (item.get("start_offset") or 0, item["id"]))
        info["statements"].sort(key=lambda item: (item.get("start_offset") or 0, item["id"]))
        info["expressions"].sort(key=lambda item: (item.get("start_offset") or 0, item["id"]))
        sources = {source["id"]: source for source in info["taint_sources"]}
        sink_nodes = {node["id"]: node for node in index.nodes_of_kind("sink")}
        for reach in info["taint_reaches"]:
            sink = sink_nodes.get(reach.get("sink_id"), {})
            callsite = sink.get("properties", {}).get("callsite_id")
            call = index.nodes.get(callsite, {})
            if callsite:
                info["tainted_calls"].append({
                    "source_id": reach.get("source_id"), "call_id": callsite,
                    "callee": call.get("properties", {}).get("callee", call.get("label")),
                    "line": call.get("properties", {}).get("start_line"),
                    "hop_count": max(0, len(reach.get("witness_ids", [])) - 1),
                })

    return sorted(infos.values(), key=lambda info: info["path"])


def compatibility_taint_path(
    files: Iterable[FileInfo], source_id: str, target_id: str,
) -> list[str]:
    file_list = list(files)
    for info in file_list:
        matching_calls = {
            call["call_id"] for call in info["tainted_calls"]
            if call.get("source_id") == source_id
        }
        if target_id not in matching_calls:
            continue
        reach = next((
            item for candidate in file_list for item in candidate["taint_reaches"]
            if item.get("source_id") == source_id
            and item.get("callsite_id") == target_id
        ), None)
        if reach:
            return list(dict.fromkeys([
                source_id, *reach.get("witness_ids", []), target_id,
            ]))
    adjacency: dict[str, list[str]] = defaultdict(list)
    source_values = {}
    for info in file_list:
        source_values.update({
            source["id"]: source.get("value_id") for source in info["taint_sources"]
        })
        for edge in info["taint_flows"]:
            adjacency[edge["source"]].append(edge["target"])
    start = source_values.get(source_id) or source_id
    queue = deque([start])
    previous = {start: None}
    while queue:
        current = queue.popleft()
        if current == target_id:
            path = []
            while current is not None:
                path.append(current)
                current = previous[current]
            result = list(reversed(path))
            return [source_id, *result] if start != source_id else result
        for target in adjacency.get(current, []):
            if target not in previous:
                previous[target] = current
                queue.append(target)
    return []
