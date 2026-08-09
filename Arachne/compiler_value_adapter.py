"""Project compiler-owned value facts into Arachne's semantic overlay records."""
from __future__ import annotations

import hashlib
from collections import defaultdict
from typing import Iterable, Mapping


def stable_id(kind: str, *parts: object) -> str:
    raw = ":".join(str(part) for part in parts)
    return f"{kind}:{hashlib.sha256((kind + ':' + raw).encode()).hexdigest()[:16]}"


def compiler_value_facts(
    info: dict, nodes: Mapping[str, dict], edges: Iterable[dict],
) -> dict:
    """Return compatibility values without inspecting TypeScript source syntax."""
    absolute = info["path"]
    local_nodes = {
        node_id: node for node_id, node in nodes.items()
        if node.get("properties", {}).get("absolute_file") == absolute
    }
    symbols = {symbol["id"]: dict(symbol) for symbol in info["symbols"]}
    module_scope = next(
        (scope["id"] for scope in info["scopes"] if scope["kind"] == "module"),
        info["scopes"][0]["id"],
    )

    property_ids = {}
    properties = []

    def symbol_for_target(target_id: str):
        target = nodes.get(target_id, {})
        target_properties = target.get("properties", {})
        symbol_id = target_properties.get("symbol_id")
        if symbol_id in symbols:
            return symbol_id
        external_id = stable_id("compiler-runtime-symbol", info["path_hash"], target_id)
        if external_id not in symbols:
            symbols[external_id] = {
                "id": external_id,
                "name": target.get("label", target_id),
                "kind": "language-global" if target_properties.get("provenance") == "standard-library" else "implicit",
                "line": 1, "scope_id": module_scope, "declaration_id": target_id,
                "start_offset": 0, "duplicate_of": None, "shadows": None,
                "owner_function_id": None,
                "declared_type": target_properties.get("type"),
            }
        return external_id

    def compatibility_target(target_id: str):
        target = nodes.get(target_id, {})
        if target.get("kind") == "property-path":
            if target_id not in property_ids:
                target_properties = target.get("properties", {})
                base_symbol_id = symbol_for_target(target_properties["base_value_id"])
                compatibility_id = stable_id(
                    "property", base_symbol_id, target_properties.get("path", ""),
                )
                property_ids[target_id] = compatibility_id
                properties.append({
                    "id": compatibility_id,
                    "compiler_node_id": target_id,
                    "base_symbol_id": base_symbol_id,
                    "path": target_properties.get("path", ""),
                    "name": target.get("label", target_properties.get("path", "")),
                })
            return property_ids[target_id]
        return symbol_for_target(target_id)

    definition_nodes = sorted(
        (node for node in local_nodes.values() if node.get("kind") == "definition"),
        key=lambda node: (
            node["properties"].get("start_offset", 0),
            node["properties"].get("version", 0),
        ),
    )
    definitions = []
    for node in definition_nodes:
        source = node["properties"]
        target_id = source.get("target_id")
        if not target_id:
            continue
        definitions.append({
            "id": node["id"],
            "compiler_node_id": node["id"],
            "symbol_id": compatibility_target(target_id),
            "version": source.get("version", 0),
            "kind": source.get("definition_kind", "definition"),
            "origin": source.get("origin", "unknown"),
            "line": source["start_line"],
            "offset": source["start_offset"],
            "previous_definition_id": source.get("previous_definition_id"),
            "operator": source.get("operator"),
            "expression_start": source.get("value_start_offset"),
            "expression_end": source.get("value_end_offset"),
        })

    arguments = []
    for node in local_nodes.values():
        if node.get("kind") != "argument":
            continue
        source = node["properties"]
        call_id = source.get("callsite_id")
        if not call_id:
            continue
        arguments.append({
            "id": node["id"], "compiler_node_id": node["id"],
            "call_id": call_id, "position": source.get("position", 0),
            "line": source["start_line"],
            "start_offset": source["start_offset"], "end_offset": source["end_offset"],
            "expression": node.get("label", ""), "origin": "literal",
        })
    arguments.sort(key=lambda item: (item["start_offset"], item["position"]))

    returns = []
    for node in local_nodes.values():
        if node.get("kind") != "return-value":
            continue
        source = node["properties"]
        returns.append({
            "id": node["id"], "compiler_node_id": node["id"],
            "kind": source.get("return_kind", "return"),
            "line": source["start_line"],
            "function_id": source.get("owner_function_id"),
            "start_offset": source["start_offset"], "end_offset": source["end_offset"],
            "expression": node.get("label", ""),
            "origin": source.get("origin", "expression"),
        })
    returns.sort(key=lambda item: item["start_offset"])

    reads = []
    for node in local_nodes.values():
        if node.get("kind") != "read":
            continue
        source = node["properties"]
        target_id = source.get("target_id")
        if not target_id:
            continue
        reads.append({
            "id": node["id"], "compiler_node_id": node["id"],
            "symbol_id": compatibility_target(target_id),
            "definition_id": source.get("definition_id"),
            "name": node.get("label", ""), "line": source["start_line"],
            "offset": source["start_offset"], "end_offset": source["end_offset"],
            "context_id": None,
        })
    reads.sort(key=lambda item: item["offset"])

    call_returns = []
    for call in info["function_calls"]:
        return_id = stable_id("call-return", call["id"])
        call["return_value_id"] = return_id
        call_returns.append({
            "id": return_id, "call_id": call["id"], "line": call["line"],
            "caller_function_id": call.get("caller_function_id"),
        })

    flows = []
    flow_keys = set()

    def add_flow(kind: str, source: str, target: str, **properties_data):
        key = (kind, source, target, repr(sorted(properties_data.items())))
        if source and target and key not in flow_keys:
            flow_keys.add(key)
            flows.append({
                "kind": kind, "source": source, "target": target,
                "properties": properties_data,
            })

    for definition in definitions:
        if definition.get("previous_definition_id"):
            add_flow(
                "PREVIOUS_VERSION", definition["previous_definition_id"], definition["id"],
            )

    definition_ids = {item["id"] for item in definitions}
    for edge in edges:
        if edge.get("kind") == "PROPERTY_READ" and edge["source"] in definition_ids and edge["target"] in definition_ids:
            add_flow("PROPERTY_READ", edge["source"], edge["target"], **edge.get("properties", {}))

    contexts = [(item, "definition") for item in definitions if item.get("expression_start") is not None]
    contexts += [(item, "argument") for item in arguments]
    contexts += [(item, "return") for item in returns]
    for read in reads:
        containing = []
        for context, context_kind in contexts:
            start = context.get("expression_start", context.get("start_offset"))
            end = context.get("expression_end", context.get("end_offset"))
            if start is not None and end is not None and start <= read["offset"] and read["end_offset"] <= end:
                containing.append((end - start, context, context_kind))
                add_flow("READS_FROM", read["definition_id"], context["id"], read_id=read["id"])
                if context_kind == "definition":
                    add_flow("FLOWS_TO", read["definition_id"], context["id"])
        if containing:
            _size, context, _kind = min(containing, key=lambda item: item[0])
            read["context_id"] = context["id"]
            if context in arguments or context in returns:
                context["origin"] = "expression"
        else:
            read["context_id"] = stable_id("read-context", info["path_hash"], read["offset"])

    for call in info["function_calls"]:
        return_id = call["return_value_id"]
        for definition in definitions:
            start, end = definition.get("expression_start"), definition.get("expression_end")
            if start is not None and end is not None and start <= call["start_offset"] < end:
                add_flow("CALL_RETURN_TO", return_id, definition["id"])
        for argument in arguments:
            if argument["start_offset"] <= call["start_offset"] < argument["end_offset"]:
                add_flow("CALL_RETURN_TO_VALUE", return_id, argument["id"])
        for returned in returns:
            if returned["start_offset"] <= call["start_offset"] < returned["end_offset"]:
                add_flow("CALL_RETURN_TO_VALUE", return_id, returned["id"])

    aliases = []
    for edge in edges:
        if edge.get("kind") != "ALIASES_VALUE":
            continue
        source_node = nodes.get(edge["source"], {})
        target_node = nodes.get(edge["target"], {})
        if source_node.get("properties", {}).get("absolute_file") != absolute and target_node.get("properties", {}).get("absolute_file") != absolute:
            continue
        aliases.append({
            "source": compatibility_target(edge["source"]),
            "target": compatibility_target(edge["target"]),
            "line": edge.get("properties", {}).get("line", 0),
        })

    return {
        "symbols": sorted(symbols.values(), key=lambda item: (item.get("start_offset", 0), item["name"])),
        "properties": properties, "definitions": definitions, "reads": reads,
        "arguments": arguments, "returns": returns, "call_returns": call_returns,
        "data_flows": flows, "aliases": aliases,
    }


def adapt_compiler_values(info: dict, nodes: Mapping[str, dict], edges: Iterable[dict]) -> None:
    facts = compiler_value_facts(info, nodes, edges)
    for key in ("symbols", "properties", "definitions", "reads", "arguments", "returns", "data_flows", "aliases"):
        info[key] = facts[key]
