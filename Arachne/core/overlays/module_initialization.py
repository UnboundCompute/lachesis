"""Module singleton state and circular dependency inference."""
from __future__ import annotations

from collections import defaultdict

from ..composition import GraphDelta
from ..identities import stable_id
from ..query import GraphIndex


def _fact(evidence_ids: list[str], confidence: str = "high") -> dict:
    return {
        "fact_origin": "core-inference",
        "confidence": confidence,
        "evidence_ids": list(dict.fromkeys(evidence_ids)),
    }


def _strongly_connected(graph: dict[str, set[str]]) -> list[list[str]]:
    counter = 0
    indices: dict[str, int] = {}
    lowlinks: dict[str, int] = {}
    stack: list[str] = []
    on_stack: set[str] = set()
    components: list[list[str]] = []

    def visit(node: str) -> None:
        nonlocal counter
        indices[node] = lowlinks[node] = counter
        counter += 1
        stack.append(node)
        on_stack.add(node)
        for target in sorted(graph.get(node, set())):
            if target not in indices:
                visit(target)
                lowlinks[node] = min(lowlinks[node], lowlinks[target])
            elif target in on_stack:
                lowlinks[node] = min(lowlinks[node], indices[target])
        if lowlinks[node] != indices[node]:
            return
        component = []
        while stack:
            member = stack.pop()
            on_stack.discard(member)
            component.append(member)
            if member == node:
                break
        if len(component) > 1 or node in graph.get(node, set()):
            components.append(sorted(component))

    for node in sorted(graph):
        if node not in indices:
            visit(node)
    return components


class ModuleInitialization:
    """Derive module-owned singleton/mutable state from canonical value flow."""

    overlay_id = "module-initialization"

    def applies(self, graph: dict) -> bool:
        return any(node.get("kind") == "file" for node in graph.get("nodes", []))

    def enrich(self, graph: dict) -> GraphDelta:
        index = GraphIndex(graph)
        nodes = []
        edges = []
        file_by_value: dict[str, str] = {}
        exports: set[str] = set()
        definitions: dict[str, list[dict]] = defaultdict(list)
        writes: dict[str, list[dict]] = defaultdict(list)

        for edge in graph.get("edges", []):
            kind = index.semantic_edge_kind(edge)
            if kind == "DECLARES_VALUE" and \
                    index.nodes.get(edge["source"], {}).get("kind") == "file" and \
                    not index.nodes[edge["source"]].get("properties", {}).get("declaration_file"):
                file_by_value[edge["target"]] = edge["source"]
            elif kind == "EXPORTS":
                exports.add(edge["target"])
            elif kind == "DEFINES":
                definition = index.nodes.get(edge["target"])
                if definition:
                    definitions[edge["source"]].append(definition)
            elif kind == "WRITES_TO":
                write = index.nodes.get(edge["source"])
                if write:
                    writes[edge["target"]].append(write)

        sources_by_variable: dict[str, list[dict]] = defaultdict(list)
        for source in index.nodes_of_kind("allocation", "call-value"):
            frontier = [source["id"]]
            seen = {source["id"]}
            for _depth in range(3):
                next_frontier = []
                for current in frontier:
                    for target in index.targets(current, "VALUE_FLOWS_TO"):
                        if target["id"] in seen:
                            continue
                        seen.add(target["id"])
                        if target.get("kind") == "variable" and target["id"] in file_by_value:
                            sources_by_variable[target["id"]].append(source)
                        else:
                            next_frontier.append(target["id"])
                frontier = next_frontier

        for variable in index.nodes_of_kind("variable"):
            variable_id = variable["id"]
            file_id = file_by_value.get(variable_id)
            if not file_id:
                continue
            properties = variable.get("properties", {})
            binding_kind = properties.get("symbol_kind")
            value_sources = list({
                item["id"]: item
                for item in sources_by_variable.get(variable_id, [])
            }.values())
            exported = variable_id in exports

            for source in value_sources:
                source_properties = source.get("properties", {})
                singleton_id = stable_id(
                    "core", self.overlay_id, "singleton", variable_id, source["id"],
                )
                evidence = [file_id, variable_id, source["id"]]
                fact = _fact(evidence)
                singleton_kind = "factory" if source["kind"] == "call-value" else \
                    source_properties.get("allocation_kind", "allocation")
                nodes.append({
                    "id": singleton_id,
                    "kind": "singleton",
                    "label": variable.get("label", variable_id),
                    "properties": {
                        **fact,
                        "file_id": file_id,
                        "symbol_id": variable_id,
                        "value_source_id": source["id"],
                        "singleton_kind": singleton_kind,
                        "allocated_type": source_properties.get("allocated_type")
                            or source_properties.get("type"),
                        "exported": exported,
                    },
                })
                edges.extend([
                    {
                        "kind": "HAS_SINGLETON", "source": file_id,
                        "target": singleton_id, "properties": fact,
                    },
                    {
                        "kind": "SINGLETON_OF", "source": singleton_id,
                        "target": variable_id, "properties": fact,
                    },
                ])

            later_definitions = [
                definition for definition in definitions.get(variable_id, [])
                if definition.get("properties", {}).get("version", 0) > 0
            ]
            non_initializer_writes = [
                write for write in writes.get(variable_id, [])
                if write.get("properties", {}).get("write_kind") != "initializer"
            ]
            mutable_source = next((
                source for source in value_sources
                if source.get("kind") == "allocation"
                and source.get("properties", {}).get("allocation_kind")
                    in {"object", "array", "class-instance"}
            ), None)
            state_kind = "reassignable" if binding_kind in {"let", "var"} else \
                "mutated" if later_definitions or non_initializer_writes else \
                "mutable-allocation" if mutable_source else None
            if not state_kind:
                continue
            state_evidence = [
                file_id, variable_id,
                *(item["id"] for item in later_definitions),
                *(item["id"] for item in non_initializer_writes),
                *([mutable_source["id"]] if mutable_source else []),
            ]
            state_id = stable_id("core", self.overlay_id, "module-state", variable_id)
            state_fact = _fact(state_evidence)
            nodes.append({
                "id": state_id,
                "kind": "module-state",
                "label": variable.get("label", variable_id),
                "properties": {
                    **state_fact,
                    "file_id": file_id,
                    "symbol_id": variable_id,
                    "state_kind": state_kind,
                    "binding_kind": binding_kind,
                    "exported": exported,
                },
            })
            edges.extend([
                {
                    "kind": "HAS_MODULE_STATE", "source": file_id,
                    "target": state_id, "properties": state_fact,
                },
                {
                    "kind": "STATE_OF", "source": state_id,
                    "target": variable_id, "properties": state_fact,
                },
            ])

        dependency_graph: dict[str, set[str]] = {
            node["id"]: set() for node in index.nodes_of_kind("file")
        }
        for edge in graph.get("edges", []):
            if index.semantic_edge_kind(edge) not in {
                "DEPENDS_ON", "RUNTIME_DEPENDS_ON", "RE_EXPORTS",
            }:
                continue
            if edge["source"] in dependency_graph and edge["target"] in dependency_graph:
                dependency_graph[edge["source"]].add(edge["target"])
        for component in _strongly_connected(dependency_graph):
            cycle_id = stable_id("core", self.overlay_id, "import-cycle", *component)
            fact = _fact(component, "exact")
            nodes.append({
                "id": cycle_id,
                "kind": "import-cycle",
                "label": f"import cycle ({len(component)} modules)",
                "properties": {
                    **fact,
                    "member_file_ids": component,
                    "size": len(component),
                },
            })
            for member in component:
                edges.append({
                    "kind": "PARTICIPATES_IN_IMPORT_CYCLE",
                    "source": member, "target": cycle_id,
                    "properties": fact,
                })

        return GraphDelta(self.overlay_id, nodes, edges)
