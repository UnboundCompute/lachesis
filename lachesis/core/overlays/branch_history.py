"""Branch-sensitive reaching definitions over the canonical control-flow graph."""
from __future__ import annotations

from collections import defaultdict, deque

from ..composition import GraphDelta
from ..identities import stable_id
from ..query import GraphIndex


# The control-flow node kinds of core/schema.py, spelled out so the bucket lookup can
# do the narrowing a `kind.startswith("cfg-")` scan over every node used to do.
CFG_NODE_KINDS = ("cfg-entry", "cfg-block", "cfg-condition", "cfg-merge", "cfg-exit")

CFG_EDGE_KINDS = frozenset({
    "CFG_NEXT", "TRUE_BRANCH", "FALSE_BRANCH", "LOOP_BACK", "SWITCH_CASE",
    "EXCEPTION_BRANCH", "RUNS_FINALLY", "MERGES_AT",
})


def _fact(evidence_ids: list[str], confidence: str = "high") -> dict:
    return {
        "fact_origin": "core-inference",
        "confidence": confidence,
        "evidence_ids": list(dict.fromkeys(evidence_ids)),
    }


def _copy(environment: dict[str, set[str]]) -> dict[str, set[str]]:
    """Copy the mapping, not the version sets, which nobody mutates in place.

    Both callers only ever rebind a whole target to a fresh single-element set
    (``transfer`` at the phi and definition lines, and the event walk when a
    definition is reached), and ``_merge`` reads its inputs into a new dict. So no
    version set is ever added to after it is stored, and rebuilding every one of
    them per copy allocates a set per live target per visit of every node in every
    round of the fixpoint, only to have it compared and dropped.
    """
    return dict(environment)


def _merge(environments) -> dict[str, set[str]]:
    result: dict[str, set[str]] = defaultdict(set)
    for environment in environments:
        for target, versions in environment.items():
            result[target].update(versions)
    return dict(result)


class BranchHistory:
    """Create SSA-style phi nodes and branch-correct read histories."""

    overlay_id = "branch-history"

    def applies(self, graph: dict, index: GraphIndex | None = None) -> bool:
        index = GraphIndex(graph) if index is None else index
        return index.has_kind("cfg-entry") and index.has_kind("definition")

    def enrich(self, graph: dict, index: GraphIndex | None = None) -> GraphDelta:
        index = GraphIndex(graph) if index is None else index
        nodes: list[dict] = []
        edges: list[dict] = []
        emitted: set[tuple[str, str, str]] = set()
        ast_parent: dict[str, str] = {}
        evidence_body: dict[str, str] = {}

        for edge in graph.get("edges", []):
            kind = index.semantic_edge_kind(edge)
            if kind == "AST_CHILD":
                ast_parent[edge["target"]] = edge["source"]
            elif kind in {"READ_EVIDENCED_BY", "EVIDENCED_BY"}:
                evidence_body.setdefault(edge["source"], edge["target"])

        def add_edge(kind: str, source: str, target: str, evidence: list[str], **properties) -> None:
            if not source or not target or source == target:
                return
            key = (kind, source, target)
            if key in emitted:
                return
            emitted.add(key)
            edges.append({
                "kind": kind,
                "source": source,
                "target": target,
                "properties": {**_fact(evidence), **properties},
            })

        statements_by_function: dict[str, list[dict]] = defaultdict(list)
        for statement in index.nodes_of_kind("statement"):
            owner = statement.get("properties", {}).get("owner_function_id")
            if owner:
                statements_by_function[owner].append(statement)

        def containing_statement(event: dict, function_id: str) -> str | None:
            body_id = evidence_body.get(event["id"])
            current = body_id
            while current:
                body = index.nodes.get(current)
                if body and body.get("kind") == "statement" and body.get(
                    "properties", {}
                ).get("owner_function_id") == function_id:
                    return current
                current = ast_parent.get(current)
            properties = event.get("properties", {})
            start = properties.get("start_offset")
            end = properties.get("end_offset", start)
            if not isinstance(start, int):
                return None
            candidates = []
            for statement in statements_by_function.get(function_id, []):
                statement_properties = statement.get("properties", {})
                left = statement_properties.get("start_offset")
                right = statement_properties.get("end_offset")
                if isinstance(left, int) and isinstance(right, int) \
                        and left <= start and (end is None or end <= right):
                    candidates.append((right - left, left, statement["id"]))
            return min(candidates)[2] if candidates else None

        definitions_by_function: dict[str, list[dict]] = defaultdict(list)
        reads_by_function: dict[str, list[dict]] = defaultdict(list)
        for definition in index.nodes_of_kind("definition"):
            owner = definition.get("properties", {}).get("owner_function_id")
            if owner:
                definitions_by_function[owner].append(definition)
        for read in index.nodes_of_kind("read"):
            owner = read.get("properties", {}).get("owner_function_id")
            if owner:
                reads_by_function[owner].append(read)

        # Bucket cfg nodes/entries and cfg edges by owning function ONCE, so the
        # per-function loop below never re-scans the whole graph (was O(functions x
        # (nodes + edges)) = O(files^2); now the buckets are O(nodes + edges) total).
        cfg_nodes_by_function: dict[str, set[str]] = defaultdict(set)
        cfg_entries_by_function: dict[str, list[dict]] = defaultdict(list)
        node_to_function: dict[str, str] = {}
        for node in index.nodes_of_kind(*CFG_NODE_KINDS):
            owner = node.get("properties", {}).get("function_id")
            if not owner:
                continue
            cfg_nodes_by_function[owner].add(node["id"])
            node_to_function[node["id"]] = owner
            if node.get("kind") == "cfg-entry":
                cfg_entries_by_function[owner].append(node)
        for owner, statements in statements_by_function.items():
            for statement in statements:
                node_to_function[statement["id"]] = owner
        cfg_edges_by_function: dict[str, list[tuple[str, str]]] = defaultdict(list)
        for edge in graph.get("edges", []):
            if index.semantic_edge_kind(edge) not in CFG_EDGE_KINDS:
                continue
            source, target = edge["source"], edge["target"]
            owner = node_to_function.get(source)
            if owner is not None and owner == node_to_function.get(target):
                cfg_edges_by_function[owner].append((source, target))

        for function in index.nodes_of_kind("function", "method", "constructor"):
            function_id = function["id"]
            entries = cfg_entries_by_function.get(function_id)
            if not entries:
                continue
            entry_id = entries[0]["id"]
            owned = set(cfg_nodes_by_function.get(function_id, ()))
            owned.update(statement["id"] for statement in statements_by_function[function_id])
            predecessors: dict[str, set[str]] = defaultdict(set)
            successors: dict[str, set[str]] = defaultdict(set)
            for source, target in cfg_edges_by_function.get(function_id, ()):
                predecessors[target].add(source)
                successors[source].add(target)

            definitions_by_statement: dict[str, list[dict]] = defaultdict(list)
            seed: dict[str, set[str]] = defaultdict(set)
            for definition in definitions_by_function.get(function_id, []):
                properties = definition.get("properties", {})
                target_id = properties.get("target_id")
                if not target_id:
                    target = next(index.incoming.get(definition["id"], []), None)
                    target_id = target.get("source") if target else None
                if not target_id:
                    continue
                statement_id = containing_statement(definition, function_id)
                if statement_id:
                    definitions_by_statement[statement_id].append(definition)
                elif properties.get("origin") == "parameter":
                    seed[target_id].add(definition["id"])

            for definitions in definitions_by_statement.values():
                definitions.sort(key=lambda node: (
                    node.get("properties", {}).get("start_offset", 1 << 60),
                    node["id"],
                ))

            def transfer(
                node_id: str, incoming: dict[str, set[str]],
                phis: dict[str, list[dict]] | None = None,
            ) -> dict[str, set[str]]:
                result = _copy(incoming)
                for phi in (phis or {}).get(node_id, []):
                    result[phi["properties"]["target_id"]] = {phi["id"]}
                for definition in definitions_by_statement.get(node_id, []):
                    target_id = definition.get("properties", {}).get("target_id")
                    if target_id:
                        result[target_id] = {definition["id"]}
                return result

            def solve(phis=None):
                incoming = {node_id: {} for node_id in owned}
                outgoing = {node_id: {} for node_id in owned}
                queue = deque([entry_id])
                queued = {entry_id}
                while queue:
                    node_id = queue.popleft()
                    queued.discard(node_id)
                    merged = _merge(outgoing[pred] for pred in predecessors[node_id])
                    if node_id == entry_id:
                        merged = _merge((merged, seed))
                    new_out = transfer(node_id, merged, phis)
                    if incoming[node_id] == merged and outgoing[node_id] == new_out:
                        continue
                    incoming[node_id] = merged
                    outgoing[node_id] = new_out
                    for successor in successors[node_id]:
                        if successor not in queued:
                            queue.append(successor)
                            queued.add(successor)
                return incoming, outgoing

            raw_incoming, raw_outgoing = solve()
            phis_by_node: dict[str, list[dict]] = defaultdict(list)
            for node_id in sorted(owned):
                incoming_edges = sorted(predecessors[node_id])
                if len(incoming_edges) < 2:
                    continue
                targets = set().union(*(
                    raw_outgoing[predecessor].keys() for predecessor in incoming_edges
                ))
                for target_id in sorted(targets):
                    predecessor_versions = [
                        frozenset(raw_outgoing[predecessor].get(target_id, set()))
                        for predecessor in incoming_edges
                    ]
                    versions = sorted(set().union(*predecessor_versions))
                    if len(versions) < 2 or len(set(predecessor_versions)) < 2:
                        continue
                    phi_id = stable_id(
                        "core", self.overlay_id, "phi",
                        function_id, node_id, target_id,
                    )
                    evidence = [node_id, target_id, *versions]
                    target = index.nodes.get(target_id, {})
                    phi = {
                        "id": phi_id,
                        "kind": "phi",
                        "label": f"phi:{target.get('label', target_id)}",
                        "properties": {
                            **_fact(evidence),
                            "function_id": function_id,
                            "cfg_node_id": node_id,
                            "target_id": target_id,
                            "incoming_definition_ids": versions,
                        },
                    }
                    nodes.append(phi)
                    phis_by_node[node_id].append(phi)
                    add_edge("PHI_FOR_SYMBOL", target_id, phi_id, evidence)
                    add_edge("PHI_AT", phi_id, node_id, evidence)
                    for definition_id in versions:
                        add_edge("PHI_INPUT", definition_id, phi_id, evidence)
                        add_edge("VALUE_FLOWS_TO", definition_id, phi_id, evidence, reason="phi-input")

            incoming, _outgoing = solve(phis_by_node)
            reads_by_statement: dict[str, list[dict]] = defaultdict(list)
            for read in reads_by_function.get(function_id, []):
                statement_id = containing_statement(read, function_id)
                if statement_id:
                    reads_by_statement[statement_id].append(read)

            for statement_id, reads in reads_by_statement.items():
                environment = _copy(incoming.get(statement_id, {}))
                for phi in phis_by_node.get(statement_id, []):
                    environment[phi["properties"]["target_id"]] = {phi["id"]}
                events = []
                for read in reads:
                    events.append((
                        read.get("properties", {}).get("start_offset", 1 << 60),
                        0, read["id"], "read", read,
                    ))
                for definition in definitions_by_statement.get(statement_id, []):
                    properties = definition.get("properties", {})
                    events.append((
                        properties.get("value_end_offset")
                        if properties.get("value_end_offset") is not None
                        else properties.get("end_offset", 1 << 60),
                        1, definition["id"], "definition", definition,
                    ))
                for _offset, _order, _event_id, event_kind, event in sorted(events):
                    target_id = event.get("properties", {}).get("target_id")
                    if not target_id:
                        continue
                    if event_kind == "read":
                        reaching = sorted(environment.get(target_id, set()))
                        for definition_id in reaching:
                            evidence = [definition_id, event["id"], statement_id]
                            add_edge(
                                "BRANCH_READS_FROM", definition_id, event["id"], evidence,
                                statement_id=statement_id,
                            )
                            add_edge(
                                "VALUE_FLOWS_TO", definition_id, event["id"], evidence,
                                reason="branch-reaching-definition",
                            )
                    else:
                        previous = sorted(environment.get(target_id, set()))
                        for previous_id in previous:
                            add_edge(
                                "BRANCH_PREVIOUS", previous_id, event["id"],
                                [previous_id, event["id"], statement_id],
                                statement_id=statement_id,
                            )
                        environment[target_id] = {event["id"]}

        return GraphDelta(self.overlay_id, nodes, edges)

