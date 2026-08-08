"""CFG-based reaching definitions and branch-sensitive phi histories."""
import hashlib
from collections import defaultdict, deque
from typing import Dict, Iterable, Set


def stable_id(kind: str, *parts) -> str:
    raw = ":".join(str(part) for part in parts)
    digest = hashlib.sha256(f"{kind}:{raw}".encode("utf-8")).hexdigest()[:16]
    return f"{kind}:{digest}"


def copy_environment(environment: Dict[str, Set[str]]) -> Dict[str, Set[str]]:
    return {symbol_id: set(definitions) for symbol_id, definitions in environment.items()}


def merge_environments(environments) -> Dict[str, Set[str]]:
    merged = defaultdict(set)
    for environment in environments:
        for symbol_id, definitions in environment.items():
            merged[symbol_id].update(definitions)
    return dict(merged)


def environment_equal(left, right) -> bool:
    return left.keys() == right.keys() and all(left[key] == right[key] for key in left)


def analyze_branch_histories(files: Iterable[dict]) -> None:
    for info in files:
        statements = {statement["id"]: statement for statement in info["statements"]}
        cfg_nodes = {node["id"]: node for node in info["cfg_nodes"]}
        symbols = {symbol["id"]: symbol for symbol in info["symbols"]}
        definitions_by_statement = defaultdict(list)
        reads_by_statement = defaultdict(list)
        for attachment in info["body_attachments"]:
            if not attachment.get("statement_id"):
                continue
            if attachment["entity_kind"] == "DEFINITION":
                definition = next(
                    item for item in info["definitions"]
                    if item["id"] == attachment["entity_id"]
                )
                definitions_by_statement[attachment["statement_id"]].append(definition)
            elif attachment["entity_kind"] == "READ":
                read = next(
                    item for item in info["reads"]
                    if item["id"] == attachment["entity_id"]
                )
                reads_by_statement[attachment["statement_id"]].append(read)

        phi_nodes = []
        branch_flows = []
        for function in info["functions"]:
            function_id = function["id"]
            owned_nodes = {
                node["id"] for node in info["cfg_nodes"]
                if node["function_id"] == function_id
            }
            owned_nodes.update(
                statement["id"] for statement in info["statements"]
                if statement["function_id"] == function_id
            )
            owned_nodes.update(
                operation["id"] for operation in info["operations"]
                if operation.get("function_id") == function_id
            )
            owned_nodes.update(
                expression["id"] for expression in info["expressions"]
                if expression.get("function_id") == function_id
            )
            edges = [
                edge for edge in info["cfg_edges"]
                if edge["kind"] != "CFG_UNREACHABLE"
                and edge["source"] in owned_nodes and edge["target"] in owned_nodes
            ]
            predecessors = defaultdict(set)
            successors = defaultdict(set)
            for edge in edges:
                predecessors[edge["target"]].add(edge["source"])
                successors[edge["source"]].add(edge["target"])

            entry = function.get("cfg_entry_id")
            if not entry:
                continue
            seed = {}
            latest_seed = {}
            captured = set(function.get("captures", []))
            for definition in sorted(info["definitions"], key=lambda item: item["offset"]):
                symbol = symbols.get(definition["symbol_id"])
                owner = (symbol or {}).get("owner_function_id")
                include = (
                    definition["origin"] == "parameter" and owner == function_id
                ) or (
                    owner is None and definition["offset"] <= function["start_offset"]
                ) or (
                    definition["symbol_id"] in captured
                    and definition["offset"] <= function["start_offset"]
                )
                if include:
                    latest_seed[definition["symbol_id"]] = definition["id"]
            for symbol_id, definition_id in latest_seed.items():
                seed[symbol_id] = {definition_id}

            def transfer(node_id: str, incoming: Dict[str, Set[str]], phis=None):
                result = copy_environment(incoming)
                for phi in (phis or {}).get(node_id, []):
                    result[phi["symbol_id"]] = {phi["id"]}
                for definition in sorted(
                    definitions_by_statement.get(node_id, []),
                    key=lambda item: item["offset"],
                ):
                    result[definition["symbol_id"]] = {definition["id"]}
                return result

            def solve(phis=None):
                incoming = {node_id: {} for node_id in owned_nodes}
                outgoing = {node_id: {} for node_id in owned_nodes}
                queue = deque([entry])
                queued = {entry}
                while queue:
                    node_id = queue.popleft()
                    queued.discard(node_id)
                    predecessor_envs = [
                        outgoing[pred] for pred in predecessors[node_id]
                    ]
                    merged = merge_environments(predecessor_envs)
                    if node_id == entry:
                        merged = merge_environments([merged, seed])
                    new_out = transfer(node_id, merged, phis)
                    changed = (
                        not environment_equal(incoming[node_id], merged)
                        or not environment_equal(outgoing[node_id], new_out)
                    )
                    incoming[node_id] = merged
                    outgoing[node_id] = new_out
                    if changed:
                        for successor in successors[node_id]:
                            if successor not in queued:
                                queue.append(successor)
                                queued.add(successor)
                return incoming, outgoing

            raw_incoming, raw_outgoing = solve()
            phis_by_node = defaultdict(list)
            for node_id in owned_nodes:
                reachable_predecessors = [
                    predecessor for predecessor in predecessors[node_id]
                    if raw_outgoing.get(predecessor)
                    or predecessor == entry
                    or predecessor in statements
                ]
                if len(reachable_predecessors) < 2:
                    continue
                symbols_at_join = set().union(
                    *(raw_outgoing[predecessor].keys() for predecessor in reachable_predecessors)
                )
                for symbol_id in symbols_at_join:
                    predecessor_values = [
                        frozenset(raw_outgoing[predecessor].get(symbol_id, set()))
                        for predecessor in reachable_predecessors
                    ]
                    incoming_definitions = sorted(set().union(*predecessor_values))
                    if len(incoming_definitions) < 2 or len(set(predecessor_values)) < 2:
                        continue
                    node_line = (
                        statements[node_id]["start_line"] if node_id in statements
                        else cfg_nodes.get(node_id, {}).get("line")
                    )
                    phi = {
                        "id": stable_id("phi", info["path_hash"], function_id, node_id, symbol_id),
                        "symbol_id": symbol_id, "cfg_node_id": node_id,
                        "function_id": function_id, "line": node_line,
                        "incoming_definition_ids": incoming_definitions,
                    }
                    phi_nodes.append(phi)
                    phis_by_node[node_id].append(phi)
                    for definition_id in incoming_definitions:
                        branch_flows.append({
                            "kind": "PHI_INPUT", "source": definition_id,
                            "target": phi["id"], "properties": {"cfg_node_id": node_id},
                        })

            incoming, outgoing = solve(phis_by_node)
            event_statement_ids = (
                set(reads_by_statement) | set(definitions_by_statement)
            )
            for statement_id in event_statement_ids:
                if statement_id not in owned_nodes:
                    continue
                statement_reads = reads_by_statement.get(statement_id, [])
                environment = copy_environment(incoming.get(statement_id, {}))
                for phi in phis_by_node.get(statement_id, []):
                    environment[phi["symbol_id"]] = {phi["id"]}
                # Preserve evaluation order inside a statement. A definition
                # becomes visible after its initializer/RHS has evaluated, so
                # `x = x + 1` reads the prior version while a later declarator
                # in `let a = 1, b = a` sees the new `a`.
                events = []
                for read in statement_reads:
                    events.append((read["offset"], 0, read["id"], "read", read))
                for definition in definitions_by_statement.get(statement_id, []):
                    effective_offset = definition.get("expression_end")
                    if effective_offset is None:
                        effective_offset = definition["offset"]
                    events.append((
                        effective_offset, 1, definition["id"],
                        "definition", definition,
                    ))
                for _offset, _order, _id, event_kind, event in sorted(events):
                    if event_kind == "read":
                        reaching = sorted(
                            environment.get(
                                event["symbol_id"], {event["definition_id"]}
                            )
                        )
                        event["reaching_definition_ids"] = reaching
                        for definition_id in reaching:
                            branch_flows.append({
                                "kind": "BRANCH_READS_FROM",
                                "source": definition_id, "target": event["id"],
                                "properties": {"statement_id": statement_id},
                            })
                        continue
                    previous = sorted(
                        environment.get(event["symbol_id"], set())
                    )
                    event["branch_previous_definition_ids"] = previous
                    for previous_id in previous:
                        branch_flows.append({
                            "kind": "BRANCH_PREVIOUS", "source": previous_id,
                            "target": event["id"],
                            "properties": {"statement_id": statement_id},
                        })
                    environment[event["symbol_id"]] = {event["id"]}

        info["phi_nodes"] = phi_nodes
        info["branch_flows"] = branch_flows
