"""Flow C call results into the variables they initialize.

The C frontend links a declaration whose initializer is a call (``T v = f(...)``)
to that call by AST, but emits no *value-flow* edge from the call to ``v``. Every
analysis that walks value flow -- taint above all -- therefore dies at the call:
a return-value source or a library summary resolved onto the call has nowhere to
go, because a C call node has no outgoing dataflow edge. This overlay repairs that
in the enrich flow, without touching the base build: for each declaration
statement whose single AST child is a call, it emits one additive
``VALUE_FLOWS_TO`` edge from the call node to the declared variable.

The association is exact, not heuristic: clang gives a declared variable the same
source ``start_offset`` and owning function as its declaring statement, so the
variable a ``T v = call(...)`` statement introduces is the one sharing that key.

It is deliberately narrow. It covers the single-declarator declaration-with-call
form the frontend leaves unlinked; plain reassignment (``v = call()``) and
multi-declarator initializers are left to a later pass rather than guessed at, so
the overlay never invents a flow it cannot place on exactly one variable.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any

from ..composition import GraphDelta
from ..query import GraphIndex


class CCallResultDataflow:
    """Additive overlay: C call result -> the variable it initializes."""

    overlay_id = "c-call-result-dataflow"

    def applies(self, graph: dict, index: Any = None) -> bool:
        for node in graph.get("nodes", ()):
            if node.get("kind") == "call" and ":clang-c:" in node.get("id", ""):
                return True
        return False

    def enrich(self, graph: dict, index: Any = None) -> GraphDelta:
        index = GraphIndex(graph) if index is None else index
        nodes_by_id = index.nodes

        variables_by_key: dict[tuple, list] = defaultdict(list)
        for node in graph.get("nodes", ()):
            if node.get("kind") != "variable":
                continue
            props = node.get("properties", {})
            key = (props.get("owner_function_id"), props.get("start_offset"))
            variables_by_key[key].append(node)

        ast_children: dict[str, list] = defaultdict(list)
        for edge in graph.get("edges", ()):
            if edge.get("kind") == "AST_CHILD":
                ast_children[edge["source"]].append(edge["target"])

        edges = []
        for statement in graph.get("nodes", ()):
            if statement.get("kind") != "statement":
                continue
            calls = [child for child in ast_children.get(statement["id"], [])
                     if nodes_by_id.get(child, {}).get("kind") == "call"]
            if len(calls) != 1:
                continue
            props = statement.get("properties", {})
            key = (props.get("owner_function_id"), props.get("start_offset"))
            declared = variables_by_key.get(key, [])
            if len(declared) != 1:
                continue
            call_id, variable_id = calls[0], declared[0]["id"]
            edges.append({
                "kind": "VALUE_FLOWS_TO",
                "source": call_id, "target": variable_id,
                "properties": {
                    "fact_origin": "core-inference",
                    "confidence": "high",
                    "evidence_ids": [call_id, variable_id],
                    "inference": "c-call-result-to-declared-variable",
                },
            })
        return GraphDelta(self.overlay_id, [], edges)
