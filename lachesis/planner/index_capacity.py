"""Enumerate array-subscript stores and recover element-count capacities.

This is deliberately a graph-shape constructor.  Unlike call-backed sink
families, a C subscript store has no library symbol for Atropos to bind.  The
frontend's AST roles are the source of truth: assignment -> LEFT_OPERAND ->
ArraySubscriptExpr -> (RECEIVER, PROPERTY_KEY).
"""
from __future__ import annotations

import hashlib
import re
from collections import defaultdict

from .capabilities import absent_optional_capabilities
from .unbounded_copy import (
    BranchRegions, VariableContext, _node_span, condition_head,
    size_identifiers, size_semantics, syntactic_shape,
)

CONSTRUCTOR_ID = "memory.index.capacity"
DOMAIN = "memory"
_ALLOCATOR_NAMES = frozenset({
    "malloc", "calloc", "realloc", "reallocarray", "alloca",
    "new_array", "new_array_impl", "realloc_array", "realloc_array_impl",
})
_ARG_INDEX = re.compile(r"Argument\[(\d+)\]")


def _candidate_id(site_id: str) -> str:
    return "obl_" + hashlib.sha256(
        f"{CONSTRUCTOR_ID}\0{site_id}".encode()).hexdigest()[:20]


def _label(node: dict | None) -> str | None:
    if not node:
        return None
    return node.get("label") or (node.get("properties") or {}).get("name")


def _arg_index(access_path: str | None) -> int | None:
    match = _ARG_INDEX.search(str(access_path or ""))
    return int(match.group(1)) if match else None


class MemoryIndexCapacity:
    metadata = {
        "id": CONSTRUCTOR_ID,
        "domain": DOMAIN,
        "family": "index",
        "languages": ("c",),
        "required_capabilities": ("ast",),
        "optional_capabilities": ("value-flow", "points-to", "dominance"),
        "enumeration_basis": "graph:assignment -> ArraySubscriptExpr",
        "completeness_contract": "every observable array-subscript assignment in the graph",
        "obligation": "array index must remain below allocated element capacity",
        "obligation_cwe": ("CWE-787", "CWE-193"),
    }
    _MAX_CONDITIONS = 8

    def __init__(self, stamped_graph: dict, bind_summary: dict | None = None) -> None:
        self.graph = stamped_graph
        self.bind_summary = bind_summary or {}
        self.by_id = {n["id"]: n for n in stamped_graph.get("nodes", ())}
        self.edges = stamped_graph.get("edges", ())
        self.children = defaultdict(list)
        self.parents = defaultdict(list)
        for edge in self.edges:
            if edge.get("kind") == "AST_CHILD":
                self.children[edge["source"]].append(edge)
                self.parents[edge["target"]].append(edge)
        self.regions = BranchRegions(stamped_graph)
        self.variables = VariableContext(stamped_graph)

    def _children_by_role(self, node_id: str, role: str) -> list[dict]:
        return [self.by_id[e["target"]] for e in self.children.get(node_id, ())
                if (e.get("properties") or {}).get("role") == role]

    def _index_shape(self, assignment: dict) -> tuple[dict, dict, dict] | None:
        left = self._children_by_role(assignment["id"], "LEFT_OPERAND")
        subscript = next((n for n in left if
                          (n.get("properties") or {}).get("syntax_kind") ==
                          "ArraySubscriptExpr"), None)
        if not subscript:
            return None
        receiver = self._children_by_role(subscript["id"], "RECEIVER")
        key = self._children_by_role(subscript["id"], "PROPERTY_KEY")
        if not receiver or not key:
            return None
        return subscript, receiver[0], key[0]

    def _allocator_calls(self, function_id: str | None, before: int) -> list[dict]:
        calls = []
        for node in self.graph.get("nodes", ()):
            if node.get("kind") != "call":
                continue
            props = node.get("properties") or {}
            if props.get("owner_function_id") != function_id:
                continue
            if (props.get("start_line") or 0) > before:
                continue
            names = {_label(node), props.get("callee"), props.get("method_name")}
            if names & _ALLOCATOR_NAMES:
                calls.append(node)
        return sorted(calls, key=lambda n: (n.get("properties", {}).get("start_line") or 0,
                                             n["id"]))

    def _assignment_allocator(self, base: str | None, function_id: str | None,
                              before: int) -> dict | None:
        # Prefer a defining assignment whose LHS names this base.  This prevents
        # an unrelated allocator call in the same function from supplying its
        # capacity (important for functions with several heap arrays).
        for assignment in self.graph.get("nodes", ()):
            props = assignment.get("properties") or {}
            if (assignment.get("kind") != "expression" or
                    props.get("syntax_kind") != "BinaryOperator" or
                    props.get("operator") != "=" or
                    props.get("owner_function_id") != function_id or
                    (props.get("start_line") or 0) > before):
                continue
            text = str(_label(assignment) or "")
            if not base or not text.split("=", 1)[0].strip().endswith(base):
                continue
            calls = [c for c in self._allocator_calls(function_id,
                                                       props.get("start_line") or before)
                     if c.get("properties", {}).get("start_line") ==
                     props.get("start_line")]
            if calls:
                return calls[-1]
        calls = self._allocator_calls(function_id, before)
        return calls[-1] if calls else None

    def _capacity(self, base: dict, assignment: dict, site: dict) -> dict:
        base_name = _label(base)
        props = site.get("properties") or {}
        call = self._assignment_allocator(base_name, props.get("owner_function_id"),
                                          props.get("start_line") or 0)
        if not call:
            return {"status": "unknown", "reason": "no defining allocator observed"}
        cprops = call.get("properties") or {}
        arg_ids = cprops.get("argument_value_ids") or []
        # A model-stamped allocation argument is catalog truth.  Prefer the
        # element-count metadata when present; otherwise use the allocator's
        # conventional count position (calloc/malloc-family compatibility).
        count_index = None
        for stamp in self.graph.get("nodes", ()):
            sp = stamp.get("properties") or {}
            if (sp.get("fact_origin") == "atropos-model" and
                    sp.get("kind") == "alloc-size" and
                    sp.get("callsite_id") == call.get("id")):
                count_index = sp.get("element_count_arg")
                if count_index is not None:
                    break
        if count_index is None:
            name = _label(call) or cprops.get("method_name") or cprops.get("callee")
            count_index = 0 if name in {"malloc", "calloc", "alloca", "new_array",
                                        "new_array_impl"} else 1
        if not isinstance(count_index, int) or count_index >= len(arg_ids):
            return {"status": "unknown", "reason": "allocator count argument is not observable",
                    "allocator": _label(call), "allocator_node_id": call.get("id")}
        arg_node = self.by_id.get(arg_ids[count_index])
        expression = _label(arg_node)
        return {"status": "symbolic", "expression": expression,
                "element_count": expression, "allocator": _label(call),
                "allocator_node_id": call.get("id"),
                "allocator_count_argument": count_index}

    def enumerate(self) -> dict:
        candidates = []
        for assignment in self.graph.get("nodes", ()):
            ap = assignment.get("properties") or {}
            if (assignment.get("kind") != "expression" or
                    ap.get("syntax_kind") != "BinaryOperator" or
                    ap.get("operator") not in {"=", "+=", "-=", "*=", "/="}):
                continue
            shape = self._index_shape(assignment)
            if not shape:
                continue
            subscript, base, index = shape
            index_expr = _label(index)
            base_expr = _label(base)
            identifiers = size_identifiers(index_expr)
            site_span = _node_span(assignment)
            function_id = ap.get("owner_function_id")
            conditions = []
            for n in self.graph.get("nodes", ()):
                p = n.get("properties") or {}
                if n.get("kind") != "cfg-condition" or p.get("function_id") != function_id:
                    continue
                head = condition_head(n.get("label"))
                if head and any(re.search(r"\b" + re.escape(i) + r"\b", head)
                                for i in identifiers):
                    conditions.append({"condition": head,
                                       "control": p.get("control_kind", "if")})
            capacity = self._capacity(base, assignment, assignment)
            dominance = self.regions.classify(function_id, identifiers, site_span)
            value, tag = size_semantics(index_expr, syntactic_shape(index_expr))
            rank = round(value, 4)
            candidate = {
                "candidate_id": _candidate_id(assignment["id"]),
                "constructor": CONSTRUCTOR_ID, "domain": DOMAIN, "language": "c",
                "obligation": self.metadata["obligation"],
                "handles": {"site_node_id": assignment["id"],
                            "subscript_node_id": subscript["id"],
                            "enclosing_function_id": function_id,
                            "obligation_value_ids": [base["id"], index["id"]]},
                "observations": {"site": _label(assignment),
                                 "file": ap.get("absolute_file") or ap.get("file"),
                                 "line": ap.get("start_line"),
                                 "base_expression": base_expr,
                                 "index_expression": index_expr,
                                 "syntactic_shape": "array-subscript-store",
                                 "cwe": list(self.metadata["obligation_cwe"])},
                "inferences": {
                    "capacity": capacity,
                    "conditions": {"status": dominance["status"],
                                   "index_identifiers": sorted(identifiers),
                                   "referencing_conditions": conditions[:self._MAX_CONDITIONS],
                                   "referencing_condition_count": len(conditions),
                                   "dominance": dominance},
                    "variable_context": self.variables.describe(
                        [("index", index["id"]), ("base", base["id"])], site_span)},
                "rank": rank,
                "rank_reasons": [{"term": "index_semantics", "value": value,
                                  "why": f"index is {tag}"}],
                "completeness": "PARTIAL",
                "next_op": {"tool": "sources_of", "args": {"sink": index["id"]},
                            "why": "trace the index and allocator count before judging the bound"},
            }
            candidates.append(candidate)
        candidates.sort(key=lambda c: (-c["rank"], c["candidate_id"]))
        computed = {"object-size"} if any(
            c["inferences"]["capacity"].get("status") == "symbolic" for c in candidates) else set()
        return {
            "constructor": CONSTRUCTOR_ID, "domain": DOMAIN,
            "metadata": dict(self.metadata), "candidates": candidates,
            "census": {"enumerated": len(candidates), "by_status": {
                "not-queried": len(candidates)}},
            "frontiers": {"unresolved_calls": 0, "unbound_models": 0,
                          "unbound_sinks": [], "truncated_walks": 0,
                          "missing_optional_capabilities": absent_optional_capabilities(
                              self.graph, self.metadata["optional_capabilities"], computed),
                          "unselected_configs": []},
            "complete_for_observable_graph": True,
        }
