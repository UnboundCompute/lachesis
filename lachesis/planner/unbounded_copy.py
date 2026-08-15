"""Enumerate every observable ``memory.copy.capacity`` obligation.

This module never decides whether the obligation is satisfied.  Atropos tells us
which exact values are copy destinations and sizes; this enumerator joins those
facts at their callsite, attaches neutral evidence, and orders the resulting work.
No constant, API name, nearby check, or unwitnessed flow removes a site.
"""
from __future__ import annotations

import hashlib
import re
from collections import defaultdict

CONSTRUCTOR_ID = "memory.copy.capacity"
DOMAIN = "memory"

_SIZEOF = re.compile(r"sizeof\s*\([^()]*\)")
_CALL = re.compile(r"[A-Za-z_]\w*\s*\(")
_NUM = re.compile(r"\b(?:0[xX][0-9a-fA-F]+|\d+)\b")
_IDENT = re.compile(r"[A-Za-z_]\w*")

_ARG_INDEX = re.compile(r"Argument\[(\d+)\]")
# A leaked value-node label: either a copied-through source comment (the file's
# leading copyright banner is a frequent offender) or a bare clang AST kind name
# emitted instead of folded source text. Neither is the real size spelling.
_AST_KIND = re.compile(r"^[A-Z][A-Za-z]*(Expr|Literal|Operator|Cast|Stmt|Decl)$")


def looks_like_leaked_label(label: str | None) -> bool:
    """True when a value-node label is comment/AST-kind noise, not source text."""
    if not label:
        return False
    text = label.strip()
    return text.startswith(("/*", "//")) or bool(_AST_KIND.match(text))


def arg_from_callsite(call_label: str | None, access_path: str | None) -> str | None:
    """Recover the exact argument spelling from the reliable callsite label.

    Value sub-nodes sometimes carry a wrong ``label`` (see A12), but the call
    node's own label is faithful and ``access_path`` names the argument index.
    Splitting the top-level argument list is source recovery, not evaluation."""
    if not call_label or not access_path:
        return None
    match = _ARG_INDEX.search(access_path)
    if not match:
        return None
    index, start = int(match.group(1)), call_label.find("(")
    if start < 0:
        return None
    depth, current, args = 0, [], []
    for ch in call_label[start:]:
        if ch in "([{":
            depth += 1
            if depth == 1 and ch == "(":
                continue
        elif ch in ")]}":
            depth -= 1
            if depth == 0:
                args.append("".join(current).strip())
                break
            current.append(ch)
            continue
        if ch == "," and depth == 1:
            args.append("".join(current).strip())
            current = []
            continue
        current.append(ch)
    if 0 <= index < len(args):
        return args[index] or None
    return None


def syntactic_shape(label: str | None) -> str:
    """Classify source spelling only; this is not constant evaluation."""
    if not label:
        return "unknown"
    if looks_like_leaked_label(label):
        return "unknown"
    rest = _SIZEOF.sub("", label)
    if _CALL.search(rest):
        return "call-expression"
    rest = _NUM.sub("", rest)
    if _IDENT.search(rest):
        return "identifier-expression"
    return "literal-or-sizeof"


def _candidate_id(model_id: str, callsite_id: str, value_id: str) -> str:
    raw = f"{CONSTRUCTOR_ID}\0{model_id}\0{callsite_id}\0{value_id}"
    return "obl_" + hashlib.sha256(raw.encode()).hexdigest()[:20]


class MemoryCopyCapacity:
    metadata = {
        "id": CONSTRUCTOR_ID,
        "domain": DOMAIN,
        "family": "copy",
        "languages": ("c",),
        "required_capabilities": ("calls", "argument-binding"),
        "optional_capabilities": ("value-flow", "points-to", "object-size", "dominance"),
        "enumeration_basis": "atropos:sink:buffer-size",
        "completeness_contract": "every bound Atropos buffer-size attachment",
    }

    def __init__(self, stamped_graph: dict, bind_summary: dict | None = None) -> None:
        self.graph = stamped_graph
        self.bind_summary = bind_summary or {}
        self.by_id = {n["id"]: n for n in stamped_graph.get("nodes", ())}

    def _label(self, node_id: str | None) -> str | None:
        node = self.by_id.get(node_id or "", {})
        return node.get("label") or (node.get("properties") or {}).get("name")

    def _call(self, callsite_id: str | None) -> dict:
        return self.by_id.get(callsite_id or "", {})

    def _rank(self, shape: str, confidence: str) -> tuple[float, list[dict]]:
        shape_value = {
            "call-expression": 1.0, "identifier-expression": 0.75,
            "unknown": 0.5, "literal-or-sizeof": 0.2,
        }[shape]
        confidence_value = {"high": 1.0, "medium": 0.7, "low": 0.4}.get(
            confidence, 0.5)
        reasons = [
            {"term": "size_shape", "value": shape_value,
             "why": f"size spelling is {shape}"},
            {"term": "model_confidence", "value": confidence_value,
             "why": f"Atropos attachment confidence is {confidence}"},
        ]
        return round(0.7 * shape_value + 0.3 * confidence_value, 4), reasons

    def enumerate(self) -> dict:
        role_nodes = [
            n for n in self.graph.get("nodes", ())
            if n.get("kind") == "sink"
            and (n.get("properties") or {}).get("fact_origin") == "atropos-model"
        ]
        destinations: dict[str, list[dict]] = defaultdict(list)
        sizes = []
        for node in role_nodes:
            props = node.get("properties") or {}
            if props.get("sink_kind") == "buffer-write":
                destinations[props.get("callsite_id")].append(node)
            elif props.get("sink_kind") == "buffer-size":
                sizes.append(node)

        candidates = []
        for sink in sizes:
            props = sink["properties"]
            callsite_id, value_id = props.get("callsite_id"), props.get("value_id")
            call = self._call(callsite_id)
            call_props = call.get("properties") or {}
            owner_id = call_props.get("owner_function_id")
            # Prefer the argument recovered from the faithful callsite label; the
            # value node's own label is sometimes comment/AST-kind noise (A12).
            recovered = arg_from_callsite(call.get("label"), props.get("access_path"))
            value_label = self._label(value_id)
            if recovered:
                expression, expression_origin = recovered, "callsite-argument"
            else:
                expression, expression_origin = value_label, "value-node-label"
            shape = syntactic_shape(expression)
            dests = destinations.get(callsite_id, ())
            dest_values = [d["properties"].get("value_id") for d in dests]
            confidence = props.get("confidence", "medium")
            rank, reasons = self._rank(shape, confidence)
            loc_file = call_props.get("absolute_file") or call_props.get("file")
            candidate = {
                "candidate_id": _candidate_id(props.get("model_id", ""), callsite_id or "", value_id or ""),
                "constructor": CONSTRUCTOR_ID, "domain": DOMAIN, "language": "c",
                "obligation": "copy length must not exceed destination capacity",
                "handles": {"site_node_id": callsite_id,
                            "enclosing_function_id": owner_id,
                            "obligation_value_ids": [value_id, *dest_values]},
                "observations": {
                    "callee": call_props.get("callee") or call_props.get("method_name"),
                    "site": call.get("label"), "file": loc_file,
                    "line": call_props.get("start_line"),
                    "size_expression": expression, "syntactic_shape": shape,
                    "size_expression_origin": expression_origin,
                    "destination_expressions": [self._label(v) for v in dest_values],
                    "atropos_model_id": props.get("model_id"),
                    "access_path": props.get("access_path"), "cwe": props.get("cwe", []),
                    "model_confidence": confidence,
                },
                "inferences": {
                    "input_reachability": {
                        "status": "not-queried", "source_kind": None,
                        "witness_ids": [],
                        "reason": "the AI may call sources_of/reaches when investigating",
                    },
                    "destination_capacity": {"status": "unknown",
                                             "reason": "object-size analysis is unavailable"},
                    "conditions": {"status": "unavailable", "nearby": [], "dominating": []},
                },
                "rank": rank, "rank_reasons": reasons,
                # Enumeration can be complete while the evidence capsule is still
                # partial: v1 deliberately has no object-size or dominance proof.
                "completeness": "PARTIAL",
                "next_op": {"tool": "sources_of", "args": {"sink": value_id},
                            "why": "let the AI inspect provenance before judging the obligation"},
            }
            candidates.append(candidate)
        candidates.sort(key=lambda c: (-c["rank"], c["candidate_id"]))

        bind = self.bind_summary.get("per_language", {}).get("c", {}).get("bind", {})
        frontiers = {
            "unresolved_calls": 0,
            "unbound_models": sum(v for k, v in bind.items() if k != "bound"),
            "truncated_walks": 0,
            "missing_optional_capabilities": [
                "value-flow", "points-to", "object-size", "dominance"],
            "unselected_configs": [],
        }
        return {
            "constructor": CONSTRUCTOR_ID, "domain": DOMAIN,
            "metadata": dict(self.metadata), "candidates": candidates,
            "census": {"enumerated": len(candidates),
                       "by_status": {"not-queried": len(candidates)}},
            "frontiers": frontiers,
            "complete_for_observable_graph": True,
        }
