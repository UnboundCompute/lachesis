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
    quote, escaped = None, False
    for ch in call_label[start:]:
        if quote:
            # Inside a string/char literal a comma or paren is data, not syntax.
            current.append(ch)
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = None
            continue
        if ch in "\"'":
            quote = ch
            current.append(ch)
            continue
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


# A binary minus that is not the `->` member operator: a subtraction, which is
# the underflow-prone size arithmetic worth ranking to the top.
_SUBTRACT = re.compile(r"-(?!>)")
_ARITHMETIC = re.compile(r"[+*/%]|<<|>>")
# A destination written at base+offset (``buf->buffer + buf->len``): a copy into a
# pre-existing buffer where an unchecked running length is the classic overflow.
_OFFSET_WRITE = re.compile(r"\+")


def size_semantics(expression: str | None, shape: str) -> tuple[float, str]:
    """Rank the size expression by *risk shape*, not spelling. Cheap and syntactic:
    a dynamic length (arithmetic, variable) is worth a human's eyes; a constant
    (literal/sizeof) rarely is. This orders, it never suppresses."""
    if not expression or shape == "unknown":
        return 0.4, "opaque"
    stripped = _SIZEOF.sub("", expression)
    if _SUBTRACT.search(stripped):
        return 1.0, "arithmetic-subtraction"
    if _ARITHMETIC.search(stripped):
        return 0.9, "arithmetic"
    if shape == "identifier-expression":
        return 0.75, "dynamic-identifier"
    if shape == "call-expression":
        return 0.7, "dynamic-call"
    return 0.2, "constant"


def dest_semantics(dest_expressions: list[str | None]) -> tuple[float, str]:
    """Rank the destination by how easily it overflows. An offset write into an
    existing buffer is the pattern to inspect; a bare buffer is next; an unknown
    destination is least informative."""
    present = [d for d in dest_expressions if d]
    if any(_OFFSET_WRITE.search(d) for d in present):
        return 1.0, "offset-write"
    if present:
        return 0.6, "whole-buffer"
    return 0.3, "unknown"


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

    def _rank(self, expression: str | None, shape: str,
              dest_expressions: list[str | None], confidence: str
              ) -> tuple[float, list[dict]]:
        size_value, size_tag = size_semantics(expression, shape)
        dest_value, dest_tag = dest_semantics(dest_expressions)
        confidence_value = {"high": 1.0, "medium": 0.7, "low": 0.4}.get(
            confidence, 0.5)
        reasons = [
            {"term": "size_semantics", "value": size_value,
             "why": f"size is {size_tag}"},
            {"term": "destination_semantics", "value": dest_value,
             "why": f"destination is {dest_tag}"},
            {"term": "model_confidence", "value": confidence_value,
             "why": f"Atropos attachment confidence is {confidence}"},
        ]
        rank = round(0.6 * size_value + 0.2 * dest_value
                     + 0.2 * confidence_value, 4)
        return rank, reasons

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
            # Recover destinations from the callsite too, so a leaked value-node
            # label can't corrupt the destination or the rank it feeds.
            dest_expressions = [
                arg_from_callsite(call.get("label"), d["properties"].get("access_path"))
                or self._label(d["properties"].get("value_id"))
                for d in dests]
            confidence = props.get("confidence", "medium")
            rank, reasons = self._rank(expression, shape, dest_expressions, confidence)
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
                    "destination_expressions": dest_expressions,
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

        c_summary = self.bind_summary.get("per_language", {}).get("c", {})
        bind = c_summary.get("bind", {})
        # Every sink model the catalog carries that did NOT attach to a callsite.
        # Surfaced in full (not just counted) so no sink is silently dropped: the
        # AI sees exactly which copy/size sinks are missing and why. Sources are
        # excluded here because this constructor's obligation is a copy sink.
        unbound_sinks = [
            row for row in c_summary.get("unbound", ())
            if row.get("role") == "sink"]
        frontiers = {
            "unresolved_calls": 0,
            "unbound_models": sum(v for k, v in bind.items() if k != "bound"),
            "unbound_sinks": unbound_sinks,
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
