"""The generic, taxonomy-driven sink-obligation enumerator.

``memory.copy`` earns a *specialized* enumerator (unbounded_copy.py) because its
obligation joins two facts -- a size and a write destination -- at one callsite.
Every *other* taxonomy family shares one simpler shape: an Atropos sink fact
marks a single argument (a query string, a path, a URL, an allocation size, a
format) that carries an obligation, and the enumerator's job is identical across
all of them --

    join the fact to its callsite, recover the argument's exact spelling, note
    which branch conditions in the enclosing function name that argument, rank by
    the argument's syntactic risk shape, and emit one neutral pointer row.

This module is that single enumerator, *parameterized by a family spec* from the
taxonomy. Nothing here is family-specific: `sink_constructor(spec)` stamps out a
concrete constructor class for any family the taxonomy names, so the taxonomy --
not a hardcoded list -- decides which constructors exist. The row shape is the
same capsule the specialized copy constructor emits, so a harness reads every
family through one contract.

The same three rules bind this enumerator as the copy one: it reports facts, not
verdicts; it may *order* candidates but never *suppress* one; inclusion is
exhaustive (every bound sink of the family's kinds), ranking is the only triage.
"""
from __future__ import annotations

import hashlib
import re
from collections import defaultdict

from .capabilities import absent_optional_capabilities
from .unbounded_copy import (
    BranchRegions,
    VariableContext,
    _node_span,
    arg_from_callsite,
    condition_head,
    size_identifiers,
    size_semantics,
    syntactic_shape,
)


def _candidate_id(constructor_id: str, model_id: str,
                  callsite_id: str, value_id: str) -> str:
    raw = f"{constructor_id}\0{model_id}\0{callsite_id}\0{value_id}"
    return "obl_" + hashlib.sha256(raw.encode()).hexdigest()[:20]


class SinkObligation:
    """Base enumerator for single-argument sink obligations.

    Concrete per-family subclasses (built by ``sink_constructor``) set two class
    attributes: ``metadata`` (the advertised capability card) and ``_spec`` (the
    taxonomy family spec that drives binding and ranking)."""

    metadata: dict = {}
    _spec: dict = {}

    # Cap the referencing-condition list so a branch-dense function still yields a
    # bounded capsule; the total count is always reported in full.
    _MAX_CONDITIONS = 8

    def __init__(self, stamped_graph: dict, bind_summary: dict | None = None) -> None:
        self.graph = stamped_graph
        self.bind_summary = bind_summary or {}
        self.by_id = {n["id"]: n for n in stamped_graph.get("nodes", ())}
        # Region containment for the `dominance` observation, same as the copy
        # constructor: does the sink call site sit inside a branch that tests its
        # argument, or on the fall-through past it?
        self._regions = BranchRegions(stamped_graph)
        # Reaching definitions for the sink argument -- where it was last written --
        # recovered by walking value-flow edges backward. Same neutral context the
        # copy constructor attaches; not-computed without value-flow edges.
        self._variables = VariableContext(stamped_graph)
        # function_id -> [(control_kind, condition_head)], built once. Mirrors the
        # copy constructor's index so an argument can ask "does any branch in my
        # function test me?" without a graph walk per candidate.
        self._conditions_by_function: dict[str, list[tuple[str, str]]] = defaultdict(list)
        for node in stamped_graph.get("nodes", ()):
            if node.get("kind") != "cfg-condition":
                continue
            props = node.get("properties") or {}
            fn = props.get("function_id")
            head = condition_head(node.get("label"))
            if fn and head:
                self._conditions_by_function[fn].append(
                    (props.get("control_kind") or "if", head))

    def _referencing_conditions(self, function_id: str | None,
                                idents: set[str]) -> tuple[list[dict], int]:
        """Branch conditions whose controlling expression names an argument
        identifier. Neutral -- presence, never proof the guard dominates the sink
        or is even correct. Returns (capped rows, total count)."""
        if not function_id or not idents:
            return [], 0
        patterns = {i: re.compile(r"\b" + re.escape(i) + r"\b") for i in idents}
        hits = []
        for control, head in self._conditions_by_function.get(function_id, ()):
            named = sorted(i for i, p in patterns.items() if p.search(head))
            if named:
                hits.append({"control": control, "condition": head, "names": named})
        return hits[:self._MAX_CONDITIONS], len(hits)

    def _label(self, node_id: str | None) -> str | None:
        node = self.by_id.get(node_id or "", {})
        return node.get("label") or (node.get("properties") or {}).get("name")

    def _call(self, callsite_id: str | None) -> dict:
        return self.by_id.get(callsite_id or "", {})

    def _rank(self, expression: str | None, shape: str,
              confidence: str) -> tuple[float, list[dict]]:
        """Order by the argument's risk shape and the model's confidence.

        A single-argument obligation has no destination term, so the size/risk
        shape carries most of the weight: a dynamic or arithmetic argument (an
        attacker-shaped string, an unbounded multiplication feeding an allocation)
        is worth a human's eyes; a constant literal rarely is. This orders work,
        it never suppresses a candidate -- every bound sink is emitted regardless
        of rank."""
        risk_value, risk_tag = size_semantics(expression, shape)
        confidence_value = {"high": 1.0, "medium": 0.7, "low": 0.4}.get(
            confidence, 0.5)
        reasons = [
            {"term": "argument_shape", "value": risk_value,
             "why": f"argument is {risk_tag}"},
            {"term": "model_confidence", "value": confidence_value,
             "why": f"Atropos attachment confidence is {confidence}"},
        ]
        rank = round(0.75 * risk_value + 0.25 * confidence_value, 4)
        return rank, reasons

    def enumerate(self) -> dict:
        constructor_id = self.metadata["id"]
        domain = self.metadata["domain"]
        family = self.metadata["family"]
        kinds = set(self._spec["kinds"])
        obligation = self._spec["obligation"]
        obligation_cwe = set(self._spec.get("obligation_cwe", ()))
        languages = self.metadata.get("languages", ())

        sinks = [
            n for n in self.graph.get("nodes", ())
            if n.get("kind") == "sink"
            and (n.get("properties") or {}).get("fact_origin") == "atropos-model"
            and (n.get("properties") or {}).get("sink_kind") in kinds
        ]

        candidates = []
        for sink in sinks:
            props = sink["properties"]
            callsite_id, value_id = props.get("callsite_id"), props.get("value_id")
            call = self._call(callsite_id)
            call_props = call.get("properties") or {}
            owner_id = call_props.get("owner_function_id")
            # Prefer the argument recovered from the faithful callsite label; the
            # value node's own label is sometimes comment/AST-kind noise (A12).
            recovered = arg_from_callsite(call.get("label"), props.get("access_path"))
            if recovered:
                expression, expression_origin = recovered, "callsite-argument"
            else:
                expression, expression_origin = self._label(value_id), "value-node-label"
            shape = syntactic_shape(expression)
            confidence = props.get("confidence", "medium")
            model_cwe = props.get("cwe", [])
            idents = size_identifiers(expression)
            referencing, referencing_total = self._referencing_conditions(owner_id, idents)
            rank, reasons = self._rank(expression, shape, confidence)
            loc_file = call_props.get("absolute_file") or call_props.get("file")
            language = props.get("language") or (languages[0] if languages else None)
            candidate = {
                "candidate_id": _candidate_id(
                    constructor_id, props.get("model_id", ""),
                    callsite_id or "", value_id or ""),
                "constructor": constructor_id, "domain": domain, "language": language,
                "obligation": obligation,
                "handles": {"site_node_id": callsite_id,
                            "enclosing_function_id": owner_id,
                            "obligation_value_ids": [value_id]},
                "observations": {
                    "callee": call_props.get("callee") or call_props.get("method_name"),
                    "site": call.get("label"), "file": loc_file,
                    "line": call_props.get("start_line"),
                    # The argument the obligation is about, by its exact spelling.
                    # Named `size_expression` too so a harness (and the brief list
                    # projection) reads every family through one key; the neutral
                    # `argument_expression` alias states what it really is here.
                    "size_expression": expression,
                    "argument_expression": expression,
                    "syntactic_shape": shape,
                    "size_expression_origin": expression_origin,
                    "sink_kind": props.get("sink_kind"),
                    "atropos_model_id": props.get("model_id"),
                    "access_path": props.get("access_path"),
                    # `cwe` is the model's full tag set, verbatim; `obligation_cwe`
                    # is the subset this family's obligation actually concerns.
                    "cwe": model_cwe,
                    "obligation_cwe": [c for c in model_cwe if c in obligation_cwe],
                    "model_confidence": confidence,
                },
                "inferences": {
                    "input_reachability": {
                        "status": "not-queried", "source_kind": None,
                        "witness_ids": [],
                        "reason": "the AI may call sources_of/reaches when investigating",
                    },
                    # Does any branch in the enclosing function test the argument,
                    # and does the sink sit inside that branch's region or on the
                    # fall-through past it? A neutral lead, never a verdict and never
                    # fed to the rank. `dominance` is sound region containment, not
                    # proof the guard is correct -- only a place worth reading.
                    "conditions": {
                        "status": "observed" if referencing_total else "none-observed",
                        "basis": "syntactic: a control condition in the enclosing "
                                 "function names an argument variable",
                        "size_identifiers": sorted(idents),
                        "referencing_conditions": referencing,
                        "referencing_condition_count": referencing_total,
                        "dominance": self._regions.classify(
                            owner_id, idents, _node_span(call)),
                    },
                    # Where the sink argument was last written -- its reaching
                    # definition -- so a guard's bound can be read against the value
                    # the argument actually carries. Neutral fact, never a verdict;
                    # not-computed without value-flow edges.
                    "variable_context": self._variables.describe(
                        [("argument", value_id)], _node_span(call)),
                },
                "rank": rank, "rank_reasons": reasons,
                # Enumeration is complete for the observable graph; the evidence
                # capsule is partial because the flow/provenance proof is deferred
                # to the AI's own investigation (sources_of / reaches / read_body).
                "completeness": "PARTIAL",
                "next_op": {"tool": "sources_of", "args": {"sink": value_id},
                            "why": "let the AI inspect provenance before judging the obligation"},
            }
            candidates.append(candidate)
        candidates.sort(key=lambda c: (-c["rank"], c["candidate_id"]))

        # Coverage frontier: every catalog sink of THIS family's kinds that never
        # attached to a callsite, scoped by kind (now that unbound rows carry it)
        # so each family reports its own worklist, not the whole global roster.
        per_language = self.bind_summary.get("per_language", {})
        unbound_sinks = []
        unbound_models_total = 0
        for lang in languages:
            summ = per_language.get(lang)
            if not summ:
                continue
            bind = summ.get("bind", {})
            unbound_models_total += sum(v for k, v in bind.items() if k != "bound")
            for row in summ.get("unbound", ()):
                if row.get("role") == "sink" and row.get("kind") in kinds:
                    unbound_sinks.append(row)
        frontiers = {
            "unresolved_calls": 0,
            "unbound_models": unbound_models_total,
            "unbound_sinks": unbound_sinks,
            "truncated_walks": 0,
            "missing_optional_capabilities": absent_optional_capabilities(
                self.graph, self.metadata.get("optional_capabilities", ())),
            "unselected_configs": [],
        }
        return {
            "constructor": constructor_id, "domain": domain,
            "metadata": dict(self.metadata), "candidates": candidates,
            "census": {"enumerated": len(candidates),
                       "by_status": {"not-queried": len(candidates)}},
            "frontiers": frontiers,
            "complete_for_observable_graph": True,
        }


def sink_constructor(spec: dict) -> type:
    """Stamp out a concrete per-family constructor class from a taxonomy spec.

    The registry calls this for every family the taxonomy names (except the one
    with a specialized enumerator), so there is no hardcoded per-family list --
    the taxonomy is the source of truth and this turns each of its family specs
    into a registrable constructor with its own advertised capability card."""
    meta = {
        "id": spec["id"],
        "domain": spec["domain"],
        "family": spec["family"],
        "languages": tuple(spec["languages"]),
        "required_capabilities": ("calls", "argument-binding"),
        "optional_capabilities": ("value-flow", "points-to", "object-size", "dominance"),
        "enumeration_basis": "atropos:sink:" + "|".join(spec["kinds"]),
        "completeness_contract":
            f"every bound Atropos {spec['family']} sink attachment "
            f"({', '.join(spec['kinds'])})",
        "obligation_cwe": tuple(spec.get("obligation_cwe", ())),
    }
    return type(
        "SinkObligation_" + spec["id"].replace(".", "_").replace("-", "_"),
        (SinkObligation,),
        {"metadata": meta, "_spec": dict(spec)},
    )
