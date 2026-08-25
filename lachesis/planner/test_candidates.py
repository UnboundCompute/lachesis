"""Acceptance checks for the verdict-free obligation registry."""
from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from lachesis.planner.registry import CandidateRegistry, default_candidate_registry
from lachesis.planner.unbounded_copy import (
    MemoryCopyCapacity, arg_from_callsite, array_capacity, condition_head,
    dest_semantics, destination_kind, looks_like_leaked_label, object_size_capacity,
    size_identifiers, size_semantics, syntactic_shape)


def _node(node_id, kind, label, **properties):
    return {"id": node_id, "kind": kind, "label": label, "properties": properties}


def _role(node_id, role, model_id, value_id, callsite_id, access_path, role_kind):
    return _node(
        node_id, role, f"{role}:{role_kind}", fact_origin="atropos-model",
        model_id=model_id, value_id=value_id, callsite_id=callsite_id,
        access_path=access_path, cwe=["CWE-787"], **{f"{role}_kind": role_kind})


def fixture_graph():
    return {
        "nodes": [
            _node("call:memcpy", "call", "memcpy(dst, src, n)", callee="memcpy",
                  owner_function_id="fn:copy", file="copy.c", start_line=10),
            _node("call:fgets", "call", "fgets(buf, sizeof(buf), fp)", callee="fgets",
                  owner_function_id="fn:read", file="read.c", start_line=20),
            _node("v:n", "expression", "n"),
            _node("v:sizeof", "expression", "sizeof(buf)"),
            _node("v:dst", "expression", "dst"),
            _node("v:buf", "expression", "buf"),
            _node("v:input", "expression", "request_len"),
            _node("v:middle", "expression", "parsed_len"),
            _node("source:input", "source", "source:request-body",
                  fact_origin="atropos-model", value_id="v:input",
                  source_kind="request-body", model_id="test.source"),
            _role("sink:memcpy-size", "sink", "c.std.memcpy.a2", "v:n",
                  "call:memcpy", "Argument[2]", "buffer-size"),
            _role("sink:memcpy-dest", "sink", "c.std.memcpy.a0", "v:dst",
                  "call:memcpy", "Argument[0]", "buffer-write"),
            _role("sink:fgets-size", "sink", "c.io.fgets.a1", "v:sizeof",
                  "call:fgets", "Argument[1]", "buffer-size"),
            _role("sink:fgets-dest", "sink", "c.io.fgets.a0", "v:buf",
                  "call:fgets", "Argument[0]", "buffer-write"),
        ],
        "edges": [
            {"source": "v:input", "target": "v:middle", "kind": "VALUE_FLOWS_TO",
             "properties": {}},
            {"source": "v:middle", "target": "v:n", "kind": "VALUE_FLOWS_TO",
             "properties": {}},
        ],
    }


class MemoryCopyCapacityTest(unittest.TestCase):
    def setUp(self):
        self.result = MemoryCopyCapacity(fixture_graph()).enumerate()
        self.rows = self.result["candidates"]

    def test_every_buffer_size_attachment_appears_exactly_once(self):
        self.assertEqual(len(self.rows), 2)
        self.assertCountEqual(
            [row["observations"]["atropos_model_id"] for row in self.rows],
            ["c.std.memcpy.a2", "c.io.fgets.a1"])

    def test_apparently_bounded_site_is_not_suppressed(self):
        fgets = next(row for row in self.rows
                     if row["observations"]["atropos_model_id"] == "c.io.fgets.a1")
        self.assertEqual(fgets["observations"]["syntactic_shape"], "literal-or-sizeof")
        self.assertEqual(fgets["inferences"]["input_reachability"]["status"],
                         "not-queried")
        self.assertIn(fgets, self.rows)

    def test_capsules_never_contain_a_safety_verdict(self):
        forbidden = {"safe", "unsafe", "verdict", "state", "suppressed"}
        for row in self.rows:
            self.assertTrue(forbidden.isdisjoint(row))
            self.assertEqual(row["inferences"]["destination_capacity"]["status"],
                             "unknown")

    def test_reachability_is_left_for_ai_driven_graph_tools(self):
        statuses = {row["inferences"]["input_reachability"]["status"]
                    for row in self.rows}
        self.assertEqual(statuses, {"not-queried"})
        self.assertEqual(self.result["census"]["enumerated"], 2)
        memcpy = next(row for row in self.rows
                      if row["observations"]["atropos_model_id"] == "c.std.memcpy.a2")
        self.assertEqual(memcpy["next_op"], {
            "tool": "sources_of", "args": {"sink": "v:n"},
            "why": "let the AI inspect provenance before judging the obligation",
        })

    def test_missing_source_models_do_not_change_enumeration(self):
        graph = fixture_graph()
        graph["nodes"] = [node for node in graph["nodes"]
                          if node["id"] != "source:input"]
        result = MemoryCopyCapacity(graph).enumerate()
        self.assertTrue(all(
            row["inferences"]["input_reachability"]["status"] == "not-queried"
            for row in result["candidates"]))

    def test_syntactic_shape_does_not_claim_constant_evaluation(self):
        self.assertEqual(syntactic_shape("sizeof(buf)"), "literal-or-sizeof")
        self.assertEqual(syntactic_shape("n + 4"), "identifier-expression")
        self.assertEqual(syntactic_shape("get_len()"), "call-expression")

    def test_size_expression_is_recovered_from_the_faithful_callsite(self):
        # Both fixture sites carry a correct value label, but recovery from the
        # callsite is the authoritative source regardless.
        for row in self.rows:
            self.assertEqual(row["observations"]["size_expression_origin"],
                             "callsite-argument")
        memcpy = next(r for r in self.rows
                      if r["observations"]["atropos_model_id"] == "c.std.memcpy.a2")
        self.assertEqual(memcpy["observations"]["size_expression"], "n")


class LabelLeakRecoveryTest(unittest.TestCase):
    """A12: value-node labels leak comments / AST-kind names; the callsite label
    and access path recover the true argument spelling."""

    def test_arg_from_callsite_extracts_the_right_nested_argument(self):
        self.assertEqual(
            arg_from_callsite(
                "memcpy(new->pkt, GET_PKT_DATA(p) + ltrim, GET_PKT_LEN(p) - ltrim)",
                "Argument[2]"),
            "GET_PKT_LEN(p) - ltrim")
        self.assertEqual(
            arg_from_callsite(
                "memset((uint8_t *)t + (n * sizeof(T)), 0x00, STEP * sizeof(Thread))",
                "Argument[2]"),
            "STEP * sizeof(Thread)")
        self.assertEqual(
            arg_from_callsite("fgets(buf, sizeof(buf), fp)", "Argument[1]"),
            "sizeof(buf)")

    def test_arg_from_callsite_ignores_separators_inside_string_literals(self):
        # A comma or paren inside a string/char literal is data, not an argument
        # boundary; otherwise Argument[2] here mis-recovers as a string fragment.
        self.assertEqual(
            arg_from_callsite(
                'strlcat(policy_string, ",pass:flow", sizeof(policy_string))',
                "Argument[2]"),
            "sizeof(policy_string)")
        self.assertEqual(
            arg_from_callsite(
                'strlcat(policy_string, ",pass:flow", sizeof(policy_string))',
                "Argument[1]"),
            '",pass:flow"')
        self.assertEqual(
            arg_from_callsite(r"memcpy(dst, some(a, b), sep(')', n))", "Argument[2]"),
            "sep(')', n)")

    def test_arg_from_callsite_is_none_when_unrecoverable(self):
        self.assertIsNone(arg_from_callsite(None, "Argument[0]"))
        self.assertIsNone(arg_from_callsite("memcpy(a, b, c)", None))
        self.assertIsNone(arg_from_callsite("memcpy(a, b, c)", "Argument[9]"))

    def test_leaked_labels_are_recognised_and_not_ranked_as_calls(self):
        banner = ("/* Copyright (C) 2007-2024 Open Information Security "
                  "Foundation ... */")
        self.assertTrue(looks_like_leaked_label(banner))
        self.assertTrue(looks_like_leaked_label("ImplicitCastExpr"))
        self.assertTrue(looks_like_leaked_label("IntegerLiteral"))
        self.assertFalse(looks_like_leaked_label("htp_header_value_len(h)"))
        # The banner contains "(" but must not be scored as a call-expression.
        self.assertEqual(syntactic_shape(banner), "unknown")

    def test_fallback_to_value_label_flags_leaked_noise_as_unknown(self):
        graph = fixture_graph()
        # Drop the access path so recovery fails and the enumerator must fall
        # back to the (leaked) value-node label.
        for node in graph["nodes"]:
            if node["id"] == "sink:memcpy-size":
                node["properties"]["access_path"] = None
        for node in graph["nodes"]:
            if node["id"] == "v:n":
                node["label"] = "ImplicitCastExpr"
        rows = MemoryCopyCapacity(graph).enumerate()["candidates"]
        memcpy = next(r for r in rows
                      if r["observations"]["atropos_model_id"] == "c.std.memcpy.a2")
        self.assertEqual(memcpy["observations"]["size_expression_origin"],
                         "value-node-label")
        self.assertEqual(memcpy["observations"]["syntactic_shape"], "unknown")


class SemanticRankingTest(unittest.TestCase):
    """Ranking orders by risk shape, never suppresses. Higher rank == worth a
    human's eyes first; every enumerated site still appears."""

    def test_size_semantics_orders_by_risk_shape_not_spelling(self):
        # Subtraction (underflow-prone) tops arithmetic tops dynamic tops constant.
        sub, _ = size_semantics("len - hdr", "identifier-expression")
        arith, _ = size_semantics("n + 4", "identifier-expression")
        ident, _ = size_semantics("parsed_len", "identifier-expression")
        call, _ = size_semantics("get_len()", "call-expression")
        const, _ = size_semantics("sizeof(buf)", "literal-or-sizeof")
        self.assertGreater(sub, arith)
        self.assertGreater(arith, ident)
        self.assertGreater(ident, call)
        self.assertGreater(call, const)

    def test_size_semantics_ignores_the_arrow_operator(self):
        # `->` is member access, not a subtraction; must not read as arithmetic.
        value, tag = size_semantics("buf->len", "identifier-expression")
        self.assertEqual(tag, "dynamic-identifier")

    def test_opaque_size_ranks_mid_not_bottom(self):
        # An unrecoverable size is uncertain, not proven-safe: it must not sink
        # below a plainly-constant one.
        opaque, _ = size_semantics(None, "unknown")
        const, _ = size_semantics("64", "literal-or-sizeof")
        self.assertGreater(opaque, const)

    def test_dest_semantics_boosts_offset_writes(self):
        offset, tag = dest_semantics(["new->pkt + ltrim"])
        whole, _ = dest_semantics(["buf"])
        unknown, _ = dest_semantics([None])
        self.assertEqual(tag, "offset-write")
        self.assertGreater(offset, whole)
        self.assertGreater(whole, unknown)

    def test_destination_kind_classifies_write_targets(self):
        self.assertEqual(destination_kind("new->pkt + ltrim"), "offset-write")
        self.assertEqual(destination_kind("buf[i]"), "indexed-write")
        self.assertEqual(destination_kind("*target"), "indirect-write")
        self.assertEqual(destination_kind("c->current->buffer"), "field-write")
        self.assertEqual(destination_kind("buf"), "named-buffer")
        self.assertEqual(destination_kind(None), "unknown")

    def test_destination_capacity_stays_unknown_not_guessed(self):
        # The exact-allocation-size distinction is capability-gated, never faked.
        row = MemoryCopyCapacity(fixture_graph()).enumerate()["candidates"][0]
        cap = row["inferences"]["destination_capacity"]
        self.assertEqual(cap["status"], "unknown")
        self.assertEqual(cap["needs_capability"], "object-size")

    def test_destination_kinds_are_surfaced_per_expression(self):
        graph = fixture_graph()
        for node in graph["nodes"]:
            if node["id"] == "call:memcpy":
                node["label"] = "memcpy(*target, src, n)"
        row = next(r for r in MemoryCopyCapacity(graph).enumerate()["candidates"]
                   if r["observations"]["atropos_model_id"] == "c.std.memcpy.a2")
        kinds = {k["kind"] for k in row["observations"]["destination_kinds"]}
        self.assertIn("indirect-write", kinds)

    def test_arithmetic_size_outranks_constant_copy_end_to_end(self):
        # The noise fix: a parsed-length subtraction into an offset write must
        # rank above a bounded sizeof copy, without dropping either.
        graph = fixture_graph()
        for node in graph["nodes"]:
            if node["id"] == "call:memcpy":
                node["label"] = "memcpy(new->pkt + off, src, GET_LEN(p) - hdr)"
        rows = MemoryCopyCapacity(graph).enumerate()["candidates"]
        self.assertEqual(len(rows), 2)  # nothing suppressed
        self.assertEqual(rows[0]["observations"]["atropos_model_id"],
                         "c.std.memcpy.a2")
        self.assertGreater(rows[0]["rank"], rows[1]["rank"])

    def test_write_only_copy_with_no_length_is_still_enumerated(self):
        # strcpy carries NO length argument, so it never produces a buffer-size
        # sink. It is the purest unbounded copy and must still be enumerated --
        # inclusion is exhaustive; a missing bound surfaces a site, never drops it.
        graph = fixture_graph()
        graph["nodes"] += [
            _node("call:strcpy", "call", "strcpy(dst, src)", callee="strcpy",
                  owner_function_id="fn:cp", file="cp.c", start_line=5),
            _role("sink:strcpy-dest", "sink", "c.std.strcpy.a0", "v:strcpy-dst",
                  "call:strcpy", "Argument[0]", "buffer-write"),
        ]
        rows = MemoryCopyCapacity(graph).enumerate()["candidates"]
        # The two size-bearing sites survive AND the write-only site is added.
        self.assertEqual(len(rows), 3)
        strcpy = next(r for r in rows
                      if r["observations"]["atropos_model_id"] == "c.std.strcpy.a0")
        self.assertEqual(strcpy["observations"]["syntactic_shape"], "no-length-argument")
        self.assertIsNone(strcpy["observations"]["size_expression"])
        self.assertEqual(strcpy["observations"]["callee"], "strcpy")
        # No length bound => it ranks at the ceiling, above bounded copies.
        self.assertEqual(rows[0]["observations"]["atropos_model_id"], "c.std.strcpy.a0")
        # Still verdict-free: capacity unknown, no safety claim, PARTIAL.
        self.assertEqual(strcpy["inferences"]["destination_capacity"]["status"], "unknown")
        self.assertEqual(strcpy["completeness"], "PARTIAL")

    def test_missing_capabilities_are_derived_from_the_graph_not_hardcoded(self):
        # value-flow is proven present by the graph carrying VALUE_FLOWS_TO edges;
        # it must drop off the missing list. The computed inferences this
        # enumerator does not produce (object-size, dominance) and points-to
        # (no POINTS_TO edges here) remain missing.
        missing = MemoryCopyCapacity(fixture_graph()).enumerate()[
            "frontiers"]["missing_optional_capabilities"]
        self.assertNotIn("value-flow", missing)
        self.assertIn("points-to", missing)
        self.assertIn("object-size", missing)
        self.assertIn("dominance", missing)
        # Strip the value-flow edges and the capability is honestly absent again.
        graph = fixture_graph()
        graph["edges"] = []
        missing_bare = MemoryCopyCapacity(graph).enumerate()[
            "frontiers"]["missing_optional_capabilities"]
        self.assertIn("value-flow", missing_bare)

    def test_write_only_and_sized_copy_at_same_callsite_prefers_the_size(self):
        # A site that DOES have a buffer-size is enumerated once, through its size
        # sink -- the write-only pass must not double-count it.
        rows = MemoryCopyCapacity(fixture_graph()).enumerate()["candidates"]
        self.assertEqual(len(rows), 2)
        self.assertNotIn("no-length-argument",
                         {r["observations"]["syntactic_shape"] for r in rows})


class UnboundSinkVisibilityTest(unittest.TestCase):
    """Every sink the catalog knows must be shown, bound or not. An unbound sink
    is surfaced as a named frontier row with its reason, never silently dropped."""

    def _summary(self):
        return {"per_language": {"c": {"bind": {"bound": 1, "symbol-not-found": 2,
                                                "ambiguous": 1},
            "unbound": [
                {"model_id": "c.std.alloca.a0", "method": "alloca",
                 "access_path": "Argument[0]", "role": "sink",
                 "status": "symbol-not-found", "detail": None},
                {"model_id": "c.std.snprintf.a2", "method": "snprintf",
                 "access_path": "Argument[2]", "role": "sink",
                 "status": "ambiguous", "detail": None},
                {"model_id": "c.std.getenv.ret", "method": "getenv",
                 "access_path": "ReturnValue", "role": "source",
                 "status": "ambiguous", "detail": None},
            ]}}}

    def test_frontier_lists_unbound_sinks_with_reasons(self):
        result = MemoryCopyCapacity(fixture_graph(), self._summary()).enumerate()
        sinks = result["frontiers"]["unbound_sinks"]
        methods = {row["method"] for row in sinks}
        self.assertEqual(methods, {"alloca", "snprintf"})  # sinks only, not getenv
        self.assertTrue(all("status" in row for row in sinks))
        # The count and the shown list stay consistent about what's missing.
        self.assertEqual(result["frontiers"]["unbound_models"], 3)

    def test_unbound_sinks_never_leak_into_enumerated_candidates(self):
        # Showing an unbound sink must not fabricate an obligation row for it;
        # candidates come only from bound attachments in the graph.
        result = MemoryCopyCapacity(fixture_graph(), self._summary()).enumerate()
        methods = {row["observations"]["callee"] for row in result["candidates"]}
        self.assertNotIn("alloca", methods)
        self.assertNotIn("snprintf", methods)


class CandidateRegistryTest(unittest.TestCase):
    def setUp(self):
        self.registry = default_candidate_registry(fixture_graph())

    def test_cursor_pages_without_dropping_candidates(self):
        first = self.registry.candidates(constructor="memory.copy.capacity", limit=1)
        second = self.registry.candidates(
            constructor="memory.copy.capacity", limit=1, cursor=first["next_cursor"])
        self.assertEqual(first["total"], 2)
        self.assertNotEqual(first["candidates"][0]["candidate_id"],
                            second["candidates"][0]["candidate_id"])
        self.assertIsNone(second["next_cursor"])

    def test_detail_and_census_are_addressable(self):
        page = self.registry.candidates(constructor="memory.copy.capacity", limit=1)
        candidate_id = page["candidates"][0]["candidate_id"]
        detail = self.registry.detail(candidate_id)
        self.assertEqual(detail["candidate"]["candidate_id"], candidate_id)
        self.assertIn("inferences", detail["candidate"])
        census = self.registry.census("memory.copy.capacity")
        self.assertEqual(census["constructors"][0]["census"]["enumerated"], 2)

    def test_registry_rejects_duplicate_constructor(self):
        registry = CandidateRegistry(fixture_graph())
        registry.register(MemoryCopyCapacity)
        with self.assertRaises(ValueError):
            registry.register(MemoryCopyCapacity)

    def test_invalid_cursor_is_not_silently_accepted(self):
        with self.assertRaises(ValueError):
            self.registry.candidates(constructor="memory.copy.capacity", cursor="1")


def _cond(node_id, function_id, text, control_kind="if"):
    return _node(node_id, "cfg-condition", f"condition:{text}",
                 function_id=function_id, control_kind=control_kind)


def guarded_graph():
    """One memcpy whose size `n` is tested by a branch in its own function, plus
    a decoy branch that merely mentions `n` in its body (must not match)."""
    g = fixture_graph()
    # Point the memcpy call at a known function id and give that function a guard.
    for node in g["nodes"]:
        if node["id"] == "call:memcpy":
            node["properties"]["owner_function_id"] = "fn:copy"
    g["nodes"] += [
        _cond("cond:guard", "fn:copy", "if (n > cap) return -1;"),
        _cond("cond:decoy", "fn:copy", "if (ready) { total += n; }"),  # n only in body
        _cond("cond:other", "fn:elsewhere", "if (n < 4) return;"),     # other function
    ]
    return g


class ConditionHelperTest(unittest.TestCase):
    def test_condition_head_strips_body(self):
        self.assertEqual(condition_head("condition:if (a > b) { x = 1; }"), "if (a > b)")

    def test_condition_head_balances_nested_parens(self):
        self.assertEqual(condition_head("condition:if (f(a) == g(b)) { y(); }"),
                         "if (f(a) == g(b))")

    def test_condition_head_handles_for(self):
        self.assertEqual(condition_head("condition:for (i = 0; i < n; i++) { }"),
                         "for (i = 0; i < n; i++)")

    def test_size_identifiers_drops_sizeof_and_keywords(self):
        self.assertEqual(size_identifiers("sizeof(buf) - hdr"), {"buf", "hdr"})
        self.assertEqual(size_identifiers("len"), {"len"})
        self.assertEqual(size_identifiers("1024"), set())


class ObligationCweScopingTest(unittest.TestCase):
    """The surfaced obligation_cwe is scoped to the write-capacity failure mode;
    a read-side CWE the model happens to carry stays in `cwe` but not in it."""

    def _graph(self):
        g = fixture_graph()
        for node in g["nodes"]:
            if node["id"] == "sink:memcpy-size":
                node["properties"]["cwe"] = ["CWE-787", "CWE-120", "CWE-125"]
        return g

    def test_read_side_cwe_is_excluded_from_obligation_but_kept_in_cwe(self):
        rows = MemoryCopyCapacity(self._graph()).enumerate()["candidates"]
        row = next(r for r in rows
                   if r["observations"]["atropos_model_id"] == "c.std.memcpy.a2")
        obs = row["observations"]
        self.assertIn("CWE-125", obs["cwe"])                 # nothing hidden
        self.assertNotIn("CWE-125", obs["obligation_cwe"])   # but scoped out
        self.assertEqual(set(obs["obligation_cwe"]), {"CWE-787", "CWE-120"})


class ConditionObservationTest(unittest.TestCase):
    """The conditions inference is a neutral presence fact: a branch in the
    enclosing function that names a size variable, body mentions excluded."""

    def _row(self):
        rows = MemoryCopyCapacity(guarded_graph()).enumerate()["candidates"]
        return next(r for r in rows
                    if r["observations"]["atropos_model_id"] == "c.std.memcpy.a2")

    def test_guard_on_size_var_is_observed(self):
        cond = self._row()["inferences"]["conditions"]
        self.assertEqual(cond["status"], "observed")
        heads = [h["condition"] for h in cond["referencing_conditions"]]
        self.assertIn("if (n > cap)", heads)

    def test_body_only_mention_is_not_a_referencing_condition(self):
        cond = self._row()["inferences"]["conditions"]
        heads = [h["condition"] for h in cond["referencing_conditions"]]
        self.assertNotIn("if (ready)", heads)          # `n` was only in the body
        self.assertEqual(cond["referencing_condition_count"], 1)

    def test_condition_in_another_function_is_not_borrowed(self):
        heads = [h["condition"]
                 for h in self._row()["inferences"]["conditions"]["referencing_conditions"]]
        self.assertNotIn("if (n < 4)", heads)          # belongs to fn:elsewhere

    def test_dominance_not_claimed_without_region_substrate(self):
        # This fixture carries no branch-region edges, so region containment is
        # simply unavailable -- an honest `not-computed`, never a guessed verdict.
        dominance = self._row()["inferences"]["conditions"]["dominance"]
        self.assertEqual(dominance["status"], "not-computed")

    def test_absent_guard_reads_as_none_observed(self):
        # fgets size is sizeof(buf); no branch names buf, so nothing is observed.
        rows = MemoryCopyCapacity(guarded_graph()).enumerate()["candidates"]
        fgets = next(r for r in rows
                     if r["observations"]["atropos_model_id"] == "c.io.fgets.a1")
        self.assertEqual(fgets["inferences"]["conditions"]["status"], "none-observed")

    def test_conditions_never_touch_the_rank(self):
        # The neutral guard fact must not suppress: same rank with and without it.
        guarded = self._row()["rank"]
        plain_rows = MemoryCopyCapacity(fixture_graph()).enumerate()["candidates"]
        plain = next(r for r in plain_rows
                     if r["observations"]["atropos_model_id"] == "c.std.memcpy.a2")["rank"]
        self.assertEqual(guarded, plain)


def _region_graph(copy_inside):
    """A memcpy whose size `n` is tested by a branch that owns a true-region. When
    ``copy_inside`` the copy's byte span sits inside that region (guarded); when
    not, the copy is on the fall-through past it (the carl9170 missing-guard
    shape)."""
    g = fixture_graph()
    for node in g["nodes"]:
        if node["id"] == "call:memcpy":
            node["properties"].update(
                absolute_file="/x/copy.c", start_offset=200, end_offset=230)
    region_span = (150, 260) if copy_inside else (300, 360)
    g["nodes"] += [
        _cond("cond:guard", "fn:copy", "if (n > cap) { ... }"),
        _node("region:true", "statement", "{ memcpy(dst, src, n); }",
              absolute_file="/x/copy.c",
              start_offset=region_span[0], end_offset=region_span[1]),
    ]
    g["edges"].append({"source": "cond:guard", "target": "region:true",
                       "kind": "TRUE_BRANCH", "properties": {}})
    return g


class RegionDominanceTest(unittest.TestCase):
    """`dominance` is sound region containment: whether the copy lies inside a
    size-testing branch's region or on the fall-through. Never a verdict, never a
    filter -- an observation the AI reads."""

    def _memcpy(self, graph):
        rows = MemoryCopyCapacity(graph).enumerate()["candidates"]
        return next(r for r in rows
                    if r["observations"]["atropos_model_id"] == "c.std.memcpy.a2")

    def test_copy_inside_a_size_testing_branch_reads_as_guarded_region(self):
        dominance = self._memcpy(_region_graph(copy_inside=True))[
            "inferences"]["conditions"]["dominance"]
        self.assertEqual(dominance["status"], "guarded-region")
        self.assertIn("if (n > cap)",
                      [r["condition"] for r in dominance["regions"]])

    def test_copy_on_the_fall_through_reads_as_fall_through(self):
        dominance = self._memcpy(_region_graph(copy_inside=False))[
            "inferences"]["conditions"]["dominance"]
        self.assertEqual(dominance["status"], "fall-through")
        self.assertIn("if (n > cap)",
                      [b["condition"] for b in dominance["branches"]])

    def test_region_substrate_makes_dominance_a_present_capability(self):
        # With branch-region edges in the graph, `dominance` is observably backed
        # and must drop off the missing-capability list.
        missing = MemoryCopyCapacity(_region_graph(copy_inside=True)).enumerate()[
            "frontiers"]["missing_optional_capabilities"]
        self.assertNotIn("dominance", missing)

    def test_dominance_never_touches_the_rank(self):
        # The neutral containment fact must not suppress or reorder: identical rank
        # whether the copy is guarded, fall-through, or has no region substrate.
        guarded = self._memcpy(_region_graph(copy_inside=True))["rank"]
        fell = self._memcpy(_region_graph(copy_inside=False))["rank"]
        plain = self._memcpy(fixture_graph())["rank"]
        self.assertEqual(guarded, fell)
        self.assertEqual(guarded, plain)


def _clamp_flow_graph():
    """A size variable ``n`` defined twice on the way to a memcpy: first from a
    ``hdrlen()`` initializer, then reassigned by a clamp ``n = cap``. A ``read``
    edge carries ``n`` into the size argument, and an Atropos copy-summary edge
    (src -> dst, no reason) sits across the callsite -- the exact shape that must
    NOT be walked. Modelled on the real C frontend's value-flow reasons."""
    g = fixture_graph()
    g["nodes"].extend([
        _node("v:n_init", "expression", "hdrlen()", file="copy.c",
              start_line=4, start_offset=100),
        _node("v:n_clamp", "expression", "n", file="copy.c",
              start_line=5, start_offset=150),
        _node("v:cap", "parameter", "cap", file="copy.c",
              start_line=3, start_offset=50),
        _node("v:src", "parameter", "src", file="copy.c",
              start_line=3, start_offset=60),
    ])
    for node in g["nodes"]:
        # The copy site needs a byte span so "nearest definition before the sink"
        # has a reference point; the size/dest value nodes carry files to match.
        if node["id"] == "call:memcpy":
            node["properties"].update(start_offset=195, end_offset=235)
        if node["id"] == "v:n":
            node["properties"].update(file="copy.c", start_line=6, start_offset=200)
        if node["id"] == "v:dst":
            node["properties"].update(file="copy.c", start_line=6, start_offset=210)
    g["edges"] = [
        # n's two reaching definitions: the initializer and the later clamp write.
        {"source": "v:n_init", "target": "v:n", "kind": "VALUE_FLOWS_TO",
         "properties": {"reason": "initializer"}},
        {"source": "v:n_clamp", "target": "v:n", "kind": "VALUE_FLOWS_TO",
         "properties": {"reason": "write"}},
        # cap flows into the clamp expression (a pass-through read).
        {"source": "v:cap", "target": "v:n_clamp", "kind": "VALUE_FLOWS_TO",
         "properties": {"reason": "read"}},
        # The Atropos copy summary: src -> dst, no reason. A boundary, not a def.
        {"source": "v:src", "target": "v:dst", "kind": "VALUE_FLOWS_TO",
         "properties": {"fact_origin": "atropos-model", "summary_kind": "copy"}},
    ]
    return g


class VariableContextTest(unittest.TestCase):
    """`variable_context` is the reaching definition of each sink argument -- where
    its value was last written -- recovered by walking value-flow edges backward.
    A neutral fact for judging guard adequacy, never a verdict, never fed to rank."""

    def _size_ctx(self, graph):
        row = next(r for r in MemoryCopyCapacity(graph).enumerate()["candidates"]
                   if r["observations"]["atropos_model_id"] == "c.std.memcpy.a2")
        vc = row["inferences"]["variable_context"]
        return next(a for a in vc["arguments"] if a["role"] == "size")

    def test_reaching_definitions_capture_every_write_of_the_size(self):
        size = self._size_ctx(_clamp_flow_graph())
        texts = {d["text"] for d in size["last_definitions"]}
        self.assertEqual(texts, {"hdrlen()", "n"})
        reasons = {d["reason"] for d in size["last_definitions"]}
        self.assertEqual(reasons, {"initializer", "write"})

    def test_definition_nearest_before_the_sink_is_flagged(self):
        size = self._size_ctx(_clamp_flow_graph())
        nearest = [d for d in size["last_definitions"] if d.get("nearest_to_sink")]
        self.assertEqual(len(nearest), 1)
        # The clamp at line 5 is the most recent write before the copy at line 6.
        self.assertEqual(nearest[0]["line"], 5)
        self.assertEqual(nearest[0]["reason"], "write")

    def test_taint_summary_edge_is_never_walked_as_a_definition(self):
        # The destination reaches its own parameter only -- never the source across
        # the memcpy copy-summary edge. A fabricated provenance fact is worse than
        # an absent one, so the boundary edge is not traversed.
        row = next(r for r in MemoryCopyCapacity(_clamp_flow_graph()).enumerate()[
            "candidates"] if r["observations"]["atropos_model_id"] == "c.std.memcpy.a2")
        dest = next(a for a in row["inferences"]["variable_context"]["arguments"]
                    if a["role"] == "destination")
        reached = {o["text"] for o in dest["origins"]} | {
            d["text"] for d in dest["last_definitions"]}
        self.assertNotIn("src", reached)

    def test_ast_kind_labels_are_counted_not_shown_as_definitions(self):
        # A reaching definition whose node carries only an AST-kind label (no source
        # text) must not appear as a definition -- presenting `IntegerLiteral` as a
        # def is a wrong fact. It is counted transparently instead, and never crowds
        # a real, readable definition out of the capped list.
        g = _clamp_flow_graph()
        g["nodes"].append(
            _node("v:noise", "expression", "ImplicitCastExpr", file="copy.c",
                  start_line=4, start_offset=90))
        g["edges"].append(
            {"source": "v:noise", "target": "v:n", "kind": "VALUE_FLOWS_TO",
             "properties": {"reason": "assignment"}})
        size = self._size_ctx(g)
        texts = {d["text"] for d in size["last_definitions"]}
        self.assertNotIn("ImplicitCastExpr", texts)     # noise is not a definition
        self.assertEqual({"hdrlen()", "n"}, texts)      # real defs still present
        self.assertEqual(1, size["unreadable_definition_count"])

    def test_not_computed_without_value_flow_substrate(self):
        # A graph with no value-flow edges cannot back reaching definitions; the
        # block reads not-computed, never mistaken for "no definition exists".
        g = fixture_graph()
        g["edges"] = []
        row = next(r for r in MemoryCopyCapacity(g).enumerate()["candidates"]
                   if r["observations"]["atropos_model_id"] == "c.std.memcpy.a2")
        vc = row["inferences"]["variable_context"]
        self.assertEqual(vc["status"], "not-computed")
        self.assertEqual(vc["needs_capability"], "value-flow")

    def test_variable_context_never_touches_the_rank(self):
        # The neutral fact must not reorder or suppress: identical rank with rich
        # reaching-definition context and with none at all.
        rich = self._rank(_clamp_flow_graph())
        bare = self._rank(fixture_graph())
        self.assertEqual(rich, bare)

    def _rank(self, graph):
        return next(r for r in MemoryCopyCapacity(graph).enumerate()["candidates"]
                    if r["observations"]["atropos_model_id"] == "c.std.memcpy.a2")["rank"]


def _capacity_graph(dest_type="char[64]", size_arg="128"):
    """A memcpy whose destination is a fixed array of ``dest_type`` and whose size
    argument is spelled ``size_arg``. Object-size can compare the two soundly when
    the array is a char family and the size is an integer literal."""
    g = fixture_graph()
    for node in g["nodes"]:
        if node["id"] == "call:memcpy":
            node["label"] = f"memcpy(buf, src, {size_arg})"
        if node["id"] == "v:dst":
            node["properties"]["type"] = dest_type
    return g


class ObjectSizeHelperTest(unittest.TestCase):
    """The object-size primitives are sound compile-time facts, never estimates."""

    def test_char_array_yields_a_byte_capacity(self):
        self.assertEqual(("char", 64, 64), array_capacity("char[64]"))
        self.assertEqual(("unsigned char", 16, 16), array_capacity("unsigned char[16]"))

    def test_non_char_array_count_is_exact_but_bytes_stay_unknown(self):
        # Byte size needs sizeof(int), an ABI fact this analyzer refuses to assume.
        self.assertEqual(("int", 8, None), array_capacity("int[8]"))

    def test_pointer_and_flexible_and_vla_are_not_fixed_arrays(self):
        self.assertIsNone(array_capacity("char *"))
        self.assertIsNone(array_capacity("char[]"))
        self.assertIsNone(array_capacity("char[n]"))
        self.assertIsNone(array_capacity(None))

    def test_literal_over_capacity_is_exceeds(self):
        dest = [{"label": "buf", "properties": {"type": "char[64]"}}]
        self.assertEqual("exceeds-capacity",
                         object_size_capacity(dest, "128")["status"])

    def test_literal_within_capacity_is_within(self):
        dest = [{"label": "buf", "properties": {"type": "char[64]"}}]
        self.assertEqual("within-capacity",
                         object_size_capacity(dest, "32")["status"])

    def test_symbolic_size_leaves_the_relation_unproven(self):
        dest = [{"label": "buf", "properties": {"type": "char[64]"}}]
        self.assertEqual("capacity-known-size-unknown",
                         object_size_capacity(dest, "n")["status"])

    def test_pointer_destination_stays_unknown(self):
        dest = [{"label": "p", "properties": {"type": "char *"}}]
        result = object_size_capacity(dest, "128")
        self.assertEqual("unknown", result["status"])
        self.assertEqual("object-size", result["needs_capability"])


class ObjectSizeCapacityTest(unittest.TestCase):
    """The enumerator reports destination_capacity from sound object-size, and the
    capability manifest reflects that it was actually computed."""

    def _memcpy(self, graph):
        rows = MemoryCopyCapacity(graph).enumerate()["candidates"]
        return next(r for r in rows
                    if r["observations"]["atropos_model_id"] == "c.std.memcpy.a2")

    def test_literal_copy_into_a_smaller_array_reads_as_exceeds(self):
        capacity = self._memcpy(_capacity_graph(size_arg="128"))[
            "inferences"]["destination_capacity"]
        self.assertEqual("exceeds-capacity", capacity["status"])
        self.assertEqual(128, capacity["copy_size_bytes"])
        self.assertEqual(64, capacity["capacity_bytes"])

    def test_literal_copy_that_fits_reads_as_within(self):
        capacity = self._memcpy(_capacity_graph(size_arg="16"))[
            "inferences"]["destination_capacity"]
        self.assertEqual("within-capacity", capacity["status"])

    def test_pointer_destination_still_reads_as_unknown(self):
        capacity = self._memcpy(_capacity_graph(dest_type="char *", size_arg="128"))[
            "inferences"]["destination_capacity"]
        self.assertEqual("unknown", capacity["status"])

    def test_resolved_capacity_makes_object_size_a_present_capability(self):
        missing = MemoryCopyCapacity(_capacity_graph()).enumerate()[
            "frontiers"]["missing_optional_capabilities"]
        self.assertNotIn("object-size", missing)

    def test_unresolved_capacity_keeps_object_size_missing(self):
        # A pointer destination resolves no capacity, so nothing was computed.
        missing = MemoryCopyCapacity(
            _capacity_graph(dest_type="char *")).enumerate()[
            "frontiers"]["missing_optional_capabilities"]
        self.assertIn("object-size", missing)

    def test_object_size_never_touches_the_rank(self):
        # An exceeds-capacity fact must not reorder or suppress: identical rank to
        # the same copy whose destination capacity cannot be resolved.
        exceeds = self._memcpy(_capacity_graph(dest_type="char[64]", size_arg="128"))
        opaque = self._memcpy(_capacity_graph(dest_type="char *", size_arg="128"))
        self.assertEqual("exceeds-capacity",
                         exceeds["inferences"]["destination_capacity"]["status"])
        self.assertEqual(exceeds["rank"], opaque["rank"])


class GranularDetailTierTest(unittest.TestCase):
    """The list view projects each row to one of three tiers -- brief, compact,
    full -- and never fabricates or drops a row between them."""

    def setUp(self):
        self.registry = default_candidate_registry(fixture_graph())

    def _rows(self, detail):
        return self.registry.candidates(
            constructor="memory.copy.capacity", limit=40, detail=detail)["candidates"]

    def test_brief_is_a_flat_scan_line(self):
        rows = self._rows("brief")
        self.assertEqual(len(rows), 2)
        for row in rows:
            self.assertEqual(set(row), {"candidate_id", "rank", "callee", "at",
                                        "size_expression", "size_shape", "completeness"})
            self.assertIsNone(row.get("observations"))  # heavy blocks absent
            self.assertRegex(row["at"], r":\d+$")  # file:line

    def test_compact_carries_observations_but_not_inferences(self):
        rows = self._rows("compact")
        self.assertIn("observations", rows[0])
        self.assertNotIn("inferences", rows[0])  # inferences are detail-only

    def test_full_is_the_whole_capsule(self):
        rows = self._rows("full")
        self.assertIn("inferences", rows[0])

    def test_tiers_agree_on_the_row_set(self):
        ids = {d: {r["candidate_id"] for r in self._rows(d)}
               for d in ("brief", "compact", "full")}
        self.assertEqual(ids["brief"], ids["compact"])
        self.assertEqual(ids["compact"], ids["full"])

    def test_response_names_its_detail_tier(self):
        page = self.registry.candidates(
            constructor="memory.copy.capacity", detail="brief")
        self.assertEqual(page["detail"], "brief")


class ListFrontierWeightTest(unittest.TestCase):
    """The list page reports coverage as counts and relocates the heavy
    unbound-sink roster to census -- shown, never dropped."""

    def _summary(self):
        return {"per_language": {"c": {"bind": {"bound": 1, "ambiguous": 1},
            "unbound": [
                {"model_id": "c.std.alloca.a0", "method": "alloca",
                 "access_path": "Argument[0]", "role": "sink",
                 "status": "symbol-not-found", "detail": None},
                {"model_id": "c.std.gets.a0", "method": "gets",
                 "access_path": "Argument[0]", "role": "sink",
                 "status": "symbol-not-found", "detail": None},
            ]}}}

    def setUp(self):
        self.registry = CandidateRegistry(fixture_graph(), self._summary())
        self.registry.register(MemoryCopyCapacity)

    def test_list_frontiers_carry_count_and_pointer_not_the_roster(self):
        front = self.registry.candidates(
            constructor="memory.copy.capacity")["frontiers"]
        self.assertNotIn("unbound_sinks", front)          # heavy list is gone
        self.assertEqual(front["unbound_sinks_count"], 2)  # but the count remains
        self.assertEqual(front["coverage_detail_via"], "candidate_census")

    def test_census_still_serves_every_unbound_sink_row(self):
        front = self.registry.census(
            "memory.copy.capacity")["constructors"][0]["frontiers"]
        methods = {row["method"] for row in front["unbound_sinks"]}
        self.assertEqual(methods, {"alloca", "gets"})  # full roster, with reasons


class AtroposEnvelopeSplitTest(unittest.TestCase):
    """The MCP server ships the per-language `unbound` rosters only on census;
    list/detail moves get the status counts, keeping a page bounded."""

    def _summary(self):
        return {"atropos_root": "/catalog", "languages": ["c"], "role_nodes": {},
                "per_language": {"c": {"callsites": 3, "bind": {"bound": 1},
                    "unbound": [{"model_id": "c.std.gets.a0", "role": "sink",
                                 "status": "symbol-not-found"}]}}}

    def test_non_census_moves_drop_the_unbound_roster(self):
        from lachesis.nav import mcp_server
        env = mcp_server._atropos_envelope(self._summary(), full=False)
        self.assertNotIn("unbound", env["bind"]["c"])
        self.assertEqual(env["bind"]["c"]["bind"], {"bound": 1})

    def test_census_keeps_the_unbound_roster(self):
        from lachesis.nav import mcp_server
        env = mcp_server._atropos_envelope(self._summary(), full=True)
        self.assertEqual(len(env["bind"]["c"]["unbound"]), 1)


class CandidateMcpSurfaceTest(unittest.TestCase):
    def test_tools_are_advertised_and_return_registry_payload(self):
        from lachesis.nav import mcp_server

        names = {tool["name"] for tool in mcp_server.TOOLS}
        self.assertTrue({"candidates", "candidate_detail", "candidate_census"}
                        .issubset(names))
        bundle = {
            "registry": default_candidate_registry(fixture_graph()),
            "atropos": {"applied": True, "atropos_root": "/catalog",
                        "languages": ["c"], "per_language": {}, "role_nodes": {}},
        }
        # The candidates handler binds through Analysis._bound_bind now (temporal fast path +
        # hard-stop), so the mock ctx serves the pre-built bundle from there.
        fake_ctx = SimpleNamespace(
            store=SimpleNamespace(gl=None), candidate_bundle=bundle,
            _bound_bind=lambda **_kwargs: bundle)
        with patch.object(mcp_server, "ctx", return_value=fake_ctx):
            payload = mcp_server.call_tool(
                "candidates", {"constructor_id": "memory.copy.capacity", "limit": 1},
                format="json")
        decoded = __import__("json").loads(payload)
        self.assertTrue(decoded["applied"])
        self.assertEqual(decoded["returned"], 1)
        self.assertEqual(decoded["total"], 2)


class SinkTaxonomyTest(unittest.TestCase):
    """The domain->family->kind tree stays coherent and honest."""

    def test_every_kind_is_placed_in_exactly_one_family(self):
        from lachesis.planner import taxonomy

        seen: dict[str, tuple[str, str]] = {}
        for domain_id, domain in taxonomy.SINK_TAXONOMY.items():
            for family_id, family in domain["families"].items():
                for kind in family["kinds"]:
                    self.assertNotIn(kind, seen,
                                     f"{kind} placed twice: {seen.get(kind)} and "
                                     f"{(domain_id, family_id)}")
                    seen[kind] = (domain_id, family_id)
        # locate() agrees with the walk for every placed kind.
        for kind, where in seen.items():
            self.assertEqual(taxonomy.locate(kind), where)
        self.assertIsNone(taxonomy.locate("not-a-real-kind"))

    def test_sources_and_summaries_are_not_sinks(self):
        from lachesis.planner import taxonomy

        sinks = taxonomy.all_sink_kinds()
        self.assertTrue(sinks.isdisjoint(taxonomy.SOURCE_KINDS))
        self.assertTrue(sinks.isdisjoint(taxonomy.SUMMARY_KINDS))

    def test_registered_constructor_matches_its_family(self):
        # Metadata (domain, family, id) on every registered constructor must
        # name a real taxonomy family whose `constructor` points back at it --
        # so the tree and the enumerators can never silently disagree.
        from lachesis.planner import taxonomy

        registry = default_candidate_registry(fixture_graph())
        for meta in registry.constructors:
            domain = taxonomy.SINK_TAXONOMY[meta["domain"]]
            family = domain["families"][meta["family"]]
            self.assertEqual(family["constructor"], meta["id"])

    def test_overview_marks_only_registered_families_enumerable(self):
        from lachesis.planner import taxonomy

        registered = {"memory.copy.capacity"}
        by_domain = {d["domain"]: d for d in taxonomy.overview(registered)}
        copy = next(f for f in by_domain["memory"]["families"] if f["family"] == "copy")
        alloc = next(f for f in by_domain["memory"]["families"] if f["family"] == "alloc")
        self.assertTrue(copy["enumerable"])
        self.assertFalse(alloc["enumerable"])
        self.assertTrue(by_domain["memory"]["enumerable"])
        self.assertFalse(by_domain["injection"]["enumerable"])
        # No registrations -> nothing is enumerable, but the menu is still full.
        empty = taxonomy.overview(set())
        self.assertTrue(all(not d["enumerable"] for d in empty))
        self.assertEqual(len(empty), len(taxonomy.SINK_TAXONOMY))

    def test_taxonomy_covers_the_live_catalog_kinds(self):
        # Best-effort drift guard: if the Atropos catalog is locatable, every
        # sink kind it models must be placed in the tree. Skipped when the
        # catalog is not checked out beside us (unit runs stay hermetic).
        try:
            from lachesis.integrations.atropos.enrich import locate_atropos, _load_binder
        except Exception:  # pragma: no cover - integration module optional
            self.skipTest("atropos integration unavailable")
        root = locate_atropos(None)
        if root is None:
            self.skipTest("atropos catalog not checked out")
        binder = _load_binder(root)
        models = binder.load_models(root / "models")
        from lachesis.planner import taxonomy

        # load_models returns a flat list of role entries; each sink entry
        # carries its `kind`. Placement must cover every one.
        catalog_sink_kinds = {
            entry.get("kind")
            for entry in models
            if entry.get("role") == "sink" and entry.get("kind")}
        placed = taxonomy.all_sink_kinds()
        missing = catalog_sink_kinds - placed
        self.assertEqual(missing, set(),
                         f"catalog sink kinds not placed in taxonomy: {sorted(missing)}")


class CensusTaxonomyTest(unittest.TestCase):
    def test_census_advertises_the_taxonomy(self):
        registry = default_candidate_registry(fixture_graph())
        census = registry.census("memory.copy.capacity")
        domains = {d["domain"] for d in census["taxonomy"]}
        self.assertIn("memory", domains)
        self.assertIn("injection", domains)
        memory = next(d for d in census["taxonomy"] if d["domain"] == "memory")
        self.assertTrue(memory["enumerable"])


def multi_family_graph():
    """A graph with sinks from three families: a copy (buffer-size), an
    allocation (alloc-size), and an injection (sql-injection) -- so a test can
    prove the generic enumerator serves every non-copy family off one contract."""
    return {
        "nodes": [
            _node("call:memcpy", "call", "memcpy(dst, src, n)", callee="memcpy",
                  owner_function_id="fn:a", file="a.c", start_line=10),
            _node("call:kzalloc", "call", "kzalloc(count * size, GFP_KERNEL)",
                  callee="kzalloc", owner_function_id="fn:a", file="a.c",
                  start_line=11, method_name="kzalloc"),
            _node("call:query", "call", "mysql_query(db, sql)", callee="mysql_query",
                  owner_function_id="fn:a", file="a.c", start_line=12),
            _node("v:n", "expression", "n"),
            _node("v:allocsz", "expression", "count * size"),
            _node("v:sql", "expression", "sql"),
            _role("sink:memcpy-size", "sink", "c.std.memcpy.a2", "v:n",
                  "call:memcpy", "Argument[2]", "buffer-size"),
            _role("sink:kzalloc-size", "sink", "c.kernel.kzalloc.a0", "v:allocsz",
                  "call:kzalloc", "Argument[0]", "alloc-size"),
            _role("sink:query", "sink", "c.db.mysql_query.a1", "v:sql",
                  "call:query", "Argument[1]", "sql-injection"),
        ],
        "edges": [],
    }


class StringLiteralShapeTest(unittest.TestCase):
    """A string-valued argument (a format/path/query) must classify by the
    expression AROUND the quotes, never by the bytes inside them -- otherwise a
    safe literal format ranks as if it were a dynamic, attacker-shaped value."""

    def test_literal_format_reads_as_constant_not_identifier(self):
        # Letters and a '(' inside the quotes must not make this an identifier or
        # a call: a literal format string is a constant.
        self.assertEqual(syntactic_shape('"cal-%s-%s.bin"'), "literal-or-sizeof")
        self.assertEqual(syntactic_shape('"reg dump (%d)\\n"'), "literal-or-sizeof")
        value, tag = size_semantics('"cal-%s-%s.bin"', "literal-or-sizeof")
        self.assertEqual(tag, "constant")
        self.assertEqual(value, 0.2)

    def test_dash_inside_a_literal_is_not_subtraction(self):
        # The '-' inside "a-b" is data, not underflow-prone arithmetic.
        value, tag = size_semantics('"a-b-c"', "literal-or-sizeof")
        self.assertEqual(tag, "constant")

    def test_non_literal_format_still_floats_up(self):
        # A variable or call used AS the format is the CWE-134 shape and must
        # keep its dynamic (high) risk classification.
        self.assertEqual(syntactic_shape("fmt"), "identifier-expression")
        self.assertEqual(syntactic_shape("get_fmt(idx)"), "call-expression")
        var_value, _ = size_semantics("fmt", "identifier-expression")
        lit_value, _ = size_semantics('"literal"', "literal-or-sizeof")
        self.assertGreater(var_value, lit_value)

    def test_size_expressions_are_unaffected(self):
        # Size math never carries a string literal, so stripping is a no-op there.
        self.assertEqual(syntactic_shape("len - 4"), "identifier-expression")
        value, tag = size_semantics("len - 4", "identifier-expression")
        self.assertEqual(tag, "arithmetic-subtraction")
        self.assertEqual(value, 1.0)


class GenericSinkObligationTest(unittest.TestCase):
    """The generic, taxonomy-driven enumerator for single-argument families."""

    def setUp(self):
        from lachesis.planner import taxonomy
        from lachesis.planner.sink_obligation import sink_constructor

        self.taxonomy = taxonomy
        self.sink_constructor = sink_constructor
        self.alloc_spec = next(
            s for s in taxonomy.family_specs() if s["id"] == "memory.alloc.size")

    def test_enumerates_one_candidate_per_matching_sink(self):
        ctor = self.sink_constructor(self.alloc_spec)
        result = ctor(multi_family_graph()).enumerate()
        self.assertEqual(len(result["candidates"]), 1)
        row = result["candidates"][0]
        self.assertEqual(row["observations"]["atropos_model_id"], "c.kernel.kzalloc.a0")
        self.assertEqual(row["observations"]["sink_kind"], "alloc-size")
        self.assertEqual(row["constructor"], "memory.alloc.size")
        self.assertEqual(row["domain"], "memory")

    def test_ignores_sinks_of_other_families(self):
        # An injection sink must never surface under the allocation constructor.
        ctor = self.sink_constructor(self.alloc_spec)
        result = ctor(multi_family_graph()).enumerate()
        model_ids = {r["observations"]["atropos_model_id"]
                     for r in result["candidates"]}
        self.assertNotIn("c.db.mysql_query.a1", model_ids)
        self.assertNotIn("c.std.memcpy.a2", model_ids)

    def test_row_carries_the_full_capsule_contract(self):
        ctor = self.sink_constructor(self.alloc_spec)
        row = ctor(multi_family_graph()).enumerate()["candidates"][0]
        for key in ("candidate_id", "constructor", "domain", "language",
                    "obligation", "handles", "observations", "inferences",
                    "rank", "rank_reasons", "completeness", "next_op"):
            self.assertIn(key, row)
        self.assertEqual(row["completeness"], "PARTIAL")
        self.assertEqual(row["inferences"]["input_reachability"]["status"],
                         "not-queried")
        # The argument spelling is recovered from the faithful callsite label.
        self.assertEqual(row["observations"]["size_expression"], "count * size")
        self.assertEqual(row["observations"]["size_expression_origin"],
                         "callsite-argument")

    def test_arithmetic_argument_outranks_a_constant(self):
        # An allocation whose size is `count * size` (overflow-prone) must rank
        # above a bare constant -- ordering only, never suppression.
        ctor = self.sink_constructor(self.alloc_spec)
        row = ctor(multi_family_graph()).enumerate()["candidates"][0]
        self.assertGreater(row["rank"], 0.5)
        tags = {r["value"] for r in row["rank_reasons"]}
        self.assertTrue(any(v >= 0.9 for v in tags))

    def test_obligation_cwe_is_scoped_to_the_family(self):
        # The model tags CWE-787 (from the fixture helper); the allocation
        # obligation is about overflow/oversize, so CWE-787 must NOT ride along
        # in obligation_cwe even though it stays visible in the full cwe set.
        ctor = self.sink_constructor(self.alloc_spec)
        row = ctor(multi_family_graph()).enumerate()["candidates"][0]
        self.assertIn("CWE-787", row["observations"]["cwe"])
        self.assertNotIn("CWE-787", row["observations"]["obligation_cwe"])

    def test_unbound_frontier_is_scoped_to_the_family_kinds(self):
        # Unbound rows now carry `kind`; the allocation constructor must report
        # only alloc-size misses, not another family's unbound sinks.
        bind_summary = {"per_language": {"c": {"bind": {"bound": 1, "symbol-not-found": 2},
            "unbound": [
                {"model_id": "c.kernel.kvmalloc.a0", "role": "sink",
                 "kind": "alloc-size", "status": "symbol-not-found"},
                {"model_id": "c.db.sqlite3_exec.a1", "role": "sink",
                 "kind": "sql-injection", "status": "symbol-not-found"},
            ]}}}
        ctor = self.sink_constructor(self.alloc_spec)
        result = ctor(multi_family_graph(), bind_summary).enumerate()
        unbound = result["frontiers"]["unbound_sinks"]
        self.assertEqual([u["model_id"] for u in unbound], ["c.kernel.kvmalloc.a0"])


class AllFamilyRegistryTest(unittest.TestCase):
    """The default registry spans every taxonomy family, no hardcoded list."""

    def test_every_family_has_a_registered_constructor(self):
        from lachesis.planner import taxonomy

        registry = default_candidate_registry(multi_family_graph())
        registered = {m["id"] for m in registry.constructors}
        expected = {s["id"] for s in taxonomy.family_specs()}
        self.assertEqual(registered, expected)
        # And the count matches every family in the tree, not just memory.copy.
        self.assertEqual(len(registered), sum(
            len(d["families"]) for d in taxonomy.SINK_TAXONOMY.values()))

    def test_memory_copy_keeps_its_specialist(self):
        from lachesis.planner.unbounded_copy import MemoryCopyCapacity

        registry = default_candidate_registry(multi_family_graph())
        impl = registry._specs["memory.copy.capacity"].implementation
        self.assertIs(impl, MemoryCopyCapacity)

    def test_default_query_surface_groups_across_families(self):
        # With no constructor pinned, the candidates move fans out over every
        # registered family rather than collapsing to one.
        registry = default_candidate_registry(multi_family_graph())
        out = registry.candidates()
        self.assertEqual(out["move"], "candidates")
        self.assertIn("groups", out)
        self.assertGreater(len(out["constructors"]), 1)

    def test_pinned_constructor_tests_one_family(self):
        # Pinning a single family is the deliberate "test just this" path.
        registry = default_candidate_registry(multi_family_graph())
        out = registry.candidates(constructor="memory.alloc.size")
        self.assertEqual(out["constructor"], "memory.alloc.size")
        self.assertEqual(out["total"], 1)

    def test_alloc_and_injection_candidates_are_discoverable_by_id(self):
        registry = default_candidate_registry(multi_family_graph())
        alloc = registry.candidates(constructor="memory.alloc.size")["candidates"]
        query = registry.candidates(constructor="injection.query.escaping")["candidates"]
        self.assertEqual(alloc[0]["observations"]["atropos_model_id"],
                         "c.kernel.kzalloc.a0")
        self.assertEqual(query[0]["observations"]["atropos_model_id"],
                         "c.db.mysql_query.a1")

    def test_temporal_flow_patterns_are_candidate_families(self):
        graph = {
            "nodes": [
                _node("free:1", "release", "free(p)", object_id="obj:p",
                      owner_function_id="fn:destroy", file="destroy.c", start_line=8),
                _node("read:1", "read", "p->field", object_id="obj:p",
                      owner_function_id="fn:use", file="use.c", start_line=19),
            ],
            "edges": [],
        }
        registry = default_candidate_registry(graph)
        uaf = registry.census("mem.lifetime.use-after-free")["constructors"][0]
        double_free = registry.census("mem.lifetime.double-free")["constructors"][0]
        self.assertEqual(uaf["census"]["enumerated"], 1)
        self.assertEqual(double_free["census"]["enumerated"], 1)
        self.assertEqual(uaf["metadata"]["matcher_pattern"], "uaf.deref")
        self.assertEqual(double_free["metadata"]["matcher_pattern"], "double-free")

    def test_unchecked_return_deref_is_discoverable_as_a_temporal_candidate(self):
        graph = {
            "nodes": [
                _node("read:1", "read_storage", "result->field", object_id="obj:result",
                      owner_function_id="fn:caller", file="caller.c", start_line=14),
            ],
            "edges": [],
        }
        registry = default_candidate_registry(graph)
        result = registry.census("ctrl.unchecked-return-deref")["constructors"][0]
        self.assertEqual(result["metadata"]["matcher_pattern"],
                         "unchecked-return-deref")
        self.assertEqual(result["census"]["enumerated"], 1)

    def test_temporal_candidates_are_language_neutral(self):
        graph = {
            "nodes": [
                _node("free:py", "release", "release(buf)", object_id="obj:buf",
                      owner_function_id="fn:destroy", file="destroy.py", start_line=8),
                _node("read:py", "read_storage", "buf.data", object_id="obj:buf",
                      owner_function_id="fn:use", file="use.py", start_line=19),
            ],
            "edges": [],
        }
        registry = default_candidate_registry(graph)
        rows = registry.candidates(constructor="mem.lifetime.use-after-free")["candidates"]
        self.assertEqual(rows[0]["language"], "python")
        self.assertEqual(rows[0]["observations"]["event_kind"], "read_storage")

    def test_every_catalogued_lifecycle_pattern_has_observation_routing(self):
        from lachesis.flow import atropos
        from lachesis.planner import taxonomy
        from lachesis.planner.temporal_obligation import temporal_constructor

        lifecycle = [entry for entry in atropos.pattern_catalog()
                     if (entry.get("candidate") or {}).get("domain") == "lifecycle"]
        registry = default_candidate_registry({"nodes": [], "edges": []})
        registered = {spec["id"] for spec in registry.constructors}
        self.assertTrue(lifecycle)
        for entry in lifecycle:
            candidate = entry["candidate"]
            self.assertIn(entry["id"], registered)
            spec = next(spec for spec in taxonomy.family_specs()
                        if spec["id"] == entry["id"])
            implementation = temporal_constructor(spec)
            self.assertTrue(implementation.trigger, entry["id"])

    def test_temporal_candidate_rows_are_not_verdicts(self):
        graph = {"nodes": [_node("free:1", "release", "free(p)" )], "edges": []}
        registry = default_candidate_registry(graph)
        row = registry.candidates(constructor="mem.lifetime.double-free",
                                  detail="full")["candidates"][0]
        self.assertNotIn("verdict", row)
        self.assertEqual(row["inferences"]["same_object"], "not-queried")

    def test_temporal_census_reports_uncovered_semantic_states(self):
        graph = {
            "nodes": [], "edges": [],
            "semantic_graph": {
                "coverage": {"converged": False,
                              "uncovered_states": [["worker", "source"]],
                              "uncovered_contexts": [["worker", "source", "site"]]},
                "nodes": {
                    "release": {"event": {"kind": "RELEASE", "obj": "O#g0"},
                                 "fragment": "worker"},
                },
            },
        }
        result = default_candidate_registry(graph).census(
            "mem.lifetime.double-free")["constructors"][0]
        self.assertFalse(result["complete_for_observable_graph"])
        self.assertEqual(result["frontiers"]["unresolved_calls"], 2)

    def test_temporal_registry_consumes_serialized_semantic_skeleton(self):
        graph = {
            "nodes": [], "edges": [],
            "semantic_graph": {
                "nodes": {
                    "origin": {"event": {"kind": "ORIGIN", "obj": "O#g0",
                                           "line": 10},
                               "fragment": "make", "metadata": {}},
                    "release": {"event": {"kind": "RELEASE", "obj": "O#g0",
                                            "line": 20},
                                 "fragment": "destroy", "metadata": {}},
                },
                "edges": {}, "fragments": {},
            },
        }
        registry = default_candidate_registry(graph)
        leak = registry.candidates(constructor="mem.lifetime.leak")
        double_free = registry.candidates(constructor="mem.lifetime.double-free")
        self.assertEqual(leak["total"], 1)
        self.assertEqual(double_free["total"], 1)
        self.assertEqual(leak["candidates"][0]["handles"]["enclosing_function_id"], "make")
        self.assertNotIn("verdict", leak["candidates"][0])

    def test_serialized_semantic_language_survives_without_file_metadata(self):
        graph = {
            "language": "python",
            "nodes": [], "edges": [],
            "semantic_graph": {
                "language": "python",
                "nodes": {
                    "read": {"event": {"kind": "READ_STORAGE", "obj": "buf#g0"},
                             "fragment": "use", "metadata": {}},
                },
                "edges": {}, "fragments": {},
            },
        }
        row = default_candidate_registry(graph).candidates(
            constructor="mem.lifetime.use-after-free")["candidates"][0]
        self.assertEqual(row["language"], "python")

    def test_multilanguage_semantic_nodes_keep_language_and_collisions(self):
        from lachesis.planner.temporal_obligation import merge_semantic_nodes

        class Semantic:
            def __init__(self, node):
                self.node = node

            def to_dict(self):
                return {"nodes": {"shared": self.node}}

        merged = {}
        merge_semantic_nodes(merged, Semantic({"event": {"kind": "ORIGIN"},
                                               "metadata": {}}), "c")
        merge_semantic_nodes(merged, Semantic({"event": {"kind": "ORIGIN"},
                                               "metadata": {}}), "python")
        self.assertEqual(merged["shared"]["metadata"]["language"], "c")
        self.assertEqual(merged["python:shared"]["metadata"]["language"], "python")


class GuardRelationTest(unittest.TestCase):
    """A branch guards a size only when it COMPARES the variable's magnitude.

    The region classifier used to flag any branch that merely NAMED a size variable,
    so `if (p && ...)` read as a size guard and suppressed a real overflow/lifetime
    bug. A guard must carry a magnitude relation (`< <= > >=`), not a nullness or
    presence test."""

    def _named(self, head, *idents):
        import re as _re

        from lachesis.planner.unbounded_copy import _relation_named
        patterns = {i: _re.compile(r"\b" + _re.escape(i) + r"\b") for i in idents}
        return _relation_named(head, patterns)

    def test_magnitude_comparison_is_a_guard(self):
        self.assertEqual(["cap", "len"], self._named("if (len < cap)", "len", "cap"))
        self.assertEqual(["x"], self._named("if (x >= 0)", "x"))
        self.assertEqual(["count", "i"], self._named("while (i < count)", "i", "count"))

    def test_nullness_or_presence_is_not_a_guard(self):
        self.assertEqual([], self._named("if (z && a && b)", "z", "a", "b"))
        self.assertEqual([], self._named("if (p != NULL)", "p"))
        self.assertEqual([], self._named("if (buf)", "buf"))

    def test_bit_shift_is_not_a_relation(self):
        self.assertEqual([], self._named("if (flags << 2)", "flags"))
        self.assertEqual([], self._named("if (a >> b)", "a", "b"))

    def test_only_the_operands_of_the_relation_clause_count(self):
        # `ready` shares the head but sits in its own presence clause, not the bound.
        self.assertEqual(["n", "size"],
                         self._named("if (n <= size && ready)", "n", "size", "ready"))


if __name__ == "__main__":
    unittest.main()
