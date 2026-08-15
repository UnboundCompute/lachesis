"""Acceptance checks for the verdict-free obligation registry."""
from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from lachesis.planner.registry import CandidateRegistry, default_candidate_registry
from lachesis.planner.unbounded_copy import (
    MemoryCopyCapacity, arg_from_callsite, condition_head, dest_semantics,
    looks_like_leaked_label, size_identifiers, size_semantics, syntactic_shape)


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

    def test_dominance_is_never_claimed(self):
        # Presence of a comparison is not proof it guards this copy.
        self.assertEqual(self._row()["inferences"]["conditions"]["dominance"],
                         "not-computed")

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
        fake_ctx = SimpleNamespace(
            store=SimpleNamespace(gl=None), candidate_bundle=bundle)
        with patch.object(mcp_server, "ctx", return_value=fake_ctx):
            payload = mcp_server.call_tool(
                "candidates", {"constructor_id": "memory.copy.capacity", "limit": 1},
                format="json")
        decoded = __import__("json").loads(payload)
        self.assertTrue(decoded["applied"])
        self.assertEqual(decoded["returned"], 1)
        self.assertEqual(decoded["total"], 2)


if __name__ == "__main__":
    unittest.main()
