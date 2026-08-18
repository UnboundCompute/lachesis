"""Acceptance checks for the data-driven detector: substrate, capacity seam, adapter.

The adapter tests run on a synthetic in-memory graph with an INJECTED recipe, so they
need no atropos checkout and no kuzu store -- they pin the class-routing and the one
soundness property that matters: a relational lead requires taint AND an unbounded
capacity, so a tainted copy whose capacity is unproven does NOT fire.
"""
from __future__ import annotations

import unittest

from lachesis.detect import substrate
from lachesis.detect.adapter import LachesisGraph, report
from lachesis.detect.capacity import capacity_bounds
from lachesis.detect.catalog import Detector


def _node(node_id, kind, label, **props):
    return {"id": node_id, "kind": kind, "label": label, "properties": props}


def _edge(source, target, kind):
    return {"source": source, "target": target, "kind": kind, "properties": {}}


# One catalogued kind per evaluator, plus a role bridge -- injected so the tests are
# hermetic (the real tables live in atropos and are checked by atropos's own suite).
RECIPE = {"sql-injection": "reachability", "buffer-size": "relational",
          "buffer-write": "relational", "weak-crypto": "presence"}
BRIDGE = {"database": "sql-injection"}


def _detector():
    return Detector(kind_evaluator=dict(RECIPE), role_bridge=dict(BRIDGE),
                    vocabulary="generic-security-roles")


def fixture_graph():
    """A graph exercising every class:

      * memcpy(dst, src, 128) into ``char[64]`` with a tainted size  -> relational fires
        (taint AND exceeds-capacity).
      * memcpy(d2, s2, n2) into ``char *`` with a tainted size       -> suppressed
        (tainted, but capacity unproven -> value_bound None).
      * query(db, arg) role sink with a tainted argument             -> reachability fires.
      * an untainted weak-crypto sink                                -> presence fires.
    """
    return {
        "nodes": [
            # -- relational: fires --
            _node("call:cp", "call", "memcpy(dst, src, 128)", callee="memcpy",
                  owner_function_id="fn:a", start_line=1),
            _node("v:size", "expression", "128"),
            _node("v:dst", "expression", "dst", type="char[64]"),
            _node("sink:cp-size", "sink", "buffer-size", fact_origin="atropos-model",
                  sink_kind="buffer-size", model_id="m.size", value_id="v:size",
                  callsite_id="call:cp", access_path="Argument[2]", cwe=["CWE-787"]),
            _node("sink:cp-dst", "sink", "buffer-write", fact_origin="atropos-model",
                  sink_kind="buffer-write", model_id="m.dst", value_id="v:dst",
                  callsite_id="call:cp", access_path="Argument[0]", cwe=["CWE-787"]),
            # -- relational: suppressed (pointer dest -> no capacity) --
            _node("call:cp2", "call", "memcpy(d2, s2, n2)", callee="memcpy",
                  owner_function_id="fn:b", start_line=2),
            _node("v:size2", "expression", "n2"),
            _node("v:dst2", "expression", "d2", type="char *"),
            _node("sink:cp2-size", "sink", "buffer-size", fact_origin="atropos-model",
                  sink_kind="buffer-size", model_id="m.size2", value_id="v:size2",
                  callsite_id="call:cp2", access_path="Argument[2]", cwe=["CWE-787"]),
            _node("sink:cp2-dst", "sink", "buffer-write", fact_origin="atropos-model",
                  sink_kind="buffer-write", model_id="m.dst2", value_id="v:dst2",
                  callsite_id="call:cp2", access_path="Argument[0]", cwe=["CWE-787"]),
            # -- reachability: role sink with a tainted argument --
            _node("call:q", "call", "query(db, arg)", callee="query",
                  owner_function_id="fn:c", start_line=3),
            _node("v:arg", "expression", "arg"),
            _node("sink:q", "sink", "database", fact_origin="compiler",
                  sink_kind="database"),
            # -- presence: untainted weak-crypto call --
            _node("v:key", "expression", "key"),
            _node("sink:md5", "sink", "weak-crypto", fact_origin="atropos-model",
                  sink_kind="weak-crypto", model_id="m.md5", value_id="v:key"),
            # -- taint sources --
            _node("src:1", "source", "source:request", fact_origin="atropos-model",
                  source_kind="request-body", value_id="p:1"),
            _node("p:1", "expression", "p1"),
            _node("src:2", "source", "source:request", fact_origin="atropos-model",
                  source_kind="request-body", value_id="p:2"),
            _node("p:2", "expression", "p2"),
            _node("src:3", "source", "source:request", fact_origin="atropos-model",
                  source_kind="request-body", value_id="p:3"),
            _node("p:3", "expression", "p3"),
        ],
        "edges": [
            # taint reaches each sink value / argument
            _edge("src:1", "p:1", "TAINT_SOURCE"), _edge("p:1", "v:size", "VALUE_FLOWS_TO"),
            _edge("src:2", "p:2", "TAINT_SOURCE"), _edge("p:2", "v:size2", "VALUE_FLOWS_TO"),
            _edge("src:3", "p:3", "TAINT_SOURCE"), _edge("p:3", "v:arg", "VALUE_FLOWS_TO"),
            # role sink (C shape): sink -> call, call -> argument
            _edge("sink:q", "call:q", "TAINT_SINK"),
            _edge("call:q", "v:arg", "HAS_ARGUMENT"),
        ],
    }


class SubstrateTest(unittest.TestCase):
    def test_reachability_is_taint_alone(self):
        f = lambda t: substrate.substrate("x", tainted=t, value_bound=None)
        self.assertTrue(substrate.EVALUATORS["reachability"](f(True)))
        self.assertFalse(substrate.EVALUATORS["reachability"](f(False)))

    def test_relational_needs_taint_and_unbounded(self):
        def f(t, b, g=None):
            return substrate.substrate("x", tainted=t, value_bound=b, guard=g)
        ev = substrate.EVALUATORS["relational"]
        self.assertTrue(ev(f(True, "unbounded")))
        self.assertFalse(ev(f(True, "bounded")))   # bounded length is normal
        self.assertFalse(ev(f(True, None)))        # no capacity evidence -> no lead
        self.assertFalse(ev(f(False, "unbounded")))  # unbounded constant is normal
        # a copy inside a size-testing branch is checked -> suppressed even if unbounded
        self.assertFalse(ev(f(True, "unbounded", "guarded-region")))
        # fall-through / none-observed do not suppress the size lead
        self.assertTrue(ev(f(True, "unbounded", "fall-through")))

    def test_presence_ignores_taint(self):
        ev = substrate.EVALUATORS["presence"]
        self.assertTrue(ev(substrate.substrate("x", False, None)))

    def test_missing_guard_fires_on_fall_through_only(self):
        ev = substrate.EVALUATORS["missing-guard"]
        # taint-independent: fires purely on the fall-through control-flow shape
        self.assertTrue(ev(substrate.substrate("x", False, None, guard="fall-through")))
        self.assertFalse(ev(substrate.substrate("x", True, "unbounded", guard="guarded-region")))
        self.assertFalse(ev(substrate.substrate("x", True, "unbounded", guard="none-observed")))
        self.assertFalse(ev(substrate.substrate("x", True, "unbounded", guard=None)))

    def test_evaluate_returns_empty_for_unrecipe_kind(self):
        self.assertEqual(substrate.evaluate("unknown-kind", {"tainted": True}, RECIPE), [])

    def test_evaluate_returns_list_of_fired_evaluators(self):
        # a list-valued recipe fires several patterns for one occurrence
        recipe = {"mem": ["relational", "missing-guard"]}
        both = substrate.substrate("mem", tainted=True, value_bound="unbounded",
                                   guard="fall-through")
        self.assertEqual(set(substrate.evaluate("mem", both, recipe)),
                         {"relational", "missing-guard"})
        # only relational fires when there is no fall-through
        only_rel = substrate.substrate("mem", tainted=True, value_bound="unbounded")
        self.assertEqual(substrate.evaluate("mem", only_rel, recipe), ["relational"])


class CapacityBoundsTest(unittest.TestCase):
    def test_fixed_array_is_unbounded_pointer_is_absent(self):
        bounds = capacity_bounds(fixture_graph())
        # char[64] with a literal-128 copy -> exceeds -> both obligation values unbounded
        self.assertEqual(bounds.get("v:size"), "unbounded")
        self.assertEqual(bounds.get("v:dst"), "unbounded")
        # char* destination -> capacity unproven -> no bound recorded
        self.assertNotIn("v:size2", bounds)
        self.assertNotIn("v:dst2", bounds)


class AdapterLeadsTest(unittest.TestCase):
    def setUp(self):
        self.leads = LachesisGraph(fixture_graph(), detector=_detector()).leads()
        self.by_ev = {}
        for ld in self.leads:
            self.by_ev.setdefault(ld["evaluator"], []).append(ld)

    def test_reachability_fires_on_tainted_role_sink(self):
        got = self.by_ev.get("reachability", [])
        self.assertEqual([ld["kind"] for ld in got], ["sql-injection"])

    def test_relational_fires_only_on_taint_and_unbounded(self):
        got = self.by_ev.get("relational", [])
        sinks = {ld["sink"] for ld in got}
        self.assertIn("sink:cp-size", sinks)       # tainted + unbounded
        self.assertNotIn("sink:cp2-size", sinks)   # tainted but capacity unproven
        self.assertNotIn("sink:cp2-dst", sinks)

    def test_presence_fires_untainted(self):
        got = self.by_ev.get("presence", [])
        self.assertEqual([ld["kind"] for ld in got], ["weak-crypto"])

    def test_every_lead_carries_its_vocabulary(self):
        self.assertTrue(all(ld["vocabulary"] in
                            ("generic-security-roles", "atropos-model") for ld in self.leads))


class ReportTest(unittest.TestCase):
    """report() censuses over the WHOLE graph and narrows leads to a filter."""

    def test_census_counts_all_and_filter_narrows(self):
        full = report(fixture_graph(), detector=_detector())
        # census is over every fired lead, independent of any filter
        self.assertEqual(full["census"]["total"], len(full["leads"]))
        self.assertEqual(set(full["census"]["by_evaluator"]),
                         {"reachability", "relational", "presence"})
        # kinds counted include both the fired reachability and relational/presence kinds
        self.assertEqual(full["census"]["by_kind"].get("weak-crypto"), 1)

        rel = report(fixture_graph(), detector=_detector(), evaluator="relational")
        # filtered rows are relational only, but the census still reports the whole graph
        self.assertTrue(rel["leads"])
        self.assertTrue(all(ld["evaluator"] == "relational" for ld in rel["leads"]))
        self.assertEqual(rel["census"]["total"], full["census"]["total"])

    def test_kind_filter(self):
        got = report(fixture_graph(), detector=_detector(), kind="weak-crypto")
        self.assertTrue(got["leads"])
        self.assertTrue(all(ld["kind"] == "weak-crypto" for ld in got["leads"]))


if __name__ == "__main__":
    unittest.main()
