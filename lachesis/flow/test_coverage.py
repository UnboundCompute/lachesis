import unittest
from unittest.mock import patch

from .coverage import CoverageScheduler
from .fragment_store import Claus, FragmentStore
from .semantic_graph import SkeletonGraph


class CoverageSchedulerTests(unittest.TestCase):
    def test_backtracks_to_external_source_and_explores_forward(self):
        functions = {
            "source": {"source_sites": [{"callee": "read"}], "callers": []},
            "bridge": {"callers": ["source"]},
            "deep": {"callers": ["bridge"]},
            "unrelated": {"callers": []},
        }
        plan = CoverageScheduler(functions, {
            "source": ["bridge"], "bridge": ["deep"], "deep": [], "unrelated": []
        }).plan(["deep"])
        region = plan.for_target("deep")
        self.assertEqual(region.sources, ("source",))
        self.assertEqual(region.functions, ("bridge", "deep", "source"))
        self.assertIn(("deep", "source"), region.state_keys)
        self.assertIn("unrelated", plan.uncovered_functions)
        self.assertEqual(plan.pending_regions([]), (region,))
        self.assertFalse(plan.converged([]))
        self.assertTrue(plan.converged(plan.state_keys))

    def test_structural_root_is_fallback_when_catalog_has_no_source(self):
        functions = {"entry": {"callers": []}, "deep": {"callers": ["entry"]}}
        plan = CoverageScheduler(functions, {"entry": ["deep"], "deep": []}).plan()
        self.assertEqual(plan.for_target("deep").sources, ("entry",))

    def test_fragment_store_tracks_source_state_keys(self):
        store = FragmentStore()
        store.mark_covered([("worker", "source")])
        self.assertEqual(store.uncovered([("worker", "source"), ("worker", "other")]),
                         (("worker", "other"),))

    def test_fragment_cache_key_includes_coverage_states(self):
        store = FragmentStore()
        functions = {"worker": {}}
        first = store.key(functions, "c", coverage={"state_keys": [["worker", "a"]]})
        second = store.key(functions, "c", coverage={"state_keys": [["worker", "b"]]})
        self.assertNotEqual(first, second)

    def test_fragment_cache_reuses_a_coverage_superset(self):
        store = FragmentStore()
        functions = {"worker": {}}
        graph = object()
        semantic = object()
        store.put(functions, "c", graph, semantic,
                  coverage={"state_keys": [["worker", "a"], ["worker", "b"]]})
        self.assertIs(
            store.get(functions, "c", graph,
                      coverage={"state_keys": [["worker", "a"]]}),
            semantic,
        )

    def test_fragment_cache_uses_content_not_transient_summary_identity(self):
        store = FragmentStore()
        functions = {"worker": {"events": [{"kind": "alloc"}]}}
        graph = object()
        semantic = object()
        store.put(functions, "c", graph, semantic,
                  summaries={"worker": [["alloc"]]},
                  coverage={"state_keys": [["worker", "a"]]})
        equivalent_functions = {"worker": {"events": [{"kind": "alloc"}]}}
        equivalent_summaries = {"worker": [["alloc"]]}
        self.assertIs(
            store.get(equivalent_functions, "c", graph,
                      summaries=equivalent_summaries,
                      coverage={"state_keys": [["worker", "a"]]}),
            semantic,
        )

    def test_claus_does_not_claim_skipped_fragments_are_covered(self):
        graph = SkeletonGraph()
        graph.add_node("source:entry", fragment="source")
        graph.add_node("worker:entry", fragment="worker")
        graph.add_node("skipped:entry", fragment="skipped")
        graph.add_edge("source:entry", "worker:entry")
        graph.add_fragment("source", "source:entry", ("source:entry",))
        graph.add_fragment("worker", "worker:entry", ("worker:entry",))
        graph.add_fragment("skipped", "skipped:entry", ("skipped:entry",))

        coverage = {"regions": [{"state_keys": [["worker", "source"],
                                                   ["skipped", "source"]]}]}
        fragment_store = FragmentStore()
        claus = Claus(fragment_store)
        with patch("lachesis.flow.emit.build_semantic_graph", return_value=graph):
            built = claus.build(object(), {"worker": {}, "skipped": {}}, {},
                                coverage=coverage)

        self.assertEqual(built.coverage["covered_states"], [["worker", "source"]])
        self.assertEqual(built.coverage["uncovered_states"], [["skipped", "source"]])
        self.assertFalse(built.coverage["converged"])

    def test_materialization_requires_a_valid_pushdown_return(self):
        graph = SkeletonGraph()
        for node, fragment in (("source:entry", "source"),
                               ("callee:entry", "callee"),
                               ("callee:exit", "callee"),
                               ("wrong:entry", "wrong")):
            graph.add_node(node, fragment=fragment)
        graph.add_edge("source:entry", "callee:entry", kind="call",
                       return_to="source:after")
        # This continuation does not match the pushed return site.  Ordinary
        # reachability would count it; coverage must not.
        graph.add_edge("callee:entry", "callee:exit")
        graph.add_edge("callee:exit", "wrong:entry", kind="return")
        for name, entry in (("source", "source:entry"), ("callee", "callee:entry"),
                            ("wrong", "wrong:entry")):
            graph.add_fragment(name, entry, (entry,))

        self.assertEqual(
            Claus._materialized_states(graph, [("wrong", "source")]), [])


if __name__ == "__main__":
    unittest.main()
