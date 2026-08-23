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

    def test_multiple_sources_do_not_cross_product_forward_cones(self):
        functions = {
            "source_a": {"source_sites": [{"callee": "read_a"}], "callers": []},
            "source_b": {"source_sites": [{"callee": "read_b"}], "callers": []},
            "shared": {"callers": ["source_a", "source_b"]},
            "only_a": {"callers": ["source_a"]},
            "only_b": {"callers": ["source_b"]},
            "target": {"callers": ["only_a", "only_b", "shared"]},
        }
        plan = CoverageScheduler(functions, {
            "source_a": ["shared", "only_a"], "source_b": ["shared", "only_b"],
            "shared": ["target"], "only_a": ["target"], "only_b": ["target"],
            "target": [],
        }).plan(["target"])
        region = plan.for_target("target")
        self.assertEqual(region.sources, ("source_a", "source_b"))
        self.assertIn(("only_a", "source_a"), region.state_keys)
        self.assertIn(("only_b", "source_b"), region.state_keys)
        self.assertNotIn(("only_a", "source_b"), region.state_keys)
        self.assertNotIn(("only_b", "source_a"), region.state_keys)

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

    def test_fragment_cache_composes_disjoint_source_regions(self):
        store = FragmentStore()
        functions = {"worker": {}}
        graph = object()
        first = SkeletonGraph()
        first.add_node("worker:entry")
        first.add_node("worker:a")
        first.add_edge("worker:entry", "worker:a")
        first.add_fragment("worker", "worker:entry", ("worker:a",))
        second = SkeletonGraph()
        second.add_node("worker:entry")
        second.add_node("worker:b")
        second.add_edge("worker:entry", "worker:b")
        second.add_fragment("worker", "worker:entry", ("worker:b",))
        store.put(functions, "c", graph, first,
                  coverage={"state_keys": [["worker", "source_a"]]})
        store.put(functions, "c", graph, second,
                  coverage={"state_keys": [["worker", "source_b"]]})

        merged = store.get(
            functions, "c", graph,
            coverage={"state_keys": [["worker", "source_a"],
                                      ["worker", "source_b"]]})
        self.assertIsInstance(merged, SkeletonGraph)
        self.assertEqual(set(merged.nodes), {"worker:entry", "worker:a", "worker:b"})

    def test_claus_records_coverage_when_composed_cache_is_reused(self):
        store = FragmentStore()
        functions = {"source_a": {}, "source_b": {}, "worker": {}}
        graph = object()

        def partial(source, leaf):
            result = SkeletonGraph()
            result.add_node(f"{source}:entry", fragment=source)
            result.add_node("worker:entry", fragment="worker")
            result.add_node(leaf, fragment="worker")
            result.add_edge(f"{source}:entry", "worker:entry")
            result.add_edge("worker:entry", leaf)
            result.add_fragment(source, f"{source}:entry", (f"{source}:entry",))
            result.add_fragment("worker", "worker:entry", (leaf,))
            return result

        store.put(functions, "c", graph, partial("source_a", "worker:a"),
                  coverage={"state_keys": [["worker", "source_a"]]})
        store.put(functions, "c", graph, partial("source_b", "worker:b"),
                  coverage={"state_keys": [["worker", "source_b"]]})
        coverage = {"regions": [{"state_keys": [["worker", "source_a"],
                                                   ["worker", "source_b"]]}],
                    "state_keys": [["worker", "source_a"], ["worker", "source_b"]]}
        built = Claus(store).build(object(), functions, {}, graph=graph,
                                    coverage=coverage)
        self.assertTrue(built.coverage["converged"])
        self.assertEqual(store.covered_states,
                         {("worker", "source_a"), ("worker", "source_b")})

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
