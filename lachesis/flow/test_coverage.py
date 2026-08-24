import json
import tempfile
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

    def test_callback_argument_is_a_forward_coverage_edge(self):
        functions = {
            "entry": {"callers": [], "calls": [
                {"callee": "dispatch", "args": [{"pos": 0, "root": "handler"}]},
            ]},
            "dispatch": {"params": ["callback"], "callers": ["entry"]},
            "handler": {"callers": []},
            "deep": {"callers": ["handler"]},
        }
        plan = CoverageScheduler(functions, {
            "entry": ["dispatch"], "dispatch": [], "handler": ["deep"], "deep": [],
        }).plan(["deep"])
        region = plan.for_target("deep")
        self.assertEqual(region.sources, ("entry",))
        self.assertIn(("deep", "entry"), region.state_keys)

    def test_successor_graph_is_authoritative_when_callers_metadata_is_absent(self):
        functions = {"entry": {}, "deep": {}}
        plan = CoverageScheduler(functions, {"entry": ["deep"], "deep": []}).plan()
        self.assertEqual(plan.for_target("deep").sources, ("entry",))
        self.assertNotIn(("deep", "deep"), plan.state_keys)

    def test_catalogued_sources_do_not_hide_other_external_roots(self):
        functions = {
            "catalog_entry": {
                "source_sites": [{"node": "read_site", "callee": "read"}],
                "callers": [],
            },
            "plain_entry": {"callers": []},
            "catalog_deep": {"callers": ["catalog_entry"]},
            "plain_deep": {"callers": ["plain_entry"]},
        }
        plan = CoverageScheduler(functions, {
            "catalog_entry": ["catalog_deep"], "catalog_deep": [],
            "plain_entry": ["plain_deep"], "plain_deep": [],
        }).plan()
        self.assertEqual(plan.for_target("plain_deep").sources, ("plain_entry",))
        self.assertEqual(plan.for_target("catalog_deep").sources, ("catalog_entry",))

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

    def test_source_sites_create_distinct_context_keys(self):
        functions = {
            "source": {
                "source_sites": [
                    {"node": "site_b", "callee": "read", "line": 20},
                    {"node": "site_a", "callee": "read", "line": 10},
                ],
                "callers": [],
            },
            "deep": {"callers": ["source"]},
        }
        plan = CoverageScheduler(functions, {"source": ["deep"], "deep": []}).plan(["deep"])
        self.assertEqual(plan.context_keys, (
            ("deep", "source", "site_a"),
            ("deep", "source", "site_b"),
            ("source", "source", "site_a"),
            ("source", "source", "site_b"),
        ))

    def test_source_calls_create_distinct_context_keys(self):
        functions = {
            "source": {
                "source_calls": [
                    {"node": "call_b", "callee": "read_b"},
                    {"node": "call_a", "callee": "read_a"},
                ],
            },
            "deep": {},
        }
        plan = CoverageScheduler(functions, {
            "source": ["deep"], "deep": [],
        }).plan(["deep"])
        self.assertEqual(plan.context_keys, (
            ("deep", "source", "call_a"),
            ("deep", "source", "call_b"),
            ("source", "source", "call_a"),
            ("source", "source", "call_b"),
        ))

    def test_fragment_store_tracks_source_state_keys(self):
        store = FragmentStore()
        store.mark_covered([("worker", "source")])
        self.assertEqual(store.uncovered([("worker", "source"), ("worker", "other")]),
                         (("worker", "other"),))

    def test_coverage_ledger_round_trips_states_and_contexts(self):
        store = FragmentStore()
        store.mark_covered([("worker", "source")])
        store.mark_contexts_covered([("worker", "source", "site_a")])
        restored = FragmentStore()
        restored.restore_coverage(store.coverage_snapshot())
        self.assertEqual(restored.coverage_snapshot(), store.coverage_snapshot())

    def test_fragment_snapshot_round_trips_graph_and_coverage(self):
        functions = {"source": {}, "worker": {}}
        graph_key = {"nodes": ["source", "worker"]}
        semantic = SkeletonGraph(language="c")
        semantic.add_node("source:entry", fragment="source", source_site="site",
                          source_reachable=True)
        semantic.add_node("worker:entry", fragment="worker")
        semantic.add_edge("source:entry", "worker:entry")
        semantic.add_fragment("source", "source:entry", ("source:entry",))
        semantic.add_fragment("worker", "worker:entry", ("worker:entry",))
        semantic.source_reachable.add("source:entry")

        original = FragmentStore()
        original.put(functions, "c", graph_key, semantic,
                    coverage={"state_keys": [["worker", "source"]],
                              "context_keys": [["worker", "source", "site"]]})
        original.mark_covered([("worker", "source")])
        original.mark_contexts_covered([("worker", "source", "site")])
        json.dumps(original.snapshot())

        restored = FragmentStore()
        self.assertEqual(restored.restore_snapshot(
            original.snapshot(), functions, "c", graph_key), 1)
        self.assertEqual(restored.coverage_snapshot(), original.coverage_snapshot())
        cached = restored.get(
            functions, "c", graph_key,
            coverage={"state_keys": [["worker", "source"]],
                      "context_keys": [["worker", "source", "site"]]})
        self.assertEqual(set(cached.nodes), set(semantic.nodes))

        stale = FragmentStore()
        changed_functions = {"source": {}, "worker": {"changed": True}}
        self.assertEqual(stale.restore_snapshot(
            original.snapshot(), changed_functions, "c", graph_key), 0)
        self.assertEqual(stale.covered_states, set())

    def test_snapshot_sidecar_is_atomic_and_loadable(self):
        functions = {"source": {}, "worker": {}}
        graph_key = {"nodes": ["source", "worker"]}
        semantic = SkeletonGraph(language="c")
        semantic.add_node("source:entry", fragment="source")
        semantic.add_node("worker:entry", fragment="worker")
        semantic.add_edge("source:entry", "worker:entry")
        semantic.add_fragment("source", "source:entry", ("source:entry",))
        semantic.add_fragment("worker", "worker:entry", ("worker:entry",))
        original = FragmentStore()
        original.put(functions, "c", graph_key, semantic,
                    coverage={"state_keys": [["worker", "source"]]})
        with tempfile.TemporaryDirectory() as directory:
            path = f"{directory}/semantic.pass3.json"
            original.save_snapshot(path)
            restored = FragmentStore()
            self.assertEqual(restored.load_snapshot(
                path, functions, "c", graph_key), 1)
            self.assertIsNotNone(restored.get(
                functions, "c", graph_key,
                coverage={"state_keys": [["worker", "source"]]}))

    def test_snapshot_does_not_restore_unmaterialized_state_as_covered(self):
        functions = {"source": {}, "worker": {}}
        graph_key = {"nodes": ["source", "worker"]}
        semantic = SkeletonGraph(language="c")
        semantic.add_node("source:entry", fragment="source")
        semantic.add_node("worker:entry", fragment="worker")
        semantic.add_fragment("source", "source:entry", ("source:entry",))
        semantic.add_fragment("worker", "worker:entry", ("worker:entry",))
        original = FragmentStore()
        original.put(functions, "c", graph_key, semantic,
                    coverage={"state_keys": [["worker", "source"]]})
        original.mark_covered([("worker", "source")])

        restored = FragmentStore()
        self.assertEqual(restored.restore_snapshot(
            original.snapshot(), functions, "c", graph_key), 1)
        self.assertEqual(restored.covered_states, set())

    def test_fragment_cache_key_includes_coverage_states(self):
        store = FragmentStore()
        functions = {"worker": {}}
        first = store.key(functions, "c", coverage={"state_keys": [["worker", "a"]]})
        second = store.key(functions, "c", coverage={"state_keys": [["worker", "b"]]})
        self.assertNotEqual(first, second)

    def test_fragment_cache_key_includes_source_contexts(self):
        store = FragmentStore()
        functions = {"worker": {}}
        first = store.key(functions, "c", coverage={
            "state_keys": [["worker", "source"]],
            "context_keys": [["worker", "source", "site_a"]],
        })
        second = store.key(functions, "c", coverage={
            "state_keys": [["worker", "source"]],
            "context_keys": [["worker", "source", "site_b"]],
        })
        self.assertNotEqual(first, second)

    def test_fragment_cache_key_includes_heap_state_artifacts(self):
        store = FragmentStore()
        functions = {"worker": {}}
        first = store.key(functions, "c", state_artifacts={
            "worker": {"point_states": {"n1": ["heap-a"]}},
        })
        second = store.key(functions, "c", state_artifacts={
            "worker": {"point_states": {"n1": ["heap-b"]}},
        })
        self.assertNotEqual(first, second)

    def test_fragment_cache_fingerprint_is_order_independent_for_state_shapes(self):
        store = FragmentStore()
        first = store._fingerprint({
            "point_states": {"n1": {"facts": {"b", "a"}, "env": {"x": 1, "y": 2}}},
        })
        second = store._fingerprint({
            "point_states": {"n1": {"env": {"y": 2, "x": 1}, "facts": {"a", "b"}}},
        })
        self.assertEqual(first, second)

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

    def test_claus_emits_only_pending_source_cones(self):
        functions = {
            "source_a": {"callers": []},
            "worker_a": {"callers": ["source_a"]},
            "source_b": {"callers": []},
            "worker_b": {"callers": ["source_b"]},
        }
        successors = {
            "source_a": ["worker_a"], "worker_a": [],
            "source_b": ["worker_b"], "worker_b": [],
        }
        plan = CoverageScheduler(functions, successors).plan(
            ["worker_a", "worker_b"])
        fragment_store = FragmentStore()
        fragment_store.mark_covered([("source_a", "source_a"),
                                     ("worker_a", "source_a")])
        fragment_store.mark_contexts_covered([
            ("source_a", "source_a", "__entry__"),
            ("worker_a", "source_a", "__entry__"),
        ])
        captured = {}

        def build(_store, _functions, _successors, **kwargs):
            captured["work_functions"] = kwargs["work_functions"]
            return SkeletonGraph()

        with patch("lachesis.flow.emit.build_semantic_graph", side_effect=build):
            Claus(fragment_store).build(
                object(), functions, successors, coverage=plan)

        self.assertEqual(captured["work_functions"], {"source_b", "worker_b"})

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

    def test_claus_records_materialized_source_contexts(self):
        graph = SkeletonGraph()
        graph.add_node("source:site_a:event", fragment="source")
        graph.add_node("worker:entry", fragment="worker")
        graph.add_edge("source:site_a:event", "worker:entry")
        graph.add_fragment("source", "source:site_a:event", ("source:site_a:event",))
        graph.add_fragment("worker", "worker:entry", ("worker:entry",))
        graph.source_reachable.add("source:site_a:event")
        coverage = {"regions": [{
            "state_keys": [["worker", "source"]],
            "context_keys": [["worker", "source", "site_a"]],
        }], "state_keys": [["worker", "source"]],
            "context_keys": [["worker", "source", "site_a"]]}
        store = FragmentStore()
        with patch("lachesis.flow.emit.build_semantic_graph", return_value=graph):
            built = Claus(store).build(object(), {"worker": {}, "source": {}}, {},
                                       coverage=coverage)
        self.assertTrue(built.coverage["converged"])
        self.assertEqual(store.covered_contexts,
                         {("worker", "source", "site_a")})

    def test_source_contexts_do_not_match_by_colliding_node_id_substrings(self):
        graph = SkeletonGraph()
        graph.add_node("source:site_a:event", fragment="source",
                       source_site="site_a")
        graph.add_node("source:site_ab:event", fragment="source",
                       source_site="site_ab")
        graph.add_node("worker:entry", fragment="worker")
        graph.add_edge("source:site_a:event", "worker:entry")
        graph.add_fragment("source", "source:site_a:event",
                           ("source:site_a:event", "source:site_ab:event"))
        graph.add_fragment("worker", "worker:entry", ("worker:entry",))
        graph.source_reachable.update({"source:site_a:event", "source:site_ab:event"})
        store = FragmentStore()
        context = Claus(store)._materialized_contexts(
            graph, [("worker", "source", "site_a")])
        self.assertEqual(context, [("worker", "source", "site_a")])

    def test_incompatible_partial_cache_falls_back_instead_of_raising(self):
        store = FragmentStore()
        functions = {"worker": {}}
        graph = object()

        first = SkeletonGraph()
        first.add_node("worker:entry")
        first.add_fragment("worker", "worker:entry", ("worker:entry",))
        second = SkeletonGraph()
        second.add_node("worker:other")
        second.add_fragment("worker", "worker:other", ("worker:other",))
        store.put(functions, "c", graph, first,
                  coverage={"state_keys": [["worker", "a"]]})
        store.put(functions, "c", graph, second,
                  coverage={"state_keys": [["worker", "b"]]})
        self.assertIsNone(store.get(
            functions, "c", graph,
            coverage={"state_keys": [["worker", "a"], ["worker", "b"]]}))

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

    def test_materialization_starts_at_external_launch_nodes(self):
        graph = SkeletonGraph()
        for node, fragment in (("source:entry", "source"),
                               ("source:launch", "source"),
                               ("source:internal", "source"),
                               ("target:entry", "target")):
            graph.add_node(node, fragment=fragment)
        graph.add_edge("source:entry", "source:internal")
        graph.add_edge("source:entry", "source:launch")
        graph.add_edge("source:internal", "target:entry")
        graph.add_fragment("source", "source:entry", ("source:internal", "source:launch"))
        graph.add_fragment("target", "target:entry", ("target:entry",))
        graph.source_reachable.add("source:launch")

        self.assertEqual(
            Claus._materialized_states(graph, [("target", "source")]), [])


if __name__ == "__main__":
    unittest.main()
