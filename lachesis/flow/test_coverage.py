import unittest

from .coverage import CoverageScheduler
from .fragment_store import FragmentStore


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


if __name__ == "__main__":
    unittest.main()
