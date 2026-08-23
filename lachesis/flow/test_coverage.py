import unittest

from .coverage import CoverageScheduler


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

    def test_structural_root_is_fallback_when_catalog_has_no_source(self):
        functions = {"entry": {"callers": []}, "deep": {"callers": ["entry"]}}
        plan = CoverageScheduler(functions, {"entry": ["deep"], "deep": []}).plan()
        self.assertEqual(plan.for_target("deep").sources, ("entry",))


if __name__ == "__main__":
    unittest.main()
