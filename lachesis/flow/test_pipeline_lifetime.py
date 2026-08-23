import unittest

from .pipeline import _DEFAULT_LIFETIME_ENGINE, _lifetime_slice, _select_lifetime_leads


class PipelineLifetimeTests(unittest.TestCase):
    def test_object_identity_is_the_default_lifetime_engine(self):
        self.assertEqual(_DEFAULT_LIFETIME_ENGINE, "object")

    def setUp(self):
        self.reach = {"pattern": "relational", "entry": "f", "line": 1}
        self.leak = {"pattern": "leak", "entry": "f", "line": 2}
        self.legacy = {"pattern": "double-free", "entry": "f", "line": 3,
                       "var": "name-keyed"}
        self.object = {"pattern": "use-after-free", "entry": "f", "line": 4,
                       "var": "object-keyed"}

    def test_shadow_preserves_public_leads_and_reports_difference(self):
        leads, diff = _select_lifetime_leads(
            [self.reach, self.leak, self.legacy], [self.object], "shadow")
        self.assertEqual(leads, [self.reach, self.leak, self.legacy])
        self.assertEqual((diff["legacy_only"], diff["object_only"]), (1, 1))

    def test_object_replaces_only_double_free_and_uaf_families(self):
        leads, _ = _select_lifetime_leads(
            [self.reach, self.leak, self.legacy], [self.object], "object")
        self.assertEqual(leads, [self.reach, self.leak, self.object])

    def test_same_site_ignores_renderer_specific_variable_spelling(self):
        object_lead = dict(self.legacy, var="decl-id:*field")
        _, diff = _select_lifetime_leads([self.legacy], [object_lead], "shadow")
        self.assertEqual((diff["legacy_only"], diff["object_only"]), (0, 0))

    def test_object_mode_keeps_legacy_leads_for_uncovered_functions(self):
        uncovered = dict(self.legacy, entry="too_large")
        unsafe_object = dict(self.object, entry="too_large")
        leads, _ = _select_lifetime_leads(
            [self.legacy, uncovered], [self.object, unsafe_object], "object",
            covered_entries={"f"})
        self.assertEqual(leads, [self.object, uncovered])

    def test_object_flow_drops_only_the_tainted_object_not_the_whole_function(self):
        # `f` is covered (object-trusted) but one of its objects flows into an unknown
        # callee. Only the lead on that object is dropped; the sibling lead survives.
        tainted = dict(self.object, root="escapes", var="escapes", line=5)
        clean = dict(self.object, root="safe", var="safe", line=6)
        leads, _ = _select_lifetime_leads(
            [], [tainted, clean], "object",
            covered_entries={"f"}, object_flow={"f": ["escapes"]})
        self.assertEqual(leads, [clean])


    def test_lifetime_slice_keeps_callers_and_drops_unrelated_functions(self):
        functions = {
            "alloc": {"events": [{"kind": "alloc"}]},
            "caller": {"events": []},
            "unrelated": {"events": []},
        }
        successors = {"caller": ["alloc"], "alloc": [], "unrelated": []}
        self.assertEqual(set(_lifetime_slice(functions, successors)), {"alloc", "caller"})

    def test_empty_source_artifacts_do_not_seed_lifetime_slice(self):
        functions = {
            "empty": {"source_reachable": True},
            "wrapper": {"source_reachable": True, "calls": [{"callee": "alloc"}]},
            "alloc": {"events": [{"kind": "alloc"}]},
        }
        successors = {"empty": [], "wrapper": ["alloc"], "alloc": []}
        self.assertEqual(set(_lifetime_slice(functions, successors)), {"wrapper", "alloc"})

    def test_source_reachable_parameter_function_is_not_dropped_before_semantic_pass(self):
        functions = {
            "pointer_only": {"source_reachable": True, "params": ["buffer"],
                              "file": "fixture.c", "line": 10},
        }
        self.assertEqual(set(_lifetime_slice(functions, {"pointer_only": []})),
                         {"pointer_only"})


if __name__ == "__main__":
    unittest.main()
