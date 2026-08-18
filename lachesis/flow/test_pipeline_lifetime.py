import unittest

from .pipeline import _DEFAULT_LIFETIME_ENGINE, _select_lifetime_leads


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
        leads, _ = _select_lifetime_leads(
            [self.legacy, uncovered], [self.object], "object", covered_entries={"f"})
        self.assertEqual(leads, [self.object, uncovered])


if __name__ == "__main__":
    unittest.main()
