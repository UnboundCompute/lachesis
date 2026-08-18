import unittest

from .pipeline import _select_lifetime_leads


class PipelineLifetimeTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
