"""The native temporal matcher owns the census for its families.

When the Rust matcher has run (its correlated findings ride the bind under
``native_temporal``), the temporal census must surface those confirmed
relations and suppress the pre-matcher per-dereference inventory that otherwise
emits one ``not-queried`` row per deref.  When the matcher has not run (the fast
structural path), the inventory still stands as the honest fallback.
"""
import unittest

from lachesis.planner.taxonomy import family_specs
from lachesis.planner.temporal_obligation import temporal_constructor


def _constructor(family_id):
    spec = next(s for s in family_specs()
                if s["family"] == family_id and s.get("temporal"))
    return temporal_constructor(spec)


def _graph_with_matcher():
    # One blanket read_storage node (what the inventory would enumerate) plus a
    # semantic-free native bind carrying two correlated findings on two families.
    return {
        "nodes": [{"id": "blanket", "event": {"kind": "read_storage", "line": 9}}],
        "native_temporal": {"functions": [
            {"id": "fn_a", "findings": [
                {"pattern": "double-free", "node": "free#2", "line": 55, "path": "buf"},
                {"pattern": "uaf.deref", "node": "read#7", "line": 60, "path": "obj->x"},
            ]},
        ]},
    }


class MatcherAuthoritativeTest(unittest.TestCase):
    def test_confirmed_finding_replaces_the_blanket_inventory(self):
        rows = _constructor("use-after-free")(_graph_with_matcher()).enumerate()["candidates"]
        # Exactly the one correlated uaf.deref -- the blanket read_storage node is
        # suppressed, not added alongside it.
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["handles"]["site_node_id"], "read#7")
        self.assertEqual(row["observations"]["line"], 60)
        self.assertEqual(row["observations"]["native_path"], "obj->x")

    def test_confirmed_relation_is_resolved_not_queried(self):
        row = _constructor("use-after-free")(_graph_with_matcher()).enumerate()["candidates"][0]
        self.assertEqual(row["inferences"], {
            "path_relation": "reachable", "same_object": "same",
            "same_generation": "same"})
        self.assertEqual(row["completeness"], "COMPLETE")
        self.assertEqual(row["rank"], 1.0)

    def test_capsule_carries_no_safety_verdict(self):
        row = _constructor("double-free")(_graph_with_matcher()).enumerate()["candidates"][0]
        forbidden = {"safe", "unsafe", "verdict", "state", "suppressed"}
        self.assertTrue(forbidden.isdisjoint(row))

    def test_findings_route_to_the_family_that_owns_the_pattern(self):
        graph = _graph_with_matcher()
        df = _constructor("double-free")(graph).enumerate()["candidates"]
        uaf = _constructor("use-after-free")(graph).enumerate()["candidates"]
        # double-free's pattern and use-after-free's ("uaf.deref") never cross over.
        self.assertEqual([r["handles"]["site_node_id"] for r in df], ["free#2"])
        self.assertEqual([r["handles"]["site_node_id"] for r in uaf], ["read#7"])

    def test_a_family_the_matcher_did_not_hit_is_empty_not_blanket(self):
        # null-deref shares read_storage triggers with use-after-free, so the
        # blanket path would flag the same node; with the matcher authoritative
        # and no null-deref finding, the family is honestly empty.
        rows = _constructor("null-deref")(_graph_with_matcher()).enumerate()["candidates"]
        self.assertEqual(rows, [])

    def test_confirmed_finding_resolves_its_file_from_the_location_map(self):
        # The bind attaches decl-id -> file:line (resolved from the Pass-1 store);
        # the confirmed lead must report it instead of ``file: None``, and its
        # handle must point at the real declaration, not the skeleton wrapper.
        graph = {
            "native_temporal": {
                "functions": [{"id": "native:skeleton:0:__entry__", "findings": [
                    {"pattern": "double-free", "node": "free#2", "line": 10,
                     "path": "buf", "function": "decl:bugs:double_free_bug"},
                ]}],
                "locations": {
                    "decl:bugs:double_free_bug": {"file": "/src/bugs.c", "line": 5},
                },
            },
        }
        row = _constructor("double-free")(graph).enumerate()["candidates"][0]
        self.assertEqual(row["observations"]["file"], "/src/bugs.c")
        self.assertEqual(row["observations"]["line"], 10)  # the free site, not decl
        self.assertEqual(row["handles"]["enclosing_function_id"],
                         "decl:bugs:double_free_bug")

    def test_finding_without_a_line_falls_back_to_the_declaration_line(self):
        graph = {
            "native_temporal": {
                "functions": [{"id": "w", "findings": [
                    {"pattern": "leak", "node": "exit", "line": None,
                     "path": "buf", "function": "decl:bugs:leak_fn"},
                ]}],
                "locations": {"decl:bugs:leak_fn": {"file": "/src/bugs.c",
                                                     "line": 30}},
            },
        }
        row = _constructor("leak")(graph).enumerate()["candidates"][0]
        self.assertEqual(row["observations"]["file"], "/src/bugs.c")
        self.assertEqual(row["observations"]["line"], 30)  # decl fallback

    def test_finding_resolving_to_a_non_c_file_is_dropped(self):
        # The native matcher is C-only, but semantic decl ids collide across
        # languages (equally named functions), so a decl id can resolve through
        # the store to a *non-C* declaration.  A C-memory verdict (double-free)
        # located in a Python file is that collision, not a real site, and must
        # not be surfaced -- it is a pure false positive to a reviewer.
        graph = {
            "native_temporal": {
                "functions": [{"id": "w", "findings": [
                    {"pattern": "double-free", "node": "free#2", "line": 38,
                     "path": "tmp", "function": "decl:build_helper:check"},
                ]}],
                "locations": {
                    "decl:build_helper:check":
                        {"file": "/src/scripts/build_helper.py", "line": 33},
                },
            },
        }
        rows = _constructor("double-free")(graph).enumerate()["candidates"]
        self.assertEqual(rows, [])

    def test_c_and_non_c_collisions_coexist_only_the_c_one_survives(self):
        # Two findings on one family: one resolves to a real C file (kept), one
        # to a Python file via an id collision (dropped).  The census must keep
        # exactly the C site.
        graph = {
            "native_temporal": {
                "functions": [{"id": "w", "findings": [
                    {"pattern": "double-free", "node": "free#c", "line": 10,
                     "path": "buf", "function": "decl:bugs:real_c"},
                    {"pattern": "double-free", "node": "free#py", "line": 38,
                     "path": "tmp", "function": "decl:script:collide"},
                ]}],
                "locations": {
                    "decl:bugs:real_c": {"file": "/src/bugs.c", "line": 5},
                    "decl:script:collide": {"file": "/src/tool.py", "line": 33},
                },
            },
        }
        rows = _constructor("double-free")(graph).enumerate()["candidates"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["observations"]["file"], "/src/bugs.c")
        self.assertEqual(rows[0]["completeness"], "COMPLETE")

    def test_finding_with_an_unresolved_location_is_not_dropped(self):
        # A ``None`` file is merely unresolved (no location row), not a proven
        # cross-language mis-resolution, so the C-only guard must leave it alone.
        graph = {
            "native_temporal": {
                "functions": [{"id": "w", "findings": [
                    {"pattern": "double-free", "node": "free#2", "line": 10,
                     "path": "buf", "function": "decl:bugs:unlocated"},
                ]}],
                "locations": {},
            },
        }
        rows = _constructor("double-free")(graph).enumerate()["candidates"]
        self.assertEqual(len(rows), 1)
        self.assertIsNone(rows[0]["observations"]["file"])

    def test_without_the_matcher_the_inventory_still_stands(self):
        graph = {"nodes": [{"id": "blanket",
                            "event": {"kind": "read_storage", "line": 9}}]}
        result = _constructor("use-after-free")(graph).enumerate()
        rows = result["candidates"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["inferences"]["path_relation"], "not-queried")
        self.assertEqual(result["census"]["by_status"], {"not-queried": 1})


if __name__ == "__main__":
    unittest.main()
