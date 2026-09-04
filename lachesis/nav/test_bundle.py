from __future__ import annotations

import unittest

from . import bundle


class OrderPathTests(unittest.TestCase):
    def _nodes(self, *ids):
        return [{"id": i} for i in ids]

    def test_linear_cone_orders_origin_to_sink(self):
        nodes = self._nodes("a", "b", "sink")
        edges = [{"src": "a", "tgt": "b"}, {"src": "b", "tgt": "sink"}]
        self.assertEqual(bundle._order_path(nodes, edges, "sink"),
                         ["a", "b", "sink"])

    def test_accepts_source_target_edge_spelling(self):
        # path_shape emits source/target; sources_of emits src/tgt. Both order.
        nodes = self._nodes("a", "b", "sink")
        edges = [{"source": "a", "target": "b"}, {"source": "b", "target": "sink"}]
        self.assertEqual(bundle._order_path(nodes, edges, "sink"),
                         ["a", "b", "sink"])

    def test_branch_keeps_the_longest_landing_chain(self):
        nodes = self._nodes("a", "b", "c", "sink")
        edges = [{"src": "a", "tgt": "b"}, {"src": "b", "tgt": "sink"},
                 {"src": "c", "tgt": "sink"}]
        self.assertEqual(bundle._order_path(nodes, edges, "sink"),
                         ["a", "b", "sink"])

    def test_disconnected_cone_falls_back_to_sink_alone(self):
        nodes = self._nodes("x", "sink")
        edges = []
        self.assertEqual(bundle._order_path(nodes, edges, "sink"), ["sink"])

    def test_cycle_does_not_hang(self):
        nodes = self._nodes("a", "b", "sink")
        edges = [{"src": "a", "tgt": "b"}, {"src": "b", "tgt": "a"},
                 {"src": "b", "tgt": "sink"}]
        path = bundle._order_path(nodes, edges, "sink")
        self.assertEqual(path[-1], "sink")
        self.assertEqual(len(path), len(set(path)))


class EdgeFlagTests(unittest.TestCase):
    def test_alias_edge(self):
        self.assertEqual(bundle._edge_flags({"reason": "alias-via-heap"}), (True, False))

    def test_dynamic_edge(self):
        self.assertEqual(bundle._edge_flags({"kind": "DYNAMIC_INPUT"}), (False, True))

    def test_plain_edge(self):
        self.assertEqual(
            bundle._edge_flags({"kind": "VALUE_FLOWS_TO", "reason": "argument-value"}),
            (False, False))


class FindingIdTests(unittest.TestCase):
    def test_is_64_hex(self):
        fid = bundle._finding_id("injection.query", "db/query.py", "execute")
        self.assertEqual(len(fid), 64)
        int(fid, 16)  # raises if not hex

    def test_line_independent_and_basename_only(self):
        # Same semantic sink through an absolute vs relative path == same id.
        a = bundle._finding_id("injection.query", "/tmp/proj/db/query.py", "execute")
        b = bundle._finding_id("injection.query", "query.py", "execute")
        self.assertEqual(a, b)

    def test_distinct_sinks_differ(self):
        a = bundle._finding_id("injection.query", "query.py", "execute")
        b = bundle._finding_id("memory.copy", "buf.c", "memcpy")
        self.assertNotEqual(a, b)


class StepsFromPathTests(unittest.TestCase):
    def test_roles_origin_transform_sink(self):
        steps = bundle._steps_from_path(
            ["a", "b", "sink"], {"a", "b", "sink"},
            [{"src": "b", "tgt": "sink", "kind": "DYNAMIC_INPUT"}])
        self.assertEqual([s["role"] for s in steps], ["origin", "transform", "sink"])
        self.assertEqual(steps[-1]["edge"], {"alias": False, "dynamic": True})

    def test_lone_node_is_sink(self):
        steps = bundle._steps_from_path(["sink"], {"sink"}, [])
        self.assertEqual(steps, [{"node_id": "sink", "role": "sink"}])

    def test_drops_nodes_absent_from_pool(self):
        steps = bundle._steps_from_path(["a", "ghost", "sink"], {"a", "sink"}, [])
        self.assertEqual([s["node_id"] for s in steps], ["a", "sink"])


class RelativizeTests(unittest.TestCase):
    def test_strips_shared_absolute_root(self):
        nodes = {
            "a": {"id": "a", "file": "/tmp/proj/src/foo.c"},
            "b": {"id": "b", "file": "/tmp/proj/src/bar.c"},
        }
        bundle._relativize_files(nodes)
        self.assertEqual(nodes["a"]["file"], "foo.c")
        self.assertEqual(nodes["b"]["file"], "bar.c")

    def test_keeps_nested_structure_below_root(self):
        nodes = {
            "a": {"id": "a", "file": "/tmp/proj/a/foo.c"},
            "b": {"id": "b", "file": "/tmp/proj/b/bar.c"},
        }
        bundle._relativize_files(nodes)
        self.assertEqual(nodes["a"]["file"], "a/foo.c")
        self.assertEqual(nodes["b"]["file"], "b/bar.c")

    def test_relative_paths_left_untouched(self):
        nodes = {"a": {"id": "a", "file": "already/rel.c"}}
        bundle._relativize_files(nodes)
        self.assertEqual(nodes["a"]["file"], "already/rel.c")

    def test_missing_file_is_safe(self):
        nodes = {"a": {"id": "a", "file": None}, "b": {"id": "b"}}
        bundle._relativize_files(nodes)  # no raise

    def test_location_relativize(self):
        findings = [{"locations": [{"file": "/tmp/proj/a/foo.c"},
                                   {"file": "/tmp/proj/b/bar.c"}]}]
        bundle._relativize_locations(findings)
        self.assertEqual(findings[0]["locations"][0]["file"], "a/foo.c")
        self.assertEqual(findings[0]["locations"][1]["file"], "b/bar.c")


class ValidateTests(unittest.TestCase):
    def _finding(self, fid=None):
        return {
            "finding_id": fid or ("a" * 64),
            "status": "lead",
            "analysis": {"projection": "candidate-reachability",
                         "confidence": "high", "limitations": []},
            "locations": [{"file": "db/query.py", "line": 5, "role": "sink"}],
            "witness": {"steps": [{"node_id": "a", "role": "origin"},
                                  {"node_id": "sink", "role": "sink"}],
                        "guards": {}},
        }

    def _bundle(self):
        return {
            "format": "lachesis-explorer-bundle",
            "bundle_version": "1.0",
            "evidence_manifest": {"engine_sha": "e", "catalog_sha": "c",
                                  "toolchain_fingerprint": "t"},
            "findings": [self._finding()],
            "graph": {
                "nodes": [{"id": "a"}, {"id": "sink"}],
                "edges": [{"source": "a", "target": "sink"}],
            },
        }

    def test_valid_bundle_passes(self):
        bundle.validate(self._bundle())  # no raise

    def test_empty_nodes_rejected(self):
        b = self._bundle()
        b["graph"]["nodes"] = []
        with self.assertRaises(ValueError):
            bundle.validate(b)

    def test_empty_findings_rejected(self):
        b = self._bundle()
        b["findings"] = []
        with self.assertRaises(ValueError):
            bundle.validate(b)

    def test_bad_finding_id_rejected(self):
        b = self._bundle()
        b["findings"][0]["finding_id"] = "short"
        with self.assertRaises(ValueError):
            bundle.validate(b)

    def test_duplicate_finding_id_rejected(self):
        b = self._bundle()
        b["findings"].append(self._finding())
        with self.assertRaises(ValueError):
            bundle.validate(b)

    def test_duplicate_node_id_rejected(self):
        b = self._bundle()
        b["graph"]["nodes"].append({"id": "a"})
        with self.assertRaises(ValueError):
            bundle.validate(b)

    def test_step_referencing_unknown_node_rejected(self):
        b = self._bundle()
        b["findings"][0]["witness"]["steps"][0]["node_id"] = "ghost"
        with self.assertRaises(ValueError):
            bundle.validate(b)

    def test_missing_projection_rejected(self):
        b = self._bundle()
        b["findings"][0]["analysis"]["projection"] = ""
        with self.assertRaises(ValueError):
            bundle.validate(b)

    def test_guards_must_be_object(self):
        b = self._bundle()
        b["findings"][0]["witness"]["guards"] = []
        with self.assertRaises(ValueError):
            bundle.validate(b)

    def test_empty_witness_steps_rejected(self):
        b = self._bundle()
        b["findings"][0]["witness"]["steps"] = []
        with self.assertRaises(ValueError):
            bundle.validate(b)

    def test_manifest_missing_digest_rejected(self):
        b = self._bundle()
        del b["evidence_manifest"]["engine_sha"]
        with self.assertRaises(ValueError):
            bundle.validate(b)

    def test_edge_referencing_unknown_node_rejected(self):
        b = self._bundle()
        b["graph"]["edges"].append({"source": "a", "target": "ghost"})
        with self.assertRaises(ValueError):
            bundle.validate(b)


class GraphFirstBundleTests(unittest.TestCase):
    def _legacy_bundle(self):
        return {
            "meta": {"repo": "GNOME/libxml2", "lang": "c", "commit": "abc", "loc": 42},
            "graph": {
                "nodes": [
                    {"id": "source", "kind": "parameter", "file": "src/a.c",
                     "line": 3, "label": "input", "snippet": "input"},
                    {"id": "sink", "kind": "call", "file": "src/a.c",
                     "line": 8, "label": "execute", "snippet": "execute(input)"},
                ],
                "edges": [{"source": "source", "target": "sink", "kind": "VALUE_FLOWS_TO"}],
            },
            "findings": [{
                "finding_id": "a" * 64,
                "display_name": "input → execute",
                "result_summary": "A value reaches the call.",
                "analysis": {"confidence": "high", "limitations": []},
                "witness": {"steps": [
                    {"node_id": "source", "role": "origin"},
                    {"node_id": "sink", "role": "sink"},
                ]},
            }],
        }

    def test_graph_first_uses_v2_contract_and_supported_source_placeholders(self):
        result = bundle._graph_first_bundle(
            self._legacy_bundle(), repo="GNOME/libxml2", commit="abc", lang="c", indexed_nodes=99)
        self.assertEqual(result["schema_version"], "2.0")
        self.assertEqual(result["meta"]["indexed_nodes"], 99)
        self.assertEqual(len(result["paths"]["values"]), 1)
        self.assertIn("{revision}", result["meta"]["source_url_template"])
        self.assertNotIn("{owner}", result["meta"]["source_url_template"])
        self.assertNotIn("{repo}", result["meta"]["source_url_template"])

    def test_graph_first_rejects_invalid_path_reference(self):
        legacy = self._legacy_bundle()
        legacy["findings"][0]["witness"]["steps"][1]["node_id"] = "missing"
        with self.assertRaises(ValueError):
            bundle._graph_first_bundle(
                legacy, repo="GNOME/libxml2", commit="abc", lang="c", indexed_nodes=2)


if __name__ == "__main__":
    unittest.main()
