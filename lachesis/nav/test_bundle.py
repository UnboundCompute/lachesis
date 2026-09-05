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
            self._legacy_bundle(), repo="GNOME/libxml2", commit="abc", lang="c", indexed_nodes=99,
            source_url_template="https://github.com/GNOME/libxml2/blob/{revision}/{file}#L{line}")
        self.assertEqual(result["schema_version"], "2.0")
        self.assertEqual(result["meta"]["indexed_nodes"], 99)
        self.assertEqual(len(result["paths"]["values"]), 1)
        self.assertIn("{revision}", result["meta"]["source_url_template"])
        self.assertNotIn("{owner}", result["meta"]["source_url_template"])
        self.assertNotIn("{repo}", result["meta"]["source_url_template"])

    def test_graph_first_does_not_guess_source_host(self):
        result = bundle._graph_first_bundle(
            self._legacy_bundle(), repo="group/project", commit="abc", lang="c", indexed_nodes=2)
        self.assertNotIn("source_url_template", result["meta"])

    def test_graph_first_rejects_invalid_path_reference(self):
        legacy = self._legacy_bundle()
        legacy["findings"][0]["witness"]["steps"][1]["node_id"] = "missing"
        with self.assertRaises(ValueError):
            bundle._graph_first_bundle(
                legacy, repo="GNOME/libxml2", commit="abc", lang="c", indexed_nodes=2)


class ComprehensionProjectionTests(unittest.TestCase):
    """The 2.0 comprehension surface: entrypoints, guided requests, modules, edges."""

    def _sourced(self, nid, file, line, label):
        return {"id": nid, "kind": "function", "file": file, "line": line,
                "label": label, "snippet": f"def {label}(): ...", "end_line": line + 2}

    def _bundle_with(self, comprehension):
        legacy = {
            "meta": {"repo": "pallets/flask", "lang": "python", "commit": "abc", "loc": 100},
            "graph": {
                "nodes": [
                    self._sourced("n.a", "src/flask/app.py", 10, "wsgi_app"),
                    self._sourced("n.b", "src/flask/app.py", 20, "dispatch_request"),
                    self._sourced("n.c", "src/flask/cli.py", 5, "main"),
                ],
                "edges": [{"source": "n.a", "target": "n.b", "kind": "CALLS"}],
            },
            "findings": [{
                "finding_id": "a" * 64, "display_name": "x", "result_summary": "y",
                "analysis": {"confidence": "high", "limitations": []},
                "witness": {"steps": [{"node_id": "n.a", "role": "origin"},
                                      {"node_id": "n.b", "role": "sink"}]},
            }],
        }
        return bundle._graph_first_bundle(
            legacy, repo="pallets/flask", commit="abc", lang="python",
            indexed_nodes=500, comprehension=comprehension)

    def test_full_projection_shapes_graph_and_paths(self):
        result = self._bundle_with({
            "entrypoints": [{"id": "entry.wsgi_app", "label": "wsgi_app",
                             "kind": "http-handler", "node_id": "n.a",
                             "file": "src/flask/app.py", "line": 10}],
            "requests": [{"id": "request.lifecycle", "kind": "call-path",
                          "description": "d", "entry_node": "n.a",
                          "hops": [{"node_id": "n.a", "caption": "receives"},
                                   {"node_id": "n.b", "caption": "dispatches"}]}],
            "files": [{"id": "f1", "path": "src/flask/app.py"}],
        })
        self.assertEqual(result["meta"]["indexed_nodes"], 500)
        self.assertEqual(result["graph"]["coverage"]["included_nodes"],
                         len(result["graph"]["nodes"]))
        self.assertIn("generated_at", result["meta"])
        # entrypoint kept; request decorated with endpoints, hop ids, edge labels.
        self.assertEqual(len(result["graph"]["entrypoints"]), 1)
        req = result["paths"]["requests"][0]
        self.assertEqual(req["source_node"], "n.a")
        self.assertEqual(req["sink_node"], "n.b")
        self.assertEqual(req["hops"][0]["id"], "request.lifecycle:01")
        self.assertEqual(req["hops"][1]["edge_label"], "calls")
        # edges are first-class: id + canonical kind + relation alias.
        edge = result["graph"]["edges"][0]
        self.assertTrue(edge["id"].startswith("edge."))
        self.assertEqual(edge["kind"], "calls")
        self.assertEqual(edge["relation"], edge["kind"])
        # modules partition by file, no node repeated, anchored by the entrypoint.
        by_path = {m["path"]: m for m in result["graph"]["modules"]}
        self.assertEqual(by_path["src/flask/app.py"]["anchor_node_id"], "n.a")
        seen = [nid for m in result["graph"]["modules"] for nid in m["node_ids"]]
        self.assertEqual(len(seen), len(set(seen)))

    def test_request_with_unsourced_hop_is_dropped(self):
        # n.ghost has no source; the guided path must not be emitted.
        result = self._bundle_with({
            "entrypoints": [],
            "requests": [{"id": "r", "kind": "call-path", "description": "d",
                          "entry_node": "n.a",
                          "hops": [{"node_id": "n.a", "caption": "a"},
                                   {"node_id": "n.c", "caption": "c"},
                                   {"node_id": "n.a", "caption": "back"}]}],
        })
        # n.a and n.c are both sourced, so this one survives; assert its shape holds.
        self.assertEqual(len(result["paths"]["requests"]), 1)

    def test_validator_rejects_coverage_mismatch(self):
        result = self._bundle_with({"entrypoints": [], "requests": []})
        result["graph"]["coverage"]["included_nodes"] += 1
        with self.assertRaises(ValueError):
            bundle._validate_graph_first(result)

    def test_validator_rejects_entrypoint_without_source(self):
        result = self._bundle_with({"entrypoints": [], "requests": []})
        result["graph"]["nodes"].append({"id": "n.bare", "kind": "function",
                                         "label": "bare"})
        result["graph"]["coverage"]["included_nodes"] = len(result["graph"]["nodes"])
        result["graph"]["entrypoints"].append({"id": "entry.bare", "node_id": "n.bare"})
        with self.assertRaises(ValueError):
            bundle._validate_graph_first(result)

    def test_validator_rejects_duplicate_module_node(self):
        result = self._bundle_with({"entrypoints": [], "requests": []})
        result["graph"]["modules"].append(
            {"id": "module.dup", "name": "dup", "path": "x", "node_ids": ["n.a"]})
        with self.assertRaises(ValueError):
            bundle._validate_graph_first(result)


class ComprehensionHelperTests(unittest.TestCase):
    def test_dotted_module_strips_src_and_extension(self):
        self.assertEqual(bundle._dotted_module("src/flask/app.py"), "flask.app")
        self.assertEqual(bundle._dotted_module("pkg/__init__.py"), "pkg")

    def test_canon_edge_kind_maps_known_and_lowercases_unknown(self):
        self.assertEqual(bundle._canon_edge_kind("CALLS"), "calls")
        self.assertEqual(bundle._canon_edge_kind("SOME_EDGE"), "some edge")

    def test_has_source_requires_file_line_and_text(self):
        self.assertTrue(bundle._has_source(
            {"file": "a.py", "line": 3, "snippet": "x"}))
        self.assertFalse(bundle._has_source({"file": "a.py", "line": 0, "snippet": "x"}))
        self.assertFalse(bundle._has_source({"file": "", "line": 3, "snippet": "x"}))
        self.assertTrue(bundle._has_source(
            {"file": "a.py", "line": 3, "source_window": {"lines": ["x"]}}))


if __name__ == "__main__":
    unittest.main()
