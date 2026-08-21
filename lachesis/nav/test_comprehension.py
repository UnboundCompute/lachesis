from __future__ import annotations

import json
from pathlib import Path
import subprocess
import tempfile
import types
import unittest

from .comprehension import Comprehension
from .graph_store import GraphStore
from .graph_store import _close_node_property_references


def node(node_id, kind, label, file=None, line=None, **properties):
    return {"id": node_id, "kind": kind, "label": label,
            "properties": {"file": file, "start_line": line, **properties}}


def edge(kind, source, target, **properties):
    properties.setdefault("confidence", "exact")
    return {"kind": kind, "source": source, "target": target,
            "properties": properties}


class ComprehensionTests(unittest.TestCase):
    def setUp(self):
        nodes = [
            node("fa", "file", "account.py", "api/account.py", 1,
                 provenance="application"),
            node("fs", "file", "store.py", "storage/store.py", 1,
                 provenance="application"),
            node("user", "class", "User", "api/account.py", 3),
            node("status", "property", "status", "api/account.py", 4),
            node("init", "constructor", "__init__", "api/account.py", 6,
                 owner_type_id="user"),
            node("set", "method", "setStatus", "api/account.py", 10,
                 owner_type_id="user"),
            node("w", "write", "self.status", "api/account.py", 11,
                 owner_function_id="set", target_id="status", write_kind="assignment"),
            node("r", "read", "self.status", "api/account.py", 15,
                 owner_function_id="load_mysql", target_id="status"),
            node("load_mysql", "function", "loadMysqlConfig", "api/account.py", 14),
            node("load_pg", "function", "loadPostgresConfig", "storage/store.py", 20),
            node("helper", "function", "parseConfig", "storage/store.py", 30),
            node("helper_body", "statement", "return parsed", "storage/store.py", 31,
                 owner_function_id="helper", control_kind="return"),
            node("call_helper", "call", "parseConfig(raw)", "api/account.py", 16,
                 owner_function_id="load_mysql", resolution="exact"),
            node("arg_raw", "argument", "raw", "api/account.py", 16,
                 owner_function_id="load_mysql"),
            node("param_raw", "parameter", "raw", "storage/store.py", 30,
                 owner_function_id="helper"),
            node("mystery", "call", "plugin.run(raw)", "api/account.py", 17,
                 owner_function_id="load_mysql", resolution="dynamic-or-unresolved"),
            node("register", "call", "register(table)", "api/account.py", 19,
                 owner_function_id="load_mysql", resolution="registration"),
            node("register_arg", "argument", "table", "api/account.py", 19,
                 owner_function_id="load_mysql"),
            node("callback_table", "variable", "callbacks", "api/account.py", 20,
                 owner_function_id="load_mysql"),
            node("registered_callback", "function", "onConfig", "storage/store.py", 40),
            node("if1", "statement", "if raw", "api/account.py", 18,
                 owner_function_id="load_mysql", control_kind="if"),
            node("diag", "diagnostic", "syntax recovery", "storage/store.py", 2,
                 category="parse-recovery"),
            node("diag_global", "diagnostic", "project warning", category="configuration"),
        ]
        edges = [
            edge("DECLARES_MEMBER", "user", "status"),
            edge("DECLARES_MEMBER", "user", "init"),
            edge("DECLARES_MEMBER", "user", "set"),
            edge("WRITES_TO", "w", "status"),
            edge("READS_FROM", "status", "r"),
            edge("CALLS", "load_mysql", "helper"),
            edge("ARGUMENT_BINDS_PARAMETER", "arg_raw", "param_raw"),
            edge("INVOKES", "call_helper", "helper"),
            edge("HAS_ARGUMENT", "register", "register_arg"),
            edge("REFERS_TO", "register_arg", "callback_table"),
            edge("MAY_INVOKE", "callback_table", "registered_callback",
                 dispatch="registration", slot="on_config"),
            edge("CONTAINS_BODY", "load_mysql", "call_helper"),
            edge("CONTAINS_BODY", "load_mysql", "mystery"),
            edge("CONTAINS_BODY", "load_mysql", "register"),
            edge("CONTAINS_BODY", "load_mysql", "if1"),
            edge("CONTAINS_BODY", "helper", "helper_body"),
        ]
        self.store = GraphStore({"nodes": nodes, "edges": edges})
        self.query = Comprehension(self.store)

    def test_unknowns_distinguishes_frontier_from_absence(self):
        answer = self.query.unknowns("loadMysqlConfig")
        self.assertEqual("could-not-cross", answer["status"])
        self.assertEqual(["plugin.run(raw)"], [r["name"] for r in answer["unknowns"]])
        self.assertEqual("proven-absent", self.query.unknowns("parseConfig")["status"])

    def test_cone_closes_explicit_value_and_path_references(self):
        value_id = "v2:frontend:typescript-compiler-api:value:1"
        path_id = "v2:frontend:typescript-compiler-api:path:2"
        owner_id = "v2:frontend:typescript-compiler-api:function:3"
        nodes = {
            value_id: node(value_id, "value", "receiver", value_id=path_id),
            path_id: node(path_id, "path", "result", owner_function_id=owner_id),
            owner_id: node(owner_id, "function", "owner"),
        }
        graph = {"nodes": [nodes[value_id]], "edges": []}
        added = _close_node_property_references(
            types.SimpleNamespace(nodes=nodes), graph,
        )
        self.assertEqual(2, added)
        self.assertEqual(set(nodes), {item["id"] for item in graph["nodes"]})

    def test_coverage_is_explicitly_graph_based(self):
        answer = self.query.coverage_map()
        self.assertEqual("indexed-graph", answer["basis"])
        self.assertEqual(2, answer["counts"]["files"])
        self.assertGreaterEqual(answer["counts"]["unmodeled_frontiers"], 2)
        self.assertIn("does not track per-client reads", answer["interpretation"])
        original = self.query.unknowns
        try:
            self.query.unknowns = lambda **_kwargs: self.fail(
                "a later coverage page repeated the whole-graph frontier scan",
            )
            self.assertEqual(answer["counts"], self.query.coverage_map(offset=1)["counts"])
        finally:
            self.query.unknowns = original

    def test_field_history_and_type_roles(self):
        history = self.query.field_history("status", "User")
        self.assertEqual({"modified": 1, "read": 1}, history["counts"])
        explained = self.query.type_explain("User")["types"][0]
        self.assertEqual(["status"], [f["name"] for f in explained["fields"]])
        self.assertEqual(["__init__"], [m["name"] for m in explained["roles"]["constructor"]])
        self.assertEqual(["setStatus"], [m["name"] for m in explained["roles"]["mutator"]])

    def test_sibling_compare_is_factual_and_boundary_is_bidirectional(self):
        compared = self.query.sibling_compare("loadMysqlConfig")
        self.assertEqual(2, compared["family_size"])
        self.assertNotIn("verdict", compared)
        mysql = next(m for m in compared["members"] if m["name"] == "loadMysqlConfig")
        self.assertEqual(["parseConfig"], mysql["calls"])
        late_calls = self.query.sibling_compare(
            "loadMysqlConfig", limit=100, call_offset=1,
        )
        late_mysql = next(
            member for member in late_calls["members"]
            if member["name"] == "loadMysqlConfig"
        )
        self.assertEqual(1, late_mysql["differences"]["calls_unique_page"]["total"])
        boundary = self.query.component_boundary("api", "storage")
        self.assertEqual(3, boundary["count"])
        self.assertEqual({"call", "value"},
                         {row["category"] for row in boundary["crossings"]})
        self.assertEqual({"api->storage"},
                         {row["direction"] for row in boundary["crossings"]})

    def test_mcp_dispatch_and_schema(self):
        from . import mcp_server
        old_ctx, old_format = mcp_server._CTX, mcp_server._DEFAULT_FORMAT
        try:
            mcp_server._CTX = types.SimpleNamespace(
                store=self.store, comprehension=self.query)
            mcp_server._DEFAULT_FORMAT = "json"
            answer = json.loads(mcp_server.call_tool(
                "unknowns", {"function": "loadMysqlConfig"}, format="json"))
            self.assertEqual("could-not-cross", answer["status"])
            names = {tool["name"] for tool in mcp_server._visible_tools()}
            self.assertTrue({"unknowns", "coverage_map", "field_history",
                             "sibling_compare", "type_explain",
                             "component_boundary", "indirect_targets",
                             "architecture_map", "execution_story"} <= names)
            mcp_server._PROFILE = "comprehension"
            focused = {tool["name"] for tool in mcp_server._visible_tools()}
            self.assertNotIn("candidates", focused)
            self.assertNotIn("flow_skeleton", focused)
            self.assertIn("context_pack", focused)
        finally:
            mcp_server._PROFILE = "all"
            mcp_server._CTX, mcp_server._DEFAULT_FORMAT = old_ctx, old_format

    def test_mcp_scan_returns_ranked_page_and_census(self):
        from . import mcp_server
        old_ctx, old_profile, old_format = (
            mcp_server._CTX, mcp_server._PROFILE, mcp_server._DEFAULT_FORMAT,
        )
        fake_scan = {
            "constructor": "GUARD_DIFFERENTIAL",
            "census": {"entrypoints_total": 4, "entrypoints_scanned": 2,
                       "entrypoints_skipped": 2, "queued": 2,
                       "suppressed": 1, "closures_truncated": 0},
            "queue": [
                {"id": "low", "rank": 0.25},
                {"id": "high", "rank": 0.9},
            ],
            "suppressions": [{"id": "kept"}],
        }
        try:
            mcp_server._CTX = types.SimpleNamespace(
                store=self.store,
                scan_bundle_for=lambda _limit: fake_scan,
            )
            mcp_server._PROFILE = "all"
            mcp_server._DEFAULT_FORMAT = "json"
            answer = json.loads(mcp_server.call_tool(
                "scan", {"entrypoints": 2, "min_rank": 0.5,
                          "limit": 1, "include_suppressions": True},
                format="json"))
            self.assertEqual("scan", answer["move"])
            self.assertEqual(["high"], [row["id"] for row in answer["queue"]])
            self.assertEqual(1, answer["page"]["total"])
            self.assertEqual(2, answer["census"]["entrypoints_skipped"])
            self.assertEqual([{"id": "kept"}], answer["suppressions"])
            names = {tool["name"] for tool in mcp_server._visible_tools()}
            self.assertIn("scan", names)
            mcp_server._PROFILE = "comprehension"
            self.assertNotIn("scan", {tool["name"] for tool in mcp_server._visible_tools()})
        finally:
            mcp_server._PROFILE = old_profile
            mcp_server._CTX, mcp_server._DEFAULT_FORMAT = old_ctx, old_format

    def test_backlog_capabilities_are_advertised_and_blocked_honestly(self):
        from . import mcp_server
        names = {tool["name"] for tool in mcp_server.TOOLS}
        self.assertTrue({"wrapper_model", "guard_dominance", "counterexample",
                         "invariant_trace", "representation_roundtrip",
                         "cross_boundary_paths", "range_analysis",
                         "object_lifecycle", "error_path_summary"} <= names)
        old_ctx, old_format = mcp_server._CTX, mcp_server._DEFAULT_FORMAT
        try:
            mcp_server._CTX = types.SimpleNamespace(store=self.store)
            mcp_server._DEFAULT_FORMAT = "json"
            answer = json.loads(mcp_server.call_tool(
                "range_analysis", {}, format="json"))
            self.assertEqual("blocked", answer["status"])
            self.assertIn("numeric", answer["reason"])
        finally:
            mcp_server._CTX, mcp_server._DEFAULT_FORMAT = old_ctx, old_format

    def test_backlog_deterministic_moves_run_on_fixture_graph(self):
        from . import mcp_server
        old_ctx, old_format = mcp_server._CTX, mcp_server._DEFAULT_FORMAT
        try:
            mcp_server._CTX = types.SimpleNamespace(
                store=self.store, comprehension=self.query,
            )
            mcp_server._DEFAULT_FORMAT = "json"
            calls = [
                ("wrapper_model", {"function": "loadMysqlConfig"}),
                ("invariant_trace", {"value": "status"}),
                ("representation_roundtrip", {
                    "left": "loadMysqlConfig", "right": "loadPostgresConfig",
                }),
                ("cross_boundary_paths", {
                    "from_component": "api", "to_component": "storage",
                }),
            ]
            for name, args in calls:
                answer = json.loads(mcp_server.call_tool(name, args, format="json"))
                self.assertEqual(name, answer["move"])
                self.assertNotIn("error", answer)
        finally:
            mcp_server._CTX, mcp_server._DEFAULT_FORMAT = old_ctx, old_format

    def test_wave_two_graph_algorithms_stay_deterministic(self):
        targets = self.query.indirect_targets("loadMysqlConfig")
        self.assertEqual(1, targets["counts"]["unresolved"])
        self.assertEqual("plugin.run(raw)", targets["sites"][0]["name"])

        architecture = self.query.architecture_map()
        self.assertEqual(2, architecture["counts"]["files"])
        self.assertEqual("weighted-label-propagation", architecture["algorithm"])
        self.assertTrue(architecture["communities"])

        story = self.query.execution_story("loadMysqlConfig")
        self.assertEqual(["loadMysqlConfig", "parseConfig", "onConfig"],
                         [step["function"]["name"] for step in story["steps"]])
        self.assertEqual("bounded-forward-call-and-branch-trace", story["algorithm"])

    def test_large_evidence_lists_are_retrievable_as_stable_pages(self):
        first = self.query.architecture_map(max_communities=1, max_files_per_community=1)
        community = first["communities"][0]
        self.assertEqual(1, community["files_page"]["returned"])
        if community["files_page"]["has_more"]:
            second = self.query.architecture_map(
                max_communities=1, max_files_per_community=1,
                file_offset=community["files_page"]["next_offset"],
            )
            self.assertNotEqual(community["files"], second["communities"][0]["files"])

        unknowns = self.query.unknowns(limit=1)
        self.assertEqual(1, unknowns["page"]["returned"])
        if unknowns["page"]["has_more"]:
            later = self.query.unknowns(limit=1, offset=unknowns["page"]["next_offset"])
            self.assertNotEqual(unknowns["unknowns"], later["unknowns"])

        story = self.query.execution_story("loadMysqlConfig", max_steps=1)
        self.assertTrue(story["page"]["has_more"])
        story_later = self.query.execution_story(
            "loadMysqlConfig", max_steps=1, offset=story["page"]["next_offset"],
        )
        self.assertNotEqual(story["steps"], story_later["steps"])

    def test_comprehension_answers_match_the_disk_store(self):
        from lachesis.kuzu_store import write_kuzu_graph
        from ._navharness import norm
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "graph.kuzu")
            write_kuzu_graph(self.store.graph, [], path, prune=False,
                             elide_constants=False)
            disk = Comprehension(GraphStore.load(path))
            calls = (
                lambda q: q.unknowns("loadMysqlConfig"),
                lambda q: q.coverage_map(),
                lambda q: q.field_history("status"),
                lambda q: q.sibling_compare("loadMysqlConfig"),
                lambda q: q.type_explain("User"),
                lambda q: q.component_boundary("api", "storage"),
                lambda q: q.indirect_targets("loadMysqlConfig"),
                lambda q: q.architecture_map(),
                lambda q: q.execution_story("loadMysqlConfig"),
            )
            for call in calls:
                self.assertEqual(norm(call(self.query)), norm(call(disk)))

    def test_compact_render_strips_nested_ids_and_paths(self):
        from .render import render
        text = render("field_history", self.query.field_history("status"))
        self.assertNotIn("node_id", text)
        self.assertNotIn("owner={'", text)
        self.assertIn("account.py:11", text)

    def test_source_tree_integrations_are_evidence_only(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "api").mkdir()
            (root / "tests").mkdir()
            (root / "docs").mkdir()
            (root / "api/account.py").write_text(
                "def loadMysqlConfig():\n    return 1\n", encoding="utf-8")
            (root / "tests/test_account.py").write_text(
                "def test_load():\n    assert loadMysqlConfig() == 1\n"
                "def test_reload():\n    assert loadMysqlConfig() == 1\n", encoding="utf-8")
            (root / "docs/config.md").write_text(
                "`loadMysqlConfig` implements https://example.test/config.\n"
                "See `loadMysqlConfig` when reloading configuration.\n",
                encoding="utf-8")
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            subprocess.run(["git", "-C", str(root), "config", "user.email", "test@example.test"],
                           check=True)
            subprocess.run(["git", "-C", str(root), "config", "user.name", "Test"], check=True)
            subprocess.run(["git", "-C", str(root), "add", "."], check=True)
            subprocess.run(["git", "-C", str(root), "commit", "-qm", "add config loader"],
                           check=True)
            self.store.source_dir = str(root)

            history = self.query.change_context("loadMysqlConfig")
            self.assertEqual("add config loader", history["commits"][0]["subject"])
            tests = self.query.tests_for("loadMysqlConfig")
            self.assertTrue(tests["references"][0]["assertion_nearby"])
            tests_page = self.query.tests_for("loadMysqlConfig", limit=1, offset=1)
            self.assertEqual(1, tests_page["pagination"]["offset"])
            self.assertEqual(1, len(tests_page["references"]))
            specs = self.query.spec_links("loadMysqlConfig")
            self.assertEqual(["https://example.test/config."],
                             specs["references"][0]["urls"])
            spec_page = self.query.spec_links("loadMysqlConfig", limit=1, offset=1)
            self.assertEqual(1, spec_page["pagination"]["offset"])
            self.assertEqual(1, len(spec_page["references"]))

            pack = self.query.context_pack("How does load mysql config work?")
            self.assertEqual("identifier-token-relevance", pack["selection_basis"])
            self.assertIn("loadMysqlConfig", {seed["name"] for seed in pack["seeds"]})
            self.assertTrue(pack["tests"])
            self.assertTrue(pack["specs"])

            paged = self.query.context_pack(
                "How does load mysql config work?", max_neighbors=1,
            )
            self.assertTrue(paged["pages"]["tests"]["has_more"])
            later = self.query.context_pack(
                "How does load mysql config work?", max_neighbors=1,
                test_offset=paged["pages"]["tests"]["next_offset"],
                spec_offset=paged["pages"]["specs"]["next_offset"],
            )
            self.assertNotEqual(paged["tests"], later["tests"])
            self.assertNotEqual(paged["specs"], later["specs"])


if __name__ == "__main__":
    unittest.main()
