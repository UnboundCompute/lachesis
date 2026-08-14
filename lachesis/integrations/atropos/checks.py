"""Compiler-generated acceptance test for the Atropos C vertical slice.

This is the test the hand-authored fixtures could not be: it runs the real
Lachesis C frontend over a real .c file, projects the graph through the
canonical adapter, hands that to the Atropos binder, and asserts that each
model attaches to the *exact* graph node the source proves it should. A
name-level match is not enough here -- we check the label of the bound node.

Atropos lives in a sibling repo. The test locates it (env ATROPOS_ROOT, then a
sibling checkout, then the conventional path) and skips cleanly if it is absent
or if clang is unavailable, so it never turns a missing dependency into a
failure.
"""
from __future__ import annotations

import importlib.util
import os
import shutil
import sys
import unittest
from pathlib import Path

from lachesis.integrations.atropos import canonical_index
from lachesis.pipeline import run_project

HERE = Path(__file__).resolve().parent
FIXTURE = HERE / "fixtures_cslice"


def _locate_atropos() -> Path | None:
    candidates = []
    env = os.environ.get("ATROPOS_ROOT")
    if env:
        candidates.append(Path(env))
    repo_parent = Path(__file__).resolve().parents[3].parent
    candidates.append(repo_parent / "atropos")
    candidates.append(Path.home() / "project" / "unboundcompute" / "atropos")
    for candidate in candidates:
        if (candidate / "tools" / "bind.py").exists():
            return candidate
    return None


def _load_binder(atropos_root: Path):
    spec = importlib.util.spec_from_file_location(
        "atropos_bind", str(atropos_root / "tools" / "bind.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class AtroposCSlice(unittest.TestCase):
    """memcpy/read/getenv/strdup/system bind to exact nodes on a real C graph."""

    @classmethod
    def setUpClass(cls):
        if shutil.which("clang") is None:
            raise unittest.SkipTest("clang not available for the C frontend")
        atropos = _locate_atropos()
        if atropos is None:
            raise unittest.SkipTest("Atropos repo not found (set ATROPOS_ROOT)")
        binder = _load_binder(atropos)
        graph, _ = run_project(str(FIXTURE), enrich=False)
        cls.graph = graph
        cls.label_of = {n["id"]: n["properties"].get("label") or n.get("label")
                        for n in graph["nodes"]}
        index = canonical_index(graph, language="c", source="lachesis:c-slice")
        cls.index = index
        cls.call_id = {c["callee"]["name"]: c["id"] for c in index["callsites"]}
        models = [m for m in binder.load_models(atropos / "models")
                  if m["language"] == "c"]
        report = binder.bind_all(models, index)
        cls.byid = {r["model_id"]: r for r in report["results"]}

    def _attachment(self, model_id):
        result = self.byid.get(model_id)
        self.assertIsNotNone(result, f"{model_id} not in binding report")
        self.assertEqual(result["status"], "bound",
                         f"{model_id}: expected bound, got {result['status']}")
        self.assertEqual(len(result["attachments"]), 1,
                         f"{model_id}: expected a single attachment")
        return result["attachments"][0]

    def _label(self, node_id):
        return self.label_of.get(node_id)

    # --- sinks bind to the exact argument, not the call result ---
    def test_memcpy_size_sink_is_argument2(self):
        self.assertEqual(self._label(self._attachment("c.std.memcpy.a2")["node"]), "n")

    def test_memcpy_dest_sink_is_argument0(self):
        self.assertEqual(self._label(self._attachment("c.std.memcpy.a0")["node"]), "dst")

    def test_system_sink_is_argument0(self):
        self.assertEqual(self._label(self._attachment("c.std.system.a0")["node"]), "d")

    # --- sources bind to the right endpoint, and to the *wrong* one never ---
    def test_read_source_is_buffer_not_fd(self):
        node = self._attachment("c.std.read.a1")["node"]
        self.assertEqual(self._label(node), "buf")
        self.assertNotEqual(self._label(node), "fd")

    def test_getenv_source_is_return_value(self):
        node = self._attachment("c.std.getenv.ret")["node"]
        self.assertEqual(node, self.call_id["getenv"])

    # --- summaries bind to the exact src->dest / in->return edge ---
    def test_memcpy_copy_summary_src_to_dest(self):
        edge = self._attachment("c.std.memcpy.a1-a0")["edge"]
        self.assertEqual(self._label(edge["from"]), "src")
        self.assertEqual(self._label(edge["to"]), "dst")

    def test_strdup_copy_summary_in_to_return(self):
        edge = self._attachment("c.std.strdup.a0-ret")["edge"]
        self.assertEqual(self._label(edge["from"]), "e")
        self.assertEqual(edge["to"], self.call_id["strdup"])

    # --- the whole gold set binds; nothing silently misfires ---
    def test_gold_set_all_bound(self):
        for model_id in ("c.std.memcpy.a2", "c.std.memcpy.a0", "c.std.memcpy.a1-a0",
                         "c.std.read.a1", "c.std.getenv.ret", "c.std.strdup.a0-ret",
                         "c.std.system.a0"):
            self.assertEqual(self.byid[model_id]["status"], "bound", model_id)


class AtroposCSliceEnrich(unittest.TestCase):
    """The Atropos overlay stamps resolved facts onto exact nodes in a separate
    enrich flow, additively, and taint consumes them.

    This exercises the enrich half of the seam: the base graph is built exactly
    as today (``run_project(enrich=False)``), a separate flow folds core
    enrichment, then the Atropos overlay, then taint -- each an additive delta
    over the already-built graph, never a rebuild.
    """

    @classmethod
    def setUpClass(cls):
        if shutil.which("clang") is None:
            raise unittest.SkipTest("clang not available for the C frontend")
        atropos = _locate_atropos()
        if atropos is None:
            raise unittest.SkipTest("Atropos repo not found (set ATROPOS_ROOT)")
        binder = _load_binder(atropos)
        from lachesis.core.overlays import (
            default_overlay_registry, default_security_overlay_registry)
        from lachesis.core.overlays.registry import OverlayRegistry
        from lachesis.integrations.atropos.overlay import (
            AtroposOverlay, stamps_from_report)

        core, _ = run_project(str(FIXTURE), enrich=False)   # base graph, as built today
        enriched = default_overlay_registry().enrich(core)  # separate enrich flow
        cls.base_node_ids = {n["id"] for n in enriched["nodes"]}
        index = canonical_index(enriched, language="c", source="lachesis:c-slice")
        models = [m for m in binder.load_models(atropos / "models")
                  if m["language"] == "c"]
        models_by_id = {m["id"]: m for m in models}
        report = binder.bind_all(models, index)
        cls.stamps = stamps_from_report(report, models_by_id)
        registry = OverlayRegistry()
        registry.register(AtroposOverlay(cls.stamps))
        cls.stamped = registry.enrich(enriched)
        cls.label_of = {n["id"]: (n["properties"].get("label") or n.get("label"))
                        for n in cls.stamped["nodes"]}
        cls.final = default_security_overlay_registry().enrich(cls.stamped)

    def _role_nodes(self, kind):
        return [n for n in self.stamped["nodes"]
                if n.get("kind") == kind
                and n.get("properties", {}).get("fact_origin") == "atropos-model"]

    def _summaries(self):
        return {(self.label_of[e["source"]], self.label_of[e["target"]],
                 e["properties"]["model_id"])
                for e in self.stamped["edges"]
                if e["kind"] == "VALUE_FLOWS_TO"
                and e.get("properties", {}).get("fact_origin") == "atropos-model"}

    def test_gold_set_resolves_to_seven_stamps(self):
        self.assertEqual(len(self.stamps), 7)

    def test_sinks_land_on_exact_argument_nodes(self):
        got = {n["properties"]["model_id"]: self.label_of[n["properties"]["value_id"]]
               for n in self._role_nodes("sink")}
        self.assertEqual(got.get("c.std.system.a0"), "d")
        self.assertEqual(got.get("c.std.memcpy.a2"), "n")
        self.assertEqual(got.get("c.std.memcpy.a0"), "dst")

    def test_sources_land_on_exact_nodes(self):
        got = {n["properties"]["model_id"]: self.label_of[n["properties"]["value_id"]]
               for n in self._role_nodes("source")}
        self.assertEqual(got.get("c.std.read.a1"), "buf")
        self.assertEqual(got.get("c.std.getenv.ret"), 'getenv("PATH")')

    def test_summaries_are_flow_edges_on_exact_nodes(self):
        summaries = self._summaries()
        self.assertIn(("src", "dst", "c.std.memcpy.a1-a0"), summaries)
        self.assertIn(("e", 'strdup(e)', "c.std.strdup.a0-ret"), summaries)

    def test_overlay_is_additive_base_nodes_untouched(self):
        stamped_ids = {n["id"] for n in self.stamped["nodes"]}
        self.assertTrue(self.base_node_ids.issubset(stamped_ids))
        # the only new nodes are the five role nodes (three sinks, two sources);
        # summaries contribute edges, not nodes.
        self.assertEqual(len(stamped_ids - self.base_node_ids), 5)

    def test_taint_consumes_stamped_roles(self):
        # Taint ran over the stamped graph in setUp; it must have propagated at
        # least one flow rather than erroring on the Atropos role nodes.
        self.assertTrue(any(e["kind"] == "TAINT_FLOWS_TO"
                            for e in self.final["edges"]))



if __name__ == "__main__":
    unittest.main()
