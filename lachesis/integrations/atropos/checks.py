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


if __name__ == "__main__":
    unittest.main()
