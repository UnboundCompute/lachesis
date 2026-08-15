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
FIXTURE_OUTPARAM = HERE / "fixtures_outparam"
FIXTURE_INTERPROC = HERE / "fixtures_interproc"


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

    def test_original_gold_stamps_remain_present_as_catalog_grows(self):
        model_ids = {stamp["model_id"] for stamp in self.stamps}
        self.assertTrue({
            "c.std.memcpy.a2", "c.std.memcpy.a0", "c.std.memcpy.a1-a0",
            "c.std.read.a1", "c.std.getenv.ret", "c.std.strdup.a0-ret",
            "c.std.system.a0",
        }.issubset(model_ids))

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
        # Only source/sink role stamps add nodes; summaries contribute edges. Keep
        # this invariant independent of unrelated catalog growth.
        role_count = len(self._role_nodes("source")) + len(self._role_nodes("sink"))
        self.assertEqual(len(stamped_ids - self.base_node_ids), role_count)

    def test_copy_capacity_registry_enumerates_every_bound_size_fact(self):
        from lachesis.planner.unbounded_copy import MemoryCopyCapacity

        expected = {
            node["properties"]["model_id"] for node in self._role_nodes("sink")
            if node["properties"].get("sink_kind") == "buffer-size"
        }
        result = MemoryCopyCapacity(self.stamped).enumerate()
        actual = [row["observations"]["atropos_model_id"]
                  for row in result["candidates"]]
        self.assertCountEqual(actual, expected)
        self.assertEqual(len(actual), len(expected))
        self.assertTrue(all("state" not in row and "verdict" not in row
                            for row in result["candidates"]))

    def test_taint_consumes_stamped_roles(self):
        # Taint ran over the stamped graph in setUp; it must have propagated at
        # least one flow rather than erroring on the Atropos role nodes.
        self.assertTrue(any(e["kind"] == "TAINT_FLOWS_TO"
                            for e in self.final["edges"]))

    def test_dual_source_sink_attachment_does_not_make_a_zero_hop_witness(self):
        reaches = [node for node in self.final["nodes"]
                   if node.get("kind") == "taint-reach"]
        self.assertFalse(any(
            node["properties"].get("source_value_id")
            == node["properties"].get("sink_value_id")
            for node in reaches))



def _enrich_and_taint(atropos_root, binder, *, with_summary=True, with_dataflow=True):
    """Run the separate enrich flow over the C slice and return the tainted graph.

    Base graph as built today, then core enrichment, then (optionally) the C
    call-result dataflow overlay, then the Atropos overlay, then taint -- each an
    additive fold. ``with_summary``/``with_dataflow`` drop one contribution so a
    test can show it is load-bearing.
    """
    from lachesis.core.overlays import (
        default_overlay_registry, default_security_overlay_registry)
    from lachesis.core.overlays.registry import OverlayRegistry
    from lachesis.core.overlays.c_call_dataflow import CCallResultDataflow
    from lachesis.integrations.atropos.overlay import (
        AtroposOverlay, stamps_from_report)

    core, _ = run_project(str(FIXTURE), enrich=False)
    enriched = default_overlay_registry().enrich(core)
    index = canonical_index(enriched, language="c", source="lachesis:c-slice")
    models = [m for m in binder.load_models(atropos_root / "models")
              if m["language"] == "c"]
    models_by_id = {m["id"]: m for m in models}
    stamps = stamps_from_report(binder.bind_all(models, index), models_by_id)
    if not with_summary:
        stamps = [s for s in stamps if s["model_id"] != "c.std.strdup.a0-ret"]
    registry = OverlayRegistry()
    if with_dataflow:
        registry.register(CCallResultDataflow())
    registry.register(AtroposOverlay(stamps))
    stamped = registry.enrich(enriched)
    final = default_security_overlay_registry().enrich(stamped)
    label_of = {n["id"]: (n["properties"].get("label") or n.get("label"))
                for n in final["nodes"]}
    return final, label_of


class CCallResultDataflowCheck(unittest.TestCase):
    """The C dataflow overlay links each call result to the variable it initializes."""

    @classmethod
    def setUpClass(cls):
        if shutil.which("clang") is None:
            raise unittest.SkipTest("clang not available for the C frontend")
        from lachesis.core.overlays import default_overlay_registry
        from lachesis.core.overlays.registry import OverlayRegistry
        from lachesis.core.overlays.c_call_dataflow import CCallResultDataflow

        core, _ = run_project(str(FIXTURE), enrich=False)
        cls.enriched = default_overlay_registry().enrich(core)
        cls.before = {(e["source"], e["target"]) for e in cls.enriched["edges"]
                      if e["kind"] == "VALUE_FLOWS_TO"}
        registry = OverlayRegistry()
        registry.register(CCallResultDataflow())
        cls.after_graph = registry.enrich(cls.enriched)
        cls.label_of = {n["id"]: (n["properties"].get("label") or n.get("label"))
                        for n in cls.after_graph["nodes"]}
        cls.added = [e for e in cls.after_graph["edges"]
                     if e["kind"] == "VALUE_FLOWS_TO"
                     and e.get("properties", {}).get("inference")
                     == "c-call-result-to-declared-variable"]

    def test_links_call_results_to_their_variables(self):
        pairs = {(self.label_of[e["source"]], self.label_of[e["target"]])
                 for e in self.added}
        self.assertIn(('getenv("PATH")', "e"), pairs)
        self.assertIn(("strdup(e)", "d"), pairs)

    def test_only_declaration_inits_are_linked(self):
        # Exactly the two call-initialized declarations in the fixture, no more.
        self.assertEqual(len(self.added), 2)

    def test_overlay_is_additive(self):
        base_ids = {n["id"] for n in self.enriched["nodes"]}
        after_ids = {n["id"] for n in self.after_graph["nodes"]}
        self.assertTrue(base_ids.issubset(after_ids))
        # It contributes edges only, never nodes.
        self.assertEqual(base_ids, after_ids)


def _enrich_and_taint_outparam(atropos_root, binder, *, with_writeback=True):
    """Run the enrich flow over the out-param fixture and return the tainted graph.

    Same additive flow as :func:`_enrich_and_taint`, plus the C out-parameter
    write-back overlay driven by the resolved argument-position sources.
    ``with_writeback=False`` drops only that overlay so a test can show the
    ``read`` source strands on its own argument without it.
    """
    from lachesis.core.overlays import (
        default_overlay_registry, default_security_overlay_registry)
    from lachesis.core.overlays.registry import OverlayRegistry
    from lachesis.core.overlays.c_out_param_dataflow import COutParamWriteback
    from lachesis.integrations.atropos.overlay import (
        AtroposOverlay, stamps_from_report)

    core, _ = run_project(str(FIXTURE_OUTPARAM), enrich=False)
    enriched = default_overlay_registry().enrich(core)
    index = canonical_index(enriched, language="c", source="lachesis:c-outparam")
    models = [m for m in binder.load_models(atropos_root / "models")
              if m["language"] == "c"]
    models_by_id = {m["id"]: m for m in models}
    stamps = stamps_from_report(binder.bind_all(models, index), models_by_id)
    out_param_sources = [
        s["value_id"] for s in stamps
        if s.get("role") == "source" and "value_id" in s
        and str(s.get("access_path") or "").startswith("Argument[")
    ]
    registry = OverlayRegistry()
    if with_writeback:
        registry.register(COutParamWriteback(out_param_sources))
    registry.register(AtroposOverlay(stamps))
    stamped = registry.enrich(enriched)
    final = default_security_overlay_registry().enrich(stamped)
    label_of = {n["id"]: (n["properties"].get("label") or n.get("label"))
                for n in final["nodes"]}
    return final, label_of


class AtroposOutParamWitness(unittest.TestCase):
    """A buffer filled by ``read`` reaches a ``system`` sink through the write-back."""

    @classmethod
    def setUpClass(cls):
        if shutil.which("clang") is None:
            raise unittest.SkipTest("clang not available for the C frontend")
        atropos = _locate_atropos()
        if atropos is None:
            raise unittest.SkipTest("Atropos repo not found (set ATROPOS_ROOT)")
        cls.atropos = atropos
        cls.binder = _load_binder(atropos)

    def _witnesses(self, graph):
        by_id = {node["id"]: node for node in graph["nodes"]}
        return [n for n in graph["nodes"] if n.get("kind") == "taint-reach"
                and (by_id.get(n["properties"].get("sink_id"), {}).get("properties")
                     or {}).get("model_id") == "c.std.system.a0"]

    def test_read_reaches_system_through_buffer(self):
        graph, label_of = _enrich_and_taint_outparam(self.atropos, self.binder)
        witnesses = self._witnesses(graph)
        self.assertEqual(len(witnesses), 1)
        path = [label_of[w] for w in witnesses[0]["properties"]["witness_ids"]]
        # source is the read buffer argument; sink is the system argument; the
        # flow crossed from read's write into system's read of the same buffer.
        self.assertEqual(path[0], "buf")
        self.assertEqual(path[-1], "buf")

    def test_writeback_is_load_bearing(self):
        # Drop only the write-back: the read source strands on its argument.
        graph, _ = _enrich_and_taint_outparam(
            self.atropos, self.binder, with_writeback=False)
        self.assertEqual(len(self._witnesses(graph)), 0)


def _enrich_and_taint_interproc(atropos_root, binder, *, with_return_summary=True):
    """Run the enrich flow over the interprocedural fixture and taint it.

    Registers the intraprocedural call-result overlay (so the caller's ``p =
    get_gateway()`` result reaches ``p``) and, unless suppressed, the
    return-to-callsite overlay (so ``get_gateway``'s wrapped source reaches that
    call result). ``with_return_summary=False`` drops only the latter, stranding
    the source at the wrapper's ``return``.
    """
    from lachesis.core.overlays import (
        default_overlay_registry, default_security_overlay_registry)
    from lachesis.core.overlays.registry import OverlayRegistry
    from lachesis.core.overlays.c_call_dataflow import CCallResultDataflow
    from lachesis.core.overlays.c_return_dataflow import CReturnToCallsite
    from lachesis.integrations.atropos.overlay import (
        AtroposOverlay, stamps_from_report)

    core, _ = run_project(str(FIXTURE_INTERPROC), enrich=False)
    enriched = default_overlay_registry().enrich(core)
    index = canonical_index(enriched, language="c", source="lachesis:c-interproc")
    models = [m for m in binder.load_models(atropos_root / "models")
              if m["language"] == "c"]
    models_by_id = {m["id"]: m for m in models}
    stamps = stamps_from_report(binder.bind_all(models, index), models_by_id)
    registry = OverlayRegistry()
    registry.register(CCallResultDataflow())
    if with_return_summary:
        registry.register(CReturnToCallsite())
    registry.register(AtroposOverlay(stamps))
    stamped = registry.enrich(enriched)
    final = default_security_overlay_registry().enrich(stamped)
    label_of = {n["id"]: (n["properties"].get("label") or n.get("label"))
                for n in final["nodes"]}
    return final, label_of


class AtroposInterprocWitness(unittest.TestCase):
    """A source wrapped in a function reaches a caller-side sink via the return."""

    @classmethod
    def setUpClass(cls):
        if shutil.which("clang") is None:
            raise unittest.SkipTest("clang not available for the C frontend")
        atropos = _locate_atropos()
        if atropos is None:
            raise unittest.SkipTest("Atropos repo not found (set ATROPOS_ROOT)")
        cls.atropos = atropos
        cls.binder = _load_binder(atropos)

    def _witnesses(self, graph):
        by_id = {node["id"]: node for node in graph["nodes"]}
        return [n for n in graph["nodes"] if n.get("kind") == "taint-reach"
                and (by_id.get(n["properties"].get("sink_id"), {}).get("properties")
                     or {}).get("model_id") == "c.std.system.a0"]

    def test_wrapped_source_reaches_caller_sink(self):
        graph, label_of = _enrich_and_taint_interproc(self.atropos, self.binder)
        witnesses = self._witnesses(graph)
        self.assertEqual(len(witnesses), 1)
        path = [label_of[w] for w in witnesses[0]["properties"]["witness_ids"]]
        # source is getenv inside the wrapper; sink is the system argument in the
        # caller: the flow crossed the function boundary through the return.
        self.assertEqual(path[-1], "p")

    def test_return_summary_is_load_bearing(self):
        # Drop only the return-to-callsite overlay: the source stays in the wrapper.
        graph, _ = _enrich_and_taint_interproc(
            self.atropos, self.binder, with_return_summary=False)
        self.assertEqual(len(self._witnesses(graph)), 0)


class AtroposCSliceWitness(unittest.TestCase):
    """A real source->sink taint witness rides the Atropos summary end to end."""

    @classmethod
    def setUpClass(cls):
        if shutil.which("clang") is None:
            raise unittest.SkipTest("clang not available for the C frontend")
        atropos = _locate_atropos()
        if atropos is None:
            raise unittest.SkipTest("Atropos repo not found (set ATROPOS_ROOT)")
        cls.atropos = atropos
        cls.binder = _load_binder(atropos)

    def _witnesses(self, graph):
        by_id = {node["id"]: node for node in graph["nodes"]}
        return [n for n in graph["nodes"] if n.get("kind") == "taint-reach"
                and (by_id.get(n["properties"].get("sink_id"), {}).get("properties")
                     or {}).get("model_id") == "c.std.system.a0"]

    def test_getenv_reaches_system_through_strdup_summary(self):
        graph, label_of = _enrich_and_taint(self.atropos, self.binder)
        witnesses = self._witnesses(graph)
        self.assertEqual(len(witnesses), 1)
        reach = witnesses[0]
        self.assertEqual(reach["properties"]["sink_id"].count("sink"), 1)
        path = [label_of[w] for w in reach["properties"]["witness_ids"]]
        # source is the getenv return, sink is the system argument; the strdup
        # call appears mid-path, i.e. the flow crossed the library via the summary.
        self.assertEqual(path[0], 'getenv("PATH")')
        self.assertEqual(path[-1], "d")
        self.assertIn("strdup(e)", path)

    def test_summary_is_load_bearing(self):
        # Drop only the strdup in->return summary: taint must no longer connect.
        graph, _ = _enrich_and_taint(self.atropos, self.binder, with_summary=False)
        self.assertEqual(len(self._witnesses(graph)), 0)

    def test_call_result_dataflow_is_load_bearing(self):
        # Drop only the dataflow overlay: return values are stranded on calls.
        graph, _ = _enrich_and_taint(self.atropos, self.binder, with_dataflow=False)
        self.assertEqual(len(self._witnesses(graph)), 0)



if __name__ == "__main__":
    unittest.main()
