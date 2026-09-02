"""The candidate constructors answer identically off a materialized dict graph and
off the disk-backed Kùzu index.

Pass 3 no longer re-inflates the whole typed structural graph into RAM; the
constructors read call/expression/cfg-condition nodes, value-flow and branch-region
edges, AST children and allocator calls straight from the Kùzu index, keeping only
the small Atropos delta materialized (see ``unbounded_copy.IndexBackedGraph``). The
correctness gate for that port is exact output equivalence: for every constructor and
fixture, the candidate document built from the index must equal the one built from
the dict. This test is that gate -- it writes each dict fixture into a real Kùzu
store, wraps the store's index as the index-path input, and diffs the two documents.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

try:
    import kuzu  # noqa: F401
    _HAVE_KUZU = True
except Exception:  # pragma: no cover - environment without the engine
    _HAVE_KUZU = False

from .index_capacity import MemoryIndexCapacity
from .sink_obligation import sink_constructor
from .test_candidates import (
    _cond, _node, _role, fixture_graph, multi_family_graph, _region_graph,
)
from .unbounded_copy import (
    IndexBackedGraph, MemoryCopyCapacity, present_index_capabilities,
)


def _atropos_delta(graph: dict) -> list[dict]:
    """The only fact the index does not serve: the Atropos-authored nodes (sinks and
    the alloc-size element-count stamps). Sourced from the graph the same way the
    live path sources them from ``.bind.pb``."""
    return [n for n in graph["nodes"]
            if (n.get("properties") or {}).get("fact_origin") == "atropos-model"]


def _rich_alloc_graph() -> dict:
    """A generic (alloc-size) sink whose size has a reaching definition and a
    parameter origin, guarded by a size-testing branch -- so the index path must
    serve VariableContext (value-flow walk) and BranchRegions (cfg-condition +
    TRUE_BRANCH region), not merely per-id lookups."""
    return {
        "nodes": [
            _node("call:kmalloc", "call", "kmalloc(sz, GFP_KERNEL)", callee="kmalloc",
                  method_name="kmalloc", owner_function_id="fn:a", file="a.c",
                  start_line=11, absolute_file="/x/a.c", start_offset=200,
                  end_offset=230),
            _node("v:sz", "expression", "sz", absolute_file="/x/a.c",
                  start_offset=100, end_offset=110),
            _node("v:len", "expression", "len", absolute_file="/x/a.c",
                  start_offset=50, end_offset=60),
            _node("p:len", "parameter", "len", absolute_file="/x/a.c",
                  start_offset=10, end_offset=20),
            _cond("cond:g", "fn:a", "if (sz > MAX)"),
            _node("region:true", "statement", "{ kmalloc(sz, GFP_KERNEL); }",
                  absolute_file="/x/a.c", start_offset=150, end_offset=260),
            _role("sink:alloc", "sink", "c.kernel.kmalloc.a0", "v:sz",
                  "call:kmalloc", "Argument[0]", "alloc-size"),
        ],
        "edges": [
            {"source": "v:len", "target": "v:sz", "kind": "VALUE_FLOWS_TO",
             "properties": {"reason": "assignment"}},
            {"source": "p:len", "target": "v:len", "kind": "VALUE_FLOWS_TO",
             "properties": {"reason": "call-argument"}},
            {"source": "cond:g", "target": "region:true", "kind": "TRUE_BRANCH",
             "properties": {}},
        ],
    }


def _index_capacity_graph() -> dict:
    """An array-subscript store `arr[i] = v` with an allocator (`arr = malloc(n)`)
    and an Atropos alloc-size stamp naming the element-count argument, plus a bound
    check `if (i < n)` -- exercises AST_CHILD role adjacency, the allocator/assignment
    scans, and the alloc-size stamp lookup on the index path."""
    return {
        "nodes": [
            _node("asg", "expression", "arr[i] = v", syntax_kind="BinaryOperator",
                  operator="=", owner_function_id="fn:a", file="a.c", start_line=20,
                  absolute_file="/x/a.c", start_offset=400, end_offset=412),
            _node("sub", "expression", "arr[i]", syntax_kind="ArraySubscriptExpr"),
            _node("arr", "expression", "arr"),
            _node("i", "expression", "i"),
            _node("asg_def", "expression", "arr = malloc(n)",
                  syntax_kind="BinaryOperator", operator="=",
                  owner_function_id="fn:a", start_line=10),
            _node("call:malloc", "call", "malloc(n)", callee="malloc",
                  method_name="malloc", owner_function_id="fn:a", start_line=10,
                  argument_value_ids=["v:n"]),
            _node("v:n", "expression", "n"),
            _cond("cond:i", "fn:a", "if (i < n)"),
            # Atropos alloc-size stamp: top-level kind is a model annotation, and its
            # ``properties.kind == alloc-size`` is what ``_capacity`` matches on -- built
            # as a literal so ``properties.kind`` is free of ``_node``'s positional kind.
            {"id": "alloc-stamp", "kind": "annotation", "label": "alloc-size",
             "properties": {"fact_origin": "atropos-model", "kind": "alloc-size",
                            "callsite_id": "call:malloc", "element_count_arg": 0}},
        ],
        "edges": [
            {"source": "asg", "target": "sub", "kind": "AST_CHILD",
             "properties": {"role": "LEFT_OPERAND"}},
            {"source": "sub", "target": "arr", "kind": "AST_CHILD",
             "properties": {"role": "RECEIVER"}},
            {"source": "sub", "target": "i", "kind": "AST_CHILD",
             "properties": {"role": "PROPERTY_KEY"}},
        ],
    }


@unittest.skipUnless(_HAVE_KUZU, "the Kùzu engine is required for the index path")
class CandidateIndexEquivalenceTest(unittest.TestCase):
    def _index_backed(self, graph: dict, tmp: str) -> IndexBackedGraph:
        from lachesis.kuzu_store import write_kuzu_graph
        from lachesis.nav.graph_store import GraphStore

        path = str(Path(tmp) / "g.kuzu")
        write_kuzu_graph(graph, [], path, prune=False, elide_constants=False)
        index = GraphStore.load(path).index
        return IndexBackedGraph(index, _atropos_delta(graph),
                                present_index_capabilities(index))

    def _assert_identical(self, constructor, graph: dict, label: str) -> None:
        golden = constructor(graph).enumerate()
        with tempfile.TemporaryDirectory() as tmp:
            ported = constructor(self._index_backed(graph, tmp)).enumerate()
        self.assertEqual(
            json.dumps(golden, sort_keys=True, default=str),
            json.dumps(ported, sort_keys=True, default=str),
            f"index path diverged from dict path for {label}")

    def test_generic_sink_families_match(self):
        from lachesis.planner import taxonomy

        specs = {s["id"]: s for s in taxonomy.family_specs()}
        cases = [
            ("memory.alloc.size", multi_family_graph()),
            ("injection.query.escaping", multi_family_graph()),
            ("memory.alloc.size", _rich_alloc_graph()),
        ]
        for family_id, graph in cases:
            constructor = sink_constructor(specs[family_id])
            self._assert_identical(constructor, graph, f"{family_id}")

    def test_memory_copy_capacity_matches(self):
        for name, graph in (("fixture", fixture_graph()),
                            ("region-in", _region_graph(True)),
                            ("region-out", _region_graph(False))):
            self._assert_identical(MemoryCopyCapacity, graph, f"copy/{name}")

    def test_memory_index_capacity_matches(self):
        self._assert_identical(
            MemoryIndexCapacity, _index_capacity_graph(), "index-capacity")


if __name__ == "__main__":
    unittest.main()
