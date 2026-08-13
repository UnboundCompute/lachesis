"""Executable checks for the store partition, on the fixture project shipped in-tree.

  python -m unittest lachesis.checks

One claim is worth proving here and everything else is scaffolding for it:

    join(compile(source), stored) == enrich(compile(source))

That is, a store holding only the spine and the semantic layer, rejoined against a fresh
compile of the same source, reconstructs the whole enriched graph — not approximately,
but edge for edge including properties. If that holds, the bodies are recomputable and do
not need to be on disk; if it does not, the reduction loses something and the size win is
not free.

The fixture is the planner's TypeScript project, which compiles in a couple of seconds, so
this runs as an ordinary unit test rather than as an errand against a checked-out
application.
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from lachesis.partition import (
    BODY, SEMANTIC, SPINE, edge_identity, join_graphs, partition_counts,
    partition_of, reduce_graph,
)
from lachesis.pipeline import _combined_capabilities, enrich_graph, run_project

FIXTURE = ROOT / "lachesis" / "planner" / "fixtures" / "project"


def _round_trip(reduced, snapshots, db_dir: Path):
    """Write a reduced graph to a real store and read it back out."""
    from lachesis.kuzu_store import write_kuzu_graph
    from lachesis.nav.kuzu_index import KuzuGraphIndex, materialize_graph

    write_kuzu_graph(reduced, snapshots, db_dir=str(db_dir), overwrite=True,
                     prune=False, elide_constants=False,
                     carry_unresolved_edges=True)
    return materialize_graph(KuzuGraphIndex(str(db_dir)))


class PartitionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory()
        try:
            core, snapshots = run_project(
                str(FIXTURE), output_root=str(Path(cls._tmp.name) / "frontend"),
                enrich=False,
            )
        except Exception as error:                       # pragma: no cover - environment
            raise unittest.SkipTest(f"could not compile the fixture: {error}")
        cls.core = core
        cls.enriched = enrich_graph(
            core,
            {language for s in snapshots for language in s.languages},
            _combined_capabilities(snapshots),
        )
        cls.reduced = reduce_graph(core, cls.enriched)
        cls.snapshots = snapshots

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmp.cleanup()

    def test_every_node_lands_in_exactly_one_layer(self) -> None:
        counts = partition_counts(self.enriched)
        self.assertEqual(len(self.enriched["nodes"]), sum(counts.values()))
        for layer in (SPINE, SEMANTIC, BODY):
            self.assertGreater(counts[layer], 0, f"no {layer} nodes in the fixture graph")

    def test_bodies_are_the_bulk_of_the_graph(self) -> None:
        # The reduction is only worth doing if what it drops is most of what is there.
        counts = partition_counts(self.enriched)
        self.assertGreater(counts[BODY], counts[SPINE] + counts[SEMANTIC])
        self.assertLess(len(self.reduced["nodes"]), len(self.enriched["nodes"]))

    def test_the_store_carries_every_edge_the_compiler_will_not_remake(self) -> None:
        # The failure this guards against is specific: judging an edge's provenance by
        # looking at its endpoints files body-to-body enrichment edges, taint among them,
        # as "a compiler must have made this", and then nothing ever makes them again.
        core = {edge_identity(e) for e in self.core["edges"]}
        carried = {edge_identity(e) for e in self.reduced["edges"]}
        missing = [e for e in self.enriched["edges"]
                   if edge_identity(e) not in core and edge_identity(e) not in carried]
        self.assertEqual([], missing[:5])

    def test_stored_edges_reach_into_bodies_the_store_does_not_hold(self) -> None:
        # Not a defect to be tolerated but the mechanism itself: a semantic fact about a
        # value inside a function is an edge to a node the store deliberately drops, and
        # it survives because ids are content-addressed rather than positional.
        held = {n["id"] for n in self.reduced["nodes"]}
        dangling = [e for e in self.reduced["edges"]
                    if e["source"] not in held or e["target"] not in held]
        self.assertTrue(dangling, "the fixture should exercise a cross-layer edge")

    def test_a_fresh_compile_reproduces_every_endpoint_the_store_needs(self) -> None:
        # The number that decides the design. An endpoint the compiler does not hand back
        # is a stored semantic fact with nothing left to attach to.
        fresh_ids = {n["id"] for n in self.core["nodes"]}
        semantic = {n["id"] for n in self.reduced["nodes"]
                    if partition_of(n) == SEMANTIC}
        unresolved = {end for e in self.reduced["edges"]
                      for end in (e["source"], e["target"])
                      if end not in semantic and end not in fresh_ids}
        self.assertEqual(set(), unresolved)

    def test_the_join_reconstructs_the_enriched_graph_exactly(self) -> None:
        joined = join_graphs(self.core, self.reduced)
        self.assertEqual(
            {n["id"] for n in self.enriched["nodes"]},
            {n["id"] for n in joined["nodes"]},
        )
        # Including properties. Comparing on (kind, source, target) alone calls the join
        # exact while it has quietly merged edges that differ only in what they record.
        self.assertEqual(
            {edge_identity(e) for e in self.enriched["edges"]},
            {edge_identity(e) for e in joined["edges"]},
        )

    def test_the_store_survives_a_real_write_and_read(self) -> None:
        # The claim, but through Kùzu rather than in memory: an edge into a body node
        # cannot be a rel row (both rel endpoints are foreign keys into `Node`), so it
        # rides in a table of its own, and the round trip has to bring it back intact
        # along with its properties.
        import json as _json

        from lachesis.kuzu_store import read_store_manifest

        db_dir = Path(self._tmp.name) / "reduced.kuzu"
        read_back = _round_trip(self.reduced, self.snapshots, db_dir)
        manifest = read_store_manifest(str(db_dir))
        self.assertGreater(manifest["deferred_edge_count"], 0)
        self.assertEqual(manifest["unresolved_edge_count"],
                         manifest["deferred_edge_count"])
        self.assertEqual(
            {edge_identity(e) for e in self.reduced["edges"]},
            {edge_identity(e) for e in read_back["edges"]},
        )
        joined = join_graphs(self.core, read_back)
        self.assertEqual(
            {edge_identity(e) for e in self.enriched["edges"]},
            {edge_identity(e) for e in joined["edges"]},
        )
        self.assertEqual(
            _json.dumps(sorted(n["id"] for n in self.enriched["nodes"])),
            _json.dumps(sorted(n["id"] for n in joined["nodes"])),
        )

    def test_an_ordinary_store_defers_nothing(self) -> None:
        # The lever is off by default, and it has to stay off: for a whole-graph store an
        # edge with a missing endpoint is a bug, and a table quietly absorbing it hides
        # one.
        from lachesis.kuzu_store import read_store_manifest, write_kuzu_graph

        db_dir = Path(self._tmp.name) / "whole.kuzu"
        write_kuzu_graph(self.enriched, self.snapshots, db_dir=str(db_dir),
                         overwrite=True, prune=False, elide_constants=False)
        manifest = read_store_manifest(str(db_dir))
        self.assertEqual(0, manifest["deferred_edge_count"])
        self.assertEqual(0, manifest["unresolved_edge_count"])

    def test_the_join_prefers_the_fresh_compile_over_the_store(self) -> None:
        # A store can be stale; the source in front of us cannot. Where both describe the
        # same id, the compile wins.
        stale = {
            "nodes": [dict(n, label="stale") for n in self.reduced["nodes"][:50]],
            "edges": [],
        }
        joined = join_graphs(self.core, stale)
        by_id = {n["id"]: n for n in joined["nodes"]}
        for node in self.core["nodes"][:200]:
            if node["id"] in by_id:
                self.assertEqual(node["label"], by_id[node["id"]]["label"])


if __name__ == "__main__":                               # pragma: no cover
    unittest.main()
