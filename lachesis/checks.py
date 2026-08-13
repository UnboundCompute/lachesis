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

import json
import os
import shutil
import subprocess
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

    def test_the_primed_compressor_writes_what_a_fresh_one_would(self) -> None:
        # `PropsCodec` clones one compressor primed with the store's dictionary rather
        # than constructing one per row, which is worth ~4x on the write phase and is
        # only worth anything if the bytes are the same bytes. zlib documents `.copy()`
        # as duplicating the compression state, but "the store is byte-identical" is a
        # claim about this store, so it is checked here against real props rather than
        # inherited from the manual.
        import zlib

        from lachesis.kuzu_store import (
            PropsCodec, _COLUMN_KEYS, _PROPS_ZLIB_LEVEL, _props_text,
            build_props_dictionary,
        )

        rows = [(n.get("properties") or {}, _COLUMN_KEYS)
                for n in self.enriched["nodes"]]
        rows += [(e.get("properties") or {}, frozenset())
                 for e in self.enriched["edges"]]
        zdict = build_props_dictionary(
            _props_text(props, True, drop) for props, drop in rows)
        self.assertTrue(zdict, "the fixture should share enough to fill a dictionary")

        texts = [_props_text(props, True, drop) for props, drop in rows]
        # `cached` is how the writer runs: the tails the dictionary pre-pass built,
        # handed back rather than rebuilt. `codec` recomputes them. The two have to
        # agree, or the saved pass has quietly changed what is stored.
        cached, codec, plain = (PropsCodec(zdict, texts), PropsCodec(zdict),
                                PropsCodec())
        for index, (props, drop) in enumerate(rows):
            text = texts[index]
            fresh = zlib.compressobj(_PROPS_ZLIB_LEVEL, zlib.DEFLATED, zlib.MAX_WBITS,
                                     zlib.DEF_MEM_LEVEL, 0, zdict)
            expected = fresh.compress(text) + fresh.flush()
            self.assertEqual(expected, codec.blob(index, props, True, drop))
            self.assertEqual(expected, cached.blob(index, props, True, drop))
            # and the no-dictionary path is still plain deflate, which is what a reader
            # holding an empty dictionary inflates against.
            self.assertEqual(zlib.compress(text, _PROPS_ZLIB_LEVEL),
                             plain.blob(index, props, True, drop))

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


def _build(source: Path, destination: Path, *reduced: str) -> None:
    completed = subprocess.run(
        [sys.executable, "-m", "lachesis.cli.analyze", str(source), str(destination),
         "--frontend-out", str(destination) + ".frontends", "--enrich", *reduced],
        cwd=ROOT, text=True, capture_output=True, check=False,
        env={**os.environ, "PYTHONPATH": str(ROOT)},
    )
    if completed.returncode != 0:                        # pragma: no cover - environment
        raise unittest.SkipTest(f"could not build the fixture:\n{completed.stderr}")


class LoadTests(unittest.TestCase):
    """The other half: what a reduced store is like to open.

    The producer's job is proven above. This is the consumer's — that a caller which
    knows nothing about the split gets the same answers from a store with no bodies in
    it, because the loader put them back before handing the store over.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory()
        root = Path(cls._tmp.name)
        # A copy, so a check can edit a source file without touching the repo.
        cls.source = root / "src"
        shutil.copytree(FIXTURE, cls.source)
        cls.whole = root / "whole.kuzu"
        cls.reduced_store = root / "reduced.kuzu"
        _build(cls.source, cls.whole)
        _build(cls.source, cls.reduced_store, "--reduced")

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmp.cleanup()

    def _guard_rows(self, store) -> dict:
        from lachesis.nav.guards import GuardProfiles
        return {row["name"]: row["guard_signal"]
                for row in GuardProfiles(store).top(50)}

    def test_a_reduced_store_answers_like_a_whole_one(self) -> None:
        from lachesis.nav.graph_store import GraphStore
        from lachesis.nav.kuzu_index import materialize_graph

        whole = materialize_graph(GraphStore.load(str(self.whole)).index)
        rejoined = materialize_graph(GraphStore.load(str(self.reduced_store)).index)
        self.assertEqual(
            sorted(n["id"] for n in whole["nodes"]),
            sorted(n["id"] for n in rejoined["nodes"]),
        )
        self.assertEqual(
            {edge_identity(e) for e in whole["edges"]},
            {edge_identity(e) for e in rejoined["edges"]},
        )

    def test_guard_profiles_survive_the_round_trip(self) -> None:
        # Named specifically because this is the tool that failed loudest when the
        # rejoin was missing: a body-less store reported a real guard as class
        # "passthrough" with score 0.0 and zero conditions. Every counted field comes
        # from a body edge, so if the bodies did not come back this inverts rather than
        # thins out.
        from lachesis.nav.graph_store import GraphStore

        whole = self._guard_rows(GraphStore.load(str(self.whole)))
        rejoined = self._guard_rows(GraphStore.load(str(self.reduced_store)))
        self.assertTrue(any(row["score"] > 0 for row in whole.values()),
                        "the fixture should contain at least one guard-shaped function")
        self.assertEqual(whole, rejoined)

    def test_the_second_load_does_not_recompile(self) -> None:
        from lachesis.nav.graph_store import GraphStore, joined_store_path

        GraphStore.load(str(self.reduced_store))
        cache = Path(joined_store_path(str(self.reduced_store)))
        self.assertTrue(cache.is_dir())
        stamp = (cache / "graph.kuzu").stat().st_mtime_ns
        GraphStore.load(str(self.reduced_store))
        self.assertEqual(stamp, (cache / "graph.kuzu").stat().st_mtime_ns)

    def test_a_changed_source_tree_is_refused(self) -> None:
        # Not degraded, refused. The stored semantics describe source that is no longer
        # there, and answering from them anyway is the confident-wrong-answer failure.
        from lachesis.nav.graph_store import GraphStore

        edited = next(self.source.rglob("*.ts"))
        original = edited.read_text(encoding="utf-8")
        edited.write_text(original + "\nexport const added = 1;\n", encoding="utf-8")
        try:
            with self.assertRaises(ValueError) as caught:
                GraphStore.load(str(self.reduced_store))
            self.assertIn("--reduced", str(caught.exception))
        finally:
            edited.write_text(original, encoding="utf-8")

    def test_a_missing_source_tree_names_the_path_it_wanted(self) -> None:
        from lachesis.kuzu_store import read_store_manifest, store_manifest_file
        from lachesis.nav.graph_store import GraphStore

        moved = Path(self._tmp.name) / "moved.kuzu"
        shutil.copytree(self.reduced_store, moved)
        manifest = read_store_manifest(str(moved))
        manifest["source_dir"] = "/nowhere/at/all"
        with open(store_manifest_file(str(moved)), "w", encoding="utf-8") as handle:
            json.dump(manifest, handle)
        with self.assertRaises(ValueError) as caught:
            GraphStore.load(str(moved))
        self.assertIn("/nowhere/at/all", str(caught.exception))


if __name__ == "__main__":                               # pragma: no cover
    unittest.main()
