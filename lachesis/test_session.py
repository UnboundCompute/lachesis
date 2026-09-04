"""Unit tests for the warm-session substrate: LeadSet filters, persistence, and honesty.

The filters resolve function -> file through the symbol index, but that resolution is the
only part that needs a real store; the filter *logic* is pure over the lead dicts. So these
tests drive the logic directly on synthetic leads (fast, no graph build) and inject the
name->file map where ``near``/``at`` need one. A separate integration test exercises the whole
``Analysis.open().analyze()`` path against a built graph when one is available.
"""
from __future__ import annotations

import json
import os
import tempfile
import unittest

from lachesis.session import Analysis, Deadline, Lead, LeadSet


def _leads():
    return (
        Lead.from_dict({"pattern": "double-free", "entry": "parse", "var": "buf", "line": 40}),
        Lead.from_dict({"pattern": "double-free", "entry": "parse", "var": "tmp", "line": 55}),
        Lead.from_dict({"pattern": "leak", "entry": "parse", "var": "node", "line": 60}),
        Lead.from_dict({"pattern": "leak", "entry": "emit", "var": "out", "line": 120}),
        Lead.from_dict({"pattern": "missing-guard", "entry": "emit", "var": "len", "line": 130}),
    )


class LeadSetFilterTests(unittest.TestCase):
    def setUp(self):
        self.ls = LeadSet(leads=_leads())

    def test_len_iter_bool(self):
        self.assertEqual(len(self.ls), 5)
        self.assertTrue(self.ls)
        self.assertEqual(len(list(self.ls)), 5)
        self.assertFalse(LeadSet())

    def test_summary_counts_and_honesty_fields(self):
        summary = self.ls.summary()
        self.assertEqual(summary["total"], 5)
        self.assertEqual(summary["by_pattern"],
                         {"double-free": 2, "leak": 2, "missing-guard": 1})
        self.assertFalse(summary["timed_out"])
        # summary must be JSON-safe on its own -- the MCP surface json.dumps it directly.
        json.dumps(summary)

    def test_summary_surfaces_partial_run(self):
        partial = LeadSet(leads=_leads(), timed_out=True,
                          truncated_functions=("big_fn",))
        summary = partial.summary()
        self.assertTrue(summary["timed_out"])
        self.assertEqual(summary["truncated_functions"], ["big_fn"])

    def test_by_pattern(self):
        df = self.ls.by_pattern("double-free")
        self.assertEqual(len(df), 2)
        self.assertTrue(all(lead["pattern"] == "double-free" for lead in df))
        self.assertEqual(len(self.ls.by_pattern("nope")), 0)

    def test_by_function(self):
        parse = self.ls.by_function("parse")
        self.assertEqual(len(parse), 3)
        self.assertTrue(all(lead["entry"] == "parse" for lead in parse))

    def test_by_function_line_window(self):
        windowed = self.ls.by_function("parse", (50, 65))
        self.assertEqual({lead["line"] for lead in windowed}, {55, 60})

    def test_filters_chain(self):
        chained = self.ls.by_function("parse").by_pattern("leak")
        self.assertEqual(len(chained), 1)
        self.assertEqual(chained.leads[0]["var"], "node")

    def test_patterns_sorted_unique(self):
        self.assertEqual(self.ls.patterns(),
                         ["double-free", "leak", "missing-guard"])

    def test_near_and_at_resolve_through_index(self):
        # Inject the name->file map that a real store would build, so near/at are tested
        # without a graph. `parse` lives in two files (a homonym); `emit` in one.
        index = {"parse": {"/src/parse.c", "/vendor/parse.c"}, "emit": {"/src/emit.c"}}
        object.__setattr__(self.ls, "_index_cache", index)
        # basename match
        self.assertEqual(len(self.ls.near("parse.c")), 3)
        # path-suffix match
        self.assertEqual(len(self.ls.near("src/emit.c")), 2)
        # a homonym file still resolves (set membership, never collapsed)
        self.assertEqual(len(self.ls.near("/vendor/parse.c")), 3)
        # at = a single-line window
        self.assertEqual(len(self.ls.at("parse.c", 40)), 1)
        self.assertEqual(len(self.ls.near("parse.c", (39, 56))), 2)
        # an unknown file resolves cleanly to nothing (never an error)
        self.assertEqual(len(self.ls.near("missing.c")), 0)

    def test_to_json_payload_and_atomic_write(self):
        payload = self.ls.to_json()
        self.assertEqual(set(payload), {"schema", "summary", "leads"})
        self.assertEqual(len(payload["leads"]), 5)
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "leads.json")
            written = self.ls.to_json(path)
            self.assertEqual(written, path)
            with open(path) as stream:
                back = json.load(stream)
            self.assertEqual(len(back["leads"]), 5)
            self.assertEqual(back["summary"]["total"], 5)


class DeadlineTests(unittest.TestCase):
    def test_of_returns_none_for_unbounded(self):
        self.assertIsNone(Deadline.of(None))
        self.assertIsNone(Deadline.of(0))
        self.assertIsNone(Deadline.of(-1))

    def test_of_builds_a_budget(self):
        deadline = Deadline.of(100)
        self.assertIsNotNone(deadline)
        self.assertFalse(deadline.expired())
        self.assertGreater(deadline.remaining(), 0)

    def test_expired_budget(self):
        self.assertTrue(Deadline(0.0).expired())


class _FakeStore:
    """The only surface bind_cache reads: an on-disk graph path (or None)."""

    def __init__(self, graph_path):
        self.graph_path = graph_path


class BindCacheTests(unittest.TestCase):
    """The persistent catalog-bind sidecar: a hit is exact, and every doubt is a miss."""

    def setUp(self):
        from lachesis import bind_cache

        self.bind_cache = bind_cache
        self._dir = tempfile.TemporaryDirectory()
        self.graph = os.path.join(self._dir.name, "graph.kuzu")
        self.store = _FakeStore(self.graph)
        # The store's content hash is what a real manifest would stamp; pin it so the test
        # controls invalidation without building a graph.
        self._real_core_hash = bind_cache._core_hash
        bind_cache._core_hash = lambda path: "hash-A"
        self.addCleanup(self._restore_core_hash)
        self.addCleanup(self._dir.cleanup)
        self.addCleanup(lambda: os.environ.pop("LACHESIS_BIND_SIDECAR", None))
        self.addCleanup(lambda: os.environ.pop("LACHESIS_BIND_SIDECAR_MAX_MB", None))

    def _restore_core_hash(self):
        self.bind_cache._core_hash = self._real_core_hash

    def test_round_trip_is_exact(self):
        stamped = {"nodes": [{"id": "n1", "kind": "alloc"}], "edges": [],
                   "semantic_graph": {"nodes": {}}}
        summary = {"languages": ["c"], "sinks": 3}
        self.bind_cache.store(self.store, stamped, summary)
        self.assertTrue(os.path.isfile(self.bind_cache.sidecar_path(self.graph)))
        back = self.bind_cache.load(self.store)
        self.assertIsNotNone(back)
        # Typed caches keep graph records on disk and return metadata lazily; loading a
        # cache must not materialize the full stamped graph just to answer a cache hit.
        self.assertEqual(back[0]["nodes"], [])
        self.assertEqual(back[0]["edges"], [])
        self.assertTrue(back[0]["_typed_bind_cache_path"].endswith(".bind.pb"))
        self.assertEqual(
            self.bind_cache._load_typed_graph(back[0]["_typed_bind_cache_path"])["stamped"],
            stamped,
        )
        self.assertEqual(back[1], summary)

    def test_content_hash_change_invalidates(self):
        self.bind_cache.store(self.store, {"nodes": [], "edges": []}, {"languages": ["c"]})
        self.assertIsNotNone(self.bind_cache.load(self.store))
        # A different store content hash must miss the file written for the old one.
        self.bind_cache._core_hash = lambda path: "hash-B"
        self.assertIsNone(self.bind_cache.load(self.store))

    def test_unkeyable_store_never_uses_sidecar(self):
        # A store with no content hash can neither be trusted nor invalidated -> decline both.
        self.bind_cache._core_hash = lambda path: ""
        self.bind_cache.store(self.store, {"nodes": [], "edges": []}, {"languages": ["c"]})
        self.assertFalse(os.path.isfile(self.bind_cache.sidecar_path(self.graph)))
        self.assertIsNone(self.bind_cache.load(self.store))

    def test_no_path_store_is_a_miss(self):
        pathless = _FakeStore(None)
        self.bind_cache.store(pathless, {"nodes": [], "edges": []}, {"languages": ["c"]})
        self.assertIsNone(self.bind_cache.load(pathless))

    def test_opt_out_disables_read_and_write(self):
        os.environ["LACHESIS_BIND_SIDECAR"] = "0"
        self.bind_cache.store(self.store, {"nodes": [], "edges": []}, {"languages": ["c"]})
        self.assertFalse(os.path.isfile(self.bind_cache.sidecar_path(self.graph)))
        # Even with a file present, the opt-out declines the read.
        os.environ.pop("LACHESIS_BIND_SIDECAR")
        self.bind_cache.store(self.store, {"nodes": [], "edges": []}, {"languages": ["c"]})
        os.environ["LACHESIS_BIND_SIDECAR"] = "0"
        self.assertIsNone(self.bind_cache.load(self.store))

    def test_size_ceiling_declines_the_write(self):
        os.environ["LACHESIS_BIND_SIDECAR_MAX_MB"] = "0.0001"  # ~100 bytes
        self.bind_cache.store(self.store, {"nodes": [{"id": "n", "big": "x" * 10000}], "edges": []},
                              {"languages": ["c"]})
        self.assertFalse(os.path.isfile(self.bind_cache.sidecar_path(self.graph)))


class GuardViewTests(unittest.TestCase):
    """`_guard_view` folds two independent guard channels -- branch conditions and
    validation-shaped calls -- into one neutral observation. Pure over a dict, so it
    needs no built graph."""

    def test_guard_view_folds_validation_calls(self):
        # A sink with no branch condition but a validation call it passes through
        # reads as `observed` (the guard was previously invisible), and the call
        # rows ride along -- neutral presence, never a "safe" verdict.
        view = Analysis._guard_view({
            "conditions": {"status": "none-observed", "dominance": "none-observed",
                           "referencing_conditions": []},
            "guard_calls": {"status": "observed",
                            "validation_calls": [{"callee": "validate_redirect_uri"}]},
        })
        self.assertEqual(view["status"], "observed")
        self.assertEqual(view["dominance"], "none-observed")
        self.assertEqual(view["validation_calls"][0]["callee"], "validate_redirect_uri")

    def test_guard_view_stays_none_observed_without_either_guard(self):
        view = Analysis._guard_view({
            "conditions": {"status": "none-observed", "dominance": "none-observed"},
            "guard_calls": {"status": "none-observed", "validation_calls": []},
        })
        self.assertEqual(view["status"], "none-observed")


class FixtureIntegrationTests(unittest.TestCase):
    """The whole warm path over a real built graph, when one is present locally."""

    GRAPH = os.path.expanduser("~/.lachesis/graphs/fixture_p3.kuzu")

    def setUp(self):
        if not os.path.isdir(self.GRAPH):
            self.skipTest(f"fixture graph not built at {self.GRAPH}")

    def test_open_analyze_query(self):
        analysis = Analysis.open(self.GRAPH)
        leads = analysis.analyze()
        self.assertGreater(len(leads), 0)
        self.assertFalse(leads.timed_out)
        # the bundle is memoized: a second analyze does not recompute the pass
        self.assertIs(analysis._flow_bundle("object", "c"),
                      analysis._flow_bundle("object", "c"))
        # every filter narrows to a subset
        for pattern in leads.patterns():
            subset = leads.by_pattern(pattern)
            self.assertLessEqual(len(subset), len(leads))
            self.assertTrue(all(lead["pattern"] == pattern for lead in subset))

    def test_hard_stop_returns_partial_not_hang(self):
        analysis = Analysis.open(self.GRAPH)
        # a sub-millisecond budget forces the cooperative deadline to trip; the pass must
        # return partial leads flagged timed_out, never raise or hang.
        leads = analysis.analyze(hard_stop=0.0001)
        self.assertTrue(leads.timed_out)

    def test_structural_fast_path_skips_the_flow_pass(self):
        import os

        # A complete cached bind would (correctly) satisfy a temporal=False request as a
        # superset; clear it so this exercises the genuine structural-only fast path.
        sidecar = self.GRAPH + ".bind.pb"
        if os.path.isfile(sidecar):
            os.remove(sidecar)
        analysis = Analysis.open(self.GRAPH)
        census = analysis.census(temporal=False)
        # the fast path answers the structural families but does not evaluate the temporal
        # ones, and must never force the dataflow-tier flow pass (no ("flow", ...) built) nor
        # write a sidecar (the structural bind is a partial answer).
        self.assertFalse(census["temporal_evaluated"])
        self.assertTrue(census["constructors"])
        self.assertNotIn(("flow", None, "c"), analysis._built)
        self.assertIn(("bind", False), analysis._built)
        self.assertFalse(os.path.isfile(sidecar))

    def test_constructors_lists_the_taxonomy(self):
        # `constructors` is a @property on the registry, not a method -- regression guard so
        # Analysis.constructors() never calls the tuple it returns.
        analysis = Analysis.open(self.GRAPH)
        families = analysis.constructors()
        self.assertIsInstance(families, tuple)
        self.assertTrue(families)
        self.assertIn("id", families[0])

    def _first_candidate(self, analysis):
        """A structural candidate row that carries a source position over the fixture.

        Picks the first candidate whose observations name a file, not merely ``[0]``: a cached
        temporal bind (any prior test may have written one) legitimately satisfies this
        ``temporal=False`` query as a superset, and its lifecycle rows can sort first without a
        file/body -- which explain-by-position needs. Robust to sidecar state, so test order
        cannot flip which candidate this returns."""
        groups = analysis.candidates(temporal=False, limit=200)["groups"]
        rows = [row for group in groups for row in group.get("candidates", [])]
        for row in rows:
            if (row.get("observations") or {}).get("file"):
                return row
        if rows:
            return rows[0]
        self.skipTest("fixture graph carries no candidates")

    def test_explain_composes_the_whole_chain(self):
        analysis = Analysis.open(self.GRAPH)
        row = self._first_candidate(analysis)
        result = analysis.explain(row["candidate_id"], temporal=False)
        # one structured record standing in for census->candidates->detail->sources_of->read_body
        self.assertEqual(result["candidate_id"], row["candidate_id"])
        self.assertTrue(result["obligation"])
        self.assertEqual(result["sink"]["line"], row["observations"]["line"])
        # the guard is read straight from the inference -- present, and never silently "safe"
        self.assertIn("dominance", result["guard"])
        # provenance is a bounded reverse cone (evidence, honest counts), source is read inline
        self.assertIn("cone", result["provenance"])
        self.assertIsNotNone(result["source"])
        self.assertTrue(result["source"]["body"])
        # bounded run flags its own honesty, same as every candidate move
        self.assertIn("temporal_evaluated", result)

    def test_explain_sink_resolves_a_position(self):
        analysis = Analysis.open(self.GRAPH)
        row = self._first_candidate(analysis)
        observations = row["observations"]
        # a bare basename plus the line resolves to the same candidate as its opaque id
        by_position = analysis.explain_sink(os.path.basename(observations["file"]),
                                            observations["line"], temporal=False)
        self.assertEqual(by_position["candidate_id"], row["candidate_id"])

    def test_explain_miss_is_honest_not_empty(self):
        analysis = Analysis.open(self.GRAPH)
        # an unknown id is a named miss, not a bare empty record
        self.assertIn("error", analysis.explain("obl_deadbeef", temporal=False))
        # an unmodeled position says an absent candidate is not a proof of safety
        miss = analysis.explain_sink("nonexistent.c", 999999, temporal=False)
        self.assertIn("error", miss)
        self.assertIn("note", miss)

    def test_full_temporal_bind_evaluates_and_flags(self):
        analysis = Analysis.open(self.GRAPH)
        census = analysis.census()  # temporal on by default
        self.assertTrue(census["temporal_evaluated"])

    def test_bounded_temporal_degrades_not_hangs(self):
        import os

        # remove any sidecar so the sub-ms budget genuinely times out the merge rather than
        # loading a complete cached bind.
        sidecar = self.GRAPH + ".bind.pb"
        if os.path.isfile(sidecar):
            os.remove(sidecar)
        analysis = Analysis.open(self.GRAPH)
        census = analysis.census(hard_stop=0.0001)
        # a timed-out temporal merge degrades to structural families, flagged, and is never
        # cached to the sidecar (a partial answer must not poison a later patient run).
        self.assertFalse(census["temporal_evaluated"])
        self.assertFalse(os.path.isfile(sidecar))


if __name__ == "__main__":
    unittest.main()
