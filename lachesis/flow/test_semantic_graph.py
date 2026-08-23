import unittest

from .emit import _cfg_guard_proofs
from .semantic_graph import Event, EventKind, ObjRef, SkeletonGraph, match_graph


class SemanticGraphTests(unittest.TestCase):
    def _graph(self, events, edges):
        g = SkeletonGraph()
        for node, event in events:
            g.add_node(node, event)
        for source, target, *kind in edges:
            g.add_edge(source, target, kind=kind[0] if kind else "normal")
        g.add_fragment("main", events[0][0], [events[-1][0]])
        g.validate()
        return g

    def test_relational_and_index_guards_keep_distinct_typed_proofs(self):
        class Sub:
            @staticmethod
            def label(_node):
                return "idx < bound"

        proofs = _cfg_guard_proofs(Sub(), "condition", 0, 2)
        self.assertEqual([proof.kind for proof in proofs], ["VALUE", "BOUNDED"])

    def test_branch_arms_do_not_form_a_linear_false_positive(self):
        o = ObjRef("O_buf", generation="g0")
        events = [("start", None), ("true_free", Event.release(o, 2)),
                  ("false_keep", None), ("merge", None),
                  ("use", Event.read(o, ".data", 5))]
        g = self._graph(events, [("start", "true_free"), ("start", "false_keep"),
                                 ("true_free", "merge"), ("false_keep", "merge"),
                                 ("merge", "use")])
        # The use is reachable from the true arm and is therefore correctly a lead; the graph
        # does not invent a free->use order by flattening the false arm into the true arm.
        self.assertEqual(len(match_graph(g)), 1)
        self.assertEqual(match_graph(g)[0]["pattern"], "uaf.deref")

    def test_storage_free_does_not_free_pointee(self):
        buf = ObjRef("O_buf", generation="g0")
        payload = ObjRef("O_payload", generation="g0")
        events = [("start", None), ("capture", Event(EventKind.DERIVE, value=payload, line=1)),
                  ("free", Event.release(buf, 2)), ("saved_use", Event(EventKind.PASS_VALUE,
                                                                         obj=payload, line=3))]
        g = self._graph(events, [("start", "capture"), ("capture", "free"), ("free", "saved_use")])
        self.assertEqual(match_graph(g), [])

    def test_derive_preserves_alias_identity(self):
        original = ObjRef("O", generation="g0")
        alias = ObjRef("saved", generation="g0")
        events = [("start", Event.origin(original)),
                  ("derive", Event(EventKind.DERIVE, obj=alias, value=original)),
                  ("free", Event.release(original, 2)),
                  ("use", Event.read(alias, "*", 3))]
        g = self._graph(events, [("start", "derive"), ("derive", "free"), ("free", "use")])
        self.assertTrue(any(h["pattern"] == "uaf.deref" for h in match_graph(g)))

    def test_compare_is_a_dangling_value_use_not_a_deref(self):
        obj = ObjRef("p", generation="g0")
        events = [("origin", Event.origin(obj)), ("free", Event.release(obj, 2)),
                  ("compare", Event(EventKind.COMPARE_VALUE, obj=obj, line=3))]
        g = self._graph(events, [("origin", "free"), ("free", "compare")])
        patterns = {hit["pattern"] for hit in match_graph(g)}
        self.assertEqual(patterns, {"use.dangling"})

    def test_leak_requires_a_non_escaped_origin_at_top_level_exit(self):
        leaked = ObjRef("leaked", generation="g0")
        g = self._graph([("origin", Event.origin(leaked)), ("exit", None)],
                        [("origin", "exit")])
        self.assertEqual({hit["pattern"] for hit in match_graph(g)}, {"leak"})

        returned = ObjRef("returned", generation="g0")
        g = self._graph([("origin", Event.origin(returned)),
                         ("return", Event(EventKind.RETURN_VALUE, obj=returned)),
                         ("exit", None)], [("origin", "return"), ("return", "exit")])
        self.assertNotIn("leak", {hit["pattern"] for hit in match_graph(g)})

    def test_null_rebind_is_not_a_second_free_and_null_deref_is_distinct(self):
        obj = ObjRef("p", generation="g0")
        events = [("start", Event.origin(obj)),
                  ("null", Event(EventKind.WRITE_STORAGE_NULL, obj=obj)),
                  ("free", Event.release(obj, 2)),
                  ("use", Event.read(obj, "*", 3))]
        g = self._graph(events, [("start", "null"), ("null", "free"), ("free", "use")])
        patterns = {h["pattern"] for h in match_graph(g)}
        self.assertIn("null-deref", patterns)
        self.assertNotIn("double-free", patterns)

    def test_nulling_one_alias_does_not_null_the_other_slot(self):
        obj = ObjRef("p", generation="g0")
        alias = ObjRef("q", generation="g0")
        events = [
            ("origin", Event.origin(obj)),
            ("derive", Event(EventKind.DERIVE, obj=alias, value=obj)),
            ("null_p", Event(EventKind.WRITE_STORAGE_NULL, obj=obj)),
            ("free_q", Event.release(alias, 4)),
            ("use_q", Event.read(alias, "*", 5)),
        ]
        g = self._graph(events, [("origin", "derive"), ("derive", "null_p"),
                                 ("null_p", "free_q"), ("free_q", "use_q")])
        patterns = {hit["pattern"] for hit in match_graph(g)}
        self.assertIn("uaf.deref", patterns)
        self.assertNotIn("null-deref", patterns)

    def test_source_tiers_are_preserved_on_leads(self):
        obj = ObjRef("p", generation="g0")
        g = SkeletonGraph()
        g.add_node("s", Event.release(obj), fragment="source",
                   source_reachable=True, source_influenced=True)
        g.add_node("u", Event.read(obj), fragment="source",
                   source_reachable=True, source_influenced=False)
        g.add_edge("s", "u")
        g.add_fragment("source", "s", ["u"])
        hits = match_graph(g)
        self.assertEqual([(h["pattern"], h["tier"]) for h in hits if h["pattern"] == "uaf.deref"],
                         [("uaf.deref", 2)])

    def test_call_returns_only_to_pushed_continuation(self):
        o = ObjRef("O", generation="g0")
        g = SkeletonGraph()
        for node, event in [("caller", None), ("enter", Event(EventKind.SEAM_ENTER)),
                            ("free", Event.release(o, 10)), ("exit", Event(EventKind.SEAM_EXIT)),
                            ("after", Event(EventKind.READ_STORAGE, base=o, line=11)),
                            ("wrong", Event(EventKind.READ_STORAGE, base=o, line=99)),
                            ("callee_end", None)]:
            g.add_node(node, event)
        g.add_fragment("caller", "caller", ["after"])
        g.add_fragment("callee", "enter", ["exit"])
        g.add_edge("caller", "enter", kind="call", return_to="after")
        g.add_edge("enter", "free")
        g.add_edge("free", "exit")
        g.add_edge("exit", "after", kind="return")
        g.add_edge("exit", "wrong", kind="return")
        self.assertEqual([h["node"] for h in match_graph(g) if h["pattern"] == "uaf.deref"], ["after"])


if __name__ == "__main__":
    unittest.main()
