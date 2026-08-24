import unittest

from .emit import _cfg_guard_proofs
from . import atropos
from .semantic_graph import Edge, Event, EventKind, GuardProof, ObjRef, SkeletonGraph, match_graph


class SemanticGraphTests(unittest.TestCase):
    def test_default_pattern_registry_covers_every_atropos_matcher(self):
        from lachesis.flow.patterns import EVALUATORS
        from lachesis.flow.semantic_graph import FROZEN_PATTERNS

        for entry in atropos.pattern_catalog():
            matcher = entry.get("matcher") or {}
            pattern = matcher.get("pattern")
            self.assertTrue(
                pattern in FROZEN_PATTERNS or pattern in EVALUATORS,
                entry.get("id"),
            )

    def _graph(self, events, edges):
        g = SkeletonGraph()
        for node, event in events:
            g.add_node(node, event)
        for source, target, *kind in edges:
            g.add_edge(source, target, kind=kind[0] if kind else "normal")
        g.add_fragment("main", events[0][0], [events[-1][0]])
        g.validate()
        return g

    def test_atropos_public_ids_cover_generic_lifetime_and_write_findings(self):
        self.assertEqual(atropos.flow_pattern_id("leak"), "mem.lifetime.leak")
        self.assertEqual(atropos.flow_pattern_id("use.dangling"),
                         "mem.lifetime.dangling-use")
        self.assertEqual(atropos.flow_pattern_evaluator("uaf.deref"), "typestate")
        self.assertEqual(atropos.flow_pattern_evaluator("double-free"), "typestate")
        self.assertEqual(atropos.flow_pattern_id("relational", "buffer-write"),
                         "mem.write.tainted-unbounded")
        self.assertEqual(atropos.flow_pattern_id("missing-guard", "alloc-size"),
                         "mem.alloc.missing-guard")

    def test_public_atropos_pattern_id_selects_the_internal_matcher(self):
        obj = ObjRef("object", generation="g0")
        g = self._graph(
            [("origin", Event.origin(obj)), ("free", Event.release(obj)),
             ("use", Event.read(obj))],
            [("origin", "free"), ("free", "use")],
        )
        hits = match_graph(g, patterns={"mem.lifetime.use-after-free"})
        self.assertEqual({hit["pattern"] for hit in hits}, {"uaf.deref"})
        self.assertEqual({hit["evaluator"] for hit in hits}, {"typestate"})

    def test_relational_and_index_guards_keep_distinct_typed_proofs(self):
        class Sub:
            @staticmethod
            def label(_node):
                return "idx < bound"

        proofs = _cfg_guard_proofs(Sub(), "condition", 0, 2)
        self.assertEqual([proof.kind for proof in proofs], ["VALUE", "BOUNDED"])

    def test_atropos_sink_history_matches_size_mismatch(self):
        events = [
            ("alloc", Event(EventKind.SINK, obj=ObjRef("buf"), facts={
                "family": "alloc-size", "callee": "malloc", "dst": "buf",
                "size_expr": "capacity", "tainted": True, "guarded": False,
            })),
            ("copy", Event(EventKind.SINK, obj=ObjRef("buf"), facts={
                "family": "buffer-write", "callee": "memcpy", "dst": "buf",
                "size_expr": "incoming", "tainted": True, "guarded": False,
            })),
        ]
        g = self._graph(events, [("alloc", "copy")])
        hit = next(hit for hit in match_graph(g)
                   if hit["pattern"] == "mem.alloc-copy.size-mismatch")
        self.assertEqual(hit["pattern_id"], "mem.alloc-copy.size-mismatch")

    def test_fall_through_guard_routes_to_missing_bounds(self):
        event = Event(EventKind.SINK, obj=ObjRef("buf"), facts={
            "family": "buffer-write", "callee": "memcpy", "arg": 2,
            "tainted": True, "guarded": False, "guard_status": "fall-through",
        })
        g = self._graph([("sink", event)], [])
        hit = next(hit for hit in match_graph(g) if hit["pattern"] == "missing-guard")
        self.assertEqual(hit["pattern_id"], "mem.write.missing-bounds")

    def test_inverted_capacity_guard_is_catalogued_and_generic(self):
        event = Event(EventKind.SINK, obj=ObjRef("name"), facts={
            "family": "buffer-write", "callee": "memcpy", "arg": 0,
            "tainted": True, "guarded": True,
            "guard_status": "guarded-region", "size_expr": "incoming",
            "guard_predicates": ("incoming >= capacity",),
        })
        g = self._graph([("sink", event)], [])
        hit = next(hit for hit in match_graph(g)
                   if hit["pattern"] == "inverted-capacity-guard")
        self.assertEqual(hit["pattern_id"],
                         "mem.write.inverted-capacity-guard")

    def test_arithmetic_overflow_guard_is_catalogued(self):
        event = Event(EventKind.SINK, obj=ObjRef("data"), facts={
            "family": "buffer-size", "callee": "memset", "arg": 2,
            "tainted": True, "guarded": True,
            "guard_predicates": ("offset + length <= capacity",),
        })
        g = self._graph([("sink", event)], [])
        hit = next(hit for hit in match_graph(g)
                   if hit["pattern"] == "arithmetic-overflow-guard")
        self.assertEqual(hit["pattern_id"],
                         "mem.arithmetic.overflow-before-bound")

    def test_pointer_arithmetic_before_validation_has_public_id(self):
        base = ObjRef("buffer")
        derived = ObjRef("location")
        events = [
            ("derive", Event(EventKind.POINTER_ARITHMETIC,
                              obj=derived, base=base, line=1)),
            ("read", Event.read(derived, "*", 2)),
        ]
        g = self._graph(events, [("derive", "read")])
        hit = next(hit for hit in match_graph(g)
                   if hit["pattern"] == "pointer-arithmetic-before-validation")
        self.assertEqual(hit["pattern_id"],
                         "mem.pointer-arithmetic.before-validation")

    def test_checked_nullable_return_deref_is_not_unchecked(self):
        obj = ObjRef("result")
        events = [
            ("origin", Event(EventKind.ORIGIN, obj=obj,
                              facts={"return_may_null": True})),
            ("check", None),
            ("use", Event.read(obj)),
        ]
        g = self._graph(events, [("origin", "check"), ("check", "use")])
        g.edges["check"][0] = Edge(
            target="use", guard=(GuardProof("NONNULL", obj.render()),))
        self.assertNotIn("unchecked-return-deref",
                         {hit["pattern"] for hit in match_graph(g)})

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
        self.assertEqual(match_graph(g)[0]["witness"], ["start", "true_free", "merge", "use"])
        trace = match_graph(g)[0]["witness_trace"]
        self.assertEqual([item["node"] for item in trace],
                         ["start", "true_free", "merge", "use"])
        self.assertEqual(trace[1]["kind"], str(EventKind.RELEASE))
        self.assertEqual(trace[-1]["line"], 5)
        self.assertEqual(match_graph(g)[0]["source_node"], "start")
        self.assertIsNone(match_graph(g)[0]["source_entry"])

    def test_storage_free_does_not_free_pointee(self):
        buf = ObjRef("O_buf", generation="g0")
        payload = ObjRef("O_payload", generation="g0")
        events = [("start", None), ("capture", Event(EventKind.DERIVE, value=payload, line=1)),
                  ("free", Event.release(buf, 2)), ("saved_use", Event(EventKind.PASS_VALUE,
                                                                         obj=payload, line=3))]
        g = self._graph(events, [("start", "capture"), ("capture", "free"), ("free", "saved_use")])
        self.assertEqual(match_graph(g), [])

    def test_field_pointee_release_matches_field_pointee_dereference(self):
        aggregate = ObjRef("b", generation="g0")
        payload = aggregate.child("*data")
        events = [
            ("start", None),
            ("free", Event.release(payload, 2)),
            ("use", Event.read(payload, "[*]", 3)),
        ]
        g = self._graph(events, [("start", "free"), ("free", "use")])
        hits = match_graph(g)
        self.assertEqual([hit["pattern"] for hit in hits], ["uaf.deref"])
        self.assertEqual(hits[0]["object"], payload.render())

    def test_derive_preserves_alias_identity(self):
        original = ObjRef("O", generation="g0")
        alias = ObjRef("saved", generation="g0")
        events = [("start", Event.origin(original)),
                  ("derive", Event(EventKind.DERIVE, obj=alias, value=original)),
                  ("free", Event.release(original, 2)),
                  ("use", Event.read(alias, "*", 3))]
        g = self._graph(events, [("start", "derive"), ("derive", "free"), ("free", "use")])
        self.assertTrue(any(h["pattern"] == "uaf.deref" for h in match_graph(g)))

    def test_address_and_deref_algebra_survives_a_call_seam(self):
        """A multi-level address chain must identify the released pointee.

        The shape is deliberately expressed only in the skeleton alphabet: the caller
        builds ``p1 = &object`` and ``p2 = &p1``; the callee receives ``p2`` as a
        triple-pointer formal and releases ``**formal``.  The unrelated alias must still
        match the release after the pushdown return.
        """
        obj = ObjRef("object", generation="g0")
        alias = ObjRef("alias", generation="g0")
        p1 = ObjRef("p1", generation="g0")
        p2 = ObjRef("p2", generation="g0")
        formal = ObjRef("formal", generation="g0")
        target = ObjRef("target", generation="g0")

        g = SkeletonGraph()
        for node, event in [
                ("start", Event.origin(obj)),
                ("alias", Event(EventKind.DERIVE, obj=alias, value=obj)),
                ("p1", Event(EventKind.DERIVE, obj=p1,
                              value=ObjRef(obj.base, ("&",), obj.generation))),
                ("p2", Event(EventKind.DERIVE, obj=p2,
                              value=ObjRef(p1.base, ("&",), p1.generation))),
                ("enter", Event(EventKind.SEAM_ENTER)),
                ("target", Event(EventKind.DERIVE, obj=target,
                                  value=ObjRef(formal.base, ("*", "*"), formal.generation))),
                ("free", Event.release(target)),
                ("return", Event(EventKind.SEAM_EXIT)),
                ("use", Event.read(alias)),
                ("exit", None),
        ]:
            g.add_node(node, event, fragment="main")
        g.add_edge("start", "alias")
        g.add_edge("alias", "p1")
        g.add_edge("p1", "p2")
        g.add_edge("p2", "enter")
        g.add_edge("enter", "target", kind="call", return_to="return",
                    binding=((formal, p2),))
        g.add_edge("target", "free")
        g.add_edge("free", "return", kind="return")
        g.add_edge("return", "use")
        g.add_edge("use", "exit")
        g.add_fragment("main", "start", ["exit"])
        g.validate()

        hits = match_graph(g)
        self.assertTrue(any(hit["pattern"] == "uaf.deref"
                            and hit["node"] == "use" for hit in hits))

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

    def test_realloc_failure_loses_slot_but_preserves_an_existing_alias(self):
        old = ObjRef("p", generation="g0")
        saved = ObjRef("saved", generation="g0")
        events = [
            ("origin", Event.origin(old)),
            ("derive", Event(EventKind.DERIVE, obj=saved, value=old)),
            ("failed", Event.realloc_failed(old, old)),
            ("null", Event.write_null(old)),
            ("lost", Event(EventKind.LOST_FROM_SLOT, obj=old, slot=old)),
            ("exit", None),
        ]
        g = self._graph(events, [(events[i][0], events[i + 1][0]) for i in range(len(events) - 1)])
        self.assertNotIn("leak", {hit["pattern"] for hit in match_graph(g)})

    def test_realloc_failure_without_an_alias_is_a_leak(self):
        old = ObjRef("p", generation="g0")
        events = [
            ("origin", Event.origin(old)),
            ("failed", Event.realloc_failed(old, old)),
            ("null", Event.write_null(old)),
            ("lost", Event(EventKind.LOST_FROM_SLOT, obj=old, slot=old)),
            ("exit", None),
        ]
        g = self._graph(events, [(events[i][0], events[i + 1][0]) for i in range(len(events) - 1)])
        self.assertEqual({hit["pattern"] for hit in match_graph(g)},
                         {"leak", "mem.lifetime.realloc-failure-leak"})

    def test_loop_reorigin_does_not_rebind_an_old_alias(self):
        slot = ObjRef("p", generation="g0")
        alias = ObjRef("saved", generation="g0")
        events = [
            ("first_origin", Event.origin(slot)),
            ("save", Event(EventKind.DERIVE, obj=alias, value=slot)),
            ("loop", Event(EventKind.LOOP)),
            ("release_old", Event.release(slot)),
            # The source-level slot spelling is unchanged; the matcher must
            # widen this into a new incarnation at the loop boundary.
            ("next_origin", Event.origin(slot, facts={"loop_widening": True})),
            ("use_old_alias", Event.read(alias)),
        ]
        g = self._graph(events, [(events[i][0], events[i + 1][0])
                                 for i in range(len(events) - 1)])
        hit = next(hit for hit in match_graph(g) if hit["pattern"] == "uaf.deref")
        self.assertEqual(hit["object"], "p#g0")

    def test_returning_an_owner_keeps_its_field_allocation_reachable(self):
        owner = ObjRef("b", generation="g0")
        field = ObjRef("b", ("*", "data"), generation="g0")
        events = [
            ("owner", Event.origin(owner)),
            ("field", Event.origin(field)),
            ("return_value", Event(EventKind.RETURN_VALUE, obj=owner)),
            ("return", Event(EventKind.RETURN, obj=owner)),
        ]
        g = self._graph(events, [(events[i][0], events[i + 1][0])
                                 for i in range(len(events) - 1)])
        self.assertNotIn("leak", {hit["pattern"] for hit in match_graph(g)})

    def test_live_is_not_a_frozen_guard_proof(self):
        obj = ObjRef("p", generation="g0")
        g = self._graph(
            [("origin", Event.origin(obj)), ("free", Event.release(obj)),
             ("use", Event.read(obj))],
            [("origin", "free"), ("free", "use", "normal")],
        )
        g.edges["free"][0] = Edge(target="use", guard=(GuardProof("LIVE", obj.render()),))
        self.assertIn("uaf.deref", {hit["pattern"] for hit in match_graph(g)})

    def test_address_and_deref_bindings_cancel_across_multiple_derives(self):
        node = ObjRef("node")
        p1 = ObjRef("p1")
        p2 = ObjRef("p2")
        target = ObjRef("target")
        alias = ObjRef("alias")
        events = [
            ("origin", Event.origin(node)),
            ("p1", Event(EventKind.DERIVE, obj=p1, value=ObjRef("node", ("&",)))),
            ("p2", Event(EventKind.DERIVE, obj=p2, value=ObjRef("p1", ("&",)))),
            ("target", Event(EventKind.DERIVE, obj=target,
                             value=ObjRef("p2", ("*", "*")))),
            ("release", Event.release(target)),
            ("alias", Event(EventKind.DERIVE, obj=alias, value=node)),
            ("use", Event.write(alias)),
        ]
        g = self._graph(events, [(events[i][0], events[i + 1][0]) for i in range(len(events) - 1)])
        self.assertIn("uaf.deref", {hit["pattern"] for hit in match_graph(g)})

    def test_field_binding_composes_across_a_call_seam(self):
        formal = ObjRef("formal", ("*", "data"))
        actual = ObjRef("actual", ("*", "data"))
        g = SkeletonGraph()
        for node, event in [("caller", Event.origin(ObjRef("actual"))),
                            ("enter", Event(EventKind.SEAM_ENTER)),
                            ("free", Event.release(formal)),
                            ("exit", Event(EventKind.SEAM_EXIT)),
                            ("use", Event.write(actual))]:
            g.add_node(node, event)
        g.add_fragment("caller", "caller", ["use"])
        g.add_fragment("callee", "enter", ["exit"])
        g.add_edge("caller", "enter", kind="call", return_to="use",
                   binding=((ObjRef("formal"), ObjRef("actual")),))
        g.add_edge("enter", "free")
        g.add_edge("free", "exit")
        g.add_edge("exit", "use", kind="return")
        self.assertIn("uaf.deref", {hit["pattern"] for hit in match_graph(g)})

    def test_abstract_provenance_composes_across_a_call_seam(self):
        formal = ObjRef("formal")
        actual = ObjRef("actual")
        formal_id = repr(("param", 0, ()))
        actual_id = repr(("alloc", "recent", "caller-site"))
        g = SkeletonGraph()
        g.add_node("caller", Event.origin(actual))
        g.add_node("enter", Event(EventKind.SEAM_ENTER))
        g.add_node("free", Event(EventKind.RELEASE, obj=formal,
                                   facts={"abstract_object_ids": [formal_id]}))
        g.add_node("exit", Event(EventKind.SEAM_EXIT))
        g.add_node("use", Event(EventKind.READ_STORAGE, obj=actual, base=actual,
                                  facts={"abstract_object_ids": [actual_id]}))
        g.add_fragment("caller", "caller", ["use"])
        g.add_fragment("callee", "enter", ["exit"])
        g.add_edge("caller", "enter", kind="call", return_to="use",
                   binding=((formal, actual),), provenance=((formal_id, actual_id),))
        g.add_edge("enter", "free")
        g.add_edge("free", "exit")
        g.add_edge("exit", "use", kind="return")
        self.assertIn("uaf.deref", {hit["pattern"] for hit in match_graph(g)})

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

    def test_witness_reports_edges_and_external_context(self):
        obj = ObjRef("p", generation="g0")
        g = SkeletonGraph()
        g.add_node("launch", Event.origin(obj), fragment="main")
        g.add_node("free", Event.release(obj), fragment="main")
        g.add_node("use", Event.read(obj), fragment="main")
        g.add_edge("launch", "free", guard=(GuardProof("NONNULL", "p#g0"),))
        g.add_edge("free", "use", kind="normal")
        g.add_fragment("main", "launch", ["use"])
        g.source_reachable.add("launch")
        hit = next(item for item in match_graph(g) if item["pattern"] == "uaf.deref")
        self.assertEqual(hit["source_context"], "launch")
        self.assertTrue(hit["witness_complete"])
        self.assertEqual(hit["witness_edges"][0]["guards"][0]["kind"], "NONNULL")

    def test_witness_keeps_the_edge_taken_when_parallel_guards_share_nodes(self):
        obj = ObjRef("p", generation="g0")
        g = SkeletonGraph()
        g.add_node("start", Event.origin(obj), fragment="main")
        g.add_node("free", Event.release(obj), fragment="main")
        g.add_node("use", Event.read(obj), fragment="main")
        # The ISNULL arm cannot release p; only the NONNULL arm reaches the
        # lifecycle violation.  Both arms intentionally have the same nodes,
        # so choosing the first graph edge during report reconstruction would
        # attach the wrong proof to the witness.
        g.add_edge("start", "free", guard=(GuardProof("ISNULL", "p#g0"),))
        g.add_edge("start", "free", guard=(GuardProof("NONNULL", "p#g0"),))
        g.add_edge("free", "use")
        g.add_fragment("main", "start", ["use"])
        hit = next(item for item in match_graph(g) if item["pattern"] == "uaf.deref")
        self.assertTrue(hit["witness_complete"])
        self.assertEqual(hit["witness_edges"][0]["guards"],
                         [{"kind": "NONNULL", "value": "p#g0"}])

    def test_guard_compatibility_survives_a_formal_to_field_seam(self):
        actual = ObjRef("s", ("*", "request"), generation="g0")
        formal = ObjRef("b", generation="g0")
        g = SkeletonGraph()
        for node, event in [
                ("start", Event.origin(actual)),
                ("enter", Event(EventKind.SEAM_ENTER)),
                ("check", None),
                ("free", Event.release(formal)),
                ("exit", Event(EventKind.SEAM_EXIT)),
                ("after", Event.read(actual)),
        ]:
            g.add_node(node, event, fragment="caller" if node in {"start", "after"}
                       else "callee")
        g.add_edge("start", "enter", kind="call", return_to="after",
                   binding=((formal, actual),))
        g.add_edge("enter", "check")
        g.add_edge("check", "free", guard=(GuardProof("ISNULL", "b#g0"),))
        g.add_edge("check", "free", guard=(GuardProof("NONNULL", "b#g0"),))
        g.add_edge("free", "exit")
        g.add_edge("exit", "after", kind="return")
        g.add_fragment("caller", "start", ["after"])
        g.add_fragment("callee", "enter", ["exit"])
        hit = next(item for item in match_graph(g) if item["pattern"] == "uaf.deref")
        self.assertEqual(hit["witness_edges"][2]["guards"],
                         [{"kind": "NONNULL", "value": "b#g0"}])

    def test_guard_state_does_not_cross_mutually_exclusive_cfg_arms(self):
        obj = ObjRef("p", generation="g0")
        g = SkeletonGraph()
        g.add_node("start", Event.origin(obj), fragment="main")
        g.add_node("first_check", Event(EventKind.BRANCH), fragment="main")
        g.add_node("success", None, fragment="main")
        g.add_node("failure", None, fragment="main")
        g.add_node("merge", None, fragment="main")
        g.add_node("second_check", Event(EventKind.BRANCH), fragment="main")
        g.add_node("free", Event.release(obj), fragment="main")
        g.add_node("use", Event.read(obj), fragment="main")
        g.add_edge("start", "first_check")
        g.add_edge("first_check", "success",
                   guard=(GuardProof("NONNULL", "p#g0"),))
        g.add_edge("first_check", "failure",
                   guard=(GuardProof("ISNULL", "p#g0"),))
        g.add_edge("success", "merge")
        g.add_edge("failure", "merge")
        # This resembles a real CFG join: the later null arm is only feasible
        # on the earlier null path, never after the known-nonnull arm.
        g.add_edge("merge", "second_check")
        g.add_edge("second_check", "free",
                   guard=(GuardProof("ISNULL", "p#g0"),))
        g.add_edge("free", "use")
        g.add_fragment("main", "start", ["use"])
        self.assertNotIn("uaf.deref", {hit["pattern"] for hit in match_graph(g)})

    def test_value_guards_do_not_create_an_impossible_temporal_path(self):
        obj = ObjRef("p", generation="g0")
        g = SkeletonGraph()
        for node, event in [
                ("start", Event.origin(obj)),
                ("first_check", Event(EventKind.BRANCH)),
                ("free", Event.release(obj)),
                ("merge", None),
                ("use", Event.read(obj)),
        ]:
            g.add_node(node, event, fragment="main")
        g.add_edge("start", "first_check")
        g.add_edge("first_check", "free",
                   guard=(GuardProof("VALUE", "mode==1"),))
        g.add_edge("first_check", "merge",
                   guard=(GuardProof("VALUE", "mode!=1"),))
        g.add_edge("free", "merge")
        # The only edge to the use requires mode != 1.  A release on the
        # mode == 1 arm must not be carried through the join into this use.
        g.add_edge("merge", "use",
                   guard=(GuardProof("VALUE", "mode!=1"),))
        g.add_fragment("main", "start", ["use"])
        self.assertNotIn("uaf.deref", {hit["pattern"] for hit in match_graph(g)})

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
