import unittest

from .object_state import (
    AbstractState,
    AccessPath,
    ObjectFact,
    ObjectStateAnalyzer,
    OpKind,
    Operation,
    ParamEffect,
    join_states,
)


P = AccessPath("p")
Q = AccessPath("q")


def op(kind, node, target=None, source=None, **kw):
    return Operation(kind, node, target=target, source=source, site=kw.pop("site", node), **kw)


class ObjectStateTests(unittest.TestCase):
    def test_rebinding_null_does_not_double_free(self):
        ops = [
            op(OpKind.ALLOC, "a", P),
            op(OpKind.FREE, "f1", P),
            op(OpKind.CLOBBER, "n", P, is_null=True),
            op(OpKind.FREE, "f2", P),
        ]
        result = ObjectStateAnalyzer().analyze(["a", "f1", "n", "f2"], {
            "a": ["f1"], "f1": ["n"], "n": ["f2"],
        }, ops)
        self.assertEqual(result.findings, set())

    def test_copy_alias_carries_lifetime(self):
        ops = [
            op(OpKind.ALLOC, "a", P),
            op(OpKind.COPY, "c", Q, source=P),
            op(OpKind.FREE, "f1", P),
            op(OpKind.FREE, "f2", Q),
        ]
        result = ObjectStateAnalyzer().analyze(["a", "c", "f1", "f2"], {
            "a": ["c"], "c": ["f1"], "f1": ["f2"],
        }, ops)
        self.assertEqual({finding.pattern for finding in result.findings}, {"double-free"})

    def test_fields_follow_base_object_aliases(self):
        pa, qa = P.child("->a"), Q.child("->a")
        ops = [
            op(OpKind.ALLOC, "base", P),
            op(OpKind.COPY, "copy", Q, source=P),
            op(OpKind.ALLOC, "field", pa),
            op(OpKind.FREE, "free", pa),
            op(OpKind.USE, "use", qa),
        ]
        nodes = ["base", "copy", "field", "free", "use"]
        result = ObjectStateAnalyzer().analyze(nodes, dict(zip(nodes, ([n] for n in nodes[1:]))), ops)
        self.assertEqual({finding.pattern for finding in result.findings}, {"use-after-free"})

    def test_mutually_exclusive_frees_do_not_meet(self):
        nodes = ["alloc", "branch", "left", "right", "exit"]
        succ = {"alloc": ["branch"], "branch": ["left", "right"],
                "left": ["exit"], "right": ["exit"]}
        ops = [op(OpKind.ALLOC, "alloc", P), op(OpKind.FREE, "left", P),
               op(OpKind.FREE, "right", P)]
        result = ObjectStateAnalyzer().analyze(nodes, succ, ops)
        self.assertEqual(result.findings, set())

    def test_loop_back_edge_reaches_second_iteration(self):
        nodes = ["alloc", "use", "free", "exit"]
        succ = {"alloc": ["use"], "use": ["free"], "free": ["use", "exit"]}
        ops = [op(OpKind.ALLOC, "alloc", P), op(OpKind.USE, "use", P),
               op(OpKind.FREE, "free", P)]
        result = ObjectStateAnalyzer().analyze(nodes, succ, ops)
        self.assertEqual({finding.pattern for finding in result.findings},
                         {"double-free", "use-after-free"})

    def test_recency_keeps_old_alias_separate_from_new_instance(self):
        state, findings = AbstractState(), set()
        state.apply(op(OpKind.ALLOC, "first", P, site="site"), findings)
        state.apply(op(OpKind.COPY, "save", Q, source=P), findings)
        state.apply(op(OpKind.FREE, "old-free", Q), findings)
        state.apply(op(OpKind.ALLOC, "second", P, site="site"), findings)
        state.apply(op(OpKind.USE, "old-use", Q), findings)
        before = set(findings)
        state.apply(op(OpKind.USE, "new-use", P), findings)
        self.assertTrue(any(f.path == Q and f.pattern == "use-after-free" for f in before))
        self.assertEqual(findings, before)

    def test_widening_preserves_must_alias(self):
        states = []
        for index in range(80):
            state = AbstractState()
            state.apply(op(OpKind.ALLOC, f"a{index}", P), set())
            state.apply(op(OpKind.COPY, f"c{index}", Q, source=P), set())
            states.append(state)
        merged = join_states(states, "join")
        findings = set()
        merged.apply(op(OpKind.FREE, "f1", P), findings)
        merged.apply(op(OpKind.FREE, "f2", Q), findings)
        self.assertEqual({finding.pattern for finding in findings}, {"double-free"})

    def test_widening_preserves_may_freed(self):
        live = AbstractState()
        live.apply(op(OpKind.ALLOC, "a", P), set())
        freed = live.clone()
        freed.apply(op(OpKind.FREE, "f", P), set())
        merged = join_states([live, freed], "join")
        findings = set()
        merged.apply(op(OpKind.USE, "u", P), findings)
        self.assertEqual({finding.pattern for finding in findings}, {"use-after-free"})

    def test_analyzer_applies_disjunct_budget_without_capping(self):
        nodes = ["alloc", "branch", "left", "right", "join", "use"]
        successors = {"alloc": ["branch"], "branch": ["left", "right"],
                      "left": ["join"], "right": ["join"], "join": ["use"]}
        operations = [op(OpKind.ALLOC, "alloc", P), op(OpKind.FREE, "left", P),
                      op(OpKind.USE, "use", P)]
        result = ObjectStateAnalyzer(max_disjuncts=1).analyze(nodes, successors, operations)
        self.assertGreater(result.widenings, 0)
        self.assertFalse(result.capped)
        self.assertEqual({finding.pattern for finding in result.findings}, {"use-after-free"})

    def test_summary_alternatives_remain_path_correlated(self):
        free_effect = op(OpKind.FREE, "call", P)
        summary = Operation(OpKind.SUMMARY, "call", alternatives=((free_effect,), ()))
        nodes = ["alloc", "call", "use"]
        result = ObjectStateAnalyzer().analyze(nodes, {"alloc": ["call"], "call": ["use"]}, [
            op(OpKind.ALLOC, "alloc", P), summary, op(OpKind.USE, "use", P),
        ])
        self.assertEqual({finding.pattern for finding in result.findings}, {"use-after-free"})

    def test_realloc_through_pointer_field_nets_to_live_in_summary(self):
        # free(p->buf); p->buf = realloc(...) -- a store *through* the pointer parameter.
        # The compensating ALLOC must join the trace so the caller sees a live object,
        # not a free-only summary that reads as a loop-carried double-free.
        state = AbstractState()
        state.seed_parameter(P, 0)
        buf = P.child("->buf")
        state.apply(op(OpKind.FREE, "free", buf), set())
        state.apply(op(OpKind.ALLOC, "realloc", buf), set())
        self.assertEqual(state.trace, (
            ParamEffect(OpKind.FREE, 0, ("->buf",)),
            ParamEffect(OpKind.ALLOC, 0, ("->buf",)),
        ))

    def test_free_then_reassign_bare_param_stays_freed(self):
        # free(p); p = malloc(...) reassigns a by-value parameter -- the caller's own
        # pointer still dangles, so the free must remain visible (no compensating ALLOC).
        state = AbstractState()
        state.seed_parameter(P, 0)
        state.apply(op(OpKind.FREE, "free", P), set())
        state.apply(op(OpKind.ALLOC, "malloc", P), set())
        self.assertEqual(state.trace, (ParamEffect(OpKind.FREE, 0, ()),))

    def test_realloc_dangles_unrebased_interior_alias(self):
        # cursor = data; data = realloc(data, ...); use cursor
        # realloc may relocate the block, so the old generation `cursor` still holds is
        # freed. The use-after-free must fall out of the EXISTING USE-on-FREED machinery
        # -- there is no realloc-specific finding rule in the engine.
        data, cursor = AccessPath("data"), AccessPath("cursor")
        ops = [
            op(OpKind.ALLOC, "a", data),
            op(OpKind.COPY, "c", cursor, source=data),
            op(OpKind.REALLOC, "r", data, source=data),
            op(OpKind.USE, "u", cursor),
        ]
        result = ObjectStateAnalyzer().analyze(["a", "c", "r", "u"], {
            "a": ["c"], "c": ["r"], "r": ["u"],
        }, ops)
        self.assertEqual({f.pattern for f in result.findings}, {"use-after-free"})

    def test_realloc_rebased_pointer_is_live(self):
        # data = realloc(data, ...); use data -- the name itself was rebased onto the
        # returned (fresh) block, so a use of it is NOT a use-after-free.
        data = AccessPath("data")
        ops = [
            op(OpKind.ALLOC, "a", data),
            op(OpKind.REALLOC, "r", data, source=data),
            op(OpKind.USE, "u", data),
        ]
        result = ObjectStateAnalyzer().analyze(["a", "r", "u"],
                                               {"a": ["r"], "r": ["u"]}, ops)
        self.assertEqual(result.findings, set())

    def test_realloc_of_freed_pointer_is_double_free(self):
        # free(p); q = realloc(p, ...) -- reallocating an already-freed block is a
        # double-free, caught by the same freed-marking FREE uses (shared _free_object).
        ops = [
            op(OpKind.ALLOC, "a", P),
            op(OpKind.FREE, "f", P),
            op(OpKind.REALLOC, "r", Q, source=P),
        ]
        result = ObjectStateAnalyzer().analyze(["a", "f", "r"],
                                               {"a": ["f"], "f": ["r"]}, ops)
        self.assertEqual({f.pattern for f in result.findings}, {"double-free"})

    def test_unplaced_operation_is_reported(self):
        missing = op(OpKind.FREE, "missing", P)
        result = ObjectStateAnalyzer().analyze(["entry"], {}, [missing])
        self.assertEqual(result.unplaced, (missing,))


if __name__ == "__main__":
    unittest.main()
