"""Unit tests for the closed tier-1 evaluator set (``lachesis/flow/patterns.py``).

Pure predicates over synthetic substrate facts -- no graph, no artifacts, fast.
These lock the FP-critical *polarity* invariant of the shape evaluators, verified
by reading the guard-stamping pass (``dataflow/substrate.py::_compute_call_guard_facts``):

  * ``guard_predicates`` is populated ONLY for a ``guarded-region`` sink, and it
    carries that region's *holding* condition. A ``fall-through`` sink -- e.g. the
    copy after a protective early return ``if (len > cap) return; memcpy(..,len)``
    -- is stamped with NO predicates.

So the inverted-capacity / arithmetic-overflow shape evaluators must stay SILENT
when there are no predicates (the protective-guard case) and fire only on the
genuinely inverted / additive region condition. A regression that let them read a
raw branch condition of the wrong polarity would reintroduce exactly the false
positive these assert against.
"""
import unittest

from lachesis.flow.patterns import (
    substrate,
    _reachability, _relational, _presence, _missing_guard,
    _inverted_capacity_guard, _arithmetic_overflow_guard,
    _allocation_overflow_size,
)


class CoreEvaluatorTest(unittest.TestCase):
    def test_reachability_is_taint_alone(self):
        self.assertTrue(_reachability(substrate("xss", True, None, False)))
        self.assertFalse(_reachability(substrate("xss", False, None, False)))

    def test_relational_requires_taint_AND_unbounded(self):
        self.assertTrue(_relational(substrate("buffer-size", True, "unbounded", False)))
        # either dimension alone is normal, not a lead
        self.assertFalse(_relational(substrate("buffer-size", True, "bounded", False)))
        self.assertFalse(_relational(substrate("buffer-size", False, "unbounded", False)))
        self.assertFalse(_relational(substrate("buffer-size", True, None, False)))

    def test_presence_fires_regardless_of_taint(self):
        self.assertTrue(_presence(substrate("weak-crypto", False, None, False)))
        self.assertTrue(_presence(substrate("weak-crypto", True, None, True)))

    def test_missing_guard_only_on_fall_through(self):
        self.assertTrue(_missing_guard(substrate(
            "buffer-write", True, "unbounded", False, guard_status="fall-through")))
        self.assertFalse(_missing_guard(substrate(
            "buffer-write", True, "unbounded", True, guard_status="guarded-region")))
        self.assertFalse(_missing_guard(substrate("buffer-write", True, "unbounded", False)))


class InvertedCapacityGuardPolarityTest(unittest.TestCase):
    """The load-bearing FP guard: no predicates (protective/fall-through) => silent."""

    def test_silent_when_no_predicates_even_if_tainted(self):
        # protective `if (len > cap) return; copy(..,len)` -> fall-through, no preds
        fact = substrate("buffer-write", True, "unbounded", False,
                         size_expr="len", guard_predicates=())
        self.assertFalse(_inverted_capacity_guard(fact))

    def test_silent_on_protective_region_condition(self):
        # sink inside `if (len <= cap) { copy }` -> region holds len<=cap: SAFE
        fact = substrate("buffer-write", True, "bounded", True,
                         size_expr="len", guard_predicates=("len<=cap",))
        self.assertFalse(_inverted_capacity_guard(fact))

    def test_fires_on_inverted_region_condition(self):
        # sink inside `if (len >= cap) { copy }` -> region holds len>=cap: INVERTED
        fact = substrate("buffer-write", True, "unbounded", True,
                         size_expr="len", guard_predicates=("len>=cap",))
        self.assertTrue(_inverted_capacity_guard(fact))

    def test_silent_without_taint(self):
        fact = substrate("buffer-write", False, "unbounded", True,
                         size_expr="len", guard_predicates=("len>=cap",))
        self.assertFalse(_inverted_capacity_guard(fact))


class ArithmeticOverflowGuardTest(unittest.TestCase):
    def test_fires_on_additive_region_bound(self):
        # `if (off + len <= cap) { copy }` -- additive bound defeatable by wrap
        fact = substrate("buffer-write", True, "unbounded", True,
                         guard_predicates=("off+len<=cap",))
        self.assertTrue(_arithmetic_overflow_guard(fact))

    def test_silent_on_plain_non_additive_bound(self):
        fact = substrate("buffer-write", True, "unbounded", True,
                         guard_predicates=("len<=cap",))
        self.assertFalse(_arithmetic_overflow_guard(fact))

    def test_requires_taint_and_guarded(self):
        preds = ("off+len<=cap",)
        self.assertFalse(_arithmetic_overflow_guard(substrate(
            "buffer-write", False, "unbounded", True, guard_predicates=preds)))
        self.assertFalse(_arithmetic_overflow_guard(substrate(
            "buffer-write", True, "unbounded", False, guard_predicates=preds)))


class AllocationOverflowSizeTest(unittest.TestCase):
    def test_fires_on_tainted_multiplicative_alloc_size(self):
        fact = substrate("alloc-size", True, None, False, size_expr="n * width")
        self.assertTrue(_allocation_overflow_size(fact))

    def test_silent_on_constant_or_non_multiplicative(self):
        self.assertFalse(_allocation_overflow_size(
            substrate("alloc-size", True, None, False, size_expr="1024")))
        self.assertFalse(_allocation_overflow_size(
            substrate("alloc-size", True, None, False, size_expr="n + 4")))

    def test_silent_off_family_or_untainted(self):
        self.assertFalse(_allocation_overflow_size(
            substrate("buffer-size", True, None, False, size_expr="n * width")))
        self.assertFalse(_allocation_overflow_size(
            substrate("alloc-size", False, None, False, size_expr="n * width")))


if __name__ == "__main__":
    unittest.main()
