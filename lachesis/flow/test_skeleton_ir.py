#!/usr/bin/env python3
"""Tests for the universal skeleton IR.

The point of these tests is to demonstrate the ONE claim that makes the structure universal:
a single role-pattern set matches the same bug SHAPE across different languages and different
concrete verbs. A C use-after-free and a Python use-after-close are the same universal finding.
"""
import unittest

from lachesis.flow.skeleton_ir import (
    Category, Role, Proof, ObjRef, Guard, Event, Skeleton,
    roles_for, match_universal, from_flow_skeleton, render,
)


def _find(hits, pattern):
    return [h for h in hits if h["pattern"] == pattern]


class TestRoleBinding(unittest.TestCase):
    def test_verb_maps_to_role(self):
        self.assertIn(Role.RELEASE, roles_for("free"))
        self.assertIn(Role.RELEASE, roles_for("close"))
        self.assertIn(Role.OBSERVE, roles_for("deref"))
        self.assertIn(Role.ORIGIN, roles_for("malloc"))

    def test_realloc_is_invalidate_and_reinit(self):
        self.assertEqual(set(roles_for("realloc")), {Role.INVALIDATE, Role.REINIT})

    def test_unknown_verb_has_no_role(self):
        # honest: an unclassified verb is a catalog gap, not a silent misclassification
        self.assertEqual(roles_for("frobnicate"), ())

    def test_language_override(self):
        # python adds context-manager verbs without touching the universal core
        self.assertIn(Role.RELEASE, roles_for("__exit__", lang="python"))
        self.assertEqual(roles_for("__exit__", lang="c"), ())


class TestUniversalityAcrossLanguages(unittest.TestCase):
    """The same pattern set, the same shape, different languages and verbs."""

    def _use_after_release(self, origin_verb, release_verb, observe_verb):
        obj = ObjRef(base="x")
        return Skeleton(kind="typestate", entry="f", events=[
            Event.op(origin_verb, obj, 0, line=1),
            Event.op(release_verb, obj, 0, line=2),
            Event.op(observe_verb, obj, 0, line=3),
        ])

    def test_c_use_after_free(self):
        skel = self._use_after_release("malloc", "free", "deref")
        hits = _find(match_universal(skel), "use-after-release")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["steps"], [2, 3])

    def test_python_use_after_close(self):
        skel = self._use_after_release("open", "close", "read")
        hits = _find(match_universal(skel), "use-after-release")
        self.assertEqual(len(hits), 1, "same shape as C UAF, different verbs")

    def test_lock_double_release_equals_double_free(self):
        obj = ObjRef(base="m")
        skel = Skeleton(kind="typestate", entry="f", events=[
            Event.op("lock", obj, 0, line=1),
            Event.op("unlock", obj, 0, line=2),
            Event.op("unlock", obj, 0, line=3),
        ])
        # unlock plays RELEASE, so two unlocks with no re-acquire is the double-release shape
        self.assertEqual(len(_find(match_universal(skel), "double-release")), 1)


class TestCoReferenceAndForbidWindow(unittest.TestCase):
    def test_different_objects_do_not_match(self):
        a, b = ObjRef(base="a"), ObjRef(base="b")
        skel = Skeleton(kind="typestate", entry="f", events=[
            Event.op("free", a, 0, line=1),
            Event.op("deref", b, 0, line=2),   # different object -> not a UAF
        ])
        self.assertEqual(_find(match_universal(skel), "use-after-release"), [])

    def test_reinit_between_free_and_use_kills_uaf(self):
        obj = ObjRef(base="p")
        skel = Skeleton(kind="typestate", entry="f", events=[
            Event.op("free", obj, 0, line=1),
            Event.op("reassign", obj, 0, line=2),   # REINIT: p now points at a fresh object
            Event.op("deref", obj, 0, line=3),
        ])
        self.assertEqual(_find(match_universal(skel), "use-after-release"), [],
                         "a reassign between free and use makes the deref safe")

    def test_realloc_generation_separates_old_from_new(self):
        # free of gen0 then deref of gen1 (the rebased pointer) is NOT a UAF, because the ObjRefs
        # differ by generation -- they are different objects. This is the interior-pointer story.
        obj0 = ObjRef(base="buf", generation=0)
        obj1 = obj0.aged()
        skel = Skeleton(kind="typestate", entry="f", events=[
            Event.op("free", obj0, 0, line=1),
            Event.op("deref", obj1, 0, line=2),
        ])
        self.assertEqual(_find(match_universal(skel), "use-after-release"), [])
        # but a stale interior pointer still on gen0 IS a UAF
        skel2 = Skeleton(kind="typestate", entry="f", events=[
            Event.op("free", obj0, 0, line=1),
            Event.op("deref", obj0, 0, line=2),
        ])
        self.assertEqual(len(_find(match_universal(skel2), "use-after-release")), 1)


class TestGuardAsProof(unittest.TestCase):
    def test_liveness_guard_discharges_uaf(self):
        obj = ObjRef(base="p")
        skel = Skeleton(kind="typestate", entry="f", events=[
            Event.op("free", obj, 0, line=1),
            Event.region_open("if", 0, guard=Guard(cond="alive(p)",
                                                    establishes=((Proof.LIVE, "p"),))),
            Event.op("deref", obj, 1, line=3),
            Event.region_close("if", 0),
        ])
        self.assertEqual(_find(match_universal(skel), "use-after-release"), [],
                         "a guard that proves LIVE(p) discharges the obligation")

    def test_nullness_guard_does_not_discharge_uaf(self):
        # the misleading-guard case: `if (p != NULL)` proves NONNULL, not LIVE -> still a UAF
        obj = ObjRef(base="p")
        skel = Skeleton(kind="typestate", entry="f", events=[
            Event.op("free", obj, 0, line=1),
            Event.region_open("if", 0, guard=Guard(cond="p != NULL",
                                                   establishes=((Proof.NONNULL, "p"),))),
            Event.op("deref", obj, 1, line=3),
            Event.region_close("if", 0),
        ])
        self.assertEqual(len(_find(match_universal(skel), "use-after-release")), 1,
                         "a nullness test must NOT mask a use-after-release")


class TestLeak(unittest.TestCase):
    def test_origin_without_release_is_leak(self):
        obj = ObjRef(base="h")
        skel = Skeleton(kind="typestate", entry="f", events=[Event.op("open", obj, 0, line=1)])
        self.assertEqual(len(_find(match_universal(skel), "leak")), 1)

    def test_origin_with_release_is_not_leak(self):
        obj = ObjRef(base="h")
        skel = Skeleton(kind="typestate", entry="f", events=[
            Event.op("open", obj, 0, line=1),
            Event.op("close", obj, 0, line=2),
        ])
        self.assertEqual(_find(match_universal(skel), "leak"), [])


class TestSerialisationAndAdapter(unittest.TestCase):
    def test_event_to_dict_roundtrips_shape(self):
        obj = ObjRef(base="b", path=("*", "data"))
        e = Event.op("free", obj, 1, line=42)
        d = e.to_dict()
        self.assertEqual(d["category"], "op")
        self.assertEqual(d["verb"], "free")
        self.assertIn("release", d["roles"])
        self.assertEqual(d["obj"], "b*.data")
        self.assertEqual(d["obj_key"], ["b", ["*", "data"], 0])

    def test_adapter_lifts_legacy_typestate_tokens(self):
        legacy = {"kind": "typestate", "entry": "f", "var": "p", "tokens": [
            {"t": "enter", "fn": "f", "depth": 0},
            {"t": "free", "var": "p", "line": 2, "fn": "f", "depth": 1},
            {"t": "use", "var": "p", "line": 3, "fn": "f", "depth": 1},
            {"t": "exit", "fn": "f", "depth": 0},
        ]}
        skel = from_flow_skeleton(legacy)
        hits = _find(match_universal(skel), "use-after-release")
        self.assertEqual(len(hits), 1, "legacy free->use lifts to a universal UAF hit")

    def test_render_is_stable_text(self):
        obj = ObjRef(base="x")
        skel = Skeleton(kind="typestate", entry="f", obj=obj, events=[
            Event.op("free", obj, 0, line=1),
            Event.op("deref", obj, 0, line=2),
        ])
        text = render(skel)
        self.assertIn("free[release/invalidate] x@1", text)
        self.assertIn("deref[observe] x@2", text)


if __name__ == "__main__":
    unittest.main()
