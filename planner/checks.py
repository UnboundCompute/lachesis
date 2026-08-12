"""Executable checks for the planner, on the fixture project shipped in-tree.

  python -m unittest planner.checks

The suite builds ``planner/fixtures/project`` into a real store once, then asserts
the four behaviours the layer exists for, each of which is a case some simpler
implementation gets wrong:

  * a guard on the registered wrapper suppresses an effect one hop down
    (the wrapper-anchoring false positive),
  * a handler with no guard anywhere on the path stays on the queue,
  * a requirement declared on the registration is recognized even though nothing
    calls it, and does **not** suppress, because its value is not readable,
  * nothing static is ever emitted as ``PROVEN_VIOLATED``.

The fixture is a handful of small TypeScript files and no dependencies, so the
whole suite runs in seconds and never needs a large application checked out.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

FIXTURE = ROOT / "planner" / "fixtures" / "project"
GOLDEN = ROOT / "planner" / "fixtures" / "capsule_golden.json"

from nav.graph_store import GraphStore
from planner import capsule as cap
from planner.constructors import GuardDifferential
from planner.dominance import STATE_PRESERVED, STATE_UNPROVEN
from planner.rank import ranked, score


def _build(destination: Path) -> None:
    completed = subprocess.run(
        [sys.executable, "-m", "Lachesis.cli.analyze", str(FIXTURE),
         str(destination), "--enrich", "--prune"],
        cwd=ROOT, text=True, capture_output=True, check=False,
    )
    if completed.returncode != 0:
        raise unittest.SkipTest(
            f"could not build the planner fixture graph:\n{completed.stderr}")


class PlannerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory()
        store_path = Path(cls._tmp.name) / "planner-fixture.kuzu"
        _build(store_path)
        cls.store = GraphStore.load(str(store_path))
        cls.store.ensure_dataflow_tier()
        cls.planner = GuardDifferential(cls.store)
        cls.result = cls.planner.run()
        cls.capsules = cls.result["queue"] + cls.result["suppressions"]

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmp.cleanup()

    # -- helpers -------------------------------------------------------------

    def capsules_from(self, entrypoint: str) -> list[dict]:
        return [c for c in self.capsules
                if c["entrypoint"]["symbol"] == entrypoint]

    def function_id(self, name: str) -> str:
        hits = [h for h in self.store.resolve(name) if h.get("name") == name]
        self.assertTrue(hits, f"no declaration named {name!r} in the fixture graph")
        return hits[0]["node_id"]

    # -- anchoring -----------------------------------------------------------

    def test_registered_handlers_are_the_entrypoints(self):
        handlers = {self.store.gl.label(self.store.gl.nodes.get(h))
                    for h in self.planner.entry_points.by_handler()}
        self.assertEqual(handlers, {"archiveRecord", "purgeRecord", "renameRecord",
                                    "deleteRecord", "touchRecord", "exportRecords",
                                    "importRecord", "submitRecord",
                                    "cleanupRecord", "dropRecord", "wipeRecord"})

    def test_implementation_is_anchored_at_its_registered_wrapper(self):
        # archiveRecordRow is never registered; the route reaches it through
        # archiveRecord. Without the climb its guard is invisible.
        anchors = self.planner.entry_points.anchors_for(
            self.function_id("archiveRecordRow"))
        self.assertTrue(anchors, "the implementation found no anchor at all")
        self.assertEqual(anchors[0]["how"], "route")
        self.assertEqual(anchors[0]["distance"], 1)
        self.assertEqual(anchors[0]["anchor_label"], "POST /records.archive")

    def test_object_literal_registration_is_an_anchor(self):
        # Neither shape passes a callback positionally and neither is a route, so
        # without this recognition both handlers are never scanned at all.
        anchored = {}
        for handler_id, anchors in self.planner.entry_points.by_handler().items():
            for anchor in anchors:
                if anchor["how"] == "object-literal-registration":
                    anchored[self.store.gl.label(
                        self.store.gl.nodes[handler_id])] = anchor["property_shape"]
        self.assertEqual(anchored, {"dropRecord": "shorthand-reference",
                                    "wipeRecord": "declared-inline"})

    def test_a_registered_method_is_scanned_like_any_other_entrypoint(self):
        guarded = [c for c in self.result["suppressions"]
                   if c["entrypoint"]["symbol"] == "dropRecord"]
        self.assertTrue(guarded, "the guarded registered method produced no capsule")
        unguarded = [c for c in self.result["queue"]
                     if c["entrypoint"]["symbol"] == "wipeRecord"]
        self.assertTrue(unguarded, "the unguarded registered method was not queued")
        for capsule in unguarded:
            self.assertEqual(capsule["state"], STATE_UNPROVEN)
            self.assertEqual(capsule["sensitive_effect"]["kind"], "database")

    # -- dominance -----------------------------------------------------------

    def test_guard_on_the_wrapper_suppresses_the_effect_below_it(self):
        suppressed = [c for c in self.capsules_from("archiveRecord")
                      if c["state"] == STATE_PRESERVED]
        self.assertTrue(suppressed, "the guarded handler produced no suppression")
        for capsule in suppressed:
            names = [g["predicate"] for g in capsule["guards_present"]
                     if g["dominates"]]
            self.assertIn("checkPermission", names,
                          "a suppression that does not name its guard is not auditable")

    def test_the_implementation_alone_carries_no_guard(self):
        # The point of the previous test: the suppression comes from the anchor,
        # not from the function that performs the effect.
        guards = self.planner.guard_set.for_function(
            self.function_id("archiveRecordRow"))
        self.assertEqual(guards, [])

    def test_unguarded_handler_stays_on_the_queue(self):
        queued = [c for c in self.result["queue"]
                  if c["entrypoint"]["symbol"] == "purgeRecord"]
        self.assertTrue(queued, "the unguarded handler was not queued")
        for capsule in queued:
            self.assertEqual(capsule["state"], STATE_UNPROVEN)
            self.assertEqual(capsule["guards_present"], [])
            self.assertEqual(capsule["sensitive_effect"]["kind"], "database")

    def test_a_checked_answer_that_is_branched_on_suppresses(self):
        # isPermitted throws nothing; the suppression has to come from the caller
        # acting on the answer, and it has to say so.
        suppressed = [c for c in self.result["suppressions"]
                      if c["entrypoint"]["symbol"] == "deleteRecord"]
        self.assertTrue(suppressed, "a branched-on permission check did not suppress")
        for capsule in suppressed:
            basis = {g["predicate"]: g.get("suppression_basis")
                     for g in capsule["guards_present"] if g["dominates"]}
            self.assertEqual(basis.get("isPermitted"), "branch")

    def test_a_throwing_guard_suppresses_without_a_branch_at_the_call_site(self):
        suppressed = [c for c in self.result["suppressions"]
                      if c["entrypoint"]["symbol"] == "archiveRecord"]
        self.assertTrue(suppressed)
        for capsule in suppressed:
            basis = {g["predicate"]: g.get("suppression_basis")
                     for g in capsule["guards_present"] if g["dominates"]}
            self.assertEqual(basis.get("checkPermission"), "callee-throws")

    def test_an_authorization_name_whose_answer_is_ignored_does_not_suppress(self):
        # The whole point of the rule: refreshPermissionCache lands in the authz
        # family by name, checks nothing, and must not clear anything.
        queued = [c for c in self.result["queue"]
                  if c["entrypoint"]["symbol"] == "touchRecord"]
        self.assertTrue(queued,
                        "a call that only looks like authorization suppressed a "
                        "candidate")
        for capsule in queued:
            self.assertEqual(capsule["state"], STATE_UNPROVEN)
            reported = {g["predicate"] for g in capsule["guards_present"]}
            self.assertIn("refreshPermissionCache", reported,
                          "the call still has to reach the consumer as evidence")
            self.assertFalse(any(g["dominates"] for g in capsule["guards_present"]))
            self.assertTrue(any("never branched on" in note
                                for note in capsule["uncertainty"]),
                            "the reason it did not suppress must reach the consumer")

    def test_verifying_an_authentication_object_suppresses(self):
        suppressed = [c for c in self.result["suppressions"]
                      if c["entrypoint"]["symbol"] == "importRecord"]
        self.assertTrue(suppressed, "a branched-on signature check did not suppress")
        for capsule in suppressed:
            basis = {g["predicate"]: g.get("suppression_basis")
                     for g in capsule["guards_present"] if g["dominates"]}
            self.assertEqual(basis.get("verifySignature"), "branch")

    def test_verifying_the_payload_is_not_authorization(self):
        # Same family, same branch shape as importRecord above. Only the object
        # being verified differs, and that is the whole distinction.
        queued = [c for c in self.result["queue"]
                  if c["entrypoint"]["symbol"] == "submitRecord"]
        self.assertTrue(queued,
                        "a required-fields check cleared an authorization question")
        for capsule in queued:
            self.assertEqual(capsule["state"], STATE_UNPROVEN)
            reported = {g["predicate"] for g in capsule["guards_present"]}
            self.assertIn("verifyRequiredFields", reported,
                          "the check still has to reach the consumer as evidence")
            self.assertFalse(any(g["dominates"] for g in capsule["guards_present"]))
            self.assertTrue(any("authentication object" in note
                                for note in capsule["uncertainty"]),
                            "the reason it did not suppress must reach the consumer")

    def test_a_validator_is_reported_but_does_not_clear_the_candidate(self):
        queued = [c for c in self.result["queue"]
                  if c["entrypoint"]["symbol"] == "renameRecord"]
        self.assertTrue(queued, "a validated but unauthorized handler was suppressed")
        for capsule in queued:
            names = {g["predicate"] for g in capsule["guards_present"]}
            self.assertIn("validateRecordId", names,
                          "the validator has to reach the consumer as evidence")
            self.assertFalse(any(g["dominates"] for g in capsule["guards_present"]),
                             "input validation is not authorization")
            self.assertTrue(any("authorization" in note
                                for note in capsule["uncertainty"]))

    # -- the sink catalog ------------------------------------------------------

    def test_a_delegating_call_is_not_itself_a_sensitive_effect(self):
        # `renameRecordRow` and `executeRecordCleanup` read like sink names and
        # perform nothing; the operations are one hop down and are candidates
        # there. Matching the delegator manufactures a duplicate candidate whose
        # named effect is a function call.
        effects = self.planner.effects()
        delegating = {"renameRecordRow", "executeRecordCleanup"}
        named = {e["symbol"].split("(")[0]
                 for rows in effects.values() for e in rows}
        self.assertEqual(named & delegating, set(),
                         f"a delegating call was materialized as a sink: {named}")
        # and the real operations inside it still are effects
        performed = {e["symbol"].split("(")[0] for e in
                     effects.get(self.function_id("executeRecordCleanup"), [])}
        self.assertIn("store.deleteMany", performed)
        self.assertIn("store.executeStatement", performed)

    # -- declarative recognition ---------------------------------------------

    def test_declarative_requirement_is_recognized_and_does_not_suppress(self):
        capsules = self.capsules_from("exportRecords")
        self.assertTrue(capsules, "the declaratively guarded route produced nothing")
        for capsule in capsules:
            names = {g["predicate"] for g in capsule["guards_present"]}
            self.assertTrue(
                {"authRequired", "permissionsRequired"} & names,
                f"the declared requirement was not recognized: {names}")
            self.assertFalse(any(g["dominates"] for g in capsule["guards_present"]),
                             "a declared requirement whose value is unreadable must "
                             "not suppress")
            self.assertEqual(capsule["state"], STATE_UNPROVEN)
            self.assertTrue(any("not observable" in note or "not readable" in note
                                for note in capsule["uncertainty"]),
                            "the reason it did not suppress must reach the consumer")

    # -- the capsule contract -------------------------------------------------

    def test_every_capsule_validates_against_the_schema(self):
        schema = cap.load_schema()
        for capsule in self.capsules:
            problems = cap.validate(capsule, schema)
            self.assertEqual(problems, [], f"{capsule['id']}: {problems}")

    def test_nothing_static_claims_a_violation(self):
        for capsule in self.capsules:
            self.assertNotEqual(capsule["state"], "PROVEN_VIOLATED")
        with self.assertRaises(ValueError):
            cap.new_capsule(
                constructor="GUARD_DIFFERENTIAL", claim={}, entrypoint={},
                sensitive_effect={}, objective="", state="PROVEN_VIOLATED",
                provenance="STATIC_PROVEN", completeness="DETERMINISTIC")

    def test_capsule_identity_is_content_derived(self):
        again = GuardDifferential(self.store).run()
        self.assertEqual([c["id"] for c in again["queue"]],
                         [c["id"] for c in self.result["queue"]])

    def test_golden_capsule_round_trips(self):
        golden = json.loads(GOLDEN.read_text(encoding="utf-8"))
        self.assertEqual(cap.validate(golden), [])
        self.assertEqual(
            golden["id"],
            cap.capsule_id(golden["claim"], golden["entrypoint"]["node_id"],
                           golden["sensitive_effect"]["node_id"]))

    # -- ranking --------------------------------------------------------------

    def test_ranking_is_explained_and_ordered(self):
        queue = self.result["queue"]
        self.assertEqual([c["rank"] for c in queue],
                         sorted((c["rank"] for c in queue), reverse=True))
        for capsule in queue:
            self.assertTrue(capsule["rank_reasons"])
            self.assertTrue(all(r.get("why") for r in capsule["rank_reasons"]))

    def test_an_uncertain_capsule_is_lowered_and_not_removed(self):
        base = {"id": "cap_0000000000000000",
                "sensitive_effect": {"kind": "database"}, "attacker_inputs": [],
                "guards_present": [], "cross_reference": None, "dataflow": [],
                "completeness": "DETERMINISTIC", "provenance": "STATIC_PROVEN"}
        certain, _ = score(base)
        opaque, _ = score({**base, "completeness": "OPAQUE",
                           "provenance": "AGENT_INFERRED"})
        self.assertLess(opaque, certain)
        self.assertGreater(opaque, 0.0)
        self.assertEqual(len(ranked([base])), 1)


if __name__ == "__main__":
    unittest.main()
