#!/usr/bin/env python3
"""B3 — ranking: order the queue, and show the work.

The queue is the product. A consumer that always works the top of a justified
ordering never wanders, which is the whole point of the planner — so the ordering
has to be arguable, not a number that fell out of a model. ``score`` returns the
rank **with the terms that produced it**, each carrying its contribution and a
sentence saying why, and the capsule keeps that list in ``rank_reasons``.

Two rules constrain the arithmetic:

**Directional trust.** An inferred fact may only *lower* a rank; it may never raise
one and it may never eliminate a candidate. Only a proven fact — ``STATIC_PROVEN``
here, ``RUNTIME_OBSERVED`` downstream — is allowed to remove something from the
queue, and that removal happens in the constructor as a suppression with the guard
named, not silently in a score. So provenance and completeness enter as a multiplier
capped at 1.0 with a floor above 0: a capsule the analysis barely saw sinks, but it
stays on the queue.

**Absence of evidence is not evidence of absence.** ``OPAQUE`` — the analysis ran out
of room — is scored *below* a complete look but above nothing, because an unexamined
path is a worse reason to ignore something than an examined one.

The weights below are a starting ordering, not a calibrated model. They are here to
be argued with, which is why every one of them is named in the output.

  python3 planner/rank.py capsules.json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# How much damage the effect can do. Taken from the sink kinds the security-role
# model already emits, so this table has nothing to invent.
SINK_SEVERITY = {
    "dynamic-code": 1.0,
    "process": 0.95,
    "deserialize": 0.8,
    "database": 0.7,
    "filesystem-write": 0.7,
    "network": 0.5,
    "filesystem-read": 0.35,
    "response": 0.2,
}
DEFAULT_SEVERITY = 0.4

# How directly an attacker holds the input, by the source kinds the same model emits.
INPUT_DIRECTNESS = {
    "request-input": 1.0,
    "route-handler-parameter": 0.9,
    "resource-identifier": 0.75,
    "boundary-parameter": 0.5,
}
NO_INPUT_DIRECTNESS = 0.25

# Completeness is a multiplier, never a gate. OPAQUE sits below a complete look and
# above nothing: an unexamined path is a worse reason to ignore a candidate than an
# examined one.
COMPLETENESS_TRUST = {
    "DETERMINISTIC": 1.0,
    "RESOLVED": 0.9,
    "PARTIAL": 0.75,
    "CONFLICTING": 0.6,
    "OPAQUE": 0.5,
}
# Directional trust: no entry may exceed 1.0, so inference can only lower a rank.
PROVENANCE_TRUST = {
    "STATIC_PROVEN": 1.0,
    "RUNTIME_OBSERVED": 1.0,
    "AGENT_INFERRED": 0.8,
}
# The floor keeps a heavily discounted capsule on the queue instead of vanishing.
TRUST_FLOOR = 0.3

WEIGHTS = {
    "sink_severity": 0.30,
    "input_directness": 0.25,
    "guard_absence": 0.25,
    "differential": 0.12,
    "path_directness": 0.08,
}


def score(capsule: dict) -> tuple[float, list[dict]]:
    """(rank, reasons) for one capsule. Pure — no graph, no I/O, no ordering effects."""
    reasons: list[dict] = []

    effect_kind = (capsule.get("sensitive_effect") or {}).get("kind")
    severity = SINK_SEVERITY.get(effect_kind, DEFAULT_SEVERITY)
    reasons.append({"term": "sink_severity", "value": severity,
                    "why": f"the effect is a {effect_kind or 'unclassified'} sink"})

    inputs = capsule.get("attacker_inputs") or []
    if inputs:
        directness = max(INPUT_DIRECTNESS.get(i.get("origin"), 0.4) for i in inputs)
        origins = ", ".join(sorted({str(i.get("origin")) for i in inputs}))
        why = f"attacker input reaches the entrypoint as {origins}"
    else:
        directness = NO_INPUT_DIRECTNESS
        why = ("no attacker-controlled input was identified at the entrypoint, which "
               "lowers the rank without removing the candidate")
    reasons.append({"term": "input_directness", "value": directness, "why": why})

    guards = capsule.get("guards_present") or []
    dominating = [g for g in guards if g.get("dominates")]
    if dominating:
        absence = 0.0
        why = "a guard was proven present on the path"
    elif guards:
        absence = 0.55
        why = ("a guard is declared but its effect could not be confirmed, so it "
               "lowers the rank rather than clearing the candidate")
    else:
        absence = 1.0
        why = "no guard of any recognized kind was found on the path"
    reasons.append({"term": "guard_absence", "value": absence, "why": why})

    cross = capsule.get("cross_reference")
    differential = 0.85 if cross else 0.25
    reasons.append({
        "term": "differential", "value": differential,
        "why": (f"a peer ({cross.get('symbol', cross.get('sibling_id'))}) does guard "
                f"this effect" if cross else
                "no guarded peer was found, so the absence stands on its own"),
    })

    hops = max(len(capsule.get("dataflow") or []) - 1, 0)
    path_directness = max(0.2, 1.0 - 0.12 * hops)
    reasons.append({"term": "path_directness", "value": path_directness,
                    "why": f"{hops} call hop(s) from the entrypoint to the effect"})

    base = sum(WEIGHTS[r["term"]] * r["value"] for r in reasons)

    completeness = capsule.get("completeness")
    provenance = capsule.get("provenance")
    trust = (COMPLETENESS_TRUST.get(completeness, 0.5)
             * PROVENANCE_TRUST.get(provenance, 0.8))
    trust = max(TRUST_FLOOR, min(1.0, trust))
    reasons.append({
        "term": "trust", "value": round(trust, 3),
        "why": (f"completeness {completeness} and provenance {provenance} discount "
                f"the rank; a discount can only lower it, never eliminate it"),
    })

    return round(base * trust, 4), reasons


def ranked(capsules: list[dict]) -> list[dict]:
    """Score every capsule and return the queue, strongest first.

    The tie-break is the capsule id, which is content-derived, so two runs over the
    same graph produce the same queue in the same order."""
    scored = []
    for capsule in capsules:
        rank, reasons = score(capsule)
        scored.append({**capsule, "rank": rank, "rank_reasons": reasons})
    scored.sort(key=lambda c: (-c["rank"], c["id"]))
    return scored


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="B3 — explainable capsule ranking")
    p.add_argument("capsules", help="a JSON capsule or list of capsules")
    p.add_argument("--limit", type=int, default=0, help="print only the top N")
    return p


def main(argv: list[str]) -> int:
    args = _parser().parse_args(argv)
    payload = json.loads(Path(args.capsules).read_text(encoding="utf-8"))
    queue = ranked(payload if isinstance(payload, list) else [payload])
    if args.limit:
        queue = queue[:args.limit]
    print(json.dumps(queue, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
