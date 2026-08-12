#!/usr/bin/env python3
"""B4 — the investigation capsule: schema, constructor, serializer, validator.

A capsule is the unit of work the planner hands downstream: one bounded, falsifiable
security question with its structural evidence already attached. The point of
freezing it is that the consumer's job becomes "prove or kill *this*", not "go look
at the codebase" — so the fields a consumer needs to decide are required, and the
fields that would let it mistake a guess for a fact are typed.

Three fields are required and have no default, because a capsule without them is
exactly the thing this layer exists to stop being produced:

  * ``state`` — the whole claim. ``PROVEN_VIOLATED`` is in the vocabulary for a
    downstream reasoner holding runtime evidence; ``new_capsule`` refuses to build
    one, so nothing static can emit it.
  * ``provenance`` — where the facts came from (``STATIC_PROVEN`` /
    ``AGENT_INFERRED`` / ``RUNTIME_OBSERVED``). The ranking layer reads this to
    enforce that inferred facts may only lower a rank.
  * ``completeness`` — how much the analysis actually saw. ``PARTIAL`` and
    ``OPAQUE`` are honest answers and must survive to the consumer intact.

The identity is content-derived, so the same claim about the same entrypoint and
effect is the same capsule across runs and across machines: re-runs are comparable
and families dedupe without a registry.

Validation is against ``capsule.schema.json`` and is written against the standard
library. The schema is the artifact of record for an external consumer; the checker
here covers the parts that carry meaning — required fields, enums, no stray keys —
rather than pulling in a validator dependency for a document this small.

  python3 planner/capsule.py --schema
  python3 planner/capsule.py --check some_capsule.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

SCHEMA_VERSION = 1
SCHEMA_PATH = Path(__file__).resolve().parent / "capsule.schema.json"

STATE_UNPROVEN = "UNPROVEN"
STATE_PRESERVED = "PROVEN_PRESERVED"
# Present in the schema for a downstream consumer; never produced here.
STATE_VIOLATED = "PROVEN_VIOLATED"

PROVENANCE = ("STATIC_PROVEN", "AGENT_INFERRED", "RUNTIME_OBSERVED")
COMPLETENESS = ("DETERMINISTIC", "RESOLVED", "PARTIAL", "OPAQUE", "CONFLICTING")
# Capability roles, deliberately generic: a capsule says what *kind* of actor should
# take it next, never which product does the taking.
ACTORS = ("judge", "runtime-probe", "browser")


def load_schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def capsule_id(claim: dict, entrypoint_id: str, effect_id: str) -> str:
    """Content-derived identity — stable across runs, machines and orderings."""
    payload = json.dumps(
        {"claim": claim, "entrypoint": entrypoint_id, "effect": effect_id},
        sort_keys=True, ensure_ascii=False,
    )
    return "cap_" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def new_capsule(*, constructor: str, claim: dict, entrypoint: dict,
                sensitive_effect: dict, objective: str, state: str,
                provenance: str, completeness: str,
                attacker_inputs: list | None = None,
                dataflow: list | None = None, witness: dict | None = None,
                guards_present: list | None = None,
                missing_guard: dict | None = None,
                cross_reference: dict | None = None,
                uncertainty: list | None = None,
                suggested_actors: list | None = None,
                rank: float = 0.0, rank_reasons: list | None = None) -> dict:
    """Build a capsule, or refuse.

    Keyword-only on purpose: a capsule with its state and its provenance swapped by
    argument order would be a silent lie, and there is no ordering of these fields
    obvious enough to trust to position."""
    if state == STATE_VIOLATED:
        raise ValueError(
            "the planner cannot emit PROVEN_VIOLATED: static analysis proves a guard "
            "present or proves nothing, and declaring a violation is a downstream "
            "judgement made against runtime evidence")
    if state not in (STATE_UNPROVEN, STATE_PRESERVED):
        raise ValueError(f"unknown capsule state: {state!r}")
    if provenance not in PROVENANCE:
        raise ValueError(f"unknown provenance: {provenance!r}")
    if completeness not in COMPLETENESS:
        raise ValueError(f"unknown completeness: {completeness!r}")

    capsule = {
        "id": capsule_id(claim, entrypoint.get("node_id", ""),
                         sensitive_effect.get("node_id", "")),
        "schema_version": SCHEMA_VERSION,
        "constructor": constructor,
        "claim": claim,
        "entrypoint": entrypoint,
        "attacker_inputs": attacker_inputs or [],
        "sensitive_effect": sensitive_effect,
        "dataflow": dataflow or [],
        "guards_present": guards_present or [],
        "missing_guard": missing_guard,
        "cross_reference": cross_reference,
        "uncertainty": uncertainty or [],
        "objective": objective,
        "suggested_actors": list(suggested_actors or ("judge",)),
        "state": state,
        "provenance": provenance,
        "completeness": completeness,
        "rank": rank,
        "rank_reasons": rank_reasons or [],
    }
    if witness is not None:
        capsule["witness"] = witness
    return capsule


# -- validation --------------------------------------------------------------


def validate(capsule: dict, schema: dict | None = None) -> list[str]:
    """Return the list of problems with a capsule; empty means it validates."""
    schema = schema or load_schema()
    return _check(capsule, schema, schema, "capsule")


def _check(value, node: dict, root: dict, where: str) -> list[str]:
    if "$ref" in node:
        return _check(value, _deref(node["$ref"], root), root, where)
    problems: list[str] = []
    if "const" in node and value != node["const"]:
        problems.append(f"{where}: expected {node['const']!r}, got {value!r}")
    if "enum" in node and value not in node["enum"]:
        problems.append(f"{where}: {value!r} is not one of {node['enum']}")
    expected = node.get("type")
    if expected and not _typed(value, expected):
        problems.append(f"{where}: expected type {expected}, got "
                        f"{type(value).__name__}")
        return problems
    if isinstance(value, dict) and node.get("properties") is not None:
        for key in node.get("required", ()):
            if key not in value:
                problems.append(f"{where}: missing required field {key!r}")
        properties = node["properties"]
        for key, item in value.items():
            if key in properties:
                problems += _check(item, properties[key], root, f"{where}.{key}")
            elif node.get("additionalProperties") is False:
                problems.append(f"{where}: unexpected field {key!r}")
    if isinstance(value, list) and "items" in node:
        for position, item in enumerate(value):
            problems += _check(item, node["items"], root, f"{where}[{position}]")
    if isinstance(value, str) and "pattern" in node:
        import re
        if not re.search(node["pattern"], value):
            problems.append(f"{where}: {value!r} does not match {node['pattern']}")
    return problems


_JSON_TYPES = {
    "object": dict, "array": list, "string": str, "number": (int, float),
    "integer": int, "boolean": bool, "null": type(None),
}


def _typed(value, expected) -> bool:
    names = expected if isinstance(expected, list) else [expected]
    for name in names:
        wanted = _JSON_TYPES.get(name)
        if wanted is None:
            return True
        if name in ("number", "integer") and isinstance(value, bool):
            continue  # a bool is an int in Python and is not a number here
        if isinstance(value, wanted):
            return True
    return False


def _deref(ref: str, root: dict) -> dict:
    node = root
    for part in ref.lstrip("#/").split("/"):
        node = node[part]
    return node


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="B4 — capsule schema and validator")
    p.add_argument("--schema", action="store_true", help="print the JSON Schema")
    p.add_argument("--check", metavar="FILE",
                   help="validate a capsule (or a JSON list of capsules)")
    return p


def main(argv: list[str]) -> int:
    args = _parser().parse_args(argv)
    if args.schema:
        print(json.dumps(load_schema(), indent=2, ensure_ascii=False))
        return 0
    if args.check:
        payload = json.loads(Path(args.check).read_text(encoding="utf-8"))
        capsules = payload if isinstance(payload, list) else [payload]
        schema = load_schema()
        failed = 0
        for capsule in capsules:
            problems = validate(capsule, schema)
            if problems:
                failed += 1
                print(f"{capsule.get('id', '<no id>')}:", file=sys.stderr)
                for problem in problems:
                    print(f"  {problem}", file=sys.stderr)
        print(f"{len(capsules) - failed}/{len(capsules)} capsule(s) validate")
        return 1 if failed else 0
    print("need --schema or --check FILE", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
