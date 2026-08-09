"""Deterministic, model-independent context budgeting for reasoning slices."""
from __future__ import annotations

import json
from typing import Iterable


DEFAULT_BUDGET_TOKENS = 12_000
CHARS_PER_TOKEN = 4


def estimate_tokens(value: object) -> int:
    serialized = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    )
    return max(1, (len(serialized) + CHARS_PER_TOKEN - 1) // CHARS_PER_TOKEN)


def fit_sections(
    base: dict, sections: Iterable[tuple[str, list[dict]]], budget_tokens: int,
) -> dict:
    """Fit ordered sections and emit stable continuation handles for omissions."""
    result = dict(base)
    result["sections"] = {}
    result["continuations"] = []
    omitted = {}
    content_budget = max(128, budget_tokens - 512)
    for section_name, records in sections:
        included = []
        for position, record in enumerate(records):
            candidate = dict(result)
            candidate["sections"] = {**result["sections"], section_name: [*included, record]}
            if estimate_tokens(candidate) <= content_budget:
                included.append(record)
                continue
            remaining = records[position:]
            omitted[section_name] = len(remaining)
            first = remaining[0] if remaining else {}
            node_id = first.get("id") or first.get("node_id") \
                or first.get("target") or first.get("source")
            result["continuations"].append({
                "operation": "continue-slice", "query": base.get("query"),
                "focus_id": (base.get("focus") or {}).get("id"),
                "section": section_name, "offset": position,
                "omitted_count": len(remaining), "next_node_id": node_id,
                "reason": "budget",
            })
            break
        result["sections"][section_name] = included
    budget = {
        "requested_tokens": budget_tokens,
        "truncated": bool(omitted),
        "omitted": omitted,
        "estimator": "serialized-characters/4",
    }
    result["budget"] = budget
    budget["estimated_tokens"] = estimate_tokens(result)
    return result
