"""Stable, ownership-qualified identities for canonical graph facts."""
from __future__ import annotations

import hashlib
import json
from typing import Any, Iterable


VALID_OWNERS = frozenset({"frontend", "core", "runtime-model", "framework-model"})


def _stable_part(value: Any) -> str:
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(value, sort_keys=True, separators=(",", ":"))
    return str(value)


def stable_id(owner: str, namespace: str, kind: str, *parts: Any) -> str:
    """Return a stable v2 ID whose owner cannot collide with another layer."""
    if owner not in VALID_OWNERS:
        raise ValueError(f"invalid graph identity owner: {owner}")
    if not namespace or ":" in namespace:
        raise ValueError("identity namespace must be non-empty and contain no colon")
    raw = "\u0000".join(_stable_part(part) for part in parts)
    digest = hashlib.sha256(
        f"v2\u0000{owner}\u0000{namespace}\u0000{kind}\u0000{raw}".encode("utf-8")
    ).hexdigest()[:20]
    return f"v2:{owner}:{namespace}:{kind}:{digest}"


def identity_owner(node_id: str) -> str | None:
    pieces = node_id.split(":", 5)
    if len(pieces) != 5 or pieces[0] != "v2":
        return None
    return pieces[1]


def identity_namespace(node_id: str) -> str | None:
    pieces = node_id.split(":", 5)
    if len(pieces) != 5 or pieces[0] != "v2":
        return None
    return pieces[2]


def validate_identity(node_id: str, expected_owner: str | None = None) -> bool:
    owner = identity_owner(node_id)
    return owner in VALID_OWNERS and (expected_owner is None or owner == expected_owner)
