"""Scope lookup and binding helpers consumed by semantic overlays.

Scope construction itself is compiler-owned. These functions only query the
canonical scope records or split a variable binding used by data-flow logic.
"""
import re
from typing import List


VARIABLE_RE = re.compile(
    r"\b(?P<kind>const|let|var)\s+"
    r"(?P<binding>[A-Za-z_$][\w$]*|\{[^}\n]*\}|\[[^\]\n]*\])"
)


def innermost_scope(scopes: List[dict], line: int) -> dict:
    candidates = [
        scope for scope in scopes
        if scope["start_line"] <= line <= scope["end_line"]
    ]
    return min(
        candidates,
        key=lambda scope: (
            scope["end_line"] - scope["start_line"],
            2 if scope["kind"] == "module" else
            1 if scope["kind"] == "function" else 0,
        ),
    )


def innermost_scope_at(scopes: List[dict], offset: int, line: int = None) -> dict:
    candidates = [
        scope for scope in scopes
        if scope.get("start_offset", 0) <= offset < scope.get("end_offset", 0)
    ]
    if not candidates:
        return innermost_scope(scopes, line or 1)
    return min(
        candidates,
        key=lambda scope: (
            scope.get("end_offset", 0) - scope.get("start_offset", 0),
            2 if scope["kind"] == "module" else
            1 if scope["kind"] == "function" else 0,
        ),
    )


def binding_names(binding: str) -> List[str]:
    binding = binding.strip()
    if binding.startswith(("{", "[")):
        names = []
        for part in binding[1:-1].split(","):
            part = part.strip()
            if not part:
                continue
            candidate = part.split("=", 1)[0].split(":")[-1].strip()
            if re.fullmatch(r"[A-Za-z_$][\w$]*", candidate):
                names.append(candidate)
        return names
    match = re.match(r"[A-Za-z_$][\w$]*", binding)
    return [match.group(0)] if match else []
