"""Optional bridge to the Rust object-lifetime batch solver.

The bridge is opt-in while parity is being established.  It deliberately accepts the
same prepared batch as ``ObjectStateAnalyzer`` and reconstructs the existing Python
``AnalysisResult`` shape, including point/post snapshots consumed by Pass 3.
"""
from __future__ import annotations

import ctypes
import json
import os
from pathlib import Path
from typing import Any

from .object_state import (
    AbstractState,
    AccessPath,
    AnalysisResult,
    Finding,
    ObjectFact,
    OpKind,
    Operation,
    ParamEffect,
    ReturnEffect,
)


def _library_candidates() -> tuple[Path, ...]:
    configured = os.environ.get("LACHESIS_NATIVE_LIFETIME_LIB")
    if configured:
        return (Path(configured),)
    root = Path(__file__).resolve().parents[2]
    return tuple(root / "native" / "lifetime_kernel" / "target" / "release" / name
                 for name in (
                     "liblachesis_lifetime_kernel.dylib",
                     "liblachesis_lifetime_kernel.so",
                     "lachesis_lifetime_kernel.dll",
                 ))


def _load():
    for candidate in _library_candidates():
        if not candidate.is_file():
            continue
        library = ctypes.CDLL(str(candidate))
        library.lachesis_lifetime_solve_json.argtypes = [ctypes.c_char_p]
        library.lachesis_lifetime_solve_json.restype = ctypes.c_void_p
        library.lachesis_lifetime_free_json.argtypes = [ctypes.c_void_p]
        library.lachesis_lifetime_free_json.restype = None
        return library
    return None


def available() -> bool:
    return _load() is not None


def _path(path: AccessPath | None) -> dict[str, Any] | None:
    if path is None:
        return None
    return {"root": path.root, "selectors": list(path.selectors)}


def _operation(operation: Operation) -> dict[str, Any] | None:
    # SUMMARY contains nested operations and is intentionally left to Python until the
    # native fixpoint implementation is complete.
    if operation.kind == OpKind.SUMMARY or not isinstance(operation.node, str):
        return None
    return {
        "kind": operation.kind.name.title(),
        "node": operation.node,
        "target": _path(operation.target),
        "source": _path(operation.source),
        "site": str(operation.site if operation.site is not None else operation.node),
        "line": operation.line,
        "is_null": operation.is_null,
        "access": operation.access,
    }


def _oid(table: dict[str, Any], handle: str, memo: dict[str, tuple]) -> tuple:
    cached = memo.get(handle)
    if cached is not None:
        return cached
    meta = table[handle]
    if "Param" in meta:
        value = ("param", int(meta["Param"]["position"]),
                 tuple(meta["Param"]["selectors"]))
    elif "UnknownRoot" in meta:
        value = ("unknown-root", meta["UnknownRoot"]["root"])
    elif "UnknownSlot" in meta:
        slot = meta["UnknownSlot"]
        value = ("unknown-slot", _oid(table, slot["base"], memo), slot["selector"])
    elif "Allocation" in meta:
        allocation = meta["Allocation"]
        target = allocation["target"]
        value = (allocation["kind"].lower(), allocation["generation"], allocation["site"],
                 AccessPath(target["root"], tuple(target["selectors"])))
    elif "Phi" in meta:
        phi = meta["Phi"]
        value = (phi["tag"], phi["node"], int(phi["index"]))
    else:
        raise ValueError(f"unknown native object metadata: {meta!r}")
    memo[handle] = value
    return value


def _effect(raw: dict[str, Any]):
    if "Param" in raw:
        value = raw["Param"]
        return ParamEffect(OpKind[value["kind"].upper()], int(value["position"]),
                           tuple(value["selectors"]))
    value = raw["Return"]
    return ReturnEffect(int(value["position"]), tuple(value["selectors"]))


def _snapshot(raw: dict[str, Any], memo: dict[str, tuple]) -> AbstractState:
    table = dict(raw["objects"])
    state = AbstractState()
    state.env = {root: _oid(table, handle, memo)
                 for root, handle in raw["env"]}
    state.facts = {
        _oid(table, handle, memo): frozenset(ObjectFact[value.upper()] for value in values)
        for handle, values in raw["facts"]
    }
    state.slots = {
        (_oid(table, pair[0], memo), pair[1]): _oid(table, handle, memo)
        for pair, handle in raw["slots"]
    }
    state.trace = tuple(_effect(item) for item in raw["trace"])
    state.freed_paths = {
        AccessPath(path["root"], tuple(path["selectors"])): _oid(table, handle, memo)
        for path, handle in raw["freed_paths"]
    }
    return state


def solve_linear(nodes, successors, operations, initial: AbstractState):
    """Return a native ``(summary, AnalysisResult)`` or ``None`` when unsupported."""
    if any(not isinstance(node, str) for node in nodes):
        return None
    if any(operation.kind == OpKind.SUMMARY for operation in operations):
        return None
    encoded = [_operation(operation) for operation in operations]
    if any(item is None for item in encoded):
        return None
    parameters = []
    for root, oid in initial.env.items():
        if isinstance(oid, tuple) and len(oid) == 3 and oid[0] == "param":
            parameters.append((root, int(oid[1])))
    payload = json.dumps({
        "nodes": list(nodes),
        "successors": {node: list(successors.get(node, ())) for node in nodes},
        "parameters": parameters,
        "operations": encoded,
    }).encode()
    library = _load()
    if library is None:
        return None
    pointer = library.lachesis_lifetime_solve_json(payload)
    if not pointer:
        return None
    try:
        result = json.loads(ctypes.string_at(pointer).decode())
    finally:
        library.lachesis_lifetime_free_json(pointer)
    if "error" in result:
        raise RuntimeError(f"native lifetime solver failed: {result['error']}")
    memo: dict[str, tuple] = {}
    point_states = {
        node: tuple(_snapshot(snapshot, memo) for snapshot in snapshots)
        for node, snapshots in result["point_states"]
    }
    post_states = {
        node: tuple(_snapshot(snapshot, memo) for snapshot in snapshots)
        for node, snapshots in result["post_states"]
    }
    exit_states = tuple(_snapshot(snapshot, memo) for snapshot in result["exit_states"])
    exit_state = exit_states[0] if exit_states else _snapshot(result["exit_state"], memo)
    placed = {operation for operation in operations if operation.node in set(nodes)}
    unplaced = tuple(operation for operation in operations if operation not in placed)
    analysis = AnalysisResult(
        findings=set(),
        exit_states=exit_states or (exit_state,),
        unplaced=unplaced,
        transfers=int(result["transfers"]),
        widenings=int(result["widenings"]),
        capped=bool(result["capped"]),
        point_states=point_states,
        post_states=post_states,
    )
    return tuple(sorted({state.trace for state in analysis.exit_states}, key=repr)), analysis
