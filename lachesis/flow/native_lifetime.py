"""Optional bridge to the Rust object-lifetime batch solver.

The bridge is opt-in while parity is being established.  It deliberately accepts the
same prepared batch as ``ObjectStateAnalyzer`` and reconstructs the existing Python
``AnalysisResult`` shape, including point/post snapshots consumed by Pass 3.
"""
from __future__ import annotations

import ctypes
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
from lachesis.core import lifetime_pb2


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
        library.lachesis_lifetime_solve_pb.argtypes = [
            ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
        library.lachesis_lifetime_solve_pb.restype = ctypes.c_void_p
        library.lachesis_lifetime_free_bytes.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        library.lachesis_lifetime_free_bytes.restype = None
        return library
    return None


def available() -> bool:
    return _load() is not None


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


def _meta_dict(meta) -> dict[str, Any]:
    kind = meta.WhichOneof("value")
    if kind == "param":
        return {"Param": {"position": meta.param.position,
                           "selectors": list(meta.param.selectors)}}
    if kind == "unknown_root":
        return {"UnknownRoot": {"root": meta.unknown_root.root}}
    if kind == "unknown_slot":
        return {"UnknownSlot": {"base": meta.unknown_slot.base,
                                 "selector": meta.unknown_slot.selector}}
    if kind == "allocation":
        return {"Allocation": {
            "kind": lifetime_pb2.Operation.Kind.Name(meta.allocation.kind).lower(),
            "generation": meta.allocation.generation,
            "site": meta.allocation.site,
            "target": {"root": meta.allocation.target.root,
                       "selectors": list(meta.allocation.target.selectors)},
        }}
    if kind == "phi":
        return {"Phi": {"tag": meta.phi.tag, "node": meta.phi.node,
                         "index": meta.phi.index}}
    raise ValueError("native snapshot object has no metadata")


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


_FACT_NAMES = ("ALLOCATED", "FREED", "NULL", "UNKNOWN")


def _snapshot_message(raw, memo: dict[str, tuple]) -> AbstractState:
    table = {item.id: _meta_dict(item.meta) for item in raw.objects}
    converted = {
        "objects": table,
        "env": [(item.root, item.object_id) for item in raw.env],
        "facts": [(item.object_id,
                   [_FACT_NAMES[value] for value in item.values])
                  for item in raw.facts],
        "slots": [((item.base, item.selector), item.object_id) for item in raw.slots],
        "trace": [],
        "freed_paths": [(
            {"root": item.path.root, "selectors": list(item.path.selectors)},
            item.object_id,
        ) for item in raw.freed_paths],
    }
    for effect in raw.trace:
        kind = effect.WhichOneof("value")
        if kind == "param":
            converted["trace"].append({"Param": {
                "kind": lifetime_pb2.Operation.Kind.Name(effect.param.kind),
                "position": effect.param.position,
                "selectors": list(effect.param.selectors),
            }})
        elif kind == "return_value":
            converted["trace"].append({"Return": {
                "position": effect.return_value.position,
                "selectors": list(effect.return_value.selectors),
            }})
    return _snapshot(converted, memo)


def _request(nodes, successors, operations, initial: AbstractState) -> bytes:
    request = lifetime_pb2.Request()
    request.nodes.extend(nodes)
    for node, targets in successors.items():
        entry = request.successors.add(node=node)
        entry.targets.extend(targets)
    for operation in operations:
        if operation.kind == OpKind.SUMMARY or not isinstance(operation.node, str):
            raise ValueError("native protobuf lifetime solver does not accept SUMMARY operations")
        encoded = request.operations.add(
            kind=getattr(lifetime_pb2.Operation, operation.kind.name),
            node=operation.node,
            site=str(operation.site if operation.site is not None else operation.node),
            is_null=operation.is_null,
            access=operation.access,
        )
        if operation.target is not None:
            encoded.target.root = operation.target.root
            encoded.target.selectors.extend(operation.target.selectors)
        if operation.source is not None:
            encoded.source.root = operation.source.root
            encoded.source.selectors.extend(operation.source.selectors)
        if operation.line is not None:
            encoded.line = int(operation.line)
            encoded.has_line = True
    for root, object_id in initial.env.items():
        parsed = object_id if isinstance(object_id, tuple) else None
        if parsed is not None and len(parsed) == 3 and parsed[0] == "param":
            parameter = request.parameters.add(root=root, position=int(parsed[1]))
            # Selectors are materialized from operations by Rust, just as in the
            # Python initializer; the parameter wire record only needs its root/index.
            del parameter
    return request.SerializeToString()


def solve_linear(nodes, successors, operations, initial: AbstractState):
    """Return a native ``(summary, AnalysisResult)`` or ``None`` when unsupported."""
    if any(not isinstance(node, str) for node in nodes):
        return None
    if any(operation.kind == OpKind.SUMMARY for operation in operations):
        return None
    if any(operation.kind == OpKind.SUMMARY or not isinstance(operation.node, str)
           for operation in operations):
        return None
    payload = _request(nodes, successors, operations, initial)
    library = _load()
    if library is None:
        return None
    output_length = ctypes.c_size_t()
    request_buffer = ctypes.create_string_buffer(payload)
    pointer = library.lachesis_lifetime_solve_pb(
        ctypes.cast(request_buffer, ctypes.c_void_p), len(payload),
        ctypes.byref(output_length))
    if not pointer or not output_length.value:
        return None
    try:
        result = lifetime_pb2.Result()
        result.ParseFromString(ctypes.string_at(pointer, output_length.value))
    finally:
        library.lachesis_lifetime_free_bytes(pointer, output_length.value)
    return _decode_result(result, nodes, operations)


def _decode_result(result, nodes, operations):
    memo: dict[str, tuple] = {}
    point_states = {
        item.node: tuple(_snapshot_message(snapshot, memo) for snapshot in item.states)
        for item in result.point_states
    }
    post_states = {
        item.node: tuple(_snapshot_message(snapshot, memo) for snapshot in item.states)
        for item in result.post_states
    }
    exit_states = tuple(_snapshot_message(snapshot, memo) for snapshot in result.exit_states)
    exit_state = (exit_states[0] if exit_states else
                  _snapshot_message(result.exit_state, memo))
    placed = {operation for operation in operations if operation.node in set(nodes)}
    unplaced = tuple(operation for operation in operations if operation not in placed)
    analysis = AnalysisResult(
        findings=set(),
        exit_states=exit_states or (exit_state,),
        unplaced=unplaced,
        transfers=int(result.transfers),
        widenings=int(result.widenings),
        capped=bool(result.capped),
        point_states=point_states,
        post_states=post_states,
    )
    return tuple(sorted({state.trace for state in analysis.exit_states}, key=repr)), analysis
