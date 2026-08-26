"""Optional bridge to the Rust object-lifetime batch solver.

The bridge is opt-in while parity is being established.  It deliberately accepts the
same prepared batch as ``ObjectStateAnalyzer`` and reconstructs the existing Python
``AnalysisResult`` shape, including point/post snapshots consumed by Pass 3.
"""
from __future__ import annotations

import ctypes
import mmap
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


def _call_sidecar(symbol: str, sidecar_path: str | os.PathLike[str], response_type,
                  operation: str):
    """Call a native sidecar ABI without materializing a second Python bytes copy.

    ``ACCESS_COPY`` gives ctypes a writable buffer view while keeping the pages backed by
    the immutable sidecar file (writes are never performed).  The mapping remains alive for
    the duration of the synchronous native call, so Rust can consume the framed protobuf
    directly and Python does not retain both ``read_bytes()`` and ``create_string_buffer``.
    """
    library = _load()
    if library is None:
        raise RuntimeError("native lifetime library is unavailable")
    function = getattr(library, symbol)
    function.argtypes = [ctypes.c_void_p, ctypes.c_size_t,
                         ctypes.POINTER(ctypes.c_size_t)]
    function.restype = ctypes.c_void_p
    path = os.fspath(sidecar_path)
    descriptor = os.open(path, os.O_RDONLY)
    try:
        length = os.fstat(descriptor).st_size
        if length <= 0:
            raise RuntimeError(f"{operation} received an empty sidecar")
        with mmap.mmap(descriptor, length, access=mmap.ACCESS_COPY) as mapped:
            view = ctypes.c_char.from_buffer(mapped)
            output_length = ctypes.c_size_t()
            pointer = function(ctypes.c_void_p(ctypes.addressof(view)), length,
                               ctypes.byref(output_length))
            del view
            if not pointer or not output_length.value:
                raise RuntimeError(f"{operation} returned no result")
            try:
                result = response_type()
                result.ParseFromString(ctypes.string_at(pointer, output_length.value))
            finally:
                library.lachesis_lifetime_free_bytes(pointer, output_length.value)
            return result
    finally:
        os.close(descriptor)


def prepare_pb_request(functions, request=None) -> bytes:
    """Encode raw function graph records into the native binary request."""

    request = request or lifetime_pb2.PrepareRequest()
    for item in functions:
        encoded_function = request.functions.add(id=str(item["id"]))
        for node in item.get("nodes", ()):
            encoded_node = encoded_function.nodes.add(
                id=str(node.get("id", "")), kind=str(node.get("kind", "")),
                label=str(node.get("label", "")),
            )
            for key, value in (node.get("properties") or {}).items():
                prop = encoded_node.properties.add(key=str(key))
                if isinstance(value, bool):
                    prop.boolean = value
                elif isinstance(value, int):
                    prop.integer = value
                elif isinstance(value, (str, bytes)):
                    prop.text = value.decode() if isinstance(value, bytes) else value
        for edge in item.get("edges", ()):
            encoded_edge = encoded_function.edges.add(
                kind=str(edge.get("kind", "")), source=str(edge.get("source", "")),
                target=str(edge.get("target", "")), role=str(edge.get("role", "")),
            )
            if isinstance(edge.get("position"), int):
                encoded_edge.position = edge["position"]
                encoded_edge.has_position = True
        encoded_function.parameters.extend(str(value) for value in item.get("parameters", ()))
        for call in item.get("calls", ()):
            encoded_call = encoded_function.calls.add(
                node=str(call.get("node", "")), callee=str(call.get("callee", "")),
                assigned=str(call.get("assigned", "") or ""),
                receiver=str(call.get("receiver", "") or ""),
                is_alloc=bool(call.get("is_alloc")), is_release=bool(call.get("is_release")),
                is_realloc=bool(call.get("is_realloc")), is_source=bool(call.get("is_source")),
                is_aggregate_copy=bool(call.get("is_aggregate_copy")),
            )
            if call.get("line") is not None:
                encoded_call.line = int(call["line"])
                encoded_call.has_line = True
            for argument in call.get("args", ()):
                encoded_call.arguments.add(
                    position=int(argument["pos"]),
                    node=str(argument.get("node") or argument.get("root") or ""),
                )
        for summary in item.get("summaries", ()):
            encoded_summary = encoded_function.summaries.add(callee=str(summary["callee"]))
            for alternative in summary.get("alternatives", ()):
                encoded_alternative = encoded_summary.alternatives.add()
                for effect in alternative:
                    encoded_effect = encoded_alternative.effects.add(
                        kind=getattr(lifetime_pb2.Operation, str(effect["kind"]).upper()),
                        position=int(effect.get("position", 0)),
                        is_return=bool(effect.get("is_return", False)),
                    )
                    encoded_effect.selectors.extend(str(value) for value in effect.get("selectors", ()))
    return request.SerializeToString()


def prepare_pb(functions) -> dict[str, lifetime_pb2.PreparedFunction]:
    """Prepare raw function graph records in Rust and return binary-projected CFGs.

    The input is intentionally a plain mapping only at this public adapter seam;
    it is encoded immediately and never enters the native implementation as JSON
    or Python objects. This is the migration boundary for moving CFG/operation
    preparation out of the Python lifetime pipeline.
    """
    payload = prepare_pb_request(functions)
    library = _load()
    if library is None:
        raise RuntimeError("native lifetime library is unavailable")
    prepare = library.lachesis_lifetime_prepare_pb
    prepare.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    prepare.restype = ctypes.c_void_p
    output_length = ctypes.c_size_t()
    request_buffer = ctypes.create_string_buffer(payload)
    pointer = prepare(ctypes.cast(request_buffer, ctypes.c_void_p), len(payload),
                      ctypes.byref(output_length))
    if not pointer or not output_length.value:
        raise RuntimeError("native lifetime preparation returned no result")
    try:
        result = lifetime_pb2.PrepareResult()
        result.ParseFromString(ctypes.string_at(pointer, output_length.value))
    finally:
        library.lachesis_lifetime_free_bytes(pointer, output_length.value)
    return {function.id: function for function in result.functions}


def solve_prepared_pb(prepared) -> dict[str, lifetime_pb2.PreparedFunctionResult]:
    """Solve a native ``PrepareResult`` without repeating graph preparation.

    The native response contains results only.  Prepared CFG metadata is already
    resident at this adapter boundary, so reattach it here instead of sending a
    second copy through the Rust response protobuf.
    """
    library = _load()
    if library is None:
        raise RuntimeError("native lifetime library is unavailable")
    solve = library.lachesis_lifetime_solve_prepared_pb
    solve.argtypes = [ctypes.c_void_p, ctypes.c_size_t,
                      ctypes.POINTER(ctypes.c_size_t)]
    solve.restype = ctypes.c_void_p
    prepared_by_id = None
    if isinstance(prepared, dict):
        prepared_by_id = prepared
        message = lifetime_pb2.PrepareResult()
        message.functions.extend(prepared.values())
        prepared = message
    elif hasattr(prepared, "functions"):
        prepared_by_id = {item.id: item for item in prepared.functions}
    payload = (prepared.SerializeToString()
               if hasattr(prepared, "SerializeToString") else bytes(prepared))
    output_length = ctypes.c_size_t()
    request_buffer = ctypes.create_string_buffer(payload)
    pointer = solve(ctypes.cast(request_buffer, ctypes.c_void_p), len(payload),
                    ctypes.byref(output_length))
    if not pointer or not output_length.value:
        raise RuntimeError("native prepared lifetime solve returned no result")
    try:
        result = lifetime_pb2.PrepareSolveResult()
        result.ParseFromString(ctypes.string_at(pointer, output_length.value))
    finally:
        library.lachesis_lifetime_free_bytes(pointer, output_length.value)
    if prepared_by_id is not None:
        for function in result.functions:
            original = prepared_by_id.get(function.id)
            if original is not None:
                function.prepared.CopyFrom(original)
    return {function.id: function for function in result.functions}


def prepare_graph_pb(sidecar_path: str | os.PathLike[str]) -> dict[str, lifetime_pb2.PreparedFunction]:
    """Prepare the complete Pass-1 binary substrate inside Rust.

    This is the whole-graph migration boundary.  The Python side reads only
    the immutable sidecar bytes and passes them through the ABI; it does not
    materialize nodes, edges, calls, or per-function records.
    """
    result = _call_sidecar("lachesis_lifetime_prepare_graph_pb", sidecar_path,
                           lifetime_pb2.PrepareResult,
                           "native whole-graph preparation")
    return {function.id: function for function in result.functions}


def translate_graph_pb(sidecar_path: str | os.PathLike[str]):
    """Return compact native call/return facts without prepared CFG expansion."""
    result = _call_sidecar("lachesis_lifetime_translate_graph_pb", sidecar_path,
                           lifetime_pb2.TranslationResult,
                           "native whole-graph translation")
    return {function.id: function for function in result.functions}


def plan_pass2_pb(functions, source_catalog):
    """Run native source discovery and coverage planning over translation facts.

    ``functions`` is the compact ``TranslationFunction`` mapping already loaded
    by Pass 2.  Only protobuf crosses this boundary; no Python F records or JSON
    graph representation is sent to Rust.
    """
    library = _load()
    if library is None:
        raise RuntimeError("native lifetime library is unavailable")
    request = lifetime_pb2.NativePlanRequest()
    request.translation.functions.extend(functions.values())
    for name, spec in source_catalog.items():
        entry = request.sources.add(name=str(name))
        if isinstance(spec, dict):
            entry.kind = str(spec.get("kind") or "external-input")
        else:
            entry.kind = "external-input"
    payload = request.SerializeToString()
    buffer = ctypes.create_string_buffer(payload)
    function = library.lachesis_lifetime_plan_pb
    function.argtypes = [ctypes.c_void_p, ctypes.c_size_t,
                         ctypes.POINTER(ctypes.c_size_t)]
    function.restype = ctypes.c_void_p
    output_length = ctypes.c_size_t()
    pointer = function(ctypes.cast(buffer, ctypes.c_void_p), len(payload),
                       ctypes.byref(output_length))
    if not pointer or not output_length.value:
        raise RuntimeError("native Pass-2 planning returned no result")
    try:
        result = lifetime_pb2.NativePlanResult()
        result.ParseFromString(ctypes.string_at(pointer, output_length.value))
    finally:
        library.lachesis_lifetime_free_bytes(pointer, output_length.value)
    return result


def prepare_graph_solve_pb(sidecar_path: str | os.PathLike[str]):
    """Run the complete binary-substrate preparation/solve path in Rust."""
    result = _call_sidecar("lachesis_lifetime_prepare_graph_solve_pb", sidecar_path,
                           lifetime_pb2.PrepareSolveResult,
                           "native whole-graph preparation/solve")
    return {function.id: function for function in result.functions}


def solve_selected_graph_pb(sidecar_path: str | os.PathLike[str], function_ids):
    """Prepare and solve only selected sidecar functions inside Rust."""
    library = _load()
    if library is None:
        raise RuntimeError("native lifetime library is unavailable")
    solve = library.lachesis_lifetime_prepare_graph_solve_selected_pb
    solve.argtypes = [ctypes.c_void_p, ctypes.c_size_t,
                      ctypes.c_void_p, ctypes.c_size_t,
                      ctypes.POINTER(ctypes.c_size_t)]
    solve.restype = ctypes.c_void_p
    selection = lifetime_pb2.PrepareRequest()
    for function_id in function_ids:
        selection.functions.add(id=str(function_id))
    selection_payload = selection.SerializeToString()
    selection_buffer = ctypes.create_string_buffer(selection_payload)
    path = os.fspath(sidecar_path)
    descriptor = os.open(path, os.O_RDONLY)
    try:
        length = os.fstat(descriptor).st_size
        if length <= 0:
            raise RuntimeError("selected lifetime solve received an empty sidecar")
        with mmap.mmap(descriptor, length, access=mmap.ACCESS_COPY) as mapped:
            view = ctypes.c_char.from_buffer(mapped)
            output_length = ctypes.c_size_t()
            pointer = solve(
                ctypes.c_void_p(ctypes.addressof(view)), length,
                ctypes.cast(selection_buffer, ctypes.c_void_p), len(selection_payload),
                ctypes.byref(output_length))
            del view
            if not pointer or not output_length.value:
                raise RuntimeError("native selected lifetime solve returned no result")
            try:
                result = lifetime_pb2.PrepareSolveResult()
                result.ParseFromString(ctypes.string_at(pointer, output_length.value))
            finally:
                library.lachesis_lifetime_free_bytes(pointer, output_length.value)
            return {function.id: function for function in result.functions}
    finally:
        os.close(descriptor)


def prepare_selected_graph_pb(sidecar_path: str | os.PathLike[str], function_ids):
    """Prepare selected functions without running the lifetime fixpoint."""
    library = _load()
    if library is None:
        raise RuntimeError("native lifetime library is unavailable")
    prepare = library.lachesis_lifetime_prepare_graph_selected_pb
    prepare.argtypes = [ctypes.c_void_p, ctypes.c_size_t,
                        ctypes.c_void_p, ctypes.c_size_t,
                        ctypes.POINTER(ctypes.c_size_t)]
    prepare.restype = ctypes.c_void_p
    selection = lifetime_pb2.PrepareRequest()
    for function_id in function_ids:
        selection.functions.add(id=str(function_id))
    selection_payload = selection.SerializeToString()
    selection_buffer = ctypes.create_string_buffer(selection_payload)
    path = os.fspath(sidecar_path)
    descriptor = os.open(path, os.O_RDONLY)
    try:
        length = os.fstat(descriptor).st_size
        if length <= 0:
            raise RuntimeError("selected lifetime preparation received an empty sidecar")
        with mmap.mmap(descriptor, length, access=mmap.ACCESS_COPY) as mapped:
            view = ctypes.c_char.from_buffer(mapped)
            output_length = ctypes.c_size_t()
            pointer = prepare(
                ctypes.c_void_p(ctypes.addressof(view)), length,
                ctypes.cast(selection_buffer, ctypes.c_void_p), len(selection_payload),
                ctypes.byref(output_length))
            del view
            if not pointer or not output_length.value:
                raise RuntimeError("native selected lifetime preparation returned no result")
            try:
                result = lifetime_pb2.PrepareResult()
                result.ParseFromString(ctypes.string_at(pointer, output_length.value))
            finally:
                library.lachesis_lifetime_free_bytes(pointer, output_length.value)
            return {function.id: function for function in result.functions}
    finally:
        os.close(descriptor)


def prepare_graph_solve_details_pb(sidecar_path: str | os.PathLike[str]):
    """Return native prepared CFGs and results without rebuilding them in Python."""
    prepared = prepare_graph_pb(sidecar_path)
    return solve_prepared_pb(prepared)


def _path_message(message):
    if not message or not message.root:
        return None
    return AccessPath(message.root, tuple(message.selectors))


def _operation_message(message, ordinal=0):
    kind = OpKind(lifetime_pb2.Operation.Kind.Name(message.kind).lower())
    alternatives = tuple(
        tuple(_operation_message(effect, index) for index, effect in enumerate(alternative.effects))
        for alternative in message.alternatives
    )
    return Operation(
        kind, message.node, target=_path_message(message.target),
        source=_path_message(message.source), site=message.site or message.node,
        line=message.line if message.has_line else None, is_null=message.is_null,
        ordinal=ordinal, alternatives=alternatives, access=message.access or "deref",
        generation=message.generation or None,
        fresh_generation=message.fresh_generation or None,
    )


def prepared_operations(prepared: lifetime_pb2.PreparedFunction) -> tuple[Operation, ...]:
    """Decode only the native operation stream for semantic adapters."""
    return tuple(_operation_message(operation, index)
                 for index, operation in enumerate(prepared.operations))


def decode_prepared_result(item: lifetime_pb2.PreparedFunctionResult):
    """Convert one native whole-graph result to the existing solver adapter shape."""
    prepared = item.prepared
    operations = prepared_operations(prepared)
    return _decode_result(item.result, prepared.nodes, operations)


def prepare_and_solve_pb(functions) -> dict[str, lifetime_pb2.Result]:
    """Run native preparation and lifetime solving in one binary call."""
    request = lifetime_pb2.PrepareRequest()
    # Reuse the exact marshaling contract without exposing an intermediate
    # Python prepared-operation representation to callers.
    # The helper accepts a request builder through the local implementation below
    # to keep the C ABI payload construction in one place.
    encoded = prepare_pb_request(functions, request)
    library = _load()
    if library is None:
        raise RuntimeError("native lifetime library is unavailable")
    solve = library.lachesis_lifetime_prepare_solve_pb
    solve.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    solve.restype = ctypes.c_void_p
    output_length = ctypes.c_size_t()
    request_buffer = ctypes.create_string_buffer(encoded)
    pointer = solve(ctypes.cast(request_buffer, ctypes.c_void_p), len(encoded),
                    ctypes.byref(output_length))
    if not pointer or not output_length.value:
        raise RuntimeError("native lifetime preparation/solve returned no result")
    try:
        result = lifetime_pb2.PrepareSolveResult()
        result.ParseFromString(ctypes.string_at(pointer, output_length.value))
    finally:
        library.lachesis_lifetime_free_bytes(pointer, output_length.value)
    return {function.id: function.result for function in result.functions}


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
    def encode(parent, operation):
        if not isinstance(operation.node, str):
            raise ValueError("native protobuf lifetime solver requires string operation nodes")
        encoded = parent.add(
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
        for alternative in operation.alternatives:
            encoded_alternative = encoded.alternatives.add()
            for effect in alternative:
                encode(encoded_alternative.effects, effect)
    for operation in operations:
        encode(request.operations, operation)
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
    if any(not isinstance(operation.node, str) for operation in operations):
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
        findings={Finding(
            item.pattern, item.line if item.has_line else None,
            AccessPath(item.path.root, tuple(item.path.selectors)), item.node,
        ) for item in result.findings if item.path is not None},
        exit_states=exit_states or (exit_state,),
        unplaced=unplaced,
        transfers=int(result.transfers),
        widenings=int(result.widenings),
        capped=bool(result.capped),
        point_states=point_states,
        post_states=post_states,
    )
    return tuple(sorted({state.trace for state in analysis.exit_states}, key=repr)), analysis
