"""Frontend-only decoding of the native Pass-3 query sidecar.

The analysis engine never imports this module.  Rust owns Pass-3 generation and
matching; this adapter exists only for explicit SDK/MCP graph-report queries
that request a Python object view of the binary protobuf sidecar.
"""
from __future__ import annotations

from pathlib import Path

from lachesis.core import lifetime_pb2


def _function_language(function, fallback: str) -> str:
    explicit = getattr(function, "language", "")
    if explicit:
        return explicit
    identifier = getattr(function, "id", "")
    if ":cpython-ast:" in identifier or ":python:" in identifier:
        return "python"
    if ":typescript-compiler-api:" in identifier or ":typescript:" in identifier:
        return "typescript"
    if ":javascript:" in identifier:
        return "javascript"
    if ":clang-c:" in identifier or ":clang-cpp:" in identifier:
        return "c"
    return fallback


def _decode(result, lang="mixed"):
    from lachesis.flow.semantic_graph import Event, EventKind, GuardProof, ObjRef, SkeletonGraph

    graph = SkeletonGraph(language=lang)
    for function in result.functions:
        if not function.nodes:
            continue
        node_ids = {node.id for node in function.nodes}
        function_language = _function_language(function, lang)
        for node in function.nodes:
            event = None
            if node.event_kind:
                kind = getattr(EventKind, node.event_kind, node.event_kind)
                obj = (ObjRef(node.object_root, tuple(node.object_selectors),
                              node.generation or "g0")
                       if node.object_root else None)
                event = Event(kind, obj=obj, base=obj,
                              path="*" if obj is not None else None,
                              line=node.line if node.has_line else None)
            graph.add_node(node.id, event, fragment=function.id,
                           owner_function_id=function.id, native_anchor=node.anchor,
                           language=function_language)
        for edge in function.edges:
            if edge.source in node_ids and edge.target in node_ids:
                guards = tuple(GuardProof(item.kind, item.value) for item in edge.guards)
                bindings = []
                for binding in edge.bindings:
                    for item in binding.formal_to_actual:
                        formal, separator, actual = item.partition("\x1f")
                        if separator and formal and actual:
                            bindings.append((ObjRef(formal, (), "g0"),
                                             ObjRef(actual, (), "g0")))
                graph.add_edge(
                    edge.source, edge.target, kind=edge.seam_kind or edge.kind or "normal",
                    guard=guards, return_to=edge.return_to or None,
                    binding=bindings,
                    provenance=((edge.provenance, edge.callee),) if edge.provenance else (),
                )
        exits = [node for node in function.exits if node in node_ids]
        graph.add_fragment(
            function.id,
            function.entry if function.entry in node_ids else function.nodes[0].id,
            exits=exits or [function.nodes[-1].id],
        )
    # Seam edges are emitted outside function-local edge lists because their
    # endpoints belong to different fragments. They remain binary in the
    # engine; this reconstruction exists only for explicit query consumers.
    for edge in result.seams:
        if edge.source not in graph.nodes or edge.target not in graph.nodes:
            continue
        guards = tuple(GuardProof(item.kind, item.value) for item in edge.guards)
        bindings = []
        for binding in edge.bindings:
            for item in binding.formal_to_actual:
                formal, separator, actual = item.partition("\x1f")
                if separator and formal and actual:
                    bindings.append((ObjRef(formal, (), "g0"), ObjRef(actual, (), "g0")))
        graph.add_edge(
            edge.source, edge.target, kind=edge.seam_kind or edge.kind or "seam",
            guard=guards, return_to=edge.return_to or None, binding=bindings,
            provenance=((edge.provenance, edge.callee),) if edge.provenance else (),
        )
    if not result.complete:
        graph.coverage["converged"] = False
    return graph


def load_semantic_sidecar(path, lang="mixed"):
    """Decode a full native sidecar for an explicit frontend query."""
    try:
        result = lifetime_pb2.NativeSemanticResult()
        result.ParseFromString(Path(path).read_bytes())
    except (OSError, ValueError) as error:
        raise RuntimeError("native Pass-3 semantic sidecar is invalid") from error
    return _decode(result, lang)


def load_event_sidecar(path, lang="mixed"):
    """Decode only event nodes for an explicit frontend query."""
    from lachesis.flow.semantic_graph import Event, EventKind, ObjRef, SkeletonGraph

    try:
        result = lifetime_pb2.NativeSemanticResult()
        result.ParseFromString(Path(f"{path}.events.pb").read_bytes())
    except (OSError, ValueError) as error:
        raise RuntimeError("native Pass-3 event sidecar is invalid") from error
    graph = SkeletonGraph(language=lang)
    for function in result.functions:
        for node in function.nodes:
            if not node.event_kind:
                continue
            kind = getattr(EventKind, node.event_kind, node.event_kind)
            obj = (ObjRef(node.object_root, tuple(node.object_selectors),
                          node.generation or "g0")
                   if node.object_root else None)
            graph.add_node(
                node.id,
                Event(kind, obj=obj, base=obj, path="*" if obj else None,
                      line=node.line if node.has_line else None),
                fragment=function.id,
                owner_function_id=function.id,
                native_anchor=node.anchor,
            )
    if not result.complete:
        graph.coverage["converged"] = False
    return graph
