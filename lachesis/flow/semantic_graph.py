"""Frozen v1 semantic flow graph and matcher.

This module is deliberately independent of the legacy linear skeleton renderer.  Claus emits
facts into :class:`SkeletonGraph`; the matcher derives findings by graph reachability.  In
particular, a graph edge is never an implicit ordering between sibling branch arms.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable


class EventKind(str, Enum):
    ALLOC_ATTEMPT = "ALLOC_ATTEMPT"
    ORIGIN = "ORIGIN"
    REALLOC_ATTEMPT = "REALLOC_ATTEMPT"
    REALLOC_FAILED = "REALLOC_FAILED"
    INVALIDATE = "INVALIDATE"
    RELEASE = "RELEASE"
    READ_STORAGE = "READ_STORAGE"
    WRITE_STORAGE = "WRITE_STORAGE"
    PASS_VALUE = "PASS_VALUE"
    COMPARE_VALUE = "COMPARE_VALUE"
    RETURN_VALUE = "RETURN_VALUE"
    DERIVE = "DERIVE"
    WRITE_STORAGE_NULL = "WRITE_STORAGE_NULL"
    LOST_FROM_SLOT = "LOST_FROM_SLOT"
    BRANCH = "branch"
    MERGE = "merge"
    LOOP = "loop"
    SEAM_ENTER = "seam_enter"
    SEAM_EXIT = "seam_exit"
    RETURN = "return"


@dataclass(frozen=True)
class PatternSpec:
    """Declarative matcher substrate for one frozen-v1 lead shape."""

    name: str
    trigger_kinds: tuple[EventKind, ...]
    requires_same_generation: bool = True
    path_specific: bool = True


FROZEN_PATTERNS = {
    "uaf.deref": PatternSpec("uaf.deref", (EventKind.READ_STORAGE, EventKind.WRITE_STORAGE)),
    "use.dangling": PatternSpec("use.dangling", (EventKind.PASS_VALUE,
                                                     EventKind.COMPARE_VALUE,
                                                     EventKind.RETURN_VALUE)),
    "double-free": PatternSpec("double-free", (EventKind.RELEASE,)),
    "null-deref": PatternSpec("null-deref", (EventKind.READ_STORAGE, EventKind.WRITE_STORAGE)),
    "leak": PatternSpec("leak", (EventKind.ORIGIN,)),
}


@dataclass(frozen=True, order=True)
class ObjRef:
    """Storage/pointee identity.  ``generation`` may be symbolic inside a fragment."""

    base: str
    path: tuple[str, ...] = ()
    generation: Any = "G0"

    def child(self, selector: str) -> "ObjRef":
        return ObjRef(self.base, self.path + (selector,), self.generation)

    def render(self) -> str:
        path = "".join(self.path)
        return f"{self.base}{path}#{self.generation}"


@dataclass(frozen=True)
class GuardProof:
    kind: str
    value: str


@dataclass(frozen=True)
class Event:
    kind: EventKind | str
    obj: ObjRef | None = None
    base: ObjRef | None = None
    path: str | None = None
    value: ObjRef | None = None
    slot: ObjRef | None = None
    line: int | None = None
    facts: dict[str, Any] = field(default_factory=dict)
    proofs: tuple[GuardProof, ...] = ()

    @classmethod
    def origin(cls, obj: ObjRef, line: int | None = None) -> "Event":
        return cls(EventKind.ORIGIN, obj=obj, line=line)

    @classmethod
    def alloc_attempt(cls, *, result: ObjRef | None = None, line: int | None = None) -> "Event":
        return cls(EventKind.ALLOC_ATTEMPT, value=result, line=line)

    @classmethod
    def realloc_attempt(cls, obj: ObjRef, line: int | None = None) -> "Event":
        return cls(EventKind.REALLOC_ATTEMPT, obj=obj, line=line)

    @classmethod
    def realloc_failed(cls, obj: ObjRef, slot: ObjRef | None = None,
                       line: int | None = None) -> "Event":
        return cls(EventKind.REALLOC_FAILED, obj=obj, slot=slot, line=line)

    @classmethod
    def pass_value(cls, obj: ObjRef, line: int | None = None) -> "Event":
        return cls(EventKind.PASS_VALUE, obj=obj, line=line)

    @classmethod
    def release(cls, obj: ObjRef, line: int | None = None) -> "Event":
        return cls(EventKind.RELEASE, obj=obj, line=line)

    @classmethod
    def read(cls, base: ObjRef, path: str = "*", line: int | None = None) -> "Event":
        return cls(EventKind.READ_STORAGE, base=base, path=path, obj=base, line=line)

    @classmethod
    def write(cls, base: ObjRef, path: str = "*", line: int | None = None,
              value: ObjRef | None = None) -> "Event":
        return cls(EventKind.WRITE_STORAGE, base=base, path=path, obj=base,
                   value=value, line=line)


@dataclass(frozen=True)
class Edge:
    target: str
    kind: str = "normal"
    guard: tuple[GuardProof, ...] = ()
    return_to: str | None = None
    binding: tuple[tuple[ObjRef, ObjRef], ...] = ()


@dataclass
class GraphNode:
    id: str
    event: Event | None = None
    fragment: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class Fragment:
    name: str
    entry: str
    exits: set[str] = field(default_factory=set)
    params: tuple[str, ...] = ()


@dataclass
class SkeletonGraph:
    nodes: dict[str, GraphNode] = field(default_factory=dict)
    edges: dict[str, list[Edge]] = field(default_factory=dict)
    fragments: dict[str, Fragment] = field(default_factory=dict)
    source_reachable: set[str] = field(default_factory=set)

    def add_node(self, node_id: str, event: Event | None = None, *, fragment: str | None = None,
                 **metadata: Any) -> GraphNode:
        if node_id in self.nodes:
            raise ValueError(f"duplicate skeleton node: {node_id}")
        node = GraphNode(node_id, event, fragment, metadata)
        self.nodes[node_id] = node
        self.edges.setdefault(node_id, [])
        return node

    def add_edge(self, source: str, target: str, *, kind: str = "normal",
                 guard: Iterable[GuardProof] = (), return_to: str | None = None,
                 binding: Iterable[tuple[ObjRef, ObjRef]] = ()) -> None:
        if source not in self.nodes or target not in self.nodes:
            raise KeyError(f"edge endpoint not in graph: {source}->{target}")
        self.edges.setdefault(source, []).append(
            Edge(target, kind, tuple(guard), return_to, tuple(binding)))

    def add_fragment(self, name: str, entry: str, exits: Iterable[str] = (),
                     params: Iterable[str] = ()) -> Fragment:
        if name in self.fragments:
            raise ValueError(f"duplicate fragment: {name}")
        f = Fragment(name, entry, set(exits), tuple(params))
        self.fragments[name] = f
        return f

    def validate(self) -> None:
        for name, f in self.fragments.items():
            if f.entry not in self.nodes:
                raise ValueError(f"fragment {name} has missing entry {f.entry}")
            if not f.exits:
                raise ValueError(f"fragment {name} has no exit")
            if not f.exits <= self.nodes.keys():
                raise ValueError(f"fragment {name} has missing exit")
        for src, edges in self.edges.items():
            if src not in self.nodes or any(e.target not in self.nodes for e in edges):
                raise ValueError("graph contains an edge to a missing node")

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": {n: {"event": _event_dict(x.event), "fragment": x.fragment,
                           "metadata": x.metadata} for n, x in self.nodes.items()},
            "edges": {n: [{"target": e.target, "kind": e.kind,
                           "guard": [{"kind": p.kind, "value": p.value} for p in e.guard],
                           "return_to": e.return_to,
                           "binding": [[a.render(), b.render()] for a, b in e.binding]}
                          for e in es] for n, es in self.edges.items()},
            "fragments": {n: {"entry": f.entry, "exits": sorted(f.exits), "params": f.params}
                          for n, f in self.fragments.items()},
            "source_reachable": sorted(self.source_reachable),
        }


def _event_dict(event: Event | None) -> dict[str, Any] | None:
    if event is None:
        return None
    kind = event.kind.value if isinstance(event.kind, EventKind) else event.kind
    return {"kind": kind, "obj": event.obj.render() if event.obj else None,
            "base": event.base.render() if event.base else None,
            "path": event.path,
            "value": event.value.render() if event.value else None,
            "slot": event.slot.render() if event.slot else None, "line": event.line,
            "facts": event.facts, "proofs": [{"kind": p.kind, "value": p.value} for p in event.proofs]}


@dataclass(frozen=True)
class _State:
    node: str
    released: frozenset[tuple[ObjRef, str]] = frozenset()
    origins: frozenset[ObjRef] = frozenset()
    stack: tuple[str, ...] = ()
    guards: frozenset[GuardProof] = frozenset()
    bindings: tuple[tuple[ObjRef, ObjRef], ...] = ()
    nulls: frozenset[ObjRef] = frozenset()
    escaped: frozenset[ObjRef] = frozenset()


def match_graph(graph: SkeletonGraph, *, patterns: Iterable[str] | None = None) -> list[dict[str, Any]]:
    """Find facts on compatible pushdown paths.

    ``seam_enter`` edges push their explicit continuation; ``seam_exit`` edges pop it.  This
    means a shared fragment cannot return to a different caller.  The released set is keyed by
    the exact object and generation, so freeing a storage object never frees its pointee.
    """
    wanted = set(FROZEN_PATTERNS if patterns is None else patterns)
    starts = sorted(graph.source_reachable) if graph.source_reachable else [f.entry for f in graph.fragments.values()]
    starts = starts or list(graph.nodes)
    queue = deque(_State(s) for s in starts)
    seen: set[_State] = set()
    hits: dict[tuple[str, str, str | None, int | None], dict[str, Any]] = {}
    exits = {x for f in graph.fragments.values() for x in f.exits}

    while queue:
        state = queue.popleft()
        if state in seen:
            continue
        seen.add(state)
        node = graph.nodes[state.node]
        event = node.event
        released = set(state.released)
        origins = set(state.origins)
        nulls = set(state.nulls)
        bindings = dict(state.bindings)
        escaped = set(state.escaped)

        def canonical(value: ObjRef | None) -> ObjRef | None:
            seen = set()
            while value in bindings and value not in seen:
                seen.add(value)
                value = bindings[value]
            return value

        def equivalent(left: ObjRef | None, right: ObjRef | None) -> bool:
            """Treat seam/derive bindings as an alias relation for conclusions."""
            if left is None or right is None:
                return left == right
            frontier = [left]
            visited = set()
            reverse = {}
            for source, target in bindings.items():
                reverse.setdefault(target, set()).add(source)
            while frontier:
                current = frontier.pop()
                if current in visited:
                    continue
                visited.add(current)
                if current == right:
                    return True
                if current in bindings:
                    frontier.append(bindings[current])
                frontier.extend(reverse.get(current, ()))
            return False

        if event:
            raw_obj = event.obj
            raw_base = event.base
            obj = canonical(event.obj)
            base = canonical(event.base)
            if event.kind == EventKind.DERIVE and event.obj and event.value:
                bindings[event.obj] = canonical(event.value) or event.value
                obj = canonical(event.obj)
            if event.kind == EventKind.WRITE_STORAGE_NULL and obj:
                # NULL is a value in this storage slot, not a property of the
                # heap object reached through another alias.
                nulls.add(raw_obj)
                obj = None
            if event.kind == EventKind.RELEASE and raw_obj in nulls:
                obj = None
            if event.kind == EventKind.RELEASE and obj:
                prior_sites = {site for released_obj, site in released if released_obj == obj}
                if "double-free" in wanted and any(site != node.id for site in prior_sites):
                    _record(hits, "double-free", obj, node)
                released = {(released_obj, site) for released_obj, site in released
                            if released_obj != obj} | {(obj, node.id)}
            elif event.kind == EventKind.INVALIDATE and obj:
                released = {(released_obj, site) for released_obj, site in released
                            if released_obj != obj} | {(obj, node.id)}
            elif event.kind in (EventKind.READ_STORAGE, EventKind.WRITE_STORAGE) and base:
                live_proven = GuardProof("LIVE", base.render()) in state.guards
                if "uaf.deref" in wanted and any(released_obj == base for released_obj, _ in released) and not live_proven:
                    _record(hits, "uaf.deref", base, node)
                if "null-deref" in wanted and raw_base in nulls:
                    _record(hits, "null-deref", base, node)
            elif event.kind in (EventKind.PASS_VALUE, EventKind.COMPARE_VALUE, EventKind.RETURN_VALUE) and obj:
                if "use.dangling" in wanted and any(released_obj == obj for released_obj, _ in released):
                    _record(hits, "use.dangling", obj, node)
                if event.kind == EventKind.RETURN_VALUE:
                    escaped.add(obj)
            elif event.kind == EventKind.ORIGIN and obj:
                origins.add(obj)
                released = {(released_obj, site) for released_obj, site in released
                            if released_obj != obj}
                nulls.discard(raw_obj)

        if "leak" in wanted and node.id in exits and not state.stack:
            for obj in origins:
                live_obj = canonical(obj)
                released_live = any(equivalent(released_obj, live_obj)
                                     for released_obj, _ in released)
                escaped_live = any(equivalent(escaped_obj, live_obj) for escaped_obj in escaped)
                if not released_live and not escaped_live:
                    _record(hits, "leak", live_obj or obj, node)

        for edge in graph.edges.get(state.node, ()):
            stack = state.stack
            next_bindings = dict(bindings)
            next_bindings.update(edge.binding)
            def rebase(value):
                seen_bindings = set()
                while value in next_bindings and value not in seen_bindings:
                    seen_bindings.add(value)
                    value = next_bindings[value]
                return value
            next_origins = {rebased for origin in origins
                            if (rebased := rebase(origin)) is not None}
            next_released = {(rebased, site) for released_obj, site in released
                             if (rebased := rebase(released_obj)) is not None}
            # Local DERIVE aliases must not rebase NULL slot facts: ``q = p``
            # followed by ``p = NULL`` leaves q's value unchanged.  A seam
            # binding does transfer a formal's value/nullness to its actual.
            next_nulls = set(nulls)
            for formal, actual in edge.binding:
                if formal in next_nulls:
                    next_nulls.add(actual)
            next_escaped = {rebased for escaped_obj in escaped
                            if (rebased := rebase(escaped_obj)) is not None}
            known = set(next_origins) | set(next_nulls) | {obj for obj, _ in next_released}
            for proof in edge.guard:
                guarded_obj = None
                if "#" in proof.value:
                    stem = proof.value.rsplit("#", 1)[0]
                    # Null tests constrain the current variable binding, not a stale
                    # allocation incarnation. Prefer active origins/nulls and the
                    # highest numeric generation when the source-level proof says `p`.
                    candidates = [candidate for candidate in (next_origins | next_nulls)
                                  if candidate.render().rsplit("#", 1)[0] == stem]
                    if not candidates:
                        candidates = [candidate for candidate in known
                                      if candidate.render() == proof.value]
                    if candidates:
                        guarded_obj = max(candidates, key=lambda candidate: repr(candidate.generation))
                if guarded_obj is None:
                    continue
                if proof.kind == "ISNULL":
                    next_origins.discard(guarded_obj)
                    next_nulls.add(guarded_obj)
                elif proof.kind == "NONNULL":
                    next_nulls.discard(guarded_obj)
            if edge.kind == "call":
                if edge.return_to is None:
                    raise ValueError(f"call edge {state.node}->{edge.target} lacks return_to")
                stack = stack + (edge.return_to,)
            elif edge.kind == "return":
                if not stack:
                    continue
                if edge.target != stack[-1]:
                    continue
                stack = stack[:-1]
                # The callee's return value is now a caller-local receiver;
                # it is no longer an exit escape for the caller's leak query.
                for _formal, receiver in edge.binding:
                    next_escaped.discard(rebase(receiver))
            queue.append(_State(edge.target, frozenset(next_released), frozenset(next_origins), stack,
                                state.guards | frozenset(edge.guard),
                                tuple(sorted(next_bindings.items(), key=repr)), frozenset(next_nulls),
                                frozenset(next_escaped)))
    return sorted(hits.values(), key=lambda x: (x["pattern"], x.get("line") or -1))


def _record(hits: dict, pattern: str, obj: ObjRef, node: GraphNode) -> None:
    key = (pattern, obj.render(), node.id, node.event.line if node.event else None)
    reachable = bool(node.metadata.get("source_reachable", False))
    influenced = bool(node.metadata.get("source_influenced", False))
    hits.setdefault(key, {"pattern": pattern, "object": obj.render(), "node": node.id,
                          "entry": node.fragment, "line": node.event.line if node.event else None,
                          "source_reachable": reachable,
                          "source_influenced": influenced,
                          "tier": 1 if reachable and influenced else 2 if reachable else None})
