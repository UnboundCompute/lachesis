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
    SINK = "sink"


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
    "use-after-return": PatternSpec("use-after-return", (EventKind.RETURN_VALUE,)),
    "unchecked-return-deref": PatternSpec("unchecked-return-deref",
                                           (EventKind.READ_STORAGE, EventKind.WRITE_STORAGE)),
    "double-free": PatternSpec("double-free", (EventKind.RELEASE,)),
    "null-deref": PatternSpec("null-deref", (EventKind.READ_STORAGE, EventKind.WRITE_STORAGE)),
    "mem.lifetime.realloc-failure-leak": PatternSpec(
        "mem.lifetime.realloc-failure-leak", (EventKind.REALLOC_FAILED,)),
    "leak": PatternSpec("leak", (EventKind.ORIGIN,)),
}


_LOOP_WIDEN_LIMIT = 32


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

    @classmethod
    def write_null(cls, slot: ObjRef, line: int | None = None) -> "Event":
        """Store NULL in a pointer slot.

        NULL is a value of WRITE_STORAGE, not a separate event kind in the frozen
        schema.  ``storage_slot`` keeps the write from being mistaken for a
        dereference of the slot itself.
        """
        return cls(EventKind.WRITE_STORAGE, obj=slot, base=slot, line=line,
                   facts={"null": True, "storage_slot": True})


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
    coverage: dict[str, Any] = field(default_factory=dict)

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
            "coverage": self.coverage,
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


def _normalized_path(path: tuple[str, ...]) -> tuple[str, ...]:
    """Normalize address/dereference selectors at an identity boundary."""
    result: list[str] = []
    for selector in path:
        if result and ((result[-1], selector) in {("&", "*"), ("*", "&")}):
            result.pop()
        else:
            result.append(selector)
    return tuple(result)


@dataclass(frozen=True)
class _State:
    node: str
    released: frozenset[tuple[ObjRef, str]] = frozenset()
    origins: frozenset[ObjRef] = frozenset()
    stack: tuple[str, ...] = ()
    bindings: tuple[tuple[ObjRef, ObjRef], ...] = ()
    nulls: frozenset[ObjRef] = frozenset()
    escaped: frozenset[ObjRef] = frozenset()
    sink_allocs: tuple[tuple[str, str], ...] = ()
    nullable: frozenset[ObjRef] = frozenset()
    realloc_lost: frozenset[ObjRef] = frozenset()


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
    predecessors: dict[_State, _State | None] = {
        _State(s): None for s in starts
    }
    superseded: set[_State] = set()
    loop_buckets: dict[tuple[str, tuple[str, ...]], list[_State]] = {}

    def join_loop_states(left: _State, right: _State) -> _State:
        left_bindings, right_bindings = dict(left.bindings), dict(right.bindings)
        merged_bindings = dict(left_bindings)
        for key, value in right_bindings.items():
            merged_bindings.setdefault(key, value)
        return _State(
            right.node,
            left.released | right.released,
            left.origins | right.origins,
            right.stack,
            tuple(sorted(merged_bindings.items(), key=repr)),
            left.nulls | right.nulls,
            left.escaped | right.escaped,
            tuple(sorted(set(left.sink_allocs) | set(right.sink_allocs))),
            left.nullable | right.nullable,
            left.realloc_lost | right.realloc_lost,
        )
    seen: set[_State] = set()
    hits: dict[tuple[str, str, str | None, int | None], dict[str, Any]] = {}
    exits = {x for f in graph.fragments.values() for x in f.exits}

    while queue:
        state = queue.popleft()
        if state in superseded:
            continue
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
        sink_allocs = dict(state.sink_allocs)
        nullable = set(state.nullable)
        realloc_lost = set(state.realloc_lost)

        def canonical(value: ObjRef | None) -> ObjRef | None:
            seen = set()
            used_bindings = set()
            while value is not None and value not in seen:
                seen.add(value)
                direct = bindings.get(value)
                if direct is not None and value not in used_bindings:
                    used_bindings.add(value)
                    old_base = value.base
                    value = ObjRef(direct.base, _normalized_path(direct.path), direct.generation)
                    if direct.base == old_base:
                        break
                    continue
                # A binding for p also binds p&, p**, and field paths rooted at
                # p. Compose the suffix instead of treating those as unrelated
                # storage names. This is the address-of/multi-deref algebra used
                # by the frozen access-path representation.
                candidates = [source for source in bindings
                              if source.base == value.base
                              and source not in used_bindings
                              and value.path[:len(source.path)] == source.path]
                if not candidates:
                    break
                source = max(candidates, key=lambda item: len(item.path))
                used_bindings.add(source)
                target = bindings[source]
                suffix = value.path[len(source.path):]
                old_base = value.base
                value = ObjRef(target.base,
                               _normalized_path(target.path + suffix),
                               target.generation)
                if target.base == old_base:
                    break
            if value is None:
                return None
            return ObjRef(value.base, _normalized_path(value.path), value.generation)

        def equivalent(left: ObjRef | None, right: ObjRef | None) -> bool:
            """Compare canonical representatives after seam/derive composition."""
            return canonical(left) == canonical(right)

        def witness() -> tuple[str, ...]:
            path = []
            current: _State | None = state
            while current is not None:
                path.append(current.node)
                current = predecessors.get(current)
            return tuple(reversed(path))

        if event:
            raw_obj = event.obj
            raw_base = event.base
            obj = canonical(event.obj)
            base = canonical(event.base)
            if event.kind == EventKind.SINK:
                from .patterns import evaluate_all, substrate
                family = event.facts.get("family")
                if family:
                    fact = substrate(
                        family,
                        event.facts.get("tainted", False),
                        event.facts.get("bound"),
                        event.facts.get("guarded", False),
                        event.facts.get("guard_status"),
                    )
                    for pattern in evaluate_all(family, fact):
                        if patterns is None or pattern in wanted:
                            sink_obj = obj or ObjRef(
                                event.facts.get("callee", "sink"), generation="g0")
                            _record(hits, pattern, sink_obj, node, witness(), family)
                    control = set(event.facts.get("control") or ())
                    if (patterns is None or "mem.copy.in-loop-unbounded" in wanted):
                        if (family in {"buffer-write", "buffer-size"}
                                and control & {"for", "while", "do"}
                                and not event.facts.get("guarded", False)):
                            sink_obj = obj or ObjRef(
                                event.facts.get("callee", "sink"), generation="g0")
                            _record(hits, "mem.copy.in-loop-unbounded", sink_obj,
                                    node, witness(), family)
                    dst = event.facts.get("dst")
                    size_expr = event.facts.get("size_expr")
                    if dst and size_expr is not None:
                        if family == "alloc-size":
                            sink_allocs[str(dst)] = str(size_expr)
                        elif (family in {"buffer-write", "buffer-size"}
                              and str(dst) in sink_allocs
                              and sink_allocs[str(dst)] != str(size_expr)
                              and (patterns is None
                                   or "mem.alloc-copy.size-mismatch" in wanted)):
                            sink_obj = obj or ObjRef(
                                event.facts.get("callee", "sink"), generation="g0")
                            _record(hits, "mem.alloc-copy.size-mismatch", sink_obj,
                                    node, witness(), family)
                # Sink facts are observations, not lifetime transitions; the
                # remaining lifecycle branches below intentionally do not match
                # EventKind.SINK.
            if event is not None and event.kind == EventKind.DERIVE and event.obj and event.value:
                bindings[event.obj] = canonical(event.value) or event.value
                obj = canonical(event.obj)
            is_null_write = (event.kind == EventKind.WRITE_STORAGE_NULL or
                             (event.kind == EventKind.WRITE_STORAGE and event.facts.get("null")))
            if is_null_write and raw_obj:
                # NULL is a value in this storage slot, not a property of the
                # heap object reached through another alias.
                nulls.add(raw_obj)
                obj = None
            if event.kind == EventKind.RELEASE and raw_obj in nulls:
                obj = None
            if event.kind == EventKind.RELEASE and obj:
                prior_sites = {site for released_obj, site in released if released_obj == obj}
                if "double-free" in wanted and any(site != node.id for site in prior_sites):
                    _record(hits, "double-free", obj, node, witness())
                released = {(released_obj, site) for released_obj, site in released
                            if released_obj != obj} | {(obj, node.id)}
            elif event.kind == EventKind.INVALIDATE and obj:
                released = {(released_obj, site) for released_obj, site in released
                            if released_obj != obj} | {(obj, node.id)}
            elif event.kind in (EventKind.READ_STORAGE, EventKind.WRITE_STORAGE) and base and not is_null_write:
                if "uaf.deref" in wanted and any(released_obj == base for released_obj, _ in released):
                    _record(hits, "uaf.deref", base, node, witness())
                if "null-deref" in wanted and raw_base in nulls:
                    _record(hits, "null-deref", base, node, witness())
                if "unchecked-return-deref" in wanted and base in nullable:
                    _record(hits, "unchecked-return-deref", base, node, witness())
            elif event.kind in (EventKind.PASS_VALUE, EventKind.COMPARE_VALUE, EventKind.RETURN_VALUE) and obj:
                if "use.dangling" in wanted and any(released_obj == obj for released_obj, _ in released):
                    _record(hits, "use.dangling", obj, node, witness())
                if (event.kind == EventKind.RETURN_VALUE
                        and event.facts.get("stack_local")
                        and "use-after-return" in wanted):
                    _record(hits, "use-after-return", obj, node, witness())
                if event.kind == EventKind.RETURN_VALUE:
                    escaped.add(obj)
            elif event.kind == EventKind.ORIGIN and obj:
                origins.add(obj)
                released = {(released_obj, site) for released_obj, site in released
                            if released_obj != obj}
                nulls.discard(raw_obj)
                if event.facts.get("return_may_null"):
                    nullable.add(obj)
                else:
                    nullable.discard(obj)
            elif event.kind == EventKind.LOST_FROM_SLOT and raw_obj:
                # Losing the owning slot does not free the object.  A DERIVE
                # alias remains a live root; without one, the origin is leaked.
                nulls.add(raw_obj)
                realloc_lost.add(obj or raw_obj)

        if "mem.lifetime.realloc-failure-leak" in wanted and node.id in exits:
            for lost_obj in realloc_lost:
                live_obj = canonical(lost_obj)
                released_live = any(equivalent(released_obj, live_obj)
                                    for released_obj, _ in released)
                escaped_live = any(equivalent(escaped_obj, live_obj)
                                   for escaped_obj in escaped)
                alias_live = any(alias != live_obj and equivalent(alias, live_obj)
                                 for alias in bindings)
                if not released_live and not escaped_live and not alias_live:
                    _record(hits, "mem.lifetime.realloc-failure-leak",
                            live_obj or lost_obj, node, witness())

        if "leak" in wanted and node.id in exits and not state.stack:
            for obj in origins:
                live_obj = canonical(obj)
                released_live = any(equivalent(released_obj, live_obj)
                                     for released_obj, _ in released)
                escaped_live = any(equivalent(escaped_obj, live_obj) for escaped_obj in escaped)
                alias_live = any(alias != live_obj and equivalent(alias, live_obj)
                                 for alias in bindings)
                if not released_live and not escaped_live and not alias_live:
                    _record(hits, "leak", live_obj or obj, node, witness())

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
            next_nullable = {rebased for nullable_obj in nullable
                             if (rebased := rebase(nullable_obj)) is not None}
            next_realloc_lost = {rebased for lost_obj in realloc_lost
                                 if (rebased := rebase(lost_obj)) is not None}
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
                    next_nullable.discard(guarded_obj)
                elif proof.kind == "NONNULL":
                    next_nulls.discard(guarded_obj)
                    next_nullable.discard(guarded_obj)
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
            next_state = _State(edge.target, frozenset(next_released), frozenset(next_origins), stack,
                                tuple(sorted(next_bindings.items(), key=repr)), frozenset(next_nulls),
                                frozenset(next_escaped),
                                tuple(sorted(sink_allocs.items())),
                                frozenset(next_nullable),
                                frozenset(next_realloc_lost))
            target_event = graph.nodes[edge.target].event
            if target_event is not None and target_event.kind == EventKind.LOOP:
                bucket_key = (edge.target, stack)
                bucket = loop_buckets.setdefault(bucket_key, [])
                if len(bucket) >= _LOOP_WIDEN_LIMIT:
                    prior = bucket.pop(0)
                    superseded.add(prior)
                    next_state = join_loop_states(prior, next_state)
                bucket.append(next_state)
            predecessors.setdefault(next_state, state)
            queue.append(next_state)
    # Keep the compact node-id witness for compatibility, but also expose the
    # source-level trace needed by reports and downstream triage.  The graph is
    # the authority for locations; no source reparse or pattern-specific lookup
    # is involved here.
    for hit in hits.values():
        trace = []
        for node_id in hit["witness"]:
            witness_node = graph.nodes.get(node_id)
            event = witness_node.event if witness_node else None
            trace.append({
                "node": node_id,
                "fragment": witness_node.fragment if witness_node else None,
                "kind": str(event.kind) if event else None,
                "line": event.line if event else None,
            })
        hit["witness_trace"] = trace
        first = trace[0] if trace else {}
        hit["source_node"] = first.get("node")
        hit["source_entry"] = first.get("fragment")
        hit["source_line"] = first.get("line")
    return sorted(hits.values(), key=lambda x: (x["pattern"], x.get("line") or -1))


def _record(hits: dict, pattern: str, obj: ObjRef, node: GraphNode,
            witness: tuple[str, ...] = (), family: str | None = None) -> None:
    # A shared callee may be reached from several source-rooted callers.  Those
    # are distinct witnesses even when the sink node and normalized object are
    # identical; collapsing them loses the coverage proof the graph was built
    # to preserve.
    # Keep caller identity in the key, but collapse repeated CFG/loop steps in
    # the same call context.  Full path keys turn one loop witness into
    # thousands of equivalent leads; seam identities are the stable source-root
    # distinction that matters for shared callees.
    seam_context = tuple(sorted({step for step in witness if ":seam_enter:" in step}))
    key = (pattern, obj.render(), node.id, node.event.line if node.event else None,
           seam_context)
    reachable = bool(node.metadata.get("source_reachable", False))
    influenced = bool(node.metadata.get("source_influenced", False))
    object_name = obj.render()
    from . import atropos
    catalog_id = atropos.flow_pattern_id(pattern, family)
    hits.setdefault(key, {"pattern": pattern, "object": object_name, "node": node.id,
                          "entry": node.fragment, "line": node.event.line if node.event else None,
                          # Keep the lead contract shared with the reachability
                          # renderer.  Semantic leads are source-rooted graph
                          # findings, but callers still expect these display and
                          # triage fields even when the old skeleton is retired.
                          "is_source": reachable,
                          "guarded": False,
                          "value": object_name,
                          "var": object_name,
                          "at": node.id,
                          "pattern_id": catalog_id,
                          "source_reachable": reachable,
                          "source_influenced": influenced,
                          "witness": list(witness),
                          "tier": 1 if reachable and influenced else 2 if reachable else None})
