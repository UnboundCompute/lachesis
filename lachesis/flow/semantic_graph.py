"""Frozen v1 semantic flow graph and matcher.

This module is deliberately independent of the legacy linear skeleton renderer.  Claus emits
facts into :class:`SkeletonGraph`; the matcher derives findings by graph reachability.  In
particular, a graph edge is never an implicit ordering between sibling branch arms.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from enum import Enum
import re
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
    ESCAPE = "ESCAPE"
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
    POINTER_ARITHMETIC = "pointer_arithmetic"


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
    "pointer-arithmetic-before-validation": PatternSpec(
        "pointer-arithmetic-before-validation", (EventKind.POINTER_ARITHMETIC,
                                                   EventKind.READ_STORAGE)),
    # Sink-context relationships are accumulated by the graph walk, so these
    # must be included in the default graph pattern set too.
    "mem.copy.in-loop-unbounded": PatternSpec(
        "mem.copy.in-loop-unbounded", (EventKind.SINK,)),
    "mem.alloc-copy.size-mismatch": PatternSpec(
        "mem.alloc-copy.size-mismatch", (EventKind.SINK,)),
}


_LOOP_WIDEN_LIMIT = 32
_LOOP_PATH_LIMIT = 4


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
    def origin(cls, obj: ObjRef, line: int | None = None,
               facts: dict[str, Any] | None = None) -> "Event":
        return cls(EventKind.ORIGIN, obj=obj, line=line, facts=dict(facts or {}))

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
    def escape(cls, obj: ObjRef, line: int | None = None) -> "Event":
        return cls(EventKind.ESCAPE, obj=obj, line=line)

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
    # Abstract object identities are local to a Claus fragment.  This optional
    # relation translates those identities at an interprocedural seam without
    # pretending they are source-level ObjRefs.
    provenance: tuple[tuple[str, str], ...] = ()


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
    language: str | None = None

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
                 binding: Iterable[tuple[ObjRef, ObjRef]] = (),
                 provenance: Iterable[tuple[str, str]] = ()) -> None:
        if source not in self.nodes or target not in self.nodes:
            raise KeyError(f"edge endpoint not in graph: {source}->{target}")
        self.edges.setdefault(source, []).append(
            Edge(target, kind, tuple(guard), return_to, tuple(binding), tuple(provenance)))

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
                           "binding": [[a.render(), b.render()] for a, b in e.binding],
                           "binding_refs": [[_obj_dict(a), _obj_dict(b)]
                                            for a, b in e.binding],
                           **({"provenance": [list(pair) for pair in e.provenance]}
                              if e.provenance else {})}
                          for e in es] for n, es in self.edges.items()},
            "fragments": {n: {"entry": f.entry, "exits": sorted(f.exits), "params": f.params}
                          for n, f in self.fragments.items()},
            "source_reachable": sorted(self.source_reachable),
            "coverage": self.coverage,
            "language": self.language,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "SkeletonGraph":
        """Reconstruct a semantic graph from :meth:`to_dict` output.

        Object references are restored from the structured ``*_ref`` fields
        emitted by current versions.  The readable renderings remain in the
        public payload for reports and older consumers; legacy payloads without
        structured fields are accepted through the conservative renderer parser
        below.  This makes persisted Pass-3 fragments independent of Python
        object identity while retaining backwards compatibility.
        """
        graph = cls(language=payload.get("language"))
        for node_id, raw in (payload.get("nodes") or {}).items():
            event = _event_from_dict(raw.get("event")) if raw.get("event") else None
            graph.add_node(node_id, event, fragment=raw.get("fragment"),
                          **dict(raw.get("metadata") or {}))
        for source, raw_edges in (payload.get("edges") or {}).items():
            for raw in raw_edges or ():
                guards = tuple(GuardProof(str(item.get("kind", "")),
                                           str(item.get("value", "")))
                               for item in raw.get("guard", ()) or ())
                binding_payload = raw.get("binding_refs") or raw.get("binding", ())
                bindings = tuple(
                    (_obj_from_payload(left), _obj_from_payload(right))
                    for left, right in binding_payload
                )
                graph.add_edge(source, raw["target"], kind=raw.get("kind", "normal"),
                               guard=guards, return_to=raw.get("return_to"),
                               binding=bindings,
                               provenance=tuple(tuple(pair) for pair in
                                                 raw.get("provenance", ()) or ()))
        for name, raw in (payload.get("fragments") or {}).items():
            graph.add_fragment(name, raw["entry"], raw.get("exits", ()),
                               raw.get("params", ()))
        graph.source_reachable.update(payload.get("source_reachable", ()) or ())
        graph.coverage = dict(payload.get("coverage") or {})
        graph.validate()
        return graph


def _event_dict(event: Event | None) -> dict[str, Any] | None:
    if event is None:
        return None
    kind = event.kind.value if isinstance(event.kind, EventKind) else event.kind
    return {"kind": kind, "obj": event.obj.render() if event.obj else None,
            "obj_ref": _obj_dict(event.obj),
            "base": event.base.render() if event.base else None,
            "base_ref": _obj_dict(event.base),
            "path": event.path,
            "value": event.value.render() if event.value else None,
            "value_ref": _obj_dict(event.value),
            "slot": event.slot.render() if event.slot else None,
            "slot_ref": _obj_dict(event.slot), "line": event.line,
            "facts": event.facts, "proofs": [{"kind": p.kind, "value": p.value} for p in event.proofs]}


def _obj_dict(value: ObjRef | None) -> dict[str, Any] | None:
    if value is None:
        return None
    return {"base": value.base, "path": list(value.path), "generation": value.generation}


def _obj_from_payload(value: Any) -> ObjRef:
    """Decode a structured ObjRef or a legacy rendered reference."""
    if isinstance(value, dict):
        return ObjRef(str(value.get("base", "")), tuple(value.get("path", ()) or ()),
                      value.get("generation", "G0"))
    text = str(value)
    base_generation = text.rsplit("#", 1)
    rendered, generation = (base_generation if len(base_generation) == 2
                            else (text, "G0"))
    # Old renderings are inherently ambiguous for adjacent field selectors.
    # Preserve the common address/field forms and treat the remaining suffix as
    # one selector; new payloads always use the lossless structured form above.
    match = re.match(r"^([^*&.\[]+)((?:[&*]|\.[^.&*\[]+|\[[^]]+\])*)$", rendered)
    if not match:
        return ObjRef(rendered, generation=generation)
    base, suffix = match.groups()
    selectors = []
    for token in re.findall(r"[&*]|\.([^.&*\[]+)|(\[[^]]+\])", suffix):
        selectors.append(next(part for part in token if part))
    return ObjRef(base, tuple(selectors), generation)


def _event_from_dict(raw: dict[str, Any]) -> Event:
    kind_value = raw.get("kind")
    try:
        kind = EventKind(kind_value)
    except ValueError:
        kind = kind_value
    return Event(kind, obj=_obj_from_payload(raw["obj_ref"])
                 if raw.get("obj_ref") is not None else
                 (_obj_from_payload(raw["obj"]) if raw.get("obj") else None),
                 base=_obj_from_payload(raw["base_ref"])
                 if raw.get("base_ref") is not None else
                 (_obj_from_payload(raw["base"]) if raw.get("base") else None),
                 path=raw.get("path"),
                 value=_obj_from_payload(raw["value_ref"])
                 if raw.get("value_ref") is not None else
                 (_obj_from_payload(raw["value"]) if raw.get("value") else None),
                 slot=_obj_from_payload(raw["slot_ref"])
                 if raw.get("slot_ref") is not None else
                 (_obj_from_payload(raw["slot"]) if raw.get("slot") else None),
                 line=raw.get("line"), facts=dict(raw.get("facts") or {}),
                 proofs=tuple(GuardProof(str(p.get("kind", "")),
                                         str(p.get("value", "")))
                              for p in raw.get("proofs", ()) or ()))


def _normalized_path(path: tuple[str, ...]) -> tuple[str, ...]:
    """Normalize address/dereference selectors at an identity boundary."""
    result: list[str] = []
    for selector in path:
        if result and ((result[-1], selector) in {("&", "*"), ("*", "&")}):
            result.pop()
        else:
            result.append(selector)
    return tuple(result)


def _requested_patterns(patterns: Iterable[str] | None) -> set[str]:
    """Normalize internal evaluator names and Atropos public pattern IDs."""
    # FROZEN_PATTERNS is the compatibility floor for installations where the
    # sibling catalog is unavailable.  When Atropos is present, its matcher
    # declarations are also part of the default executable registry.  Keeping
    # this discovery here prevents a newly catalogued pattern from becoming
    # inert merely because this module's compatibility table was not edited in
    # the same change.
    requested = set(FROZEN_PATTERNS)
    explicit = patterns is not None
    if explicit:
        requested = set(patterns)
    try:
        from . import atropos
        for entry in atropos.pattern_catalog():
            public_id = entry.get("id")
            matcher = entry.get("matcher") or {}
            internal_name = matcher.get("pattern")
            if internal_name and not explicit:
                requested.add(internal_name)
            elif public_id in requested and internal_name:
                requested.add(internal_name)
    except (ImportError, OSError, ValueError, AttributeError):
        # The semantic matcher remains usable without the optional sibling catalog.
        pass
    return requested


@dataclass(frozen=True)
class _State:
    node: str
    released: frozenset[tuple[ObjRef, str]] = frozenset()
    origins: frozenset[ObjRef] = frozenset()
    stack: tuple[str, ...] = ()
    bindings: tuple[tuple[ObjRef, ObjRef], ...] = ()
    # Stable value aliases and current slot rebindings are kept separately from
    # seam/derived ``bindings``.  This prevents ``alias = p`` from following a
    # later reallocation of the owning slot ``p``.
    aliases: tuple[tuple[ObjRef, ObjRef], ...] = ()
    slot_bindings: tuple[tuple[ObjRef, ObjRef], ...] = ()
    nulls: frozenset[ObjRef] = frozenset()
    nonnull: frozenset[ObjRef] = frozenset()
    guard_values: frozenset[str] = frozenset()
    escaped: frozenset[ObjRef] = frozenset()
    sink_allocs: tuple[tuple[str, str], ...] = ()
    nullable: frozenset[ObjRef] = frozenset()
    realloc_lost: frozenset[ObjRef] = frozenset()
    pointer_arithmetic: frozenset[tuple[ObjRef, ObjRef | None]] = frozenset()
    abstract_bindings: tuple[tuple[str, str], ...] = ()
    abstract_released: frozenset[tuple[str, str]] = frozenset()
    abstract_contexts: tuple[tuple[tuple[str, str], ...], ...] = ()
    # Keep externally rooted launches distinct even when their abstract facts
    # happen to be equal at a shared node.
    launch_context: str | None = None


class _WitnessPath(tuple):
    """Node witness plus the concrete graph edges traversed to reach it."""

    def __new__(cls, nodes: tuple[str, ...], edges: tuple["Edge", ...] = ()):
        value = super().__new__(cls, nodes)
        value.edges = edges
        return value


def match_graph(graph: SkeletonGraph, *, patterns: Iterable[str] | None = None) -> list[dict[str, Any]]:
    """Find facts on compatible pushdown paths.

    ``seam_enter`` edges push their explicit continuation; ``seam_exit`` edges pop it.  This
    means a shared fragment cannot return to a different caller.  The released set is keyed by
    the exact object and generation, so freeing a storage object never frees its pointee.
    """
    wanted = _requested_patterns(patterns)
    starts = ([node_id for node_id in sorted(graph.source_reachable)
               if node_id in graph.nodes]
              if graph.source_reachable else
              [f.entry for f in graph.fragments.values()])
    starts = starts or list(graph.nodes)
    queue = deque(_State(s, launch_context=s) for s in starts)
    predecessors: dict[_State, _State | None] = {
        _State(s, launch_context=s): None for s in starts
    }
    predecessor_edges: dict[_State, Edge] = {}
    superseded: set[_State] = set()
    loop_buckets: dict[tuple[str, tuple[str, ...], str | None], list[_State]] = {}

    def join_loop_states(left: _State, right: _State) -> _State:
        left_bindings, right_bindings = dict(left.bindings), dict(right.bindings)
        merged_bindings = dict(left_bindings)
        for key, value in right_bindings.items():
            merged_bindings.setdefault(key, value)
        left_aliases, right_aliases = dict(left.aliases), dict(right.aliases)
        merged_aliases = dict(left_aliases)
        for key, value in right_aliases.items():
            merged_aliases.setdefault(key, value)
        left_slots, right_slots = dict(left.slot_bindings), dict(right.slot_bindings)
        merged_slots = dict(left_slots)
        for key, value in right_slots.items():
            merged_slots.setdefault(key, value)
        return _State(
            right.node,
            left.released | right.released,
            left.origins | right.origins,
            right.stack,
            tuple(sorted(merged_bindings.items(), key=repr)),
            tuple(sorted(merged_aliases.items(), key=repr)),
            tuple(sorted(merged_slots.items(), key=repr)),
            left.nulls | right.nulls,
            left.nonnull | right.nonnull,
            left.guard_values & right.guard_values,
            left.escaped | right.escaped,
            tuple(sorted(set(left.sink_allocs) | set(right.sink_allocs))),
            left.nullable | right.nullable,
            left.realloc_lost | right.realloc_lost,
            left.pointer_arithmetic | right.pointer_arithmetic,
            tuple(sorted(set(left.abstract_bindings) | set(right.abstract_bindings))),
            left.abstract_released | right.abstract_released,
            left.abstract_contexts,
            left.launch_context,
        )

    def widen_loop_ref(value: ObjRef) -> ObjRef:
        """Bound loop-carried access paths without inventing a lifetime event.

        Linked-list traversal is represented as repeated field selectors.  A
        raw path such as ``head->next->next...`` would otherwise create a new
        matcher identity on every iteration and prevent the worklist from
        converging.  Preserve the first two selectors (the concrete field
        context) and replace only the unbounded suffix with an abstract loop
        segment.  The same abstraction is applied to bindings and lifecycle
        sets, so it cannot manufacture a release/use link by itself.
        """
        if len(value.path) <= _LOOP_PATH_LIMIT:
            return value
        return ObjRef(value.base, value.path[:2] + ("<loop>",), value.generation)

    def widen_loop_state(state: _State) -> _State:
        def ref(value):
            return widen_loop_ref(value)
        bindings = tuple(sorted(
            ((ref(left), ref(right)) for left, right in state.bindings), key=repr))
        aliases = tuple(sorted(
            ((ref(left), ref(right)) for left, right in state.aliases), key=repr))
        slots = tuple(sorted(
            ((ref(left), ref(right)) for left, right in state.slot_bindings), key=repr))
        pointer_arithmetic = frozenset(
            (ref(pointer), ref(base) if base is not None else None)
            for pointer, base in state.pointer_arithmetic)
        return _State(
            state.node,
            frozenset((ref(value), site) for value, site in state.released),
            frozenset(ref(value) for value in state.origins),
            state.stack,
            bindings,
            aliases,
            slots,
            frozenset(ref(value) for value in state.nulls),
            frozenset(ref(value) for value in state.nonnull),
            state.guard_values,
            frozenset(ref(value) for value in state.escaped),
            state.sink_allocs,
            frozenset(ref(value) for value in state.nullable),
            frozenset(ref(value) for value in state.realloc_lost),
            pointer_arithmetic,
            state.abstract_bindings,
            state.abstract_released,
            state.abstract_contexts,
            state.launch_context,
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
        # Atropos owns the event-to-evaluator vocabulary.  Keep the old
        # compatibility behavior when a legacy catalog has no row, but do not
        # silently interpret an event routed to another evaluator as a
        # lifecycle transition.  This is the seam that lets future evaluators
        # coexist with typestate without adding another engine-side whitelist.
        if event is not None:
            from .patterns import evaluator_for_event
            event_name = (event.kind.value if isinstance(event.kind, EventKind)
                          else str(event.kind)).lower()
            declared_evaluator = evaluator_for_event(event_name)
            temporal_event = declared_evaluator in (None, "typestate")
        else:
            temporal_event = False
        released = set(state.released)
        origins = set(state.origins)
        nulls = set(state.nulls)
        nonnull = set(state.nonnull)
        guard_values = set(state.guard_values)
        bindings = dict(state.bindings)
        aliases = dict(state.aliases)
        slot_bindings = dict(state.slot_bindings)
        escaped = set(state.escaped)
        sink_allocs = dict(state.sink_allocs)
        nullable = set(state.nullable)
        realloc_lost = set(state.realloc_lost)
        pointer_arithmetic = set(state.pointer_arithmetic)
        abstract_bindings = dict(state.abstract_bindings)
        abstract_released = set(state.abstract_released)
        abstract_contexts = state.abstract_contexts

        # A LOOP node is the widening boundary for path predicates.  Values
        # controlling one iteration are not stable facts for the next; keeping
        # every accumulated relational predicate here would split the worklist
        # once per iteration and defeat the graph's finite loop abstraction.
        if event is not None and event.kind == EventKind.LOOP:
            guard_values.clear()

        def abstract_ids(event: Event | None) -> tuple[str, ...]:
            if event is None:
                return ()
            # Emitters use ``abstract_object_ids`` for the value currently
            # carried by an operation and ``abstract_source_ids`` for the
            # storage identity that operation came from.  Both describe the
            # same lifetime relation at a seam (notably realloc's old object
            # versus a stale cursor), so the matcher must retain both.
            values = (tuple(event.facts.get("abstract_object_ids") or ()) +
                      tuple(event.facts.get("abstract_source_ids") or ()))
            scoped = []
            for value in values:
                text = str(value)
                # Parameter identities are local to the fragment that emitted
                # them.  Concrete ObjRef seam bindings remain the authority for
                # interprocedural continuity; without this scope, unrelated
                # ``param 0`` values in different functions can collide.
                if text.startswith("('param',"):
                    text = f"{text}|scope={node.fragment}"
                scoped.append(text)
            return tuple(dict.fromkeys(scoped))

        def abstract_canonical(value: str) -> str:
            visited = set()
            while value in abstract_bindings and value not in visited:
                visited.add(value)
                value = abstract_bindings[value]
            return value

        def stable_abstract(value: str) -> bool:
            # Parameter and unknown-slot IDs are context-relative. Allocation
            # and clobber recency IDs are stable enough to disambiguate local
            # declarations within one source-rooted exploration.
            text = str(value)
            return (text.startswith("('alloc',")
                    or text.startswith("('clobber',")
                    or text.startswith("('param',"))

        def abstract_key(value: str, obj: ObjRef | None) -> str:
            return f"{value}@{obj.generation}" if obj is not None else str(value)

        def guard_stem(value: str) -> str:
            """Normalize source-level member spelling to ObjRef path spelling."""
            return str(value).replace("->", "*").replace(".", "*")

        def guard_reference(value: str) -> ObjRef | None:
            """Resolve a source-level guard operand in the current seam scope."""
            if "#" not in str(value):
                return None
            stem, generation = str(value).rsplit("#", 1)
            normalized = guard_stem(stem)
            parts = tuple(part for part in normalized.split("*") if part)
            if not parts:
                return None
            return canonical(ObjRef(parts[0], parts[1:], generation))

        def canonical(value: ObjRef | None, *, follow_slots: bool = True) -> ObjRef | None:
            seen = set()
            used_bindings = set()
            while value is not None and value not in seen:
                seen.add(value)
                stable = aliases.get(value)
                if stable is not None:
                    value = stable
                    break
                direct = bindings.get(value)
                if direct is not None and value not in used_bindings:
                    used_bindings.add(value)
                    old_base = value.base
                    value = ObjRef(direct.base, _normalized_path(direct.path), direct.generation)
                    if direct.base == old_base:
                        break
                    continue
                if follow_slots:
                    slotted = slot_bindings.get(value)
                    if slotted is not None:
                        value = slotted
                        break
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

        def explicit_alias(value: ObjRef | None) -> bool:
            """Whether the current state proves a non-name-based alias relation."""
            return any(key != value and equivalent(key, value)
                       for key in (*aliases.keys(), *bindings.keys()))

        def escaped_reaches(value: ObjRef | None) -> bool:
            """Whether an escaped object keeps this object/path reachable.

            Returning an owning aggregate (``return b``) also returns ownership
            of allocations stored in its fields (``b->data``).  Exact identity
            equality is insufficient for that case, while treating every
            escaped object as a root would incorrectly discharge unrelated
            allocations.  A canonical path-prefix relation is the precise
            field-sensitive boundary.
            """
            value = canonical(value)
            if value is None:
                return False
            return any(
                root.base == value.base
                and root.generation == value.generation
                and value.path[:len(root.path)] == root.path
                for root in escaped
            )

        def value_constraint(value: str):
            match = re.match(r"^(.+?)(<=|>=|==|!=|<|>)(.+)$", str(value))
            return match.groups() if match else None

        def contradictory_value(left: str, right: str) -> bool:
            """Recognize the exact opposite/equality conflicts we can prove.

            VALUE proofs remain opaque to lifecycle semantics except for these
            local contradictions.  Keeping the relation parser this small is
            intentional: an unknown expression remains feasible rather than
            being guessed away.
            """
            a = value_constraint(left)
            b = value_constraint(right)
            if not a or not b or a[0] != b[0]:
                return False
            if a[1] == "==" and b[1] == "==":
                return a[2] != b[2]
            if {a[1], b[1]} == {"==", "!="}:
                return a[2] == b[2]
            opposites = {("<", ">="), (">=", "<"),
                         (">", "<="), ("<=", ">")}
            return (a[1], b[1]) in opposites

        def witness() -> _WitnessPath:
            path = []
            edges = []
            current: _State | None = state
            while current is not None:
                path.append(current.node)
                edge = predecessor_edges.get(current)
                if edge is not None:
                    edges.append(edge)
                current = predecessors.get(current)
            return _WitnessPath(tuple(reversed(path)), tuple(reversed(edges)))

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
                        event.facts.get("size_expr"),
                        event.facts.get("guard_predicates", ()),
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
                bound = canonical(event.value) or event.value
                bindings[event.obj] = bound
                aliases[event.obj] = bound
                if event.facts.get("persistent_slot"):
                    # A persistent slot is both an alias and an ownership
                    # escape. Reads through it must observe releases made via
                    # another alias on the same source-rooted execution.
                    escaped.add(bound)
                obj = canonical(event.obj)
            if event is not None and event.kind == EventKind.POINTER_ARITHMETIC and obj:
                pointer_arithmetic.add((obj, canonical(event.base)))
            is_null_write = (event.kind == EventKind.WRITE_STORAGE_NULL or
                             (event.kind == EventKind.WRITE_STORAGE and event.facts.get("null")))
            if temporal_event and event.kind == EventKind.WRITE_STORAGE:
                # Pointer-slot writes carry the value stored in the slot. Keep
                # that relation separate from ordinary DERIVE aliases so a
                # later ``free(slot)`` or slot read resolves the pointee, while
                # nulling the slot does not rebind aliases captured earlier.
                slot = event.slot or event.base or raw_obj
                if slot is not None:
                    if is_null_write:
                        slot_bindings.pop(slot, None)
                    elif event.value is not None:
                        slot_bindings[slot] = canonical(event.value)
            if temporal_event and is_null_write and raw_obj:
                # NULL is a value in this storage slot, not a property of the
                # heap object reached through another alias.
                nulls.add(raw_obj)
                nonnull.discard(raw_obj)
                if obj is not None:
                    nonnull.discard(obj)
                obj = None
            if temporal_event and event.kind == EventKind.RELEASE and raw_obj in nulls:
                obj = None
            if (temporal_event and event.kind == EventKind.RETURN_VALUE
                    and event.facts.get("return_null")):
                # `__return__` is a synthetic callee-local slot.  The return
                # edge rebases its null fact onto the caller receiver.
                nulls.add(ObjRef("__return__", generation="g0"))
            # Prefer declaration/object identities whenever the emitter provides
            # them.  The display ObjRef remains the compatibility fallback for
            # older frontends and hand-built graphs.
            event_abstract = tuple(abstract_canonical(value) for value in abstract_ids(event))
            identity_abstract = (event_abstract
                                 if event_abstract and all(stable_abstract(value)
                                                           for value in event_abstract)
                                 else ())
            if temporal_event and event.kind == EventKind.RELEASE and obj:
                prior_sites = {site for released_obj, site in released if released_obj == obj}
                abstract_prior = {
                    site for value, site in abstract_released
                    if value in {abstract_key(item, obj) for item in identity_abstract}
                }
                prior = abstract_prior if identity_abstract else prior_sites
                if "double-free" in wanted and any(site != node.id for site in prior):
                    _record(hits, "double-free", obj, node, witness())
                released = {(released_obj, site) for released_obj, site in released
                            if released_obj != obj} | {(obj, node.id)}
                if event_abstract:
                    abstract_released = {
                        (value, site) for value, site in abstract_released
                        if value.split("@", 1)[0] not in event_abstract
                    }
                    abstract_released.update(
                        (abstract_key(value, obj), node.id) for value in event_abstract)
            elif temporal_event and event.kind == EventKind.INVALIDATE and obj:
                released = {(released_obj, site) for released_obj, site in released
                            if released_obj != obj} | {(obj, node.id)}
                # Reallocation invalidates the previous incarnation just like
                # an explicit release.  Preserve its abstract identities too,
                # otherwise aliases whose concrete spelling differs (for
                # example a loop-local cursor) cannot observe the stale use.
                if event_abstract:
                    abstract_released = {
                        (value, site) for value, site in abstract_released
                        if value.split("@", 1)[0] not in event_abstract
                    }
                    abstract_released.update(
                        (abstract_key(value, obj), node.id)
                        for value in event_abstract)
            elif (temporal_event
                  and event.kind in (EventKind.READ_STORAGE, EventKind.WRITE_STORAGE)
                  and base and not is_null_write):
                if ("pointer-arithmetic-before-validation" in wanted
                        and any(equivalent(pointer, base)
                                for pointer, _source in pointer_arithmetic)):
                    _record(hits, "pointer-arithmetic-before-validation", base,
                            node, witness())
                abstract_freed = any(
                    abstract_key(value, base) in {
                        released_value for released_value, _ in abstract_released}
                    for value in identity_abstract)
                obj_freed = any(released_obj == base for released_obj, _ in released)
                abstract_available = any(stable_abstract(value)
                                         for value, _ in abstract_released)
                alias_supported = explicit_alias(base)
                if "uaf.deref" in wanted and (
                        abstract_freed if identity_abstract and abstract_available
                        and "@loop:" not in str(base.generation)
                        and not alias_supported
                        else obj_freed):
                    _record(hits, "uaf.deref", base, node, witness())
                if "null-deref" in wanted and raw_base in nulls:
                    _record(hits, "null-deref", base, node, witness())
                if "unchecked-return-deref" in wanted and base in nullable:
                    _record(hits, "unchecked-return-deref", base, node, witness())
            elif (temporal_event
                  and event.kind in (EventKind.PASS_VALUE, EventKind.ESCAPE,
                                     EventKind.COMPARE_VALUE, EventKind.RETURN_VALUE)
                  and obj):
                abstract_freed = any(
                    abstract_key(value, obj) in {
                        released_value for released_value, _ in abstract_released}
                    for value in identity_abstract)
                obj_freed = any(released_obj == obj for released_obj, _ in released)
                abstract_available = any(stable_abstract(value)
                                         for value, _ in abstract_released)
                alias_supported = explicit_alias(obj)
                if (event.kind != EventKind.ESCAPE and "use.dangling" in wanted and (
                        abstract_freed if identity_abstract and abstract_available
                        and "@loop:" not in str(obj.generation)
                        and not alias_supported
                        else obj_freed)):
                    _record(hits, "use.dangling", obj, node, witness())
                if (event.kind == EventKind.RETURN_VALUE
                        and event.facts.get("stack_local")
                        and "use-after-return" in wanted):
                    _record(hits, "use-after-return", obj, node, witness())
                if event.kind in (EventKind.RETURN_VALUE, EventKind.ESCAPE):
                    escaped.add(obj)
            elif temporal_event and event.kind == EventKind.ORIGIN and obj:
                # Re-originating a slot creates a new lifetime incarnation.
                # Keep aliases captured before this event pinned to the old
                # object while direct references to the slot move forward.
                if (event.facts.get("loop_widening") or
                        event.facts.get("incarnation")) and (
                            obj in origins or
                            any(released_obj.base == obj.base
                                and released_obj.path == obj.path
                                for released_obj, _ in released)):
                    generation = obj.generation
                    if "@loop:" not in str(generation):
                        generation = f"{generation}@loop:{node.id}"
                    obj = ObjRef(obj.base, obj.path, generation)
                    if raw_obj is not None:
                        slot_bindings[raw_obj] = obj
                        # Events after a loop are emitted from the source slot
                        # spelling and may still carry its baseline generation
                        # (for example `item#g0`). Rebind that direct slot key,
                        # but do not touch aliases captured under their own
                        # names/generations; those must continue to identify the
                        # pre-loop object.
                        slot_bindings[ObjRef(raw_obj.base, raw_obj.path,
                                             generation="g0")] = obj
                        aliases.pop(raw_obj, None)
                origins.add(obj)
                if raw_obj is not None and obj.generation != "g0":
                    # Rebinding the source slot is distinct from rebinding an
                    # alias captured before this origin. A later event may still
                    # carry the baseline slot generation after a branch or loop
                    # join; select the active incarnation for the slot only.
                    slot_bindings[ObjRef(raw_obj.base, raw_obj.path,
                                         generation="g0")] = obj
                released = {(released_obj, site) for released_obj, site in released
                            if released_obj != obj}
                if identity_abstract:
                    # An allocation site may be invoked repeatedly (or revisited
                    # after a loop generation).  A fresh ORIGIN replaces the old
                    # abstract lifetime; retaining its release marker makes the
                    # next invocation look like a use-after-free even though it
                    # received a new object incarnation.
                    abstract_released = {
                        (value, site) for value, site in abstract_released
                        if value.split("@", 1)[0] not in identity_abstract
                    }
                nulls.discard(raw_obj)
                if event.facts.get("return_may_null"):
                    nullable.add(obj)
                    nonnull.discard(obj)
                else:
                    nullable.discard(obj)
                    nonnull.add(obj)
            elif temporal_event and event.kind == EventKind.LOST_FROM_SLOT and raw_obj:
                # Losing the owning slot does not free the object.  A DERIVE
                # alias remains a live root; without one, the origin is leaked.
                nulls.add(raw_obj)
                realloc_lost.add(obj or raw_obj)

        if "mem.lifetime.realloc-failure-leak" in wanted and node.id in exits:
            for lost_obj in realloc_lost:
                live_obj = canonical(lost_obj)
                released_live = any(equivalent(released_obj, live_obj)
                                    for released_obj, _ in released)
                escaped_live = escaped_reaches(live_obj)
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
                escaped_live = escaped_reaches(live_obj)
                alias_live = any(alias != live_obj and equivalent(alias, live_obj)
                                 for alias in bindings)
                if not released_live and not escaped_live and not alias_live:
                    _record(hits, "leak", live_obj or obj, node, witness())

        for edge in graph.edges.get(state.node, ()):
            stack = state.stack
            next_bindings = dict(bindings)
            # A synthetic ``__return__`` binding is a value-state marker for a
            # NULL return, not an object identity relation.  If it entered the
            # canonical binding map, every caller receiver would be rewritten
            # to ``__return__`` (including unrelated fields released before a
            # later call), creating spurious cross-call lifecycle matches.
            # Keep the pair available below for null/non-null transfer while
            # keeping it out of identity canonicalization.
            for formal, actual in edge.binding:
                if actual.base == "__return__":
                    continue
                # Compose a callee formal with the caller's current identity
                # before entering the seam.  Nested callbacks otherwise form
                # cycles such as ``handler.p -> dispatch.value -> caller.p``
                # and lose the concrete object at the callee event.
                next_bindings[formal] = canonical(actual) or actual
            next_aliases = dict(aliases)
            next_slot_bindings = dict(slot_bindings)
            next_abstract_bindings = dict(abstract_bindings)
            next_abstract_bindings.update(edge.provenance)
            next_abstract_contexts = abstract_contexts
            def rebase(value):
                stable = next_aliases.get(value)
                if stable is not None:
                    return stable
                seen_bindings = set()
                while value in next_bindings and value not in seen_bindings:
                    seen_bindings.add(value)
                    value = next_bindings[value]
                # Seam bindings can target a field/deref access path (for
                # example ``out->data`` to ``buffer->data``), not only a bare
                # formal root. Compose the unmatched suffix so pointer-slot
                # writes made inside a callee survive at the caller.
                candidates = [source for source in next_bindings
                              if source.base == value.base
                              and value.path[:len(source.path)] == source.path]
                if candidates:
                    source = max(candidates, key=lambda item: len(item.path))
                    target = next_bindings[source]
                    value = ObjRef(target.base,
                                   target.path + value.path[len(source.path):],
                                   target.generation)
                return value
            next_slot_bindings = {
                rebase(slot): rebase(value)
                for slot, value in next_slot_bindings.items()
            }
            next_origins = {rebased for origin in origins
                            if (rebased := rebase(origin)) is not None}
            next_released = {(rebased, site) for released_obj, site in released
                             if (rebased := rebase(released_obj)) is not None}
            # Local DERIVE aliases must not rebase NULL slot facts: ``q = p``
            # followed by ``p = NULL`` leaves q's value unchanged.  A seam
            # binding does transfer a formal's value/nullness to its actual.
            next_nulls = set(nulls)
            next_nonnull = {rebased for nonnull_obj in nonnull
                            if (rebased := rebase(nonnull_obj)) is not None}
            next_guard_values = set(guard_values)
            next_nullable = {rebased for nullable_obj in nullable
                             if (rebased := rebase(nullable_obj)) is not None}
            next_realloc_lost = {rebased for lost_obj in realloc_lost
                                 if (rebased := rebase(lost_obj)) is not None}
            next_pointer_arithmetic = {
                (rebased_pointer, rebase(source) if source is not None else None)
                for pointer, source in pointer_arithmetic
                if (rebased_pointer := rebase(pointer)) is not None
            }
            for formal, actual in edge.binding:
                if formal in next_nulls:
                    next_nulls.add(actual)
                if formal in next_nonnull:
                    next_nonnull.add(actual)
            next_escaped = {rebased for escaped_obj in escaped
                            if (rebased := rebase(escaped_obj)) is not None}
            known = (set(next_origins) | set(next_nulls) | set(next_nonnull)
                     | {obj for obj, _ in next_released})
            contradictory_guard = False
            for proof in edge.guard:
                candidates = []
                if proof.kind == "VALUE":
                    if any(contradictory_value(existing, proof.value)
                           for existing in next_guard_values):
                        contradictory_guard = True
                        break
                    next_guard_values.add(proof.value)
                    continue
                if "#" in proof.value:
                    reference = guard_reference(proof.value)
                    # Null tests constrain the current variable binding, not a stale
                    # allocation incarnation. Prefer active origins/nulls and the
                    # highest numeric generation when the source-level proof says `p`.
                    if reference is not None:
                        candidates = [candidate for candidate in
                                      (next_origins | next_nulls | next_nonnull)
                                      if (candidate.base, candidate.path) ==
                                      (reference.base, reference.path)]
                    if not candidates:
                        candidates = [candidate for candidate in known
                                      if guard_stem(candidate.render()) == guard_stem(proof.value)]
                if not candidates:
                    continue
                guarded_obj = max(candidates, key=lambda candidate: repr(candidate.generation))
                if proof.kind == "ISNULL":
                    if guarded_obj in next_nonnull:
                        # A path that has already established this value as
                        # non-null cannot enter its null arm.
                        contradictory_guard = True
                        break
                    next_origins.discard(guarded_obj)
                    next_nulls.add(guarded_obj)
                    next_nonnull.discard(guarded_obj)
                    next_nullable.discard(guarded_obj)
                elif proof.kind == "NONNULL":
                    if guarded_obj in next_nulls:
                        # A known-null value cannot enter a non-null arm.
                        contradictory_guard = True
                        break
                    next_nulls.discard(guarded_obj)
                    next_nonnull.add(guarded_obj)
                    next_nullable.discard(guarded_obj)
            if contradictory_guard:
                continue
            if edge.kind == "call":
                if edge.return_to is None:
                    raise ValueError(f"call edge {state.node}->{edge.target} lacks return_to")
                stack = stack + (edge.return_to,)
                next_abstract_contexts = abstract_contexts + (
                    (tuple(sorted(abstract_bindings.items()))),)
            elif edge.kind == "return":
                if not stack:
                    continue
                if edge.target != stack[-1]:
                    continue
                stack = stack[:-1]
                # Return bindings are stored in caller-receiver -> callee-value
                # direction for identity canonicalization.  Null/non-null facts
                # flow in the opposite direction when the callee returns.
                for receiver, returned in edge.binding:
                    if returned in next_nulls:
                        next_nulls.add(receiver)
                    if returned in next_nonnull:
                        next_nonnull.add(receiver)
                if abstract_contexts:
                    next_abstract_bindings = dict(abstract_contexts[-1])
                    next_abstract_contexts = abstract_contexts[:-1]
                # The callee's return value is now a caller-local receiver;
                # it is no longer an exit escape for the caller's leak query.
                for _formal, receiver in edge.binding:
                    next_escaped.discard(rebase(receiver))
            next_state = _State(edge.target, frozenset(next_released), frozenset(next_origins), stack,
                                tuple(sorted(next_bindings.items(), key=repr)),
                                tuple(sorted(next_aliases.items(), key=repr)),
                                tuple(sorted(next_slot_bindings.items(), key=repr)),
                                frozenset(next_nulls),
                                frozenset(next_nonnull),
                                frozenset(next_guard_values),
                                frozenset(next_escaped),
                                tuple(sorted(sink_allocs.items())),
                                frozenset(next_nullable),
                                frozenset(next_realloc_lost), frozenset(next_pointer_arithmetic),
                                tuple(sorted(next_abstract_bindings.items())),
                                frozenset(abstract_released), next_abstract_contexts,
                                state.launch_context)
            next_state = _State(
                next_state.node, next_state.released, next_state.origins,
                next_state.stack, next_state.bindings, next_state.aliases,
                next_state.slot_bindings,
                next_state.nulls,
                next_state.nonnull,
                next_state.guard_values,
                next_state.escaped, next_state.sink_allocs, next_state.nullable,
                next_state.realloc_lost, frozenset(next_pointer_arithmetic),
                next_state.abstract_bindings, next_state.abstract_released,
                next_state.abstract_contexts, next_state.launch_context)
            target_event = graph.nodes[edge.target].event
            if target_event is not None and target_event.kind == EventKind.LOOP:
                next_state = widen_loop_state(next_state)
                bucket_key = (edge.target, stack, next_state.launch_context)
                bucket = loop_buckets.setdefault(bucket_key, [])
                if len(bucket) >= _LOOP_WIDEN_LIMIT:
                    prior = bucket.pop(0)
                    superseded.add(prior)
                    next_state = join_loop_states(prior, next_state)
                bucket.append(next_state)
            if next_state not in predecessors:
                predecessors[next_state] = state
                predecessor_edges[next_state] = edge
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
        edge_trace = []
        witness = tuple(hit.get("witness", ()))
        traversed_edges = hit.pop("_witness_edge_path", ())
        for source, target, edge in zip(witness, witness[1:], traversed_edges):
            if edge is None:
                continue
            edge_trace.append({
                "source": source,
                "target": target,
                "kind": edge.kind,
                "return_to": edge.return_to,
                "guards": [{"kind": proof.kind, "value": proof.value}
                            for proof in edge.guard],
                "bindings": [[left.render(), right.render()]
                             for left, right in edge.binding],
                "provenance": [list(pair) for pair in edge.provenance],
            })
        hit["witness_edges"] = edge_trace
        launch_contexts = [node_id for node_id in witness
                           if node_id in graph.source_reachable]
        launch_id = launch_contexts[0] if launch_contexts else None
        launch_node = graph.nodes.get(launch_id) if launch_id else None
        launch_event = launch_node.event if launch_node else None
        hit["source_context"] = launch_id
        hit["source_function"] = launch_node.fragment if launch_node else None
        hit["source_site"] = (launch_node.metadata.get("source_site")
                               if launch_node else None)
        hit["witness_complete"] = len(edge_trace) == max(0, len(witness) - 1)
        first = trace[0] if trace else {}
        hit["source_node"] = first.get("node")
        hit["source_entry"] = first.get("fragment")
        hit["source_line"] = (
            launch_event.line if launch_event and launch_event.line is not None
            else (launch_node.metadata.get("source_line") if launch_node else None)
            if launch_node else first.get("line"))
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
    launch_context = witness[0] if witness else None
    key = (pattern, obj.render(), node.id, node.event.line if node.event else None,
           seam_context, launch_context)
    reachable = bool(node.metadata.get("source_reachable", False))
    influenced = bool(node.metadata.get("source_influenced", False))
    object_name = obj.render()
    from . import atropos
    catalog_id = atropos.flow_pattern_id(pattern, family)
    evaluator = atropos.flow_pattern_evaluator(pattern, family)
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
                          "evaluator": evaluator,
                          "source_reachable": reachable,
                          "source_influenced": influenced,
                          "witness": list(witness),
                          "_witness_edge_path": tuple(getattr(witness, "edges", ())),
                          "tier": 1 if reachable and influenced else 2 if reachable else None})
