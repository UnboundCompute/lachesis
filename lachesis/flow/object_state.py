"""Object-identity abstract interpretation for pointer/resource properties.

This module is deliberately graph-independent.  A frontend adapter supplies semantic
operations placed on a CFG; this engine owns access-path binding, object identity,
allocation recency, path correlation, widening, and lifetime findings.

The lifetime property is the first client, not the architecture: additional property
domains can share ``AccessPath`` and the CFG/state machinery without keying facts on a
variable's spelling.
"""
from __future__ import annotations

from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from enum import Enum
from typing import Hashable, Iterable, Mapping, Sequence


class ObjectFact(str, Enum):
    ALLOCATED = "ALLOCATED"
    FREED = "FREED"
    NULL = "NULL"
    UNKNOWN = "UNKNOWN"


class OpKind(str, Enum):
    ALLOC = "alloc"
    CLOBBER = "clobber"
    COPY = "copy"
    FREE = "free"
    USE = "use"
    SUMMARY = "summary"


@dataclass(frozen=True, order=True)
class AccessPath:
    """A declaration-rooted path; selectors are resolved one object at a time."""

    root: str
    selectors: tuple[str, ...] = ()

    def child(self, selector: str) -> "AccessPath":
        return AccessPath(self.root, self.selectors + (selector,))


@dataclass(frozen=True)
class Operation:
    kind: OpKind
    node: Hashable
    target: AccessPath | None = None
    source: AccessPath | None = None
    site: Hashable | None = None
    line: int | None = None
    is_null: bool = False
    ordinal: int = 0
    # Each alternative is an ordered sequence of already-instantiated FREE/USE ops.
    alternatives: tuple[tuple["Operation", ...], ...] = ()


@dataclass(frozen=True, order=True)
class Finding:
    pattern: str
    line: int | None
    path: AccessPath
    node: Hashable


@dataclass(frozen=True, order=True)
class ParamEffect:
    kind: OpKind
    position: int
    selectors: tuple[str, ...] = ()


ObjectId = tuple


# The access-path algebra renders an index-insensitive array subscript — a variable
# index such as ``a[i]`` — as this selector (a literal index becomes ``<0>``/``<3>``).
# An object whose identity was formed through it is a SUMMARY object: it abstracts
# every cell the loop could reach, so two frees of ``a[i]`` in a loop are frees of
# distinct cells, not the same one. Strong lifetime findings (double-free,
# use-after-free) require a MUST identity, so we suppress them on summary objects.
# This trades a rare false negative (a genuine same-index double-free the abstraction
# cannot prove) for removing the weak-update false positive a loop over ``a[i]``
# otherwise produces on every iteration. It is a general strong/weak-update rule, not
# a per-codebase heuristic.
_UNKNOWN_SUBSCRIPT = "<?>"


def _is_summary_object(oid: ObjectId) -> bool:
    if not isinstance(oid, tuple):
        return False
    # Parameter-derived object: ("param", position, selectors).
    if len(oid) == 3 and oid[0] == "param":
        return _UNKNOWN_SUBSCRIPT in oid[2]
    # Allocation/free-site object: (kind, "recent"|"summary", site, target_path).
    if len(oid) == 4 and oid[1] in ("recent", "summary"):
        target = oid[3]
        return isinstance(target, AccessPath) and _UNKNOWN_SUBSCRIPT in target.selectors
    # Heap-slot child: ("unknown-slot", parent_oid, selector) — weak if the selector
    # is the unknown subscript or the parent it hangs off is itself a summary object.
    if len(oid) == 3 and oid[0] == "unknown-slot":
        return oid[2] == _UNKNOWN_SUBSCRIPT or _is_summary_object(oid[1])
    return False


class AbstractState:
    """One path-correlated environment and object-property state."""

    TRACE_LIMIT = 16

    def __init__(
        self,
        env: Mapping[str, ObjectId] | None = None,
        facts: Mapping[ObjectId, frozenset[ObjectFact]] | None = None,
        slots: Mapping[tuple[ObjectId, str], ObjectId] | None = None,
        trace: Sequence[ParamEffect] = (),
    ):
        self.env = dict(env or {})
        self.facts = dict(facts or {})
        self.slots = dict(slots or {})
        self.trace = tuple(trace)

    def clone(self) -> "AbstractState":
        return AbstractState(self.env, self.facts, self.slots, self.trace)

    def key(self) -> tuple:
        # These mappings are mathematical sets for state-equivalence purposes.
        # Sorting them used ``repr(object_id)`` because recursively constructed phi
        # IDs are not naturally orderable; on large CFGs that repeatedly rendered
        # enormous nested tuples.  Frozensets preserve exact structural equality and
        # hashing without inventing an ordering or allocating those strings.
        return (
            frozenset(self.env.items()),
            frozenset(self.facts.items()),
            frozenset(self.slots.items()),
            self.trace,
        )

    def seed_parameter(self, path: AccessPath, position: int) -> None:
        """Bind a formal root to a symbolic caller-owned object."""
        if path.selectors:
            raise ValueError("a formal parameter seed must be a root access path")
        oid = ("param", position, ())
        self.env[path.root] = oid
        self.facts[oid] = frozenset({ObjectFact.UNKNOWN})

    @staticmethod
    def _param_child(base: ObjectId, selector: str) -> ObjectId | None:
        if isinstance(base, tuple) and len(base) == 3 and base[0] == "param":
            return ("param", base[1], base[2] + (selector,))
        return None

    def resolve(self, path: AccessPath, *, create: bool = False) -> ObjectId | None:
        oid = self.env.get(path.root)
        if oid is None and create:
            oid = ("unknown-root", path.root)
            self.env[path.root] = oid
            self.facts.setdefault(oid, frozenset({ObjectFact.UNKNOWN}))
        if oid is None:
            return None
        for selector in path.selectors:
            slot = (oid, selector)
            child = self.slots.get(slot)
            if child is None and create:
                child = self._param_child(oid, selector) or ("unknown-slot", oid, selector)
                self.slots[slot] = child
                self.facts.setdefault(child, frozenset({ObjectFact.UNKNOWN}))
            if child is None:
                return None
            oid = child
        return oid

    def bind(self, path: AccessPath, oid: ObjectId) -> None:
        if not path.selectors:
            self.env[path.root] = oid
            return
        parent = self.resolve(AccessPath(path.root, path.selectors[:-1]), create=True)
        self.slots[(parent, path.selectors[-1])] = oid

    def _record_param_effect(self, kind: OpKind, oid: ObjectId) -> None:
        if not (isinstance(oid, tuple) and len(oid) == 3 and oid[0] == "param"):
            return
        effect = ParamEffect(kind, oid[1], oid[2])
        if self.trace.count(effect) < 2 and len(self.trace) < self.TRACE_LIMIT:
            self.trace += (effect,)

    def _merge_object(self, destination: ObjectId, source: ObjectId) -> None:
        self.facts[destination] = frozenset(
            self.facts.get(destination, frozenset())
            | self.facts.get(source, frozenset({ObjectFact.UNKNOWN})),
        )
        for root, oid in list(self.env.items()):
            if oid == source:
                self.env[root] = destination
        for slot, oid in list(self.slots.items()):
            if oid == source:
                self.slots[slot] = destination

    def _age(self, recent: ObjectId, summary: ObjectId) -> None:
        if recent not in self.facts:
            return
        self._merge_object(summary, recent)
        # Move heap slots whose base is the aged object.  Collisions represent fields
        # from multiple old instances and therefore merge their property facts.
        for (base, selector), child in list(self.slots.items()):
            if base != recent:
                continue
            del self.slots[(base, selector)]
            destination_slot = (summary, selector)
            previous = self.slots.get(destination_slot)
            if previous is None:
                self.slots[destination_slot] = child
            elif previous != child:
                self._merge_object(previous, child)
        self.facts.pop(recent, None)

    def _fresh(self, op: Operation, fact: ObjectFact) -> None:
        assert op.target is not None
        site = op.site if op.site is not None else op.node
        recent = (op.kind.value, "recent", site, op.target)
        summary = (op.kind.value, "summary", site, op.target)
        self._age(recent, summary)
        self.facts[recent] = frozenset({fact})
        self.bind(op.target, recent)

    def apply(self, op: Operation, findings: set[Finding]) -> None:
        if op.kind == OpKind.ALLOC:
            self._fresh(op, ObjectFact.ALLOCATED)
            return
        if op.kind == OpKind.CLOBBER:
            self._fresh(op, ObjectFact.NULL if op.is_null else ObjectFact.UNKNOWN)
            return
        if op.kind == OpKind.COPY:
            assert op.target is not None and op.source is not None
            self.bind(op.target, self.resolve(op.source, create=True))
            return
        if op.kind not in (OpKind.FREE, OpKind.USE):
            raise ValueError(f"cannot directly apply {op.kind}")

        assert op.target is not None
        oid = self.resolve(op.target, create=(op.kind == OpKind.FREE))
        if oid is None:
            return
        self._record_param_effect(op.kind, oid)
        facts = self.facts.get(oid, frozenset({ObjectFact.UNKNOWN}))
        # A summary object (identity formed through a variable subscript) may-be-freed
        # abstracts distinct concrete cells; a repeat free/use of it is not a proven
        # violation of the same object, so it does not raise a strong finding.
        weak = _is_summary_object(oid)
        if op.kind == OpKind.USE:
            if ObjectFact.FREED in facts and not weak:
                findings.add(Finding("use-after-free", op.line, op.target, op.node))
            return

        if ObjectFact.FREED in facts and not weak:
            findings.add(Finding("double-free", op.line, op.target, op.node))
        if facts != frozenset({ObjectFact.NULL}):
            freed = frozenset({ObjectFact.FREED})
            is_summary = len(oid) > 1 and oid[1] == "summary"
            self.facts[oid] = (facts | freed) if is_summary else freed


def join_states(states: Iterable[AbstractState], node: Hashable) -> AbstractState:
    """Alias-signature-preserving may join used when path disjunctions exceed budget."""
    # State position is used consistently across every signature below, while phi IDs
    # are deliberately synthetic.  Reordering states can only rename those IDs; it
    # cannot change alias partitions or joined facts.  Avoid recursively rendering
    # entire states merely to choose an otherwise meaningless name ordering.
    ordered = list(states)
    joined = AbstractState()
    roots = sorted({root for state in ordered for root in state.env})
    signatures: dict[tuple, ObjectId] = {}
    work: deque[tuple[ObjectId, tuple[ObjectId | None, ...]]] = deque()

    def object_for(signature: tuple[ObjectId | None, ...], tag: str) -> ObjectId:
        present = [oid for oid in signature if oid is not None]
        if present and len(present) == len(signature) and all(oid == present[0] for oid in present):
            return present[0]
        key = (tag, signature)
        if key not in signatures:
            signatures[key] = (tag, node, len(signatures))
        return signatures[key]

    def attach(new_oid: ObjectId, signature: tuple[ObjectId | None, ...]) -> None:
        facts = frozenset()
        for state, old_oid in zip(ordered, signature):
            facts |= state.facts.get(old_oid, frozenset({ObjectFact.UNKNOWN})) \
                if old_oid is not None else frozenset({ObjectFact.UNKNOWN})
        joined.facts[new_oid] = joined.facts.get(new_oid, frozenset()) | facts
        work.append((new_oid, signature))

    seen_objects: set[ObjectId] = set()
    for root in roots:
        signature = tuple(state.env.get(root) for state in ordered)
        oid = object_for(signature, "phi")
        joined.env[root] = oid
        if oid not in seen_objects:
            seen_objects.add(oid)
            attach(oid, signature)

    while work:
        new_base, old_bases = work.popleft()
        selectors = sorted({selector for state, old_base in zip(ordered, old_bases)
                            for (slot_base, selector) in state.slots if slot_base == old_base})
        for selector in selectors:
            signature = tuple(state.slots.get((old_base, selector))
                              for state, old_base in zip(ordered, old_bases))
            child = object_for(signature, "phi-slot")
            joined.slots[(new_base, selector)] = child
            if child not in seen_objects:
                seen_objects.add(child)
                attach(child, signature)

    trace: list[ParamEffect] = []
    for state in ordered:
        for effect in state.trace:
            if trace.count(effect) < 2 and len(trace) < AbstractState.TRACE_LIMIT:
                trace.append(effect)
    joined.trace = tuple(trace)
    return joined


@dataclass
class AnalysisResult:
    findings: set[Finding]
    exit_states: tuple[AbstractState, ...]
    unplaced: tuple[Operation, ...]
    transfers: int
    widenings: int
    capped: bool


class ObjectStateAnalyzer:
    def __init__(self, *, max_disjuncts: int = 64, transfer_cap: int | None = None):
        if max_disjuncts < 1:
            raise ValueError("max_disjuncts must be positive")
        self.max_disjuncts = max_disjuncts
        self.transfer_cap = transfer_cap

    @staticmethod
    def _transfer(
        states: Iterable[AbstractState],
        operations: Sequence[Operation],
        findings: set[Finding],
    ) -> dict[tuple, AbstractState]:
        current = [state.clone() for state in states]
        for op in operations:
            if op.kind != OpKind.SUMMARY:
                for state in current:
                    state.apply(op, findings)
                continue
            branched: list[AbstractState] = []
            for state in current:
                for alternative in op.alternatives:
                    result = state.clone()
                    for effect in alternative:
                        result.apply(effect, findings)
                    branched.append(result)
            current = branched or current
        return {state.key(): state for state in current}

    def analyze(
        self,
        nodes: Sequence[Hashable],
        successors: Mapping[Hashable, Sequence[Hashable]],
        operations: Iterable[Operation],
        *,
        initial: AbstractState | None = None,
    ) -> AnalysisResult:
        if not nodes:
            return AnalysisResult(set(), (), tuple(operations), 0, 0, False)
        node_set = set(nodes)
        at: dict[Hashable, list[Operation]] = defaultdict(list)
        unplaced = []
        for op in operations:
            if op.node in node_set:
                at[op.node].append(op)
            else:
                unplaced.append(op)
        for placed in at.values():
            placed.sort(key=lambda op: op.ordinal)

        incoming: dict[Hashable, dict[tuple, AbstractState]] = {node: {} for node in nodes}
        seed = initial or AbstractState()
        incoming[nodes[0]][seed.key()] = seed
        work = deque([nodes[0]])
        queued = {nodes[0]}
        findings: set[Finding] = set()
        transfers = widenings = 0
        cap = self.transfer_cap or max(10000, len(nodes) * 500)

        while work and transfers < cap:
            node = work.popleft()
            queued.discard(node)
            outgoing = self._transfer(incoming[node].values(), at.get(node, ()), findings)
            transfers += len(outgoing)
            for successor in successors.get(node, ()):
                if successor not in incoming:
                    continue
                changed = False
                for key, state in outgoing.items():
                    if key not in incoming[successor]:
                        incoming[successor][key] = state
                        changed = True
                if len(incoming[successor]) > self.max_disjuncts:
                    merged = join_states(incoming[successor].values(), successor)
                    incoming[successor] = {merged.key(): merged}
                    widenings += 1
                    changed = True
                if changed and successor not in queued:
                    work.append(successor)
                    queued.add(successor)

        exits: list[AbstractState] = []
        for node in nodes:
            if not successors.get(node):
                exits.extend(self._transfer(incoming[node].values(), at.get(node, ()), findings).values())
        return AnalysisResult(
            findings=findings,
            exit_states=tuple(exits),
            unplaced=tuple(unplaced),
            transfers=transfers,
            widenings=widenings,
            capped=bool(work),
        )
