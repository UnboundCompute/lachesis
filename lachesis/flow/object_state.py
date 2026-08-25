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
from dataclasses import dataclass, field
from enum import Enum
from typing import Hashable, Iterable, Mapping, Sequence

from lachesis.timeit import timeit


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
    REALLOC = "realloc"
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
    # Access form for the frozen skeleton split: dereference, pointer-value pass, or return.
    access: str = "deref"


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


@dataclass(frozen=True, order=True)
class ReturnEffect:
    """A return value borrowed from one formal parameter access path."""

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
        trace: Sequence[ParamEffect | ReturnEffect] = (),
        freed_paths: Mapping[AccessPath, ObjectId] | None = None,
    ):
        self.env = dict(env or {})
        self.facts = dict(facts or {})
        self.slots = dict(slots or {})
        self.trace = tuple(trace)
        # Pointer-field paths freed on this path but not yet reassigned. Book-keeping for
        # the free-then-reallocate compensation; almost always empty between statements.
        self.freed_paths = dict(freed_paths or {})

    def clone(self) -> "AbstractState":
        return AbstractState(self.env, self.facts, self.slots, self.trace,
                             self.freed_paths)

    @timeit(name="object_state.AbstractState.key")
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
            frozenset(self.freed_paths.items()),
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

    def _record_return_effect(self, oid: ObjectId) -> None:
        if not (isinstance(oid, tuple) and len(oid) == 3 and oid[0] == "param"):
            return
        effect = ReturnEffect(oid[1], oid[2])
        if self.trace.count(effect) < 2 and len(self.trace) < AbstractState.TRACE_LIMIT:
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

    def _compensate_reassignment(self, op: Operation) -> None:
        # A reassignment THROUGH a pointer parameter -- a fresh allocation, a null-out,
        # or a pointer copy (``p->buf = realloc(...)`` / ``= NULL`` / ``= tmp``) -- of a
        # path this analysis has already freed restores a caller-visible live (or NULL)
        # object: the caller no longer holds a dangling pointer. Record a compensating
        # ALLOC so a free-then-reallocate idiom is not read as a loop-carried double-free
        # once the summary is instantiated at a callsite. Keyed on the freed access path
        # (not the current object id), so it survives the local rebinding the reassignment
        # itself performs, and on the FIRST reassignment only. A bare-root parameter (no
        # selectors) is by-value -- the caller's own pointer still dangles -- so it is
        # never tracked here and its free stays visible.
        if op.target is None or not op.target.selectors:
            return
        freed_param = self.freed_paths.pop(op.target, None)
        if freed_param is not None:
            self._record_param_effect(OpKind.ALLOC, freed_param)

    def _free_object(
        self,
        oid: ObjectId | None,
        path: AccessPath | None,
        node: Hashable,
        line: int | None,
        findings: set[Finding],
    ) -> None:
        # Mark the object `oid` (named via `path`) freed, raising double-free if it was
        # already freed.  Shared verbatim by FREE and the free-half of REALLOC: realloc
        # may relocate its block, so the object its first argument names is (may-be) freed
        # exactly as free() frees its argument -- no bug-specific logic, both callers get
        # identical typestate, and any surviving alias is caught by the USE-on-FREED path.
        if oid is None:
            return
        self._record_param_effect(OpKind.FREE, oid)
        if (path is not None and path.selectors
                and isinstance(oid, tuple) and len(oid) == 3 and oid[0] == "param"):
            # Remember the freed pointer-field so a later reassignment through it
            # (see _compensate_reassignment) can net the summary back to live.
            self.freed_paths[path] = oid
        facts = self.facts.get(oid, frozenset({ObjectFact.UNKNOWN}))
        # A summary object (identity formed through a variable subscript) may-be-freed
        # abstracts distinct concrete cells; a repeat free of it is not a proven
        # violation of the same object, so it does not raise a strong finding.
        weak = _is_summary_object(oid)
        if ObjectFact.FREED in facts and not weak:
            findings.add(Finding("double-free", line, path, node))
        if facts != frozenset({ObjectFact.NULL}):
            freed = frozenset({ObjectFact.FREED})
            is_summary = len(oid) > 1 and oid[1] == "summary"
            self.facts[oid] = (facts | freed) if is_summary else freed

    def apply(self, op: Operation, findings: set[Finding]) -> None:
        if op.kind == OpKind.ALLOC:
            self._compensate_reassignment(op)
            self._fresh(op, ObjectFact.ALLOCATED)
            return
        if op.kind == OpKind.CLOBBER:
            self._compensate_reassignment(op)
            self._fresh(op, ObjectFact.NULL if op.is_null else ObjectFact.UNKNOWN)
            return
        if op.kind == OpKind.COPY:
            assert op.target is not None and op.source is not None
            self._compensate_reassignment(op)
            self.bind(op.target, self.resolve(op.source, create=True))
            return
        if op.kind == OpKind.REALLOC:
            # realloc(source): the block `source` names may move, so its object is
            # (may-be) freed exactly as free() would -- an interior pointer or alias still
            # bound to it now dangles, and the existing USE-on-FREED check raises the
            # use-after-free with no per-bug rule.  The call also returns a fresh (possibly
            # relocated) object, bound to target like an allocation.  Order matters: the
            # source object is resolved and freed BEFORE target is rebound, so an in-place
            # `p = realloc(p, ...)` still frees the old generation the aliases hold.
            if op.source is not None:
                self._free_object(
                    self.resolve(op.source, create=True),
                    op.source, op.node, op.line, findings,
                )
            self._compensate_reassignment(op)
            self._fresh(op, ObjectFact.ALLOCATED)
            return
        if op.kind not in (OpKind.FREE, OpKind.USE):
            raise ValueError(f"cannot directly apply {op.kind}")

        assert op.target is not None
        oid = self.resolve(op.target, create=(op.kind == OpKind.FREE))
        if oid is None:
            return
        if op.kind == OpKind.USE:
            self._record_param_effect(OpKind.USE, oid)
            if op.access == "return":
                self._record_return_effect(oid)
            facts = self.facts.get(oid, frozenset({ObjectFact.UNKNOWN}))
            # A summary object may-be-freed abstracts distinct concrete cells; a use of it
            # is not a proven violation of the same object, so it stays a weak (no-finding).
            if ObjectFact.FREED in facts and not _is_summary_object(oid):
                findings.add(Finding("use-after-free", op.line, op.target, op.node))
            return

        self._free_object(oid, op.target, op.node, op.line, findings)


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
    # A pending free-not-yet-reassigned in any branch stays pending in the join, so a
    # reassignment after the join still nets the summary to live (param oids are stable
    # under the phi renaming, being keyed on position/selectors, not object identity).
    for state in ordered:
        for path, param_oid in state.freed_paths.items():
            joined.freed_paths.setdefault(path, param_oid)
    return joined


@dataclass
class AnalysisResult:
    findings: set[Finding]
    exit_states: tuple[AbstractState, ...]
    unplaced: tuple[Operation, ...]
    transfers: int
    widenings: int
    capped: bool
    # Abstract states immediately before each CFG node's operations.  Consumers
    # such as the semantic skeleton builder can reuse the field-sensitive,
    # loop-widened identity domain instead of reconstructing it from a flat op
    # stream.  States are snapshots, not mutable analyzer internals.
    point_states: Mapping[Hashable, tuple[AbstractState, ...]] = field(default_factory=dict)
    # States immediately after the operations anchored at each CFG point.  These
    # are retained separately because an ALLOC/REALLOC success has a new identity
    # that cannot be recovered from its incoming state.
    post_states: Mapping[Hashable, tuple[AbstractState, ...]] = field(default_factory=dict)


class _DiscardFindings:
    """Sink used by the production summary interpreter.

    Abstract-state transfer still computes lifecycle facts; vulnerability conclusions belong to
    the semantic graph matcher and are therefore not accumulated here.
    """
    def add(self, _finding):
        return None

    def __iter__(self):
        return iter(())

    def __len__(self):
        return 0


class ObjectStateAnalyzer:
    def __init__(self, *, max_disjuncts: int = 64, transfer_cap: int | None = None,
                 collect_findings: bool = True):
        if max_disjuncts < 1:
            raise ValueError("max_disjuncts must be positive")
        self.max_disjuncts = max_disjuncts
        self.transfer_cap = transfer_cap
        self.collect_findings = collect_findings

    @staticmethod
    @timeit(name="object_state.ObjectStateAnalyzer._transfer")
    def _transfer(
        states: Iterable[AbstractState] | Mapping[tuple, AbstractState],
        operations: Sequence[Operation],
        findings: set[Finding],
    ) -> dict[tuple, AbstractState]:
        if not operations and isinstance(states, Mapping):
            # A control-flow node with no placed operations cannot mutate any incoming
            # state. Preserve the caller's exact keys and state objects; cloning and
            # rehashing these nodes accounted for most of the 1.5M key calls on libxml2.
            return dict(states)
        values = states.values() if isinstance(states, Mapping) else states
        current = [state.clone() for state in values]
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
        seed = initial or AbstractState()
        findings = set() if self.collect_findings else _DiscardFindings()

        # A translated function can have a large control-flow skeleton but no placed
        # object operation (for example a pure wrapper or declaration-only body). Its
        # abstract state is identical on every path, so a fixpoint would only spend time
        # hashing and rejoining the same value. Preserve snapshots for consumers while
        # skipping the solver entirely.
        if not any(at.values()):
            state = seed.clone()
            point_states = {node: (state.clone(),) for node in nodes}
            post_states = {node: (state.clone(),) for node in nodes}
            return AnalysisResult(
                findings=findings,
                exit_states=(state.clone(),),
                unplaced=tuple(unplaced),
                transfers=0,
                widenings=0,
                capped=False,
                point_states=point_states,
                post_states=post_states,
            )

        # Most small helpers have a single straight-line CFG. There is exactly one
        # abstract state on that shape: no join, loop, or summary alternative can create
        # a second state. Carry it directly instead of allocating a keyed state map and
        # hashing five frozensets at every node. The generic fixpoint below remains the
        # authority for every graph with control-flow fan-out, fan-in, or a back-edge.
        linear_index = {node: index for index, node in enumerate(nodes)}
        linear = all(len(successors.get(node, ())) <= 1 for node in nodes)
        linear = linear and all(
            successor in linear_index and linear_index[successor] > linear_index[node]
            for node in nodes
            for successor in successors.get(node, ())
        )
        linear = linear and all(
            op.kind != OpKind.SUMMARY for placed in at.values() for op in placed)
        if linear:
            chain = []
            current = nodes[0]
            seen = set()
            while current is not None and current not in seen:
                seen.add(current)
                chain.append(current)
                next_nodes = successors.get(current, ())
                current = next_nodes[0] if next_nodes else None
            if len(chain) == len(nodes) and set(chain) == set(nodes):
                state = (initial or AbstractState()).clone()
                point_states = {}
                post_states = {}
                for node in chain:
                    point_states[node] = (state.clone(),)
                    for op in at.get(node, ()):
                        state.apply(op, findings)
                    post_states[node] = (state.clone(),)
                return AnalysisResult(
                    findings=findings,
                    exit_states=(state.clone(),),
                    unplaced=tuple(unplaced),
                    transfers=len(chain),
                    widenings=0,
                    capped=False,
                    point_states=point_states,
                    post_states=post_states,
                )

        incoming: dict[Hashable, dict[tuple, AbstractState]] = {node: {} for node in nodes}
        incoming[nodes[0]][seed.key()] = seed
        work = deque([nodes[0]])
        queued = {nodes[0]}
        widened: set[Hashable] = set()
        post_snapshots: dict[Hashable, dict[tuple, AbstractState]] = {
            node: {} for node in nodes
        }
        transfers = widenings = 0
        cap = self.transfer_cap or max(10000, len(nodes) * 500)

        while work and transfers < cap:
            node = work.popleft()
            queued.discard(node)
            outgoing = self._transfer(incoming[node], at.get(node, ()), findings)
            post_snapshots[node].update(
                (key, state.clone()) for key, state in outgoing.items())
            transfers += len(outgoing)
            for successor in successors.get(node, ()):
                if successor not in incoming:
                    continue
                target = incoming[successor]
                new_items = [(key, state) for key, state in outgoing.items()
                             if key not in target]
                # Sticky widening: once a node's disjunct budget is exceeded it stays
                # collapsed to a single joined state, and every later update joins into
                # that state instead of re-expanding. Without this a loop node oscillates
                # -- widen to one state, re-expand past the budget from the back-edge,
                # widen again -- burning the whole transfer budget and capping the
                # function. Collapsing monotonically bounds the lattice height so the
                # fixpoint terminates; the join is a sound may-approximation.
                if (len(target) + len(new_items) > self.max_disjuncts
                        or successor in widened):
                    if not new_items:
                        continue
                    old_keys = tuple(target)
                    candidates = tuple(target.values()) + tuple(
                        state for _key, state in new_items)
                    merged = join_states(candidates, successor)
                    merged_key = merged.key()
                    incoming[successor] = {merged_key: merged}
                    widened.add(successor)
                    widenings += 1
                    changed = old_keys != (merged_key,)
                else:
                    for key, state in new_items:
                        target[key] = state
                    changed = bool(new_items)
                # Re-queue only when the successor's state set actually changed; a
                # collapsed node that re-joins to the same key has reached its fixpoint.
                if changed and successor not in queued:
                    work.append(successor)
                    queued.add(successor)

        exits: list[AbstractState] = []
        for node in nodes:
            if not successors.get(node):
                # Exit nodes have no successors, so they cannot be re-queued after their
                # first transfer. ``post_snapshots`` already contains their outgoing
                # states; re-running the transfer here duplicated the hottest state-key
                # hashing step for every terminal node.
                exits.extend(post_snapshots[node].values())
        point_states = {
            node: tuple(state.clone() for state in states.values())
            for node, states in incoming.items()
        }
        post_states = {
            node: tuple(states.values()) for node, states in post_snapshots.items()
        }
        return AnalysisResult(
            findings=findings,
            exit_states=tuple(exits),
            unplaced=tuple(unplaced),
            transfers=transfers,
            widenings=widenings,
            capped=bool(work),
            point_states=point_states,
            post_states=post_states,
        )
