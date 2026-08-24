#!/usr/bin/env python3
"""Native universal-IR emitter -- project the object-identity operation stream into the
language-neutral skeleton (:mod:`lachesis.flow.skeleton_ir`).

WHY A NATIVE EMITTER (vs the legacy adapter)
--------------------------------------------
``skeleton_ir.from_flow_skeleton`` lifts the *legacy* name-keyed token stream
(``skeleton.py`` over ``summarize.py``). That stream is C-flavoured and, crucially, does
NOT carry standalone dereferences (``buf[0]`` after a free), field-sensitive identity, or
allocation generations -- so a use-after-free whose use is a bare deref never renders.

The *object* engine (:mod:`lachesis.flow.object_state` + :mod:`object_lifetime`) already
solves those: :func:`object_lifetime.extract_operations` recovers every alloc/free/use/copy/
clobber/interproc-effect with a declaration-rooted, field-sensitive :class:`AccessPath`, and
the abstract interpreter models allocation recency (a generation model) and path
correlation. That engine is the right substrate for "all cases in a language" -- but it
BAKES its bug patterns into ``AbstractState.apply`` (use-after-free / double-free are
hard-coded there).

This module makes the object engine's operation stream a first-class, serialisable
**universal skeleton**, so the bug patterns move OUT of the engine and become external
role-patterns (``skeleton_ir.UNIVERSAL_PATTERNS`` today; atropos data tomorrow). Two sides,
cleanly separated: the SKELETON (here, projected from the rich substrate) and the PATTERNS
(data, matched by ``skeleton_ir.match_universal``).

WHAT THIS FIRST CUT DOES / DOES NOT DO (honest scope)
-----------------------------------------------------
DOES: emit one typestate skeleton per function from the real object-engine operation stream
-- including standalone-deref USE events the legacy stream drops -- with field-sensitive
:class:`ObjRef` identity, and run the universal role-patterns over it.

DOES NOT (yet): carry the engine's *path-sensitive* per-point ObjectId, so co-reference here
is syntactic (same access path) rather than the engine's alias/recency identity. That means
(a) the linear stream is a may-approximation of control flow -- correct for a recall-oriented
finder, looser than the engine's CFG precision; (b) an alias introduced by COPY
(``cursor = b->data``) is not yet unified with its source object. Generation is computed at
the skeleton layer from rebinding order (transparent, see ``_generations``); wiring the
engine's ObjectId through is the next increment.
"""
from __future__ import annotations

import argparse
import ast
import json
import re
from collections import defaultdict

from lachesis.nav.dataflow.reaching_def import ReachingDef
from lachesis.nav.dataflow.substrate import Substrate

from . import atropos, skeleton_ir as ir
from .normalize import normalizer
from .patterns import evaluator_for
from .object_lifetime import (APBuilder, _argument_path, _path,
                               extract_operations, _props)
from .object_state import AccessPath, OpKind
from .pipeline import _lifetime_slice
from .semantic_graph import Event, EventKind, GuardProof, ObjRef, SkeletonGraph


# --- OpKind -> universal verb (roles are then looked up in skeleton_ir.VERB_ROLES) ------
# The verb is the concrete, per-language spelling; the ROLE is what patterns match on. We
# pick a canonical verb per OpKind so roles_for() classifies it. USE is a pointee
# read/observe; CLOBBER rebinds the name to a fresh (unknown/null) object -> REINIT.
_OP_VERB = {
    OpKind.ALLOC: "alloc",
    OpKind.FREE: "free",
    OpKind.REALLOC: "realloc",  # INVALIDATE(old generation) + REINIT(new) -- see VERB_ROLES
    OpKind.USE: "deref",
    OpKind.COPY: "copy",
    OpKind.CLOBBER: "reassign",
}

_SUBOBJECT = ("->", ".", "[", "*")


def _readable_root(sub, root: str, scope=None) -> str:
    """Render an AccessPath root (``decl:<id>`` / ``param``) as a stable, readable base.

    Local names remain readable, but ownerless declarations are program-scope storage
    identities.  Qualifying those roots with their declaration id keeps two same-named
    globals/statics from collapsing while preserving one identity across every function
    that refers to the same declaration.  This is the same declaration-vs-call-context
    distinction used by the object-state layer; a bare spelling is not a sufficient whole-
    program identity for persistent storage."""
    if root.startswith("decl:"):
        node_id = root[len("decl:"):]
        label = sub.label(node_id) or node_id
        shadowed = getattr(sub, "_shadowed_roots", None)
        if shadowed is None:
            declarations = []
            for candidate in sub.idx.nodes_of_kind("variable", "parameter"):
                props = candidate.get("properties") or {}
                owner = props.get("owner_function_id") or props.get("function_id")
                if not owner:
                    continue
                declarations.append((owner, candidate.get("label")))
            # Only labels with multiple declarations in one function need a
            # declaration discriminator; ordinary output remains readable.
            counts = defaultdict(int)
            for owner, name in declarations:
                counts[(owner, name)] += 1
            shadowed = {(owner, name) for owner, name in declarations
                        if counts[(owner, name)] > 1}
            sub._shadowed_roots = shadowed
        owner = sub.props(node_id).get("owner_function_id") or sub.props(node_id).get("function_id")
        if owner is None:
            return f"{label}@{node_id}"
        if (owner, label) in shadowed:
            return f"{label}@{node_id}"
        return label
    return root


def _objref(sub, path, generation: int = 0):
    """AccessPath -> universal ObjRef (base = readable root, path = selectors)."""
    if path is None:
        return None
    return ir.ObjRef(base=_readable_root(sub, path.root),
                     path=tuple(path.selectors), generation=generation)


def _flatten(operations):
    """Flatten SUMMARY alternatives into their constituent FREE/USE effects.

    A SUMMARY op is a path-sensitive disjunction over how a callee may act on the arg. For a
    recall-oriented linear skeleton we surface the union of effects (may-semantics: an effect
    that occurs on ANY alternative is a possible effect on the stitched path). The judge
    downstream prunes arms the abstraction could not separate."""
    flat = []
    for op in operations:
        if op.kind == OpKind.SUMMARY:
            seen = set()
            for alternative in op.alternatives:
                for effect in alternative:
                    key = (effect.kind, effect.target, effect.line)
                    if key in seen:
                        continue
                    seen.add(key)
                    flat.append(effect)
        else:
            flat.append(op)
    return flat


def _generations(ordered, sub):
    """Assign a generation to each op's target, incremented when an ALLOC/CLOBBER rebinds
    the SAME access path. A fresh allocation into a path that was live is a new generation;
    this dissolves the realloc/reassign 'same name, different object' family at the skeleton
    layer. (The engine models this precisely via ObjectId recency; here it is a transparent
    ordering fact so the emitted skeleton is self-contained.)"""
    gen = defaultdict(int)
    out = []
    for op in ordered:
        target = op.target
        tkey = (target.root, tuple(target.selectors)) if target is not None else None
        if op.kind in (OpKind.ALLOC, OpKind.CLOBBER, OpKind.REALLOC) and tkey is not None:
            # a rebind of an already-seen path opens a new generation (realloc rebases the
            # name onto a fresh block; the old generation the aliases hold is now dead)
            if tkey in gen:
                gen[tkey] += 1
        out.append(gen[tkey] if tkey is not None else 0)
    return out


def emit_function(sub, norm, function_id, function_ir, all_functions, obj_summaries, cfg,
                  lang="c"):
    """One universal typestate Skeleton per tracked object in ``function_ir``.

    We emit a SINGLE skeleton carrying every object's ordered events (the matcher scopes by
    ObjRef), which keeps cross-object ordering (a free of X then a use of X) intact and lets
    a future pattern reference more than one object."""
    operations = extract_operations(
        sub, norm, function_id, function_ir, all_functions, obj_summaries, cfg)
    flat = _flatten(operations)
    # stable linear order: by line then ordinal (the engine's serialisation order)
    ordered = sorted(flat, key=lambda op: (op.line or 0, op.ordinal))
    gens = _generations(ordered, sub)

    events = []
    name = function_ir.get("name") or (sub.label(function_id) or "?")
    events.append(ir.Event.seam_enter(name, 0))
    for op, generation in zip(ordered, gens):
        verb = _OP_VERB.get(op.kind)
        if verb is None:
            continue
        obj = _objref(sub, op.target, generation)
        if obj is None:
            continue
        ev = ir.Event.op(verb, obj, 1, line=op.line, node=op.node, fn=name)
        if op.source is not None:
            ev.facts["source"] = _objref(sub, op.source).render()
        events.append(ev)
    events.append(ir.Event.seam_exit(name, 0))

    return ir.Skeleton(kind="typestate", entry=name, lang=lang, events=events,
                       is_source=function_ir.get("is_source", False))


def build_universal_skeletons(store, F, succ, lang="c", graph=None):
    """Project the object-engine operation stream over the whole graph into universal
    skeletons. Returns list[Skeleton]. Reuses the object engine's own setup (Substrate,
    per-function CFG, interprocedural summaries) so identity/field-sensitivity match it."""
    from .object_lifetime import analyze_object_lifetimes

    functions = _lifetime_slice(F, succ, lang=lang)
    if not functions:
        return []
    sub_succ = {n: [c for c in succ.get(n, ()) if c in functions] for n in functions}
    # the object engine's own run gives us the interprocedural summaries extract_operations
    # composes at call sites (SUMMARY ops), plus the trust diagnostics.
    result = analyze_object_lifetimes(store, functions, sub_succ, lang=lang, graph=graph)
    obj_summaries = result.summaries

    analysis_graph = graph if graph is not None else store.graph
    if analysis_graph is not None and analysis_graph is not store.graph:
        from lachesis.nav.graph_store import GraphStore
        analysis_store = GraphStore(analysis_graph)
    else:
        analysis_store = store
    sub = Substrate(analysis_store.index).load().load_initializers()
    norm = normalizer(lang)

    by_name = {}
    for node in analysis_store.index.nodes_of_kind("function", "method", "constructor"):
        if _props(node).get("declaration_only"):
            continue
        nm = node.get("label")
        if nm in functions and nm not in by_name:
            by_name[nm] = node["id"]
    sub.warm_owned(by_name.values())

    skels = []
    for nm, fid in by_name.items():
        cfg = ReachingDef(sub).analyze(fid, reaching_defs=False)
        if cfg is None or cfg.get("bailed"):
            continue
        skels.append(emit_function(sub, norm, fid, functions[nm], functions,
                                   obj_summaries, cfg, lang=lang))
    return skels


def _semantic_obj(sub, path, generation="g0", scope=None):
    if path is None:
        return None
    return ObjRef(base=_readable_root(sub, path.root, scope), path=tuple(path.selectors),
                  generation=generation)


def _semantic_key(sub, path):
    if path is None:
        return None
    return (_readable_root(sub, path.root), tuple(path.selectors))


def _next_generation(current):
    if isinstance(current, str) and current.startswith("g") and current[1:].isdigit():
        return f"g{int(current[1:]) + 1}"
    return "g1"


def _operation_generations(sub, operations, cfg=None):
    """Assign incarnations only when a prior rebind dominates the operation.

    Source order is not execution order: allocations in sibling CFG arms must
    share the same abstract generation at their join, while ``p = alloc(); free(p);
    p = alloc()`` must advance it.  Dominance captures exactly that distinction
    without inventing a path-sensitive generation set in the frozen graph.
    Loop re-entry remains an explicit matcher widening event.
    """
    generations = {}
    fresh = {}
    ordered = sorted(
        enumerate(operations),
        key=lambda item: (sub.offset(item[1].node), item[1].line or 0,
                          item[1].ordinal, item[1].kind.value, item[0]))

    nodes = tuple((cfg or {}).get("nodes", ()))
    successors = {node: tuple((cfg or {}).get("succ", {}).get(node, ()))
                  for node in nodes}
    predecessors = defaultdict(set)
    for source, targets in successors.items():
        for target in targets:
            if target in successors:
                predecessors[target].add(source)
    entry = (cfg or {}).get("entry") or (nodes[0] if nodes else None)
    dominators = {}
    if entry is not None and nodes:
        all_nodes = set(nodes)
        dominators = {node: ({node} if node == entry else set(all_nodes))
                      for node in nodes}
        changed = True
        while changed:
            changed = False
            for node in nodes:
                if node == entry:
                    continue
                incoming = predecessors.get(node, set())
                candidate = ({node} | set.intersection(
                    *(dominators[parent] for parent in incoming))) if incoming else {node}
                if candidate != dominators[node]:
                    dominators[node] = candidate
                    changed = True

    def dominates(left, right):
        if left == right:
            return True
        return left in dominators.get(right, {right})

    history = defaultdict(list)
    for position, (_original_index, operation) in enumerate(ordered):
        key = _semantic_key(sub, operation.target)
        if key is None:
            continue
        prior = [item for item in history[key]
                 if (item[0] < position and
                     dominates(item[1].node, operation.node))]
        generation = max(
            (item[2] for item in prior),
            key=lambda value: int(value[1:]) if isinstance(value, str)
            and value.startswith("g") and value[1:].isdigit() else -1,
            default="g0")
        if operation.kind == OpKind.ALLOC:
            generation = _next_generation(generation) if prior else "g0"
            generations[operation] = generation
            history[key].append((position, operation, generation))
        elif operation.kind == OpKind.REALLOC:
            generations[operation] = generation
            fresh_generation = _next_generation(generation)
            fresh[operation] = fresh_generation
            history[key].append((position, operation, fresh_generation))
        else:
            generations[operation] = generation
            if operation.kind == OpKind.CLOBBER:
                history[key].append((position, operation, generation))
    return generations, fresh


def _loop_nodes(cfg):
    """Return CFG nodes belonging to a real back-edge cycle.

    ReachingDef preserves the frontend CFG, but does not annotate loop bodies
    as a separate semantic region.  For generation widening we identify the
    cycle structurally: nodes reachable from a back-edge target that can also
    reach the back-edge source.  This is language-neutral and avoids relying
    on source spelling or loop keywords.
    """
    nodes = set(cfg.get("nodes", ()))
    successors = {
        node: tuple(target for target in cfg.get("succ", {}).get(node, ())
                    if target in nodes)
        for node in nodes
    }
    reverse = defaultdict(set)
    for source, targets in successors.items():
        for target in targets:
            reverse[target].add(source)

    def walk(start, adjacency):
        seen, pending = set(), [start]
        while pending:
            current = pending.pop()
            if current in seen:
                continue
            seen.add(current)
            pending.extend(adjacency.get(current, ()))
        return seen

    result = set()
    for source, targets in successors.items():
        for target in targets:
            # Any edge whose target can reach its source is a back edge in the
            # structural sense, independent of frontend node ordering.
            if target not in nodes or source not in nodes:
                continue
            if source not in walk(target, successors):
                continue
            result.update(walk(target, successors) & walk(source, reverse))
    return result


def _semantic_event(sub, operation, generations=None):
    """Translate one object-engine fact to a frozen-schema event.

    This translation intentionally emits facts only.  No UAF/double-free state is stamped here;
    :func:`match_graph` derives those findings later.
    """
    generations = generations or {}
    if (operation.kind == OpKind.CLOBBER
            and operation.access == "return-null"):
        return [Event(EventKind.RETURN_VALUE,
                      line=operation.line, facts={"return_null": True}),
                Event(EventKind.RETURN, line=operation.line,
                      facts={"return_null": True})]
    target_key = _semantic_key(sub, operation.target)
    generation = generations.get(operation, generations.get(target_key, "g0"))
    obj = _semantic_obj(sub, operation.target, generation, operation.node)
    if operation.kind == OpKind.ALLOC:
        if not obj:
            return []
        facts = {"allocation_site": str(operation.site or operation.node),
                 "generation": generation}
        return [Event.alloc_attempt(result=obj, line=operation.line),
                Event.origin(obj, operation.line, facts=facts)]
    if operation.kind == OpKind.FREE:
        return [Event.release(obj, operation.line)] if obj else []
    if operation.kind == OpKind.REALLOC:
        if not obj:
            return []
        fresh = ObjRef(obj.base, obj.path, f"{obj.generation}+1")
        facts = {"allocation_site": str(operation.site or operation.node),
                 "generation": fresh.generation, "incarnation": "realloc-success"}
        return [Event.realloc_attempt(obj, operation.line),
                Event(EventKind.INVALIDATE, obj=obj, line=operation.line),
                Event.origin(fresh, operation.line, facts=facts)]
    if operation.kind == OpKind.USE and obj:
        if operation.access == "pointer-arithmetic":
            source_key = _semantic_key(sub, operation.source)
            source = (_semantic_obj(sub, operation.source,
                                    generations.get(source_key, "g0"), operation.node)
                      if operation.source is not None else None)
            return [Event(EventKind.POINTER_ARITHMETIC, obj=obj, base=source,
                          line=operation.line,
                          facts={"validated": False})]
        # The operation target is already the dereference base selected by Claus:
        # ``p->field`` targets ``p``, while ``b->data[i]`` targets the field-pointee
        # ``b->data``.  Preserve that distinction.  Stripping selectors here makes
        # ``free(b->data); b->data[i]`` compare a field-pointee release against the
        # containing aggregate and silently loses the cross-function field fact.
        access_path = "".join(operation.target.selectors) or "*"
        storage_obj = obj
        if operation.access == "pass":
            return [Event.pass_value(obj, operation.line)]
        if operation.access == "compare":
            return [Event(EventKind.COMPARE_VALUE, obj=obj, line=operation.line)]
        if operation.access == "return":
            return [Event(EventKind.RETURN_VALUE, obj=obj, line=operation.line),
                    Event.escape(obj, operation.line),
                    Event(EventKind.RETURN, obj=obj, line=operation.line)]
        if operation.access == "return-stack":
            return [Event(EventKind.RETURN_VALUE, obj=obj, line=operation.line,
                          facts={"stack_local": True}),
                    Event.escape(obj, operation.line),
                    Event(EventKind.RETURN, obj=obj, line=operation.line)]
        if operation.access == "write":
            source_key = _semantic_key(sub, operation.source)
            value = (_semantic_obj(sub, operation.source,
                                   generations.get(source_key, "g0"), operation.node)
                      if operation.source is not None else None)
            events = [Event.write(storage_obj, access_path, operation.line, value=value)]
            # An address-of a function-local stored into an out-parameter or
            # persistent slot escapes the activation even though the source
            # operation is a write rather than a return statement.  Keep this
            # as a semantic RETURN_VALUE fact so the typestate matcher can
            # report use-after-return without baking the sink shape into it.
            source_root = operation.source.root if operation.source is not None else ""
            source_id = source_root[len("decl:"):] if source_root.startswith("decl:") else None
            source_props = sub.props(source_id) if source_id else {}
            stack_address = bool(
                value is not None
                and operation.source is not None
                and "&" in operation.source.selectors
                and source_id
                and (source_props.get("owner_function_id")
                     or source_props.get("function_id")))
            if stack_address:
                events.append(Event(EventKind.RETURN_VALUE, obj=value,
                                    line=operation.line,
                                    facts={"stack_local": True,
                                           "escape_store": True}))
            # A declaration with no owning function is persistent program storage;
            # storing a live object there is an explicit escape from the current
            # activation.  Do not apply this shortcut to ordinary field stores:
            # their lifetime still depends on the containing object's ownership.
            target_root = operation.target.root
            if (value is not None and target_root.startswith("decl:")
                    and not (sub.props(target_root[len("decl:"):]).get("owner_function_id")
                             or sub.props(target_root[len("decl:"):]).get("function_id"))):
                events.extend((
                    Event(EventKind.DERIVE, obj=storage_obj, value=value,
                          line=operation.line,
                          facts={"persistent_slot": True}),
                    Event.escape(value, operation.line),
                ))
            return events
        return [Event.read(storage_obj, access_path, operation.line)]
    if operation.kind == OpKind.COPY and obj:
        source_key = _semantic_key(sub, operation.source)
        source = _semantic_obj(sub, operation.source, generations.get(source_key, "g0"), operation.node)
        return [Event(EventKind.DERIVE, obj=obj, value=source, line=operation.line)]
    if operation.kind == OpKind.CLOBBER and obj:
        if operation.access == "source":
            return [Event.origin(obj, operation.line)]
        if operation.is_null:
            return [Event.write_null(obj, operation.line)]
        return [Event(EventKind.DERIVE, obj=obj, line=operation.line)]
    return []


def _native_object_substrate(graph):
    """Probe for the declaration/AST roles required by the rich emitter.

    This is a substrate capability check, not a language dispatch.  Frontends without
    these roles still use the frontend-neutral F-IR graph builder below.
    """
    if not isinstance(graph, dict):
        return False
    syntax = {
        (_props(node).get("syntax_kind"))
        for node in graph.get("nodes", ())
    }
    return "DeclRefExpr" in syntax and "CallExpr" in syntax


def _ir_guard_proofs(call):
    """Translate neutral call-site guard facts into matcher-compatible proofs."""
    proofs = []
    for guard in call.get("guards", ()):
        canon = str(guard.get("canon") or "")
        var = str(guard.get("var") or "")
        compact = canon.replace(" ", "").lower()
        value = f"{var}#g0" if var else canon
        if any(token in compact for token in ("!=null", "null!=", "isnotnone", "isnotnull")):
            proofs.append(GuardProof("NONNULL", value))
        elif any(token in compact for token in ("==null", "null==", "isnone", "isnull")):
            proofs.append(GuardProof("ISNULL", value))
        elif canon:
            proofs.append(GuardProof("VALUE", canon))
    return tuple(proofs)


def _ir_ref(value):
    return ObjRef(str(value), generation="g0") if value else None


def _ir_event(record):
    """Decode frontend-neutral lifecycle/value facts into frozen events.

    F-IR deliberately carries semantic roles rather than C syntax.  Keeping this
    adapter expressive means a non-C frontend can preserve aliases and storage
    accesses for the same graph matcher without opting into the C declaration
    substrate.
    """
    kind = str(record.get("kind") or "").lower().replace("-", "_")
    line = record.get("line")
    obj = _ir_ref(record.get("var") or record.get("obj") or record.get("target"))
    base = _ir_ref(record.get("base") or record.get("var") or record.get("obj"))
    value = _ir_ref(record.get("value") or record.get("source"))
    path = record.get("path") or "*"
    if isinstance(path, (tuple, list)):
        path = "".join(str(part) for part in path)
    if kind in {"alloc", "origin"} and obj:
        return Event.origin(obj, line, facts={"frontend_ir": True})
    if kind in {"free", "release", "invalidate"} and obj:
        return Event(EventKind.INVALIDATE if kind == "invalidate" else EventKind.RELEASE,
                     obj=obj, line=line)
    if kind in {"use", "read", "deref"} and base:
        return Event.read(base, str(path), line)
    if kind in {"write", "store"} and base:
        raw_value = record.get("value")
        if (record.get("null") or
                ("value" in record and raw_value is None) or
                str(raw_value).lower() == "null"):
            return Event.write_null(base, line)
        return Event.write(base, str(path), line, value=value)
    if kind in {"derive", "copy", "alias"} and obj:
        return Event(EventKind.DERIVE, obj=obj, value=value, line=line)
    if kind in {"pass", "pass_value"} and obj:
        return Event.pass_value(obj, line)
    if kind in {"compare", "compare_value"} and obj:
        return Event(EventKind.COMPARE_VALUE, obj=obj, line=line)
    if kind == "global_store" and obj:
        # Persistent slots retain an alias across function boundaries; encode
        # that relation explicitly instead of reducing the store to escape.
        return Event(EventKind.DERIVE, obj=obj, value=value, line=line,
                     facts={"persistent_slot": True})
    if kind == "escape" and obj:
        return Event.escape(obj, line)
    if kind in {"return", "return_value"}:
        if obj:
            return Event(EventKind.RETURN_VALUE, obj=obj, line=line,
                         facts=dict(record.get("facts") or {}))
        if record.get("null"):
            return Event(EventKind.RETURN_VALUE, line=line,
                         facts={"return_null": True})
    if kind == "realloc_attempt" and obj:
        return Event.realloc_attempt(obj, line)
    if kind == "realloc_failed" and obj:
        return Event.realloc_failed(obj, record.get("slot") and _ir_ref(record["slot"]), line)
    if kind == "lost_from_slot" and obj:
        return Event(EventKind.LOST_FROM_SLOT, obj=obj,
                     slot=_ir_ref(record.get("slot")), line=line)
    return None


def _ir_lifecycle_events(call, norm, ref):
    """Lift catalogued lifecycle calls into neutral events.

    Frontends that do not expose the C object substrate still provide normalized
    calls.  Alloc/acquire and release roles are unambiguous at this boundary;
    realloc is deliberately represented only as an attempt unless the frontend
    also supplies explicit success/failure facts.
    """
    callee = call.get("callee")
    line = call.get("line")

    def argument(position=0):
        item = next((arg for arg in call.get("args", ())
                     if arg.get("pos") == position), None)
        if item is None:
            return None
        return ref(item.get("root") or item.get("var") or item.get("value"))

    if norm.is_realloc(callee):
        old = argument()
        return [Event(EventKind.REALLOC_ATTEMPT, obj=old, line=line,
                      facts={"frontend_ir": True, "callee": callee})] if old else []
    if norm.is_release(callee):
        released = argument()
        if released is None:
            # Managed-language lifecycle methods carry ownership on the
            # receiver rather than a positional argument (resource.close(),
            # stream.destroy(), ...).  Frontends use slightly different names
            # for that neutral field; accept the normalized aliases here.
            receiver = (call.get("receiver") or call.get("receiver_root")
                        or call.get("receiver_value"))
            released = ref(receiver)
        return [Event(EventKind.RELEASE, obj=released, line=line,
                      facts={"frontend_ir": True, "callee": callee})] if released else []
    if norm.is_acquire(callee):
        acquired = ref(call.get("assigned"))
        return [Event(EventKind.ORIGIN, obj=acquired, line=line,
                      facts={"frontend_ir": True, "callee": callee})] if acquired else []
    return []


def _source_call_tokens(record):
    """Return stable source-site tokens for a frontend-neutral function record."""
    tokens = set()
    for site in (record.get("source_sites", ()) or ()):
        tokens.add(str(site.get("node") or
                       f"{site.get('callee') or 'source'}@{site.get('line') or 0}"))
    for site in (record.get("source_calls", ()) or ()):
        tokens.add(str(site.get("node") or
                       f"{site.get('callee') or 'source'}@{site.get('line') or 0}"))
    return tokens


def _callback_dispatch_targets(functions):
    """Map callback formals to function-valued actuals in the projected IR."""
    targets = defaultdict(set)
    for caller_ir in functions.values():
        for call in caller_ir.get("calls", ()):
            callee = call.get("callee")
            callee_ir = functions.get(callee)
            if callee_ir is None:
                continue
            formals = tuple(callee_ir.get("params", ()))
            for argument in call.get("args", ()):
                position = argument.get("pos")
                actual = argument.get("root")
                if (isinstance(position, int) and position < len(formals)
                        and actual in functions and actual != callee):
                    targets[(callee, formals[position])].add(actual)
    return targets


def _dispatch_targets(functions, callback_targets, caller, call):
    callee = call.get("callee")
    if callee in functions:
        return (callee,)
    return tuple(sorted(callback_targets.get((caller, callee), ())))


def _build_cfg_ir_semantic_graph(functions, *, lang):
    """Build the F-IR graph over neutral CFG edges when no interprocedural seam is needed."""
    result = SkeletonGraph(language=lang)
    entries, exits = {}, {}
    pending_calls = []
    sink_catalog = atropos.sink_catalog(lang)
    norm = normalizer(lang)
    callback_targets = _callback_dispatch_targets(functions)

    def ref(value):
        return ObjRef(str(value), generation="g0") if value else None

    def event_for(record):
        return _ir_event(record)

    for fn in sorted(functions):
        record = functions[fn]
        cfg = record.get("cfg") or {}
        cfg_nodes = tuple(cfg.get("nodes") or ())
        if not cfg_nodes:
            continue
        reachable = bool(record.get("source_reachable") or record.get("is_source"))
        source_tokens = _source_call_tokens(record)
        successor_map = cfg.get("succ") or {}
        event_by_anchor = defaultdict(list)
        call_by_anchor = defaultdict(list)
        for index, event_record in enumerate(record.get("events", ())):
            event_node = event_record.get("node")
            if event_node in cfg_nodes:
                event_by_anchor[event_node].append((index, event_record))
        for index, call in enumerate(record.get("calls", ())):
            call_node = call.get("node")
            if call_node in cfg_nodes:
                call_by_anchor[call_node].append((index, call))
        tails = {}
        heads = {}
        for cfg_node in cfg_nodes:
            outgoing = successor_map.get(cfg_node, ())
            graph_node = f"{fn}:ir:cfg:{cfg_node}"
            if len(outgoing) > 1:
                structural = Event(EventKind.BRANCH, facts={"frontend_ir": True})
            elif any(edge.get("kind") == "LOOP_BACK" for edge in outgoing):
                structural = Event(EventKind.LOOP, facts={"frontend_ir": True})
            else:
                structural = None
            result.add_node(graph_node, structural, fragment=fn,
                            source_reachable=reachable)
            heads[cfg_node] = graph_node
            tail = graph_node
            items = [("event", index, item)
                     for index, item in event_by_anchor.get(cfg_node, ())]
            items.extend(("call", index, item)
                         for index, item in call_by_anchor.get(cfg_node, ()))
            items.sort(key=lambda item: (
                item[2].get("line") if item[2].get("line") is not None else 10**12,
                item[1], 0 if item[0] == "event" else 1))
            for item_kind, index, item in items:
                if item_kind == "event":
                    event = event_for(item)
                    if event is None:
                        continue
                    event_id = f"{fn}:ir:event:{index}"
                    result.add_node(event_id, event, fragment=fn,
                                    source_reachable=reachable)
                    result.add_edge(tail, event_id)
                    tail = event_id
                    continue
                callee = item.get("callee")
                call_token = str(item.get("node") or
                                 f"{callee or 'source'}@{item.get('line') or 0}")
                if call_token in source_tokens:
                    launch_id = f"{fn}:ir:source:{index}"
                    result.add_node(launch_id, None, fragment=fn,
                                    source_reachable=True, source_site=call_token)
                    result.add_edge(tail, launch_id)
                    result.source_reachable.add(launch_id)
                    tail = launch_id
                for lifecycle_index, lifecycle_event in enumerate(
                        _ir_lifecycle_events(item, norm, ref)):
                    lifecycle_id = f"{fn}:ir:lifecycle:{index}:{lifecycle_index}"
                    result.add_node(lifecycle_id, lifecycle_event,
                                    fragment=fn, source_reachable=reachable)
                    result.add_edge(tail, lifecycle_id)
                    tail = lifecycle_id
                catalog_entry = sink_catalog.get(callee) or {}
                for arg_pos in dict.fromkeys(catalog_entry.get("sink_args", ())):
                    argument = next((arg for arg in item.get("args", ())
                                     if arg.get("pos") == arg_pos), None)
                    if argument is None:
                        continue
                    family = (catalog_entry.get("kinds") or {}).get(arg_pos)
                    family = family or catalog_entry.get("family")
                    if not family:
                        continue
                    guarded = bool(item.get("guards"))
                    recipe = evaluator_for(family)
                    relational = (recipe == "relational" or
                                  isinstance(recipe, (list, tuple))
                                  and "relational" in recipe)
                    sink_obj = ref(argument.get("root") or argument.get("var") or callee)
                    sink_id = f"{fn}:ir:cfg-sink:{index}:{arg_pos}"
                    result.add_node(sink_id, Event(
                        EventKind.SINK, obj=sink_obj, line=item.get("line"), facts={
                            "family": family, "callee": callee, "arg": arg_pos,
                            "tainted": argument.get("provenance") != "const",
                            "guarded": guarded,
                            "guard_status": item.get("guard_status"),
                            "guard_predicates": item.get("guard_predicates") or (),
                            "bound": ("bounded" if guarded else "unbounded")
                                     if relational else None,
                            "size_expr": item.get("size_expr"),
                            "dst": item.get("dst"),
                            "control": item.get("control") or (),
                        }), fragment=fn, source_reachable=reachable)
                    result.add_edge(tail, sink_id)
                    tail = sink_id
                targets = _dispatch_targets(functions, callback_targets, fn, item)
                if not targets:
                    continue
                enter = f"{fn}:ir:call:{index}:enter"
                continuation = f"{fn}:ir:call:{index}:return"
                result.add_node(enter, Event(EventKind.SEAM_ENTER,
                                             line=item.get("line")), fragment=fn,
                                source_reachable=reachable)
                result.add_node(continuation, Event(EventKind.SEAM_EXIT,
                                                    line=item.get("line")), fragment=fn,
                                source_reachable=reachable)
                result.add_edge(tail, enter)
                for target in targets:
                    formals = tuple(functions[target].get("params", ()))
                    bindings = []
                    for argument in item.get("args", ()):
                        position = argument.get("pos")
                        if isinstance(position, int) and position < len(formals):
                            actual = ref(argument.get("root") or argument.get("var"))
                            formal = ref(formals[position])
                            if actual is not None and formal is not None:
                                bindings.append((formal, actual))
                    return_bindings = []
                    receiver = ref(item.get("assigned"))
                    if receiver is not None:
                        for returned in functions[target].get("returns", ()):
                            returned_ref = ref(returned.get("var"))
                            if returned_ref is not None and returned.get("kind") in {"var", "call"}:
                                return_bindings.append((receiver, returned_ref))
                    pending_calls.append((enter, target, continuation, tuple(bindings),
                                          tuple(return_bindings), _ir_guard_proofs(item)))
                tail = continuation
            tails[cfg_node] = tail
        for cfg_node in cfg_nodes:
            source = tails[cfg_node]
            for edge_index, edge in enumerate(successor_map.get(cfg_node, ())):
                target = edge.get("target")
                if target not in heads:
                    continue
                guard = ()
                if edge.get("kind") in {"TRUE_BRANCH", "FALSE_BRANCH"}:
                    predicate = str(edge.get("predicate") or cfg_node)
                    predicate = predicate.removeprefix("condition:").strip()
                    proof_value = (f"{predicate}==TRUE"
                                   if edge.get("kind") == "TRUE_BRANCH"
                                   else f"{predicate}!=TRUE")
                    guard = (GuardProof("VALUE", proof_value),)
                if edge.get("kind") == "LOOP_BACK":
                    loop_id = f"{fn}:ir:loop:{cfg_node}:{edge_index}"
                    result.add_node(loop_id, Event(EventKind.LOOP,
                                                    facts={"frontend_ir": True}),
                                    fragment=fn, source_reachable=reachable)
                    result.add_edge(source, loop_id)
                    result.add_edge(loop_id, heads[target], guard=guard)
                else:
                    result.add_edge(source, heads[target], guard=guard)
        entry = cfg.get("entry") or cfg_nodes[0]
        entry = heads.get(entry, heads[cfg_nodes[0]])
        entries[fn] = entry
        if reachable and not any(
                result.nodes[node_id].metadata.get("source_site")
                for node_id in result.source_reachable
                if node_id in result.nodes
                and result.nodes[node_id].fragment == fn):
            result.source_reachable.add(entry)
        function_exits = {tails[node] for node in cfg_nodes
                          if not successor_map.get(node)}
        exits[fn] = function_exits
        result.add_fragment(fn, entry, function_exits,
                            params=record.get("params", ()))
    for enter, callee, continuation, bindings, return_bindings, guards in pending_calls:
        result.add_edge(enter, entries[callee], kind="call", return_to=continuation,
                        binding=bindings, guard=guards)
        for callee_exit in exits[callee]:
            result.add_edge(callee_exit, continuation, kind="return",
                            binding=return_bindings)
    result.validate()
    return result


def _build_ir_semantic_graph(functions, successors, *, lang):
    """Build a conservative semantic graph from translated frontend-neutral IR.

    The F-IR path preserves lifecycle order, source roots, and pushdown call/return
    seams for frontends that do not yet expose declaration-rooted heap identities.
    It intentionally does not invent aliases or branch proofs that the frontend did
    not emit; richer frontend overlays can be added without changing the matcher.
    """
    can_use_cfg = bool(functions) and all(
        (record.get("cfg") and
         all(not event.get("node") or
             event.get("node") in set(record["cfg"].get("nodes") or ())
             for event in record.get("events", ())) and
         all(not call.get("node") or
             call.get("node") in set(record["cfg"].get("nodes") or ())
             for call in record.get("calls", ())))
        for record in functions.values()
    )
    if can_use_cfg:
        return _build_cfg_ir_semantic_graph(functions, lang=lang)

    result = SkeletonGraph(language=lang)
    entries, exits = {}, {}
    pending_calls = []
    sink_catalog = atropos.sink_catalog(lang)
    norm = normalizer(lang)
    callback_targets = _callback_dispatch_targets(functions)

    def ref(value):
        return ObjRef(str(value), generation="g0") if value else None

    def emit_event(fn, index, record, previous, reachable):
        event = _ir_event(record)
        if event is None:
            return previous
        node_id = f"{fn}:ir:event:{index}"
        result.add_node(node_id, event, fragment=fn, source_reachable=reachable)
        result.add_edge(previous, node_id)
        return node_id

    for fn in sorted(functions):
        record = functions[fn]
        reachable = bool(record.get("source_reachable") or record.get("is_source"))
        source_tokens = _source_call_tokens(record)
        entry = f"{fn}:ir:entry"
        result.add_node(entry, None, fragment=fn, source_reachable=reachable)
        entries[fn] = entry
        if reachable and not source_tokens:
            result.source_reachable.add(entry)
        items = [("event", item) for item in record.get("events", ())]
        items.extend(("call", item) for item in record.get("calls", ()))
        items.sort(key=lambda item: (
            item[1].get("line") if item[1].get("line") is not None else 10**12,
            str(item[1].get("node") or item[1].get("callee") or ""),
            0 if item[0] == "event" else 1,
        ))
        previous = entry
        for index, (kind, item) in enumerate(items):
            if kind == "event":
                previous = emit_event(fn, index, item, previous, reachable)
                continue
            callee = item.get("callee")
            call_token = str(item.get("node") or
                             f"{callee or 'source'}@{item.get('line') or 0}")
            if call_token in source_tokens:
                launch_id = f"{fn}:ir:source:{index}"
                result.add_node(launch_id, None, fragment=fn,
                                source_reachable=True, source_site=call_token)
                result.add_edge(previous, launch_id)
                result.source_reachable.add(launch_id)
                previous = launch_id
            for lifecycle_index, lifecycle_event in enumerate(
                    _ir_lifecycle_events(item, norm, ref)):
                lifecycle_id = f"{fn}:ir:lifecycle:{index}:{lifecycle_index}"
                result.add_node(lifecycle_id, lifecycle_event,
                                fragment=fn, source_reachable=reachable)
                result.add_edge(previous, lifecycle_id)
                previous = lifecycle_id
            catalog_entry = sink_catalog.get(callee) or {}
            for arg_pos in dict.fromkeys(catalog_entry.get("sink_args", ())):
                argument = next((arg for arg in item.get("args", ())
                                 if arg.get("pos") == arg_pos), None)
                if argument is None:
                    continue
                family = (catalog_entry.get("kinds") or {}).get(arg_pos)
                family = family or catalog_entry.get("family")
                if not family:
                    continue
                sink_id = f"{fn}:ir:sink:{index}:{arg_pos}"
                sink_obj = ref(argument.get("root") or argument.get("var")
                               or callee)
                recipe = evaluator_for(family)
                relational = (recipe == "relational" or
                              isinstance(recipe, (list, tuple))
                              and "relational" in recipe)
                guarded = bool(item.get("guards"))
                facts = {
                    "family": family,
                    "callee": callee,
                    "arg": arg_pos,
                    "tainted": argument.get("provenance") != "const",
                    "guarded": guarded,
                    "guard_status": item.get("guard_status"),
                    "guard_predicates": item.get("guard_predicates") or (),
                    "bound": ("bounded" if guarded else "unbounded")
                             if relational else None,
                    "size_expr": item.get("size_expr"),
                    "dst": item.get("dst"),
                    "control": item.get("control") or (),
                }
                result.add_node(sink_id, Event(EventKind.SINK, obj=sink_obj,
                                               line=item.get("line"), facts=facts),
                                fragment=fn, source_reachable=reachable,
                                source_influenced=bool(facts["tainted"]))
                result.add_edge(previous, sink_id)
                previous = sink_id
            targets = _dispatch_targets(functions, callback_targets, fn, item)
            if not targets:
                continue
            enter = f"{fn}:ir:call:{index}:enter"
            continuation = f"{fn}:ir:call:{index}:return"
            result.add_node(enter, Event(EventKind.SEAM_ENTER, line=item.get("line")),
                            fragment=fn, source_reachable=reachable)
            result.add_node(continuation,
                            Event(EventKind.SEAM_EXIT, line=item.get("line")),
                            fragment=fn, source_reachable=reachable)
            result.add_edge(previous, enter)
            for target in targets:
                formals = tuple(functions[target].get("params", ()))
                bindings = []
                for argument in item.get("args", ()):
                    position = argument.get("pos")
                    if isinstance(position, int) and position < len(formals):
                        actual = ref(argument.get("root") or argument.get("var"))
                        formal = ref(formals[position])
                        if actual is not None and formal is not None:
                            bindings.append((formal, actual))
                return_bindings = []
                receiver = ref(item.get("assigned"))
                if receiver is not None:
                    for returned in functions[target].get("returns", ()):
                        returned_ref = ref(returned.get("var"))
                        if returned_ref is not None and returned.get("kind") in {"var", "call"}:
                            return_bindings.append((receiver, returned_ref))
                pending_calls.append((enter, target, continuation, tuple(bindings),
                                      tuple(return_bindings), _ir_guard_proofs(item)))
            previous = continuation
            index += 1
        if reachable and not any(
                result.nodes[node_id].metadata.get("source_site")
                for node_id in result.source_reachable
                if node_id in result.nodes
                and result.nodes[node_id].fragment == fn):
            result.source_reachable.add(entry)
        exit_node = f"{fn}:ir:exit"
        result.add_node(exit_node, None, fragment=fn, source_reachable=reachable)
        result.add_edge(previous, exit_node)
        exits[fn] = {exit_node}
        result.add_fragment(fn, entry, exits[fn], params=record.get("params", ()))

    for enter, callee, continuation, bindings, return_bindings, guards in pending_calls:
        result.add_edge(enter, entries[callee], kind="call", return_to=continuation,
                        binding=bindings, guard=guards)
        for callee_exit in exits[callee]:
            result.add_edge(callee_exit, continuation, kind="return",
                            binding=return_bindings)
    result.validate()
    return result


def build_semantic_graph(store, F, succ, lang="c", graph=None, *, summaries=None,
                         reach_summaries=None, state_artifacts=None,
                         work_functions=None):
    """Build the production frozen-v1 graph from the enriched third-pass substrate.

    The existing object interpreter supplies identity-bearing operations and a real structured
    CFG.  This function only emits them into a graph; finding decisions remain in
    ``semantic_graph.match_graph``.  Calls are represented by seam nodes and return-site
    continuations, so a shared callee cannot return into another caller's path.
    """
    available_graph = graph if graph is not None else getattr(store, "graph", None)
    selected = None if work_functions is None else set(work_functions)
    if not _native_object_substrate(available_graph):
        if selected is not None:
            selected &= set(F)
            F = {name: F[name] for name in sorted(selected)}
            succ = {name: [callee for callee in succ.get(name, ()) if callee in F]
                    for name in F}
        return _build_ir_semantic_graph(F, succ, lang=lang)
    functions = _lifetime_slice(F, succ, lang=lang)
    if selected is not None:
        functions = {name: functions[name] for name in sorted(selected)
                     if name in functions}
    if not functions:
        return SkeletonGraph(language=lang)
    analysis_graph = graph if graph is not None else store.graph
    from lachesis.nav.graph_store import GraphStore
    analysis_store = store if analysis_graph is store.graph else GraphStore(analysis_graph)
    sub_succ = {n: [c for c in succ.get(n, ()) if c in functions] for n in functions}
    obj_summaries = summaries or analyze_object_lifetimes(
        store, functions, sub_succ, lang=lang, graph=graph).summaries
    sub = Substrate(analysis_store.index).load().load_initializers()
    norm = normalizer(lang)
    sink_catalog = atropos.sink_catalog(lang)
    by_name = {}
    for node in analysis_store.index.nodes_of_kind("function", "method", "constructor"):
        if _props(node).get("declaration_only"):
            continue
        name = node.get("label")
        if name in functions and name not in by_name:
            by_name[name] = node["id"]
    sub.warm_owned(by_name.values())

    result = SkeletonGraph(language=lang)
    pending_calls = []
    fragment_cfg = {}
    fragment_last = {}
    source_launch_nodes = defaultdict(list)

    # Resolve function-valued arguments through formal callback parameters.  A
    # callback invocation often appears in the callee as ``callback(value)``
    # with no direct target edge, while the caller's call site carries the real
    # function value.  Keep this data-driven over the projected IR: any actual
    # argument whose root is a known function becomes a target for the matching
    # formal parameter, regardless of language or callback name.
    callback_targets = defaultdict(set)
    for caller_ir in functions.values():
        for call in caller_ir.get("calls", ()):
            callee = call.get("callee")
            callee_ir = functions.get(callee)
            if callee_ir is None:
                continue
            formals = tuple(callee_ir.get("params", ()))
            for argument in call.get("args", ()):
                position = argument.get("pos")
                actual = argument.get("root")
                if (not isinstance(position, int) or position >= len(formals)
                        or actual not in functions):
                    continue
                formal = formals[position]
                callback_targets[(callee, formal)].add(actual)

    def dispatch_targets(caller, call):
        callee = call.get("callee")
        if callee in functions:
            return (callee,)
        return tuple(sorted(callback_targets.get((caller, callee), ())))

    for name, fid in by_name.items():
        cfg = ReachingDef(sub).analyze(fid, reaching_defs=False)
        if not cfg or cfg.get("bailed"):
            continue
        fragment_cfg[name] = (fid, cfg)
        cfg_nodes = list(cfg.get("nodes", ()))
        if not cfg_nodes:
            continue
        prefix = f"{name}:"
        function_source_reachable = bool(functions[name].get("source_reachable", False))
        for n in cfg_nodes:
            result.add_node(prefix + n, fragment=name,
                            source_reachable=function_source_reachable)
        predecessors = defaultdict(int)
        for source, targets in cfg.get("succ", {}).items():
            for target in targets:
                if target in cfg_nodes:
                    predecessors[target] += 1
        for n in cfg_nodes:
            # Keep structure explicit in the graph even when the node has no
            # operation attached.  A branch takes precedence over a join at a
            # synthetic CFG node; real joins remain MERGE facts.
            successors = tuple(target for target in cfg.get("succ", {}).get(n, ())
                               if target in cfg_nodes)
            if len(successors) > 1:
                result.nodes[prefix + n].event = Event(
                    EventKind.BRANCH, facts={"predicate": sub.label(n) or "branch"})
            elif predecessors[n] > 1:
                result.nodes[prefix + n].event = Event(EventKind.MERGE)
        # Native graph composition uses explicit seam edges for known callees.  Do not
        # flatten their SUMMARY effects into the caller as a second release/use stream;
        # that would manufacture double-frees when the callee fragment is also traversed.
        operations = extract_operations(
            sub, norm, fid, functions[name], functions, obj_summaries, cfg)
        operation_generations, realloc_generations = _operation_generations(
            sub, operations, cfg)
        loop_nodes = _loop_nodes(cfg)
        artifact = (state_artifacts or {}).get(name)

        def abstract_facts(operation, *, post=False):
            """Serialize point-state identities without making them matcher verdicts."""
            if artifact is None:
                return {}
            snapshots = artifact.post_states if post else artifact.point_states
            states = snapshots.get(operation.node, ())
            if not states:
                return {}
            facts = {"abstract_state_count": len(states)}
            target_ids = {
                repr(state.resolve(operation.target, create=False))
                for state in states if operation.target is not None
            }
            target_ids.discard("None")
            if target_ids:
                facts["abstract_object_ids"] = sorted(target_ids)
            source_ids = {
                repr(state.resolve(operation.source, create=False))
                for state in states if operation.source is not None
            }
            source_ids.discard("None")
            if source_ids:
                facts["abstract_source_ids"] = sorted(source_ids)
            return facts

        def annotate(events, operation):
            facts = abstract_facts(operation)
            for event in events:
                event.facts.update(facts)
            return events

        def annotate_event(event, operation, *, post=False):
            event.facts.update(abstract_facts(operation, post=post))
            return event
        by_anchor = defaultdict(list)
        source_callees = {item.get("callee") for item in functions[name].get("source_calls", ())}
        source_roots = {root for call in functions[name].get("calls", ())
                        if call.get("callee") in source_callees
                        for root in ([call.get("assigned")] +
                                     [arg.get("root") for arg in call.get("args", ())])
                        if root}
        source_roots.update(functions[name].get("source_influenced_roots", ()))
        source_reachable = bool(functions[name].get("source_reachable", False))
        for op in operations:
            if op.kind == OpKind.SUMMARY:
                continue
            by_anchor[op.node].append(op)
        last_for_cfg = {}
        for n in cfg_nodes:
            anchor = prefix + n
            previous = anchor
            ops = sorted(by_anchor.get(n, ()), key=lambda x: (x.line or 0, x.ordinal))
            for index, op in enumerate(ops):
                if op.kind == OpKind.ALLOC and op.target is not None:
                    target_key = _semantic_key(sub, op.target)
                    obj = _semantic_obj(sub, op.target, operation_generations.get(op, "g0"), op.node)
                    attempt_id = f"{anchor}:alloc:{index}:attempt"
                    branch_id = f"{anchor}:alloc:{index}:branch"
                    success_id = f"{anchor}:alloc:{index}:success"
                    failure_id = f"{anchor}:alloc:{index}:failure"
                    merge_id = f"{anchor}:alloc:{index}:merge"
                    result.add_node(attempt_id, annotate_event(
                                     Event.alloc_attempt(result=obj, line=op.line), op), fragment=name,
                                     source_reachable=source_reachable,
                                     source_influenced=op.target and op.target.root in source_roots)
                    result.add_node(branch_id, Event(EventKind.BRANCH, obj=obj, line=op.line,
                                                     facts={"predicate": "alloc_result"}), fragment=name,
                                     source_reachable=source_reachable)
                    result.add_node(success_id, annotate_event(Event.origin(
                        obj, op.line,
                        facts={"allocation_site": str(op.site or op.node),
                               "generation": obj.generation,
                               "loop_widening": op.node in loop_nodes}),
                                     op, post=True), fragment=name,
                                     source_reachable=source_reachable)
                    result.add_node(failure_id, Event(EventKind.WRITE_STORAGE, obj=obj, base=obj,
                                                     slot=obj, facts={"null": True,
                                                                      "storage_slot": True,
                                                                      "result": "NULL"}, line=op.line), fragment=name,
                                     source_reachable=source_reachable)
                    result.add_node(merge_id, None, fragment=name, source_reachable=source_reachable)
                    result.add_edge(previous, attempt_id)
                    result.add_edge(attempt_id, branch_id)
                    result.add_edge(branch_id, success_id, guard=(GuardProof("NONNULL", obj.render()),))
                    result.add_edge(branch_id, failure_id, guard=(GuardProof("ISNULL", obj.render()),))
                    result.add_edge(success_id, merge_id)
                    result.add_edge(failure_id, merge_id)
                    if obj.path:
                        slot_id = f"{success_id}:slot"
                        slot = ObjRef(obj.base, generation=obj.generation)
                        result.add_node(slot_id, Event(EventKind.WRITE_STORAGE, base=slot,
                                                       path="".join(obj.path), value=obj,
                                                       obj=slot, line=op.line), fragment=name,
                                         source_reachable=source_reachable)
                        result.add_edge(success_id, slot_id)
                        result.add_edge(slot_id, merge_id)
                        result.edges[success_id] = [edge for edge in result.edges[success_id]
                                                   if edge.target != merge_id]
                    previous = merge_id
                    continue
                if op.kind == OpKind.REALLOC and op.target is not None:
                    target_key = _semantic_key(sub, op.target)
                    old_path = op.source or op.target
                    old_key = _semantic_key(sub, old_path)
                    old_generation = operation_generations.get(op, "g0")
                    old = _semantic_obj(sub, old_path, old_generation, op.node)
                    overwrites_slot = old_key == target_key
                    target_generation = (realloc_generations.get(
                        op, _next_generation(old_generation))
                        if overwrites_slot else "g0")
                    fresh = _semantic_obj(sub, op.target, target_generation, op.node)
                    attempt_id = f"{anchor}:realloc:{index}:attempt"
                    branch_id = f"{anchor}:realloc:{index}:branch"
                    result.add_node(attempt_id, annotate_event(
                                     Event.realloc_attempt(old, op.line), op), fragment=name,
                                     source_reachable=source_reachable)
                    result.add_node(branch_id, Event(EventKind.BRANCH, obj=old, line=op.line,
                                                     facts={"predicate": "realloc_result"}), fragment=name,
                                     source_reachable=source_reachable)
                    result.add_edge(previous, attempt_id)
                    result.add_edge(attempt_id, branch_id)
                    success_id = f"{anchor}:realloc:{index}:success"
                    failure_id = f"{anchor}:realloc:{index}:failure"
                    result.add_node(success_id, annotate_event(
                                     Event(EventKind.INVALIDATE, obj=old, line=op.line), op), fragment=name,
                                     source_reachable=source_reachable)
                    result.add_node(failure_id, annotate_event(
                                     Event(EventKind.REALLOC_FAILED, obj=old, slot=old,
                                           facts={"result": "NULL"}, line=op.line), op), fragment=name,
                                     source_reachable=source_reachable)
                    result.add_edge(branch_id, success_id, guard=(GuardProof("NONNULL", "realloc_result"),))
                    result.add_edge(branch_id, failure_id, guard=(GuardProof("ISNULL", "realloc_result"),))
                    success_origin = f"{success_id}:origin"
                    failure_null = f"{failure_id}:null"
                    failure_lost = f"{failure_id}:lost"
                    merge_id = f"{anchor}:realloc:{index}:merge"
                    result.add_node(success_origin, annotate_event(Event.origin(
                        fresh, op.line,
                        facts={"allocation_site": str(op.site or op.node),
                               "generation": fresh.generation,
                               "incarnation": "realloc-success"}),
                        op, post=True), fragment=name,
                                     source_reachable=source_reachable)
                    success_slot = None
                    if overwrites_slot and op.target.selectors:
                        success_slot = f"{success_origin}:slot"
                        slot = ObjRef(fresh.base, generation=old.generation)
                        result.add_node(success_slot, Event(EventKind.WRITE_STORAGE, base=slot,
                                                            path="".join(op.target.selectors), value=fresh,
                                                            obj=slot, line=op.line), fragment=name,
                                         source_reachable=source_reachable)
                    if overwrites_slot:
                        result.add_node(failure_null, Event(EventKind.WRITE_STORAGE, obj=old, base=old,
                                                           slot=old, facts={"null": True,
                                                                            "storage_slot": True,
                                                                            "result": "NULL",
                                                                            "value": fresh.render()}, line=op.line), fragment=name,
                                         source_reachable=source_reachable)
                        result.add_node(failure_lost, Event(EventKind.LOST_FROM_SLOT, obj=old, slot=old, line=op.line), fragment=name,
                                         source_reachable=source_reachable)
                    result.add_node(merge_id, None, fragment=name, source_reachable=source_reachable)
                    result.add_edge(success_id, success_origin)
                    result.add_edge(success_origin, success_slot or merge_id)
                    if success_slot:
                        result.add_edge(success_slot, merge_id)
                    result.add_edge(failure_id, failure_null if overwrites_slot else merge_id)
                    if overwrites_slot:
                        result.add_edge(failure_null, failure_lost)
                        result.add_edge(failure_lost, merge_id)
                    previous = merge_id
                    continue
                semantic_events = annotate(
                    _semantic_event(sub, op, operation_generations), op)
                if op.kind == OpKind.ALLOC and op.node in loop_nodes:
                    for event in semantic_events:
                        if event.kind == EventKind.ORIGIN:
                            event.facts["loop_widening"] = True
                for event_index, event in enumerate(semantic_events):
                    event_id = f"{anchor}:event:{index}:{event_index}"
                    metadata = {
                        "source_reachable": source_reachable,
                        "source_influenced": bool(event.obj and event.obj.base in source_roots),
                    }
                    # Coverage contexts are source-site identities, not substrings of
                    # generated node ids.  Preserve the originating CFG site explicitly
                    # so similarly named launch sites cannot credit one another.
                    if op.access == "source" and event.kind == EventKind.ORIGIN:
                        metadata["source_site"] = str(op.node)
                    result.add_node(event_id, event, fragment=name,
                                    **metadata)
                    result.add_edge(previous, event_id)
                    if op.access == "source" and event.kind == EventKind.ORIGIN:
                        source_launch_nodes[name].append(event_id)
                    previous = event_id
            # Atropos sink observations belong in the same semantic graph as
            # lifetime facts. They are separate events because a sink does not
            # mutate object state, while its evaluator can consume guards,
            # size expressions, control nesting, and provenance.
            for call_index, call in enumerate(functions[name].get("calls", ())):
                if call.get("node") != n:
                    continue
                catalog_entry = sink_catalog.get(call.get("callee")) or {}
                for arg_pos in dict.fromkeys(catalog_entry.get("sink_args", ())):
                    argument = next((arg for arg in call.get("args", ())
                                     if arg.get("pos") == arg_pos), None)
                    if argument is None:
                        continue
                    family = (catalog_entry.get("kinds") or {}).get(arg_pos)
                    if not family:
                        family = catalog_entry.get("family")
                    if not family:
                        continue
                    recipe = evaluator_for(family)
                    relational = (recipe == "relational" or
                                  isinstance(recipe, (list, tuple))
                                  and "relational" in recipe)
                    guarded = bool(call.get("guards"))
                    root = argument.get("root") or argument.get("var")
                    sink_obj = ObjRef(str(root or call.get("callee") or "sink"),
                                      generation="g0")
                    facts = {
                        "family": family,
                        "callee": call.get("callee"),
                        "arg": arg_pos,
                        "tainted": argument.get("provenance") != "const",
                        "guarded": guarded,
                        "guard_status": call.get("guard_status"),
                        "guard_predicates": call.get("guard_predicates") or (),
                        "bound": ("bounded" if guarded else "unbounded")
                                 if relational else None,
                        "size_expr": call.get("size_expr"),
                        "dst": call.get("dst"),
                        "control": call.get("control") or (),
                    }
                    sink_id = f"{anchor}:sink:{call_index}:{arg_pos}"
                    result.add_node(
                        sink_id,
                        Event(EventKind.SINK, obj=sink_obj,
                              line=call.get("line"), facts=facts),
                        fragment=name, source_reachable=source_reachable,
                        source_influenced=bool(facts["tainted"]),
                    )
                    result.add_edge(previous, sink_id)
                    previous = sink_id
            if reach_summaries is not None and n == cfg_nodes[0]:
                # The old summary composer already resolves source provenance,
                # interprocedural argument flow, and guard dominance. Preserve
                # those facts as semantic sink observations; the old renderer
                # is no longer needed to consume them.
                for flow_index, flow in enumerate(
                        reach_summaries.get(name, {}).get("sink_flows", ())):
                    sink_name, _, pos_text = flow.get("sink", "").rpartition(".a")
                    try:
                        arg_pos = int(pos_text)
                    except (TypeError, ValueError):
                        continue
                    catalog_entry = sink_catalog.get(sink_name) or {}
                    family = (catalog_entry.get("kinds") or {}).get(arg_pos)
                    if not family:
                        family = catalog_entry.get("family")
                    if not family:
                        continue
                    recipe = evaluator_for(family)
                    recipe_names = ([recipe] if isinstance(recipe, str)
                                    else tuple(recipe or ()))
                    if not ({"reachability", "presence"} & set(recipe_names)):
                        continue
                    relational = (recipe == "relational" or
                                  isinstance(recipe, (list, tuple))
                                  and "relational" in recipe)
                    guarded = bool(flow.get("guarded"))
                    root = flow.get("root") or flow.get("value") or sink_name
                    sink_obj = ObjRef(str(root), generation="g0")
                    call = next((candidate for candidate in functions[name].get("calls", ())
                                 if candidate.get("callee") == flow.get("via")), None)
                    facts = {
                        "family": family,
                        "callee": sink_name,
                        "arg": arg_pos,
                        "tainted": flow.get("provenance") != "const",
                        "guarded": guarded,
                        "guard_status": flow.get("guard_status"),
                        "bound": ("bounded" if guarded else "unbounded")
                                 if relational else None,
                        "via": flow.get("via"),
                        "control": (call or {}).get("control") or (),
                    }
                    sink_id = f"{anchor}:summary-sink:{flow_index}"
                    result.add_node(
                        sink_id,
                        Event(EventKind.SINK, obj=sink_obj,
                              line=(call or {}).get("line") or flow.get("line"), facts=facts),
                        fragment=name, source_reachable=source_reachable,
                        source_influenced=bool(facts["tainted"]),
                    )
                    result.add_edge(previous, sink_id)
                    previous = sink_id
            # Pointer-returning calls are nullable until a compatible edge
            # proves otherwise. Keep this as an origin fact so the matcher can
            # distinguish an unchecked dereference from a guarded return; the
            # allocator/reallocator branches already emit their own NULL arms.
            for call_index, call in enumerate(functions[name].get("calls", ())):
                if call.get("node") != n or not call.get("assigned"):
                    continue
                callee = call.get("callee")
                if norm.is_alloc(callee) or norm.is_realloc(callee):
                    continue
                assigned = call.get("assigned")
                variable = next((candidate for candidate in sub.idx.nodes_of_kind(
                    "variable", "parameter")
                    if sub.label(candidate.get("id")) == assigned
                    and sub.props(candidate.get("id")).get("owner_function_id") == fid), None)
                if variable is None or "*" not in (sub.props(variable.get("id")).get("type") or ""):
                    continue
                return_id = f"{anchor}:return-origin:{call_index}"
                result.add_node(
                    return_id,
                    Event(EventKind.ORIGIN,
                          obj=ObjRef(str(assigned), generation="g0"),
                          line=call.get("line"),
                          facts={"return_may_null": True,
                                 "callee": callee}),
                    fragment=name, source_reachable=source_reachable,
                    source_influenced=bool(call.get("args")),
                )
                result.add_edge(previous, return_id)
                previous = return_id
            last_for_cfg[n] = previous
        cfg_positions = {node: index for index, node in enumerate(cfg_nodes)}
        internal_call_anchors = {
            call.get("node") for call in functions[name].get("calls", ())
            if dispatch_targets(name, call)
        }
        for n in cfg_nodes:
            source = last_for_cfg[n]
            targets = list(cfg.get("succ", {}).get(n, ()))
            for target_index, target in enumerate(targets):
                if target in cfg_nodes:
                    # A resolved internal call is represented by its seam and
                    # pushed continuation.  Keeping the raw CFG successor here
                    # would invent a path that skips the callee entirely.
                    if n in internal_call_anchors and targets:
                        continue
                    guard = _cfg_guard_proofs(sub, n, target_index, len(targets))
                    if cfg_positions.get(target, 0) <= cfg_positions.get(n, 0):
                        loop_id = f"{prefix}{n}:loop:{target_index}"
                        result.add_node(loop_id, Event(EventKind.LOOP, facts={
                            "generation_widening": "join",
                            "back_edge": f"{prefix}{target}",
                            "iteration_identity": "path-local",
                        }), fragment=name,
                                         source_reachable=bool(functions[name].get("source_reachable", False)))
                        result.add_edge(source, loop_id, guard=guard)
                        result.add_edge(loop_id, prefix + target)
                    else:
                        result.add_edge(source, prefix + target, guard=guard)
        # A CFG terminal may have a semantic event chain appended to it (most
        # importantly RETURN_VALUE -> RETURN).  The matcher must enter/leave a
        # fragment after that chain, not at the raw CFG node, otherwise a
        # caller can return before observing the returned object and the leak
        # matcher reports a false positive for every returned allocation.
        exits = {last_for_cfg[n] for n in cfg_nodes
                 if not cfg.get("succ", {}).get(n)}
        result.add_fragment(name, prefix + cfg_nodes[0],
                            exits,
                            params=tuple(functions[name].get("params", ())))
        fragment_last[name] = last_for_cfg

    # Collect seams only after every fragment has been emitted; otherwise a caller that appears
    # before its callee in graph iteration order would silently lose its return binding.
    for caller, function_ir in functions.items():
        for call in function_ir.get("calls", ()):
            for callee in dispatch_targets(caller, call):
                if caller in fragment_cfg and callee in fragment_cfg:
                    routed_call = dict(call)
                    routed_call["callee"] = callee
                    pending_calls.append((caller, routed_call, callee, fragment_last[caller]))

    # Add seam edges after all fragment nodes exist.  The return site is explicit and is pushed
    # on the matcher stack by the call edge.
    for caller, call, callee, last_for_cfg in pending_calls:
        cfg = fragment_cfg[caller][1]
        anchor = call.get("node")
        if anchor not in last_for_cfg:
            continue
        continuations = list(cfg.get("succ", {}).get(anchor, ()))
        if not continuations:
            continue
        enter = f"{caller}:seam_enter:{call.get('node')}:{callee}"
        result.add_node(enter, Event(EventKind.SEAM_ENTER, line=call.get("line")), fragment=caller)
        result.add_edge(last_for_cfg[anchor], enter)
        for continuation in continuations:
            exit_node = f"{enter}:exit:{continuation}"
            if exit_node not in result.nodes:
                result.add_node(exit_node, Event(EventKind.SEAM_EXIT, line=call.get("line")), fragment=caller)
            result.add_edge(enter, f"{callee}:{fragment_cfg[callee][1]['nodes'][0]}",
                            kind="call", return_to=exit_node,
                            guard=_call_guard_proofs(call),
                            binding=_call_bindings(sub, call, functions.get(callee, {}).get("params", ())),
                            provenance=_seam_provenance(
                                sub, call, functions.get(callee, {}).get("params", ()),
                                (state_artifacts or {}).get(caller), anchor,
                                [graph_node for graph_node in result.nodes.values()
                                 if graph_node.fragment == callee],
                                caller_function_id=by_name.get(caller),
                                continuation=continuation))
            result.add_edge(exit_node, f"{caller}:{continuation}")
            for callee_exit in result.fragments[callee].exits:
                return_binding = list(_return_bindings(
                    sub, call, functions.get(callee, {})))
                receiver = call.get("assigned")
                if receiver:
                    receiver_name = sub.label(str(receiver)) or str(receiver)
                    receiver_ref = (_expression_objref(receiver_name)
                                    if any(marker in receiver_name for marker in _SUBOBJECT)
                                    else ObjRef(receiver_name, generation="g0"))
                    # Return metadata may not carry an expression for a field
                    # return (for example `return buffer->data`). Recover the
                    # precise value from the emitted RETURN_VALUE event instead
                    # of guessing from source names. This is language-neutral at
                    # the skeleton boundary: frontends only need to emit the
                    # return event.
                    for return_node, return_graph_node in result.nodes.items():
                        if return_graph_node.fragment != callee:
                            continue
                        event = return_graph_node.event
                        if event is not None and event.kind == EventKind.RETURN_VALUE \
                                and event.obj is not None:
                            return_binding.append((receiver_ref, event.obj))
                        elif (event is not None
                              and event.kind == EventKind.RETURN_VALUE
                              and event.facts.get("return_null")):
                            # `__return__` is a path-local null marker. The
                            # matcher transfers its null fact through this
                            # formal-to-actual return binding.
                            return_binding.append((
                                receiver_ref,
                                ObjRef("__return__", generation="g0")))
                    # A returned aggregate can carry aliases between its fields
                    # (for example `result->borrowed = result->meta->name`).
                    # Local DERIVE bindings otherwise disappear when the callee
                    # returns, even though both paths are part of the returned
                    # object's observable state. Export only relations rooted in
                    # the returned object and rebase them onto the caller's
                    # receiver; unrelated callee locals must not escape.
                    returned_bases = {
                        graph_node.event.obj.base
                        for graph_node in result.nodes.values()
                        if graph_node.fragment == callee
                        and graph_node.event is not None
                        and graph_node.event.kind == EventKind.RETURN_VALUE
                        and graph_node.event.obj is not None
                    }
                    for graph_node in result.nodes.values():
                        event = graph_node.event
                        if (graph_node.fragment != callee
                                or event is None
                                or event.kind != EventKind.DERIVE
                                or event.obj is None or event.value is None
                                or event.obj.base not in returned_bases
                                or event.value.base not in returned_bases):
                            continue
                        return_binding.append((
                            ObjRef(receiver_ref.base, event.obj.path, event.obj.generation),
                            ObjRef(receiver_ref.base, event.value.path, event.value.generation),
                        ))
                result.add_edge(
                    callee_exit, exit_node, kind="return",
                    binding=tuple(dict.fromkeys(return_binding)))
    result.source_reachable = set()
    for name in functions:
        if name not in result.fragments:
            continue
        source_calls = F.get(name, {}).get("source_calls", ())
        if source_launch_nodes.get(name):
            result.source_reachable.update(source_launch_nodes[name])
        else:
            anchors = [call.get("node") for call in source_calls if call.get("node") in fragment_cfg.get(name, ({}, {}))[1].get("nodes", ())]
            if anchors:
                result.source_reachable.update(f"{name}:{anchor}" for anchor in anchors)
            elif F.get(name, {}).get("source_reachable", F.get(name, {}).get("is_source")):
                result.source_reachable.add(result.fragments[name].entry)
    result.validate()
    return result


def _call_guard_proofs(call):
    """Convert the typed null guards retained by Pass 2 into seam-edge proofs."""
    proofs = []
    for guard in call.get("guards", ()):
        condition = (guard.get("canon") or "").replace(" ", "")
        value = guard.get("var")
        if not value:
            continue
        if "!=NULL" in condition or "NULL!=" in condition:
            proofs.append(GuardProof("NONNULL", f"{value}#g0"))
        elif "==NULL" in condition or "NULL==" in condition:
            proofs.append(GuardProof("ISNULL", f"{value}#g0"))
    return tuple(proofs)


def _cfg_guard_proofs(sub, node, target_index, target_count):
    """Recover typed null proofs from the structured CFG condition node.

    ReachingDef preserves branch successor order (true arm first, false arm second).  This
    covers the pointer-null guards that determine whether allocation/free operations are
    feasible without inventing a global liveness fact.
    """
    if target_count != 2:
        return ()
    condition = (sub.label(node) or "").replace(" ", "")

    def split_boolean(value, operator):
        """Split one top-level boolean operator without parsing expressions."""
        depth = 0
        terms = []
        start = 0
        index = 0
        while index < len(value) - 1:
            char = value[index]
            if char == "(":
                depth += 1
            elif char == ")":
                depth = max(0, depth - 1)
            if depth == 0 and value[index:index + 2] == operator:
                terms.append(value[start:index])
                start = index + 2
                index += 2
                continue
            index += 1
        if terms:
            terms.append(value[start:])
        return tuple(term.strip("()") for term in terms)

    def boolean_null_proofs(value):
        # For A && B, the true arm proves both terms. For A || B, only the
        # false arm proves both terms false. The other arm is a disjunction
        # and cannot be represented as a conjunction of GuardProof values.
        conjunction = split_boolean(value, "&&")
        disjunction = split_boolean(value, "||")
        if conjunction:
            terms, constrained = conjunction, target_index == 0
        elif disjunction:
            terms, constrained = disjunction, target_index == 1
        else:
            return None
        if not constrained:
            return ()
        proofs = []
        for term in terms:
            true_kind = "ISNULL" if term.startswith("!") else "NONNULL"
            variable = term[1:] if term.startswith("!") else term
            if not re.match(r"^\**[A-Za-z_]\w*(?:(?:->|\.)[A-Za-z_]\w*)*$", variable):
                return ()
            kind = (true_kind if conjunction
                    else ("NONNULL" if true_kind == "ISNULL" else "ISNULL"))
            proofs.append(GuardProof(kind, f"{variable}#g0"))
            # Keep a scalar-compatible proof alongside the pointer null proof.
            # The matcher can use VALUE contradictions for integer/enum flags,
            # while the null proof remains authoritative for pointer objects.
            value_relation = "==0" if kind == "ISNULL" else "!=0"
            proofs.append(GuardProof("VALUE", f"{variable}{value_relation}"))
        return tuple(proofs)

    compound = boolean_null_proofs(condition)
    if compound is not None:
        return compound
    variable = None
    true_kind = None
    if condition.startswith("!"):
        variable, true_kind = condition[1:].strip("()"), "ISNULL"
    elif "!=NULL" in condition or "NULL!=" in condition:
        variable, true_kind = condition.replace("!=NULL", "").replace("NULL!=", ""), "NONNULL"
    elif "==NULL" in condition or "NULL==" in condition:
        variable, true_kind = condition.replace("==NULL", "").replace("NULL==", ""), "ISNULL"
    if variable and true_kind is not None:
        kind = true_kind if target_index == 0 else ("NONNULL" if true_kind == "ISNULL" else "ISNULL")
        return (GuardProof(kind, f"{variable}#g0"),)

    # A bare pointer/resource condition is the same nullability split as
    # ``p != NULL``.  Keep this deliberately limited to a single source-level
    # value path; compound predicates remain opaque rather than being guessed.
    simple = condition.strip("()")
    if re.match(r"^[A-Za-z_]\w*(?:(?:->|\.)[A-Za-z_]\w*)*$", simple):
        kind = "NONNULL" if target_index == 0 else "ISNULL"
        value_relation = "!=0" if kind == "NONNULL" else "==0"
        return (GuardProof(kind, f"{simple}#g0"),
                GuardProof("VALUE", f"{simple}{value_relation}"))

    # Preserve relational branch facts as typed VALUE proofs.  The matcher does
    # not treat these as lifetime verdicts, but downstream properties can consume
    # them without having to reinterpret a raw predicate string.
    relational = re.match(r"^(.+?)(<=|>=|==|!=|<|>)(.+)$", condition)
    if relational and "NULL" not in condition:
        left, relation, right = relational.groups()
        proofs = []
        if target_index:
            inverse = {"<": ">=", "<=": ">", ">": "<=", ">=": "<", "==": "!=", "!=": "=="}
            relation = inverse[relation]
        proofs.append(GuardProof("VALUE", f"{left}{relation}{right}"))
        # An index comparison can additionally establish a bounded access on
        # the true arm.  Keep VALUE as the general relational fact; BOUNDED is
        # an orthogonal proof consumed by bounds-aware patterns.
        if (target_index == 0 and relation in {"<", "<="}
                and ("[" in condition or left.lower().endswith(("i", "idx", "index")))):
            proofs.append(GuardProof("BOUNDED", f"{left},{right}"))
        return tuple(proofs)
    return ()


def _call_bindings(sub, call, formals):
    def actual_ref(arg):
        """Instantiate an actual argument as a field-sensitive object reference.

        Translation keeps both the resolved root and the source expression.  The
        root alone is insufficient for seams such as ``destroy(node->meta)``:
        the callee's formal must bind to ``node.*meta``, not to a new object named
        ``meta``.  This small expression projection mirrors APBuilder's universal
        selectors while remaining independent of any C library vocabulary.
        """
        root = arg.get("root")
        expression = (arg.get("expr") or "").strip()
        if not root:
            return None
        if not expression or expression == root:
            return ObjRef(str(root), generation="g0")
        expression = expression.strip("() ").replace("->", " -> ")
        tokens = re.findall(r"[A-Za-z_]\w*|->|\.|\*|&|\[[^]]*\]", expression)
        if not tokens:
            return ObjRef(str(root), generation="g0")
        # Preserve prefix address/dereference operators instead of falling
        # back to the bare root.  ``&node`` and ``**triple`` are precisely the
        # multi-level seam identities the semantic matcher must normalize.
        prefix = []
        index = 0
        while index < len(tokens) and tokens[index] in {"*", "&"}:
            prefix.append(tokens[index])
            index += 1
        if index >= len(tokens) or not re.match(r"^[A-Za-z_]\w*$", tokens[index]):
            return ObjRef(str(root), generation="g0")
        base = tokens[index]
        selectors = prefix
        index += 1
        while index < len(tokens):
            token = tokens[index]
            if token == "->" and index + 1 < len(tokens):
                selectors.extend(("*", tokens[index + 1]))
                index += 2
            elif token == "." and index + 1 < len(tokens):
                selectors.append(tokens[index + 1])
                index += 2
            elif token in {"*", "&"}:
                selectors.append(token)
                index += 1
            elif token.startswith("["):
                selectors.extend((token, "*"))
                index += 1
            else:
                index += 1
        return ObjRef(base, tuple(selectors), "g0")

    bindings = []
    for arg in call.get("args", ()):
        pos = arg.get("pos")
        actual = arg.get("root")
        if not isinstance(pos, int) or pos >= len(formals) or not actual:
            continue
        formal = sub.label(str(formals[pos])) or str(formals[pos])
        actual_ref_value = actual_ref(arg)
        if formal:
            bindings.append((ObjRef(formal, generation="g0"),
                             actual_ref_value or ObjRef(str(actual), generation="g0")))
    return tuple(bindings)


def _expression_objref(expression: str) -> ObjRef:
    """Project a source-level receiver expression into an ObjRef path."""
    expression = str(expression).strip().strip("() ").replace("->", " -> ")
    tokens = re.findall(r"[A-Za-z_]\w*|->|\.|\*|&|\[[^]]*\]", expression)
    prefix = []
    index = 0
    while index < len(tokens) and tokens[index] in {"*", "&"}:
        prefix.append(tokens[index])
        index += 1
    base = (tokens[index] if index < len(tokens)
            and re.match(r"^[A-Za-z_]\w*$", tokens[index]) else expression)
    selectors = prefix
    index += 1
    while index < len(tokens):
        token = tokens[index]
        if token == "->" and index + 1 < len(tokens):
            selectors.extend(("*", tokens[index + 1]))
            index += 2
        elif token == "." and index + 1 < len(tokens):
            selectors.append(tokens[index + 1])
            index += 2
        elif token in {"*", "&"}:
            selectors.append(token)
            index += 1
        elif token.startswith("["):
            selectors.extend((token, "*"))
            index += 1
        else:
            index += 1
    return ObjRef(base, tuple(selectors), "g0")


def _return_bindings(sub, call, callee):
    receiver = call.get("assigned")
    if not receiver:
        return ()
    receiver = sub.label(str(receiver)) or str(receiver)
    bindings = []
    formals = tuple(callee.get("params", ()))
    for returned in callee.get("returns", ()):
        local = returned.get("var")
        if not local:
            continue
        local = sub.label(str(local)) or str(local)
        receiver_ref = (_expression_objref(receiver)
                        if any(marker in receiver for marker in _SUBOBJECT)
                        else ObjRef(receiver, generation="g0"))
        # Canonical bindings point the caller's result at the callee's returned
        # value.  This direction lets a later caller-side use of `result` resolve
        # through the return seam to the actual object released through a formal.
        bindings.append((receiver_ref, ObjRef(local, generation="g0")))
        if local in {sub.label(str(formal)) or str(formal) for formal in formals}:
            position = next((index for index, formal in enumerate(formals)
                             if (sub.label(str(formal)) or str(formal)) == local), None)
            if position is not None:
                actual = next((arg.get("root") for arg in call.get("args", ())
                               if arg.get("pos") == position and arg.get("root")), None)
                if actual:
                    actual = sub.label(str(actual)) or str(actual)
                    bindings.append((receiver_ref, ObjRef(actual, generation="g0")))
    return tuple(bindings)


def _seam_provenance(sub, call, formals, caller_artifact, caller_node, callee_nodes,
                     *, caller_function_id=None, continuation=None):
    """Translate callee-local abstract parameter IDs to caller-local IDs.

    Object-state snapshots intentionally use parameter ordinals, so a callee's
    ``('param', 0, ...)`` is not directly comparable with the caller's allocation
    identity.  This relation is kept separate from ObjRef bindings and is consumed
    only by the optional provenance channel in the semantic matcher.
    """
    if caller_artifact is None:
        return ()
    states = caller_artifact.point_states.get(caller_node, ())
    if not states:
        return ()
    # Use the frontend's declaration-rooted access path for abstract-state lookup.
    # The display-oriented ObjRef binding intentionally uses source labels (``b``),
    # while AbstractState.env is keyed by declaration IDs (``decl:<id>``).
    ap_builder = APBuilder(sub)
    by_position = {
        argument.get("pos"): _argument_path(sub, ap_builder, call.get("node"),
                                             argument.get("pos"))
        for argument in call.get("args", ())
        if isinstance(argument.get("pos"), int)
        and argument.get("pos") < len(formals)
    }
    by_position = {position: path for position, path in by_position.items()
                   if path is not None}
    if not by_position:
        return ()
    mappings: defaultdict[str, set[str]] = defaultdict(set)
    for node in callee_nodes:
        event = node.event
        if event is None:
            continue
        for raw in event.facts.get("abstract_object_ids") or ():
            try:
                parsed = ast.literal_eval(str(raw))
            except (SyntaxError, ValueError):
                continue
            if not (isinstance(parsed, tuple) and len(parsed) == 3
                    and parsed[0] == "param" and isinstance(parsed[1], int)):
                continue
            actual = by_position.get(parsed[1])
            if actual is None:
                continue
            relative = tuple(parsed[2])
            for state in states:
                resolved = state.resolve(
                    AccessPath(actual.root, actual.selectors + relative), create=False)
                # Do not export weak/phi heap cells through the auxiliary channel.
                # Those IDs intentionally summarize multiple loop/field instances;
                # ObjRef matching remains the authority for them until a future
                # context-sensitive heap relation is available.
                concrete = (isinstance(resolved, tuple) and resolved
                            and ((resolved[0] == "param") or
                                 (resolved[0] == "alloc" and len(resolved) > 1
                                  and resolved[1] == "recent")))
                if concrete:
                    mappings[str(raw)].add(repr(resolved))
    # A single formal abstract ID mapping to multiple caller objects is a weak
    # join, not a sound identity transfer.  Leave that case to the ordinary
    # ObjRef/call-context matcher rather than manufacturing cross-object frees.
    if caller_function_id is not None and continuation is not None and call.get("assigned"):
        receiver = str(call["assigned"])
        destination = next((node for node in sub._owned(caller_function_id)
                            if sub.kind(node) in {"variable", "VarDecl"}
                            and sub.label(node) == receiver), None)
        receiver_path = _path(ap_builder, destination)
        return_ids = {
            str(raw)
            for node in callee_nodes
            if node.event is not None
            and node.event.kind == EventKind.RETURN_VALUE
            for raw in (node.event.facts.get("abstract_object_ids") or ())
        }
        if receiver_path is not None and return_ids:
            receiver_ids = set()
            for state in caller_artifact.point_states.get(continuation, ()):
                resolved = state.resolve(receiver_path, create=False)
                concrete = (isinstance(resolved, tuple) and resolved
                            and ((resolved[0] == "param") or
                                 (resolved[0] == "alloc" and len(resolved) > 1
                                  and resolved[1] == "recent")))
                if concrete:
                    receiver_ids.add(repr(resolved))
            if len(receiver_ids) == 1:
                for raw in return_ids:
                    mappings[raw].update(receiver_ids)
    return tuple(sorted((source, next(iter(targets)))
                        for source, targets in mappings.items()
                        if len(targets) == 1))


def main():
    ap = argparse.ArgumentParser(description="emit universal skeletons from a graph + match")
    ap.add_argument("graph")
    ap.add_argument("--lang", default="c")
    ap.add_argument("--emit", default=None, help="write universal-IR JSON here")
    ap.add_argument("--show", action="store_true", help="render every skeleton")
    args = ap.parse_args()

    from lachesis.nav.graph_store import GraphStore
    from .translate import build_F
    store = GraphStore.load(args.graph)
    store.ensure_dataflow_tier()
    F, succ, g = build_F(store, lang=args.lang, return_graph=True)
    skels = build_universal_skeletons(store, F, succ, lang=args.lang, graph=g)

    if args.emit:
        with open(args.emit, "w") as fh:
            json.dump([s.to_dict() for s in skels], fh, indent=2)

    total = 0
    for s in skels:
        hits = ir.match_universal(s)
        if hits or args.show:
            print(ir.render(s))
            for h in hits:
                print(f"    >> {h['pattern']}  obj={h['obj']}  steps={h['steps']}")
            print()
            total += len(hits)
    print(f"universal-emit: {len(skels)} skeleton(s), {total} role-pattern hit(s)")


if __name__ == "__main__":
    main()
