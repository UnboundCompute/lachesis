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
import json
import re
from collections import defaultdict

from lachesis.nav.dataflow.reaching_def import ReachingDef
from lachesis.nav.dataflow.substrate import Substrate

from . import skeleton_ir as ir
from .normalize import normalizer
from .object_lifetime import extract_operations, _props
from .object_state import OpKind
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


def _readable_root(sub, root: str) -> str:
    """Render an AccessPath root (``decl:<id>`` / ``param``) as a stable, readable base.

    Identity is per-skeleton (one function), so a variable's own name is a stable key here;
    the raw decl id is opaque and collides across nothing within a single function."""
    if root.startswith("decl:"):
        node_id = root[len("decl:"):]
        return sub.label(node_id) or node_id
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

    functions = _lifetime_slice(F, succ)
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


def _semantic_obj(sub, path, generation="g0"):
    if path is None:
        return None
    return ObjRef(base=_readable_root(sub, path.root), path=tuple(path.selectors),
                  generation=generation)


def _semantic_event(sub, operation, generations=None):
    """Translate one object-engine fact to a frozen-schema event.

    This translation intentionally emits facts only.  No UAF/double-free state is stamped here;
    :func:`match_graph` derives those findings later.
    """
    generations = generations or {}
    target_key = (operation.target.root, tuple(operation.target.selectors)) if operation.target else None
    obj = _semantic_obj(sub, operation.target, generations.get(target_key, "g0"))
    if operation.kind == OpKind.ALLOC:
        return [Event.alloc_attempt(result=obj, line=operation.line), Event.origin(obj, operation.line)] if obj else []
    if operation.kind == OpKind.FREE:
        return [Event.release(obj, operation.line)] if obj else []
    if operation.kind == OpKind.REALLOC:
        if not obj:
            return []
        fresh = ObjRef(obj.base, obj.path, f"{obj.generation}+1")
        return [Event.realloc_attempt(obj, operation.line),
                Event(EventKind.INVALIDATE, obj=obj, line=operation.line),
                Event.origin(fresh, operation.line)]
    if operation.kind == OpKind.USE and obj:
        # A storage access is anchored at the owning object.  Its selectors belong
        # to the event path, not to the identity used for lifetime matching.  This
        # is what lets ``free(p); p->field`` match the same generation of ``p``.
        access_path = "".join(operation.target.selectors) or "*"
        storage_obj = ObjRef(obj.base, generation=obj.generation)
        if operation.access == "pass":
            return [Event.pass_value(obj, operation.line)]
        if operation.access == "compare":
            return [Event(EventKind.COMPARE_VALUE, obj=obj, line=operation.line)]
        if operation.access == "return":
            return [Event(EventKind.RETURN_VALUE, obj=obj, line=operation.line)]
        if operation.access == "write":
            return [Event.write(storage_obj, access_path, operation.line)]
        return [Event.read(storage_obj, access_path, operation.line)]
    if operation.kind == OpKind.COPY and obj:
        source_key = (operation.source.root, tuple(operation.source.selectors)) if operation.source else None
        source = _semantic_obj(sub, operation.source, generations.get(source_key, "g0"))
        return [Event(EventKind.DERIVE, obj=obj, value=source, line=operation.line)]
    if operation.kind == OpKind.CLOBBER and obj:
        kind = EventKind.WRITE_STORAGE_NULL if operation.is_null else EventKind.DERIVE
        return [Event(kind, obj=obj, line=operation.line)]
    return []


def build_semantic_graph(store, F, succ, lang="c", graph=None, *, summaries=None):
    """Build the production frozen-v1 graph from the enriched third-pass substrate.

    The existing object interpreter supplies identity-bearing operations and a real structured
    CFG.  This function only emits them into a graph; finding decisions remain in
    ``semantic_graph.match_graph``.  Calls are represented by seam nodes and return-site
    continuations, so a shared callee cannot return into another caller's path.
    """
    functions = _lifetime_slice(F, succ)
    if not functions:
        return SkeletonGraph()
    analysis_graph = graph if graph is not None else store.graph
    from lachesis.nav.graph_store import GraphStore
    analysis_store = store if analysis_graph is store.graph else GraphStore(analysis_graph)
    sub_succ = {n: [c for c in succ.get(n, ()) if c in functions] for n in functions}
    obj_summaries = summaries or analyze_object_lifetimes(
        store, functions, sub_succ, lang=lang, graph=graph).summaries
    sub = Substrate(analysis_store.index).load().load_initializers()
    norm = normalizer(lang)
    by_name = {}
    for node in analysis_store.index.nodes_of_kind("function", "method", "constructor"):
        if _props(node).get("declaration_only"):
            continue
        name = node.get("label")
        if name in functions and name not in by_name:
            by_name[name] = node["id"]
    sub.warm_owned(by_name.values())

    result = SkeletonGraph()
    pending_calls = []
    fragment_cfg = {}
    fragment_last = {}
    for name, fid in by_name.items():
        cfg = ReachingDef(sub).analyze(fid, reaching_defs=False)
        if not cfg or cfg.get("bailed"):
            continue
        fragment_cfg[name] = (fid, cfg)
        cfg_nodes = list(cfg.get("nodes", ()))
        if not cfg_nodes:
            continue
        prefix = f"{name}:"
        for n in cfg_nodes:
            result.add_node(prefix + n, fragment=name)
        # Native graph composition uses explicit seam edges for known callees.  Do not
        # flatten their SUMMARY effects into the caller as a second release/use stream;
        # that would manufacture double-frees when the callee fragment is also traversed.
        operations = extract_operations(
            sub, norm, fid, functions[name], functions, obj_summaries, cfg)
        by_anchor = defaultdict(list)
        generations = {}
        source_callees = {item.get("callee") for item in functions[name].get("source_calls", ())}
        source_roots = {root for call in functions[name].get("calls", ())
                        if call.get("callee") in source_callees
                        for root in ([call.get("assigned")] +
                                     [arg.get("root") for arg in call.get("args", ())])
                        if root}
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
                    target_key = (op.target.root, tuple(op.target.selectors))
                    obj = _semantic_obj(sub, op.target, generations.get(target_key, "g0"))
                    attempt_id = f"{anchor}:alloc:{index}:attempt"
                    branch_id = f"{anchor}:alloc:{index}:branch"
                    success_id = f"{anchor}:alloc:{index}:success"
                    failure_id = f"{anchor}:alloc:{index}:failure"
                    merge_id = f"{anchor}:alloc:{index}:merge"
                    result.add_node(attempt_id, Event.alloc_attempt(result=obj, line=op.line), fragment=name,
                                     source_reachable=source_reachable,
                                     source_influenced=op.target and op.target.root in source_roots)
                    result.add_node(branch_id, Event(EventKind.BRANCH, obj=obj, line=op.line,
                                                     facts={"predicate": "alloc_result"}), fragment=name,
                                     source_reachable=source_reachable)
                    result.add_node(success_id, Event.origin(obj, op.line), fragment=name,
                                     source_reachable=source_reachable)
                    result.add_node(failure_id, Event(EventKind.WRITE_STORAGE_NULL, obj=obj, line=op.line), fragment=name,
                                     source_reachable=source_reachable)
                    result.add_node(merge_id, None, fragment=name, source_reachable=source_reachable)
                    result.add_edge(previous, attempt_id)
                    result.add_edge(attempt_id, branch_id)
                    result.add_edge(branch_id, success_id, guard=(GuardProof("NONNULL", obj.render()),))
                    result.add_edge(branch_id, failure_id, guard=(GuardProof("ISNULL", obj.render()),))
                    result.add_edge(success_id, merge_id)
                    result.add_edge(failure_id, merge_id)
                    previous = merge_id
                    continue
                if op.kind == OpKind.REALLOC and op.target is not None:
                    target_key = (op.target.root, tuple(op.target.selectors))
                    old_generation = generations.get(target_key, "g0")
                    old = _semantic_obj(sub, op.target, old_generation)
                    fresh_generation = f"g{int(old_generation[1:]) + 1}" if (
                        isinstance(old_generation, str) and old_generation.startswith("g") and
                        old_generation[1:].isdigit()) else f"{old_generation}+1"
                    fresh = ObjRef(old.base, old.path, fresh_generation)
                    attempt_id = f"{anchor}:realloc:{index}:attempt"
                    branch_id = f"{anchor}:realloc:{index}:branch"
                    result.add_node(attempt_id, Event.realloc_attempt(old, op.line), fragment=name,
                                     source_reachable=source_reachable)
                    result.add_node(branch_id, Event(EventKind.BRANCH, obj=old, line=op.line,
                                                     facts={"predicate": "realloc_result"}), fragment=name,
                                     source_reachable=source_reachable)
                    result.add_edge(previous, attempt_id)
                    result.add_edge(attempt_id, branch_id)
                    success_id = f"{anchor}:realloc:{index}:success"
                    failure_id = f"{anchor}:realloc:{index}:failure"
                    result.add_node(success_id, Event(EventKind.INVALIDATE, obj=old, line=op.line), fragment=name,
                                     source_reachable=source_reachable)
                    result.add_node(failure_id, Event(EventKind.REALLOC_FAILED, obj=old, line=op.line), fragment=name,
                                     source_reachable=source_reachable)
                    result.add_edge(branch_id, success_id, guard=(GuardProof("NONNULL", "realloc_result"),))
                    result.add_edge(branch_id, failure_id, guard=(GuardProof("ISNULL", "realloc_result"),))
                    success_origin = f"{success_id}:origin"
                    failure_null = f"{failure_id}:null"
                    failure_lost = f"{failure_id}:lost"
                    merge_id = f"{anchor}:realloc:{index}:merge"
                    result.add_node(success_origin, Event.origin(fresh, op.line), fragment=name,
                                     source_reachable=source_reachable)
                    result.add_node(failure_null, Event(EventKind.WRITE_STORAGE_NULL, obj=fresh, line=op.line), fragment=name,
                                     source_reachable=source_reachable)
                    result.add_node(failure_lost, Event(EventKind.LOST_FROM_SLOT, obj=old, slot=old, line=op.line), fragment=name,
                                     source_reachable=source_reachable)
                    result.add_node(merge_id, None, fragment=name, source_reachable=source_reachable)
                    result.add_edge(success_id, success_origin)
                    result.add_edge(success_origin, merge_id)
                    result.add_edge(failure_id, failure_null)
                    result.add_edge(failure_null, failure_lost)
                    result.add_edge(failure_lost, merge_id)
                    generations[target_key] = fresh_generation
                    previous = merge_id
                    continue
                for event_index, event in enumerate(_semantic_event(sub, op, generations)):
                    event_id = f"{anchor}:event:{index}:{event_index}"
                    result.add_node(event_id, event, fragment=name,
                                    source_reachable=source_reachable,
                                    source_influenced=bool(event.obj and event.obj.base in source_roots))
                    result.add_edge(previous, event_id)
                    previous = event_id
            last_for_cfg[n] = previous
        for n in cfg_nodes:
            source = last_for_cfg[n]
            targets = list(cfg.get("succ", {}).get(n, ()))
            for target_index, target in enumerate(targets):
                if target in cfg_nodes:
                    result.add_edge(source, prefix + target,
                                    guard=_cfg_guard_proofs(sub, n, target_index, len(targets)))
        exits = {n for n in cfg_nodes if not cfg.get("succ", {}).get(n)}
        result.add_fragment(name, prefix + cfg_nodes[0],
                            (prefix + n for n in exits),
                            params=tuple(functions[name].get("params", ())))
        fragment_last[name] = last_for_cfg

    # Collect seams only after every fragment has been emitted; otherwise a caller that appears
    # before its callee in graph iteration order would silently lose its return binding.
    for caller, function_ir in functions.items():
        for call in function_ir.get("calls", ()):
            callee = call.get("callee")
            if caller in fragment_cfg and callee in fragment_cfg:
                pending_calls.append((caller, call, callee, fragment_last[caller]))

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
                            binding=_call_bindings(sub, call, functions.get(callee, {}).get("params", ())))
            result.add_edge(exit_node, f"{caller}:{continuation}")
            for callee_exit in result.fragments[callee].exits:
                result.add_edge(
                    callee_exit, exit_node, kind="return",
                    binding=_return_bindings(sub, call, functions.get(callee, {})))
    result.source_reachable = set()
    for name in functions:
        if name not in result.fragments:
            continue
        source_calls = F.get(name, {}).get("source_calls", ())
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

    # Preserve relational branch facts as typed VALUE proofs.  The matcher does
    # not treat these as lifetime verdicts, but downstream properties can consume
    # them without having to reinterpret a raw predicate string.
    relational = re.match(r"^(.+?)(<=|>=|==|!=|<|>)(.+)$", condition)
    if relational and "NULL" not in condition:
        left, relation, right = relational.groups()
        if target_index:
            inverse = {"<": ">=", "<=": ">", ">": "<=", ">=": "<", "==": "!=", "!=": "=="}
            relation = inverse[relation]
        return (GuardProof("VALUE", f"{left}{relation}{right}"),)
    return ()


def _call_bindings(sub, call, formals):
    bindings = []
    for arg in call.get("args", ()):
        pos = arg.get("pos")
        actual = arg.get("root")
        if not isinstance(pos, int) or pos >= len(formals) or not actual:
            continue
        formal = sub.label(str(formals[pos])) or str(formals[pos])
        actual = sub.label(str(actual)) or str(actual)
        if formal:
            bindings.append((ObjRef(formal, generation="g0"),
                             ObjRef(actual, generation="g0")))
    return tuple(bindings)


def _return_bindings(sub, call, callee):
    receiver = call.get("assigned")
    if not receiver:
        return ()
    receiver = sub.label(str(receiver)) or str(receiver)
    bindings = []
    for returned in callee.get("returns", ()):
        local = returned.get("var")
        if not local:
            continue
        local = sub.label(str(local)) or str(local)
        bindings.append((ObjRef(local, generation="g0"),
                         ObjRef(receiver, generation="g0")))
    return tuple(bindings)


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
