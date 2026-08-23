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
from collections import defaultdict

from lachesis.nav.dataflow.reaching_def import ReachingDef
from lachesis.nav.dataflow.substrate import Substrate

from . import skeleton_ir as ir
from .normalize import normalizer
from .object_lifetime import extract_operations, _props
from .object_state import OpKind
from .pipeline import _lifetime_slice


# --- OpKind -> universal verb (roles are then looked up in skeleton_ir.VERB_ROLES) ------
# The verb is the concrete, per-language spelling; the ROLE is what patterns match on. We
# pick a canonical verb per OpKind so roles_for() classifies it. USE is a pointee
# read/observe; CLOBBER rebinds the name to a fresh (unknown/null) object -> REINIT.
_OP_VERB = {
    OpKind.ALLOC: "alloc",
    OpKind.FREE: "free",
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
        if op.kind in (OpKind.ALLOC, OpKind.CLOBBER) and tkey is not None:
            # a rebind of an already-seen path opens a new generation
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
