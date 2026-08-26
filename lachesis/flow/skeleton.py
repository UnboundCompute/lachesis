#!/usr/bin/env python3
"""Flow-skeleton renderer -- compose per-function summaries into a linear, ordered,
nesting-aware ``{control | sink | lifecycle}`` event stream per sink-bearing flow. This is
the stitched cross-function skeleton the shape matcher consumes: the composition of
per-function summaries down a sink-bearing path, spliced at each call seam.

Pure composition over F (translate.py) + summaries (summarize.py). It touches NO graph and
NO source text -- everything is already in the summaries; this only re-serialises them into
an ordered token stream a shape pattern can walk.

Two skeleton kinds, one token vocabulary:
  * REACH     -- for each value that reaches a sink, the guard-nesting around it stitched down
                 the interprocedural call chain (enter/exit at every seam). Feeds the
                 injection/size shape patterns: is the reaching value guarded, and where.
  * TYPESTATE -- for each tracked pointer, the ordered alloc/use/free/escape stream (already
                 interprocedurally spliced by summarize). Feeds the temporal shape patterns:
                 double-free, use-after-free, leak.

Token vocabulary (each token is a dict; ``depth`` = call-seam nesting level):
  {t:enter, fn, depth}                     call seam open
  {t:exit,  fn, depth}                     call seam close
  {t:guard, cond, vars, depth}             a control guard dominating what follows (control)
  {t:sink,  family, callee, arg, var, tainted, bound, guarded, depth}
  {t:alloc|use|free|escape, var, line, fn, depth}   lifecycle (object identity across seams)

Known compatibility limits (honest, and specific to this legacy renderer):
  * ``tainted`` is a coarse proxy (provenance != const), not a full source-catalog reach --
    the reach substrate tracks "a value reaches the sink", not yet "an attacker value reaches it".
  * the legacy linear renderer does not preserve standalone post-free deref identity;
    production object mode uses the semantic graph emitter for those facts. This module
    remains available for compatibility and differential diagnostics.
"""
import argparse
import json
from lachesis.timeit import timeit

from . import atropos
from .patterns import evaluator_for
from .translate import load_graph
from .order import build_order
from .summarize import summarize_one


# --- sink-kind lookup ------------------------------------------------------------
def _sink_parts(sink_id):
    """'copy_from_user.a2' -> ('copy_from_user', 2)."""
    callee, pos = sink_id.rsplit(".a", 1)
    return callee, int(pos)


def _kind_of(callee, pos, catalog):
    """The atropos sink kind at (callee, arg pos) -- 'buffer-size', 'command-injection', ..."""
    e = catalog.get(callee) or {}
    return (e.get("kinds") or {}).get(pos) or e.get("family")


def _attach_site_facts(tok, call):
    """Fold the call-site substrate translate resolved (loop/branch nesting, the size operand,
    the destination identity) onto a sink token, so a shape rule can key on structure and size
    without re-reading the graph. Absent facts are simply omitted -- an unenriched call (e.g. an
    interprocedural sink reached in a callee) carries none, and the matcher reads what is there."""
    if not call:
        return
    if call.get("control"):
        tok["control"] = call["control"]
    if call.get("size_expr") is not None:
        tok["size_expr"] = call["size_expr"]
    if call.get("dst") is not None:
        tok["dst"] = call["dst"]


# --- call-site resolution (map an actual arg to the callee's formal) --------------
def _find_call(fn_rec, callee, root):
    """First call in fn to `callee` carrying an arg rooted at `root` (fallback: any call to it)."""
    fallback = None
    for c in fn_rec["calls"]:
        if c["callee"] != callee:
            continue
        if root is None or any(a.get("root") == root for a in c["args"]):
            return c
        fallback = fallback or c
    return fallback


def _formal_for(callee_params, call, root):
    """The callee formal name the actual arg rooted at `root` binds to, or None."""
    for a in call["args"]:
        pos = a.get("pos")
        if a.get("root") == root and isinstance(pos, int) and pos < len(callee_params):
            return callee_params[pos]
    return None


# --- reach skeleton (value -> sink, stitched down the via chain) ------------------
def _expand_reach(fn, flow, F, summaries, catalog, depth, guarded_acc, chain):
    """Ordered tokens reaching flow['sink'] from `fn`, following flow['via'] interprocedurally.

    guarded_acc carries whether any hop so far already guards the value (guard dominance is
    inherited downward). Returns (tokens, complete) -- complete=False when the chain could not
    be stitched all the way to the sink (unresolved callee / missing sub-flow)."""
    callee, pos = _sink_parts(flow["sink"])
    toks = []

    if flow["via"] == "direct":
        call = _find_call(F[fn], callee, flow["root"])
        site_guards = call["guards"] if call else []
        for g in site_guards:
            toks.append({"t": "guard", "cond": g["canon"], "vars": [g["var"]], "depth": depth})
        guarded = bool(site_guards) or guarded_acc
        kind = _kind_of(callee, pos, catalog)
        bound = None
        recipe = evaluator_for(kind)
        relational = (recipe == "relational" or
                      isinstance(recipe, (list, tuple)) and "relational" in recipe)
        if relational:                                      # size sink: the guard IS the bound
            bound = "bounded" if guarded else "unbounded"
        tok = {"t": "sink", "family": kind, "callee": callee, "arg": pos,
               "var": flow.get("value"), "tainted": flow.get("provenance") != "const",
               "bound": bound, "guarded": guarded, "depth": depth}
        _attach_site_facts(tok, call)                       # control nesting, size_expr, dst
        toks.append(tok)
        return toks, True

    via = flow["via"]
    if via not in summaries or via not in F or via in chain:      # unresolved / recursion guard
        toks.append({"t": "sink", "family": _kind_of(callee, pos, catalog), "callee": callee,
                     "arg": pos, "var": flow.get("value"),
                     "tainted": flow.get("provenance") != "const", "bound": None,
                     "guarded": guarded_acc, "depth": depth, "truncated": True})
        return toks, False

    call = _find_call(F[fn], via, flow["root"])
    site_guards = call["guards"] if call else []
    for g in site_guards:
        toks.append({"t": "guard", "cond": g["canon"], "vars": [g["var"]], "depth": depth})
    guarded = bool(site_guards) or guarded_acc

    formal = _formal_for(F[via]["params"], call, flow["root"]) if call else None
    sub = None
    for f2 in summaries[via]["sink_flows"]:
        if f2["sink"] == flow["sink"] and (formal is None or f2["root"] == formal):
            sub = f2
            break
    if sub is None:                                     # callee reaches sink but not via this arg
        toks.append({"t": "sink", "family": _kind_of(callee, pos, catalog), "callee": callee,
                     "arg": pos, "var": flow.get("value"),
                     "tainted": flow.get("provenance") != "const", "bound": None,
                     "guarded": guarded, "depth": depth, "truncated": True})
        return toks, False

    toks.append({"t": "enter", "fn": via, "depth": depth})
    body, ok = _expand_reach(via, sub, F, summaries, catalog, depth + 1, guarded, chain + [via])
    toks += body
    toks.append({"t": "exit", "fn": via, "depth": depth})
    return toks, ok


# --- typestate skeleton (already ordered; re-serialise into tokens) ---------------
def _lifecycle_family(kind, lang):
    """Map the legacy event verb to the public structural family.

    C already exposes memory.alloc/free/deref and those names are part of its
    compatibility surface. Managed frontends use the language-neutral lifecycle
    alphabet; the event verb remains available for rendering/debugging.
    """
    if lang == "c":
        return {"alloc": "memory.alloc", "free": "memory.free", "use": "memory.deref",
                "escape": "lifecycle.escape"}.get(kind, "lifecycle." + kind)
    return {"alloc": "lifecycle.acquire", "free": "lifecycle.release",
            "use": "lifecycle.use", "escape": "lifecycle.escape"}.get(
                kind, "lifecycle." + kind)


def _typestate_skel(fn, var, events, depth, lang="c"):
    toks = [{"t": "enter", "fn": fn, "depth": depth}]
    for e in events:
        toks.append({"t": e["kind"], "family": e.get("family") or
                     _lifecycle_family(e["kind"], lang), "var": var,
                     "line": e.get("line"), "node": e.get("node"), "fn": fn,
                     "depth": depth + 1})
    toks.append({"t": "exit", "fn": fn, "depth": depth})
    return toks


# --- driver ----------------------------------------------------------------------
def build_skeletons(F, summaries, lang="c", *, include_typestate=True):
    """Every sink-bearing flow in the graph, rendered as an ordered token skeleton.

    A reach skeleton is emitted from EVERY function that carries the flow, so both the
    maximal source-rooted skeleton (the full stitched flow) and its sub-skeletons are
    available; ``is_source`` marks the maximal ones for a matcher that wants only those."""
    catalog = atropos.sink_catalog(lang)
    skels = []
    for fn in sorted(summaries):
        s = summaries[fn]
        is_src = F.get(fn, {}).get("is_source", False)
        for flow in s["sink_flows"]:
            toks = [{"t": "enter", "fn": fn, "depth": 0}]
            body, ok = _expand_reach(fn, flow, F, summaries, catalog, 1, False, [fn])
            toks += body
            toks.append({"t": "exit", "fn": fn, "depth": 0})
            skels.append({"kind": "reach", "entry": fn, "is_source": is_src,
                          "sink": flow["sink"], "value": flow.get("value"),
                          "complete": ok, "tokens": toks})
        if include_typestate:
            for var, events in s.get("typestate", {}).items():
                skels.append({"kind": "typestate", "entry": fn, "is_source": is_src, "var": var,
                              "complete": True, "tokens": _typestate_skel(fn, var, events, 0, lang)})
            for var, events in s.get("param_typestate", {}).items():
                skels.append({"kind": "typestate", "entry": fn, "is_source": is_src,
                              "var": "param:" + var, "complete": True,
                              "tokens": _typestate_skel(fn, "param:" + var, events, 0, lang)})
    return skels


def render_text(skel):
    """Indented, human-readable view of one skeleton's token stream."""
    if skel["kind"] == "reach":
        head = (f"[reach] {skel['entry']} -> {skel['sink']}  ({skel['value']})  "
                f"{'COMPLETE' if skel['complete'] else 'TRUNCATED'}"
                f"{'  src' if skel['is_source'] else ''}")
    else:
        head = f"[lifetime] {skel['entry']}::{skel['var']}{'  src' if skel['is_source'] else ''}"
    lines = [head]
    for t in skel["tokens"]:
        pad = "  " * (t["depth"] + 1)
        if t["t"] in ("enter", "exit"):
            lines.append(f"{pad}{t['t']} {t['fn']}")
        elif t["t"] == "guard":
            lines.append(f"{pad}guard {t['cond']} {{{','.join(t['vars'])}}}")
        elif t["t"] == "sink":
            g = "GUARDED" if t["guarded"] else "UNGUARDED"
            b = f" bound={t['bound']}" if t["bound"] else ""
            tt = " tainted" if t["tainted"] else ""
            trunc = " ~truncated" if t.get("truncated") else ""
            ctrl = f" under[{'>'.join(t['control'])}]" if t.get("control") else ""
            sz = f" size={t['size_expr']}" if t.get("size_expr") is not None else ""
            dst = f" dst={t['dst']}" if t.get("dst") is not None else ""
            lines.append(f"{pad}sink {t['family']} {t['callee']}#{t['arg']} "
                         f"var={t['var']}{tt}{b} {g}{ctrl}{sz}{dst}{trunc}")
        else:                                            # lifecycle
            ln = f"@{t['line']}" if t.get("line") is not None else ""
            fam = f" {t['family']}" if t.get("family") else ""
            lines.append(f"{pad}{t['t']}{fam} {t['var']}{ln}")
    return "\n".join(lines)


@timeit
def _summaries_for(F, succ, *, reach_only=False):
    """Run bottom-up summarisation over the whole graph.

    ``reach_only`` is the object-mode projection: it preserves the complete
    sink-flow composition but omits legacy lifetime streams, which are already
    produced by the native object engine.

    Summary order depends only on the call graph.  Use the shared SCC scheduler
    directly instead of allocating traversal traces and discovering SCCs again
    inside each traversal component.
    """
    summaries = {}
    for group in build_order(F, succ):
        comp = group["members"]
        if not group["cyclic"]:
            summaries[comp[0]] = summarize_one(
                comp[0], F, summaries, reach_only=reach_only)
            continue
        for m in comp:
            summaries[m] = {"name": m, "params": F[m]["params"], "taxonomy": F[m]["taxonomy"],
                            "sink_flows": [], "sink_params": {}, "typestate": {},
                            "param_typestate": {}, "frees_params": {}, "returns": "value",
                            "returns_param": None}
        for _ in range(len(comp) + 3):
            # Summary records are immutable from the caller's perspective;
            # summarize_one returns fresh containers and only reads callee
            # summaries.  Structural dict equality avoids serializing the
            # entire recursive group on every fixpoint iteration.
            before = {m: summaries[m] for m in comp}
            for m in comp:
                summaries[m] = summarize_one(
                    m, F, summaries, reach_only=reach_only)
            if {m: summaries[m] for m in comp} == before:
                break
    return summaries


def main():
    ap = argparse.ArgumentParser(description="render flow skeletons from a Lachesis graph")
    ap.add_argument("--graph", required=True)
    ap.add_argument("--lang", default="c")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    F, succ = load_graph(args.graph, lang=args.lang)
    summaries = _summaries_for(F, succ)
    skels = build_skeletons(F, summaries, lang=args.lang)

    if args.out:
        with open(args.out, "w") as fh:
            json.dump(skels, fh, indent=2)

    reach = [s for s in skels if s["kind"] == "reach"]
    life = [s for s in skels if s["kind"] == "typestate"]
    print(f"rendered {len(skels)} flow skeleton(s): {len(reach)} reach, {len(life)} lifetime"
          + (f" -> {args.out}" if args.out else "") + "\n")
    for s in skels:
        print(render_text(s))
        print()


if __name__ == "__main__":
    main()
