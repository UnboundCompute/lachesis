#!/usr/bin/env python3
"""Summary phase: convert each function into a deterministic, composable summary.

Walks the bottom-up schedule from order.py so every callee's summary exists before the
caller that needs it (recursive groups are iterated to a fixpoint). For each function F
it computes, purely from the substrate (no LLM):

  sink_params[param]  -> list of {sink, guards[], guarded}   where param flows to a sink,
                         composed INTERPROCEDURALLY (F passes param into G, G's summary
                         says that position reaches a sink -> F inherits it, guards merged)
  frees_params[param] -> "direct" | "via:<callee>"           (does calling F free this arg)
  returns             -> "alloc" | "param:<name>" | "value"  (ownership, composed through calls)

This is the single artifact both detectors read: detector #1 uses sink_params to know
which (callee, arg) positions are worth grouping; detector #2 uses frees_params + returns
for interprocedural alloc/free/use.
"""
import argparse
import json

from .order import load as load_order, build_order
from . import atropos
from .normalize import normalizer
from .translate import _freed_identity


def sink_id(callee, pos):
    return f"{callee}.a{pos}"


def sink_positions(call):
    """Positions of a direct sink call that carry the security-relevant value."""
    sk = call.get("sink") or {}
    sa = sk.get("size_arg")
    if sa is not None:
        return [sa]
    return [a["pos"] for a in call["args"] if a.get("var")]


def merge_records(dst, sink, guards):
    """Add/merge a (sink, guards) reaching-record into dst list, deduped."""
    gsorted = sorted(set(guards))
    for r in dst:
        if r["sink"] == sink and r["guards"] == gsorted:
            return
    dst.append({"sink": sink, "guards": gsorted, "guarded": len(gsorted) > 0})


def summarize_one(name, F, summaries):
    """Compute F's complete summary from the substrate + callee summaries already ready.

    Produces:
      sink_flows   -- EVERY value (param / local / field) that reaches a sink, guarded or
                      not, direct or through a UDF; the self-contained picture.
      sink_params  -- the param-only subset, used for bottom-up composition into callers.
      typestate    -- per pointer, the ordered alloc/free/use stream, INTERPROCEDURAL
                      (buf = xalloc(...) is an alloc; xfree(buf) is a free).
      frees_params, returns.
    """
    fn = F[name]
    # lifecycle roles (alloc/free) are DATA in atropos, read through the normalizer -- no
    # allocator/free name list is hard-coded here. lang is taken from the function's own file
    # so a mixed-language graph resolves each function against its own catalog.
    norm = normalizer(atropos.lang_of(fn.get("file") or ""))
    params = set(fn["params"])
    sink_flows = []       # complete: [{sink, value, root, provenance, guards[], guarded, via}]
    sink_params = {}      # composition: param -> [{sink, guards[], guarded}]
    frees = {}            # param -> "direct" | "via:<callee>"

    def add_flow(a, sink, guards, via, site_guards):
        gsorted = sorted(set(g for g in guards if g))
        site = sorted(set(g for g in site_guards if g))
        # display the origin (n resolved to pkt.len) so the complete picture is honest
        oroot = a.get("origin_root", a.get("root"))
        oval = a.get("origin_value", a.get("value"))
        # dedup on the security-relevant shape (a self-recursive call re-derives the same
        # value/sink/guards as the direct reach -> keep one, not two identical rows)
        key = (sink, oval, oroot, tuple(gsorted), len(site) > 0)
        if any((f["sink"], f["value"], f["root"], tuple(f["guards"]),
                f["site_guarded"]) == key for f in sink_flows):
            return
        sink_flows.append({"sink": sink, "value": oval, "root": oroot,
                           "provenance": a.get("origin_prov", a.get("provenance")),
                           "guards": gsorted, "guarded": len(gsorted) > 0,
                           "site_guarded": len(site) > 0, "via": via})
        # a value rooted at a parameter (whole param OR a field/element of it) composes
        # upward: the caller passing that param inherits this sink reach
        if oroot in params:
            merge_records(sink_params.setdefault(oroot, []), sink, gsorted)

    for call in fn["calls"]:
        callee = call["callee"]
        guard_here = {g["var"]: g["canon"] for g in call["guards"]}

        if call.get("is_sink"):
            for pos in sink_positions(call):
                a = next((x for x in call["args"] if x["pos"] == pos), None)
                if a and a.get("value"):
                    g = [guard_here[a["root"]]] if a.get("root") in guard_here else []
                    add_flow(a, sink_id(callee, pos), g, "direct", g)

        elif callee in summaries:                       # UDF with a ready summary
            gp = F[callee]["params"]
            gsum = summaries[callee]
            for a in call["args"]:
                if a["pos"] >= len(gp):
                    continue
                gparam = gp[a["pos"]]
                outer = [guard_here[a["root"]]] if a.get("root") in guard_here else []
                for rec in gsum["sink_params"].get(gparam, []):
                    # outer = guard applied AT THIS call site; rec["guards"] = guards the
                    # callee already applies internally (inherited, not on our value)
                    add_flow(a, rec["sink"], outer + rec["guards"], callee, outer)
                oroot = a.get("origin_root", a.get("root"))
                # only a WHOLE-object pass frees the param: `f(&data->field)` frees the
                # sub-object, not `data`, so it must not mark frees_params[data] -- that
                # over-claim would propagate "frees data" to every caller of this function
                # (the second-order form of the destructor-idiom phantom).
                if (gparam in gsum["frees_params"] and oroot in params
                        and _freed_identity(a) == a.get("root")):
                    frees[oroot] = f"via:{callee}"

    # direct frees on a parameter (from the event stream)
    for ev in fn["events"]:
        if ev["kind"] == "free" and ev["var"] in params:
            frees[ev["var"]] = "direct"

    # ---- interprocedural typestate per pointer ------------------------------------
    alloc_line = {}
    for a in fn.get("assigns", []):
        cn = a.get("callee")
        if norm.is_alloc(cn) or summaries.get(cn, {}).get("returns") == "alloc":
            alloc_line[a["var"]] = a["line"]
    for ev in fn["events"]:
        if ev["kind"] == "alloc":
            alloc_line.setdefault(ev["var"], ev["line"])

    def callee_param_stream(call, a):
        """The free/use/escape sub-stream a callee applies to the arg at this position,
        so a pointer passed in inherits the callee's lifetime effects (interprocedural)."""
        if call["callee"] not in summaries:
            return None
        gp = F[call["callee"]]["params"]
        if a["pos"] >= len(gp):
            return None
        return summaries[call["callee"]].get("param_typestate", {}).get(gp[a["pos"]])

    # graph node id for each alloc var's allocating call -- the CFG anchor of its alloc event,
    # so the path-sensitive matcher can seed the typestate walk at the right CFG node.
    alloc_node = {}
    for a in fn.get("assigns", []):
        alloc_node.setdefault(a["var"], a.get("node"))
    for ev in fn["events"]:
        if ev["kind"] == "alloc":
            alloc_node.setdefault(ev["var"], ev.get("node"))

    def lifetime_events_for(v, alloc_seed=None, free_seed=None):
        """Ordered alloc/use/free/escape stream for pointer `v`, composing callee effects.

        Each event carries its CFG anchor `node` (the call site for call-derived and spliced
        callee effects) so a path-sensitive matcher can walk them over the real CFG; the
        line ordering here is only a stable serialisation, not the analysis order.

        `free_seed=(line, node)` prepends a free event -- used when the pointer ARRIVES freed,
        i.e. it is the return value of a callee that handed back an already-freed pointer
        (returns_dangling), so a subsequent use in this function is a use-after-free."""
        stream = ([("alloc", alloc_seed, alloc_node.get(v))]
                  if alloc_seed is not None else [])
        if free_seed is not None:
            stream.append(("free", free_seed[0], free_seed[1]))
        for call in fn["calls"]:
            for a in call["args"]:
                if a.get("root") != v:
                    continue
                # object AS WRITTEN, not the base pointer: passing `&v->field` (or `v->field`,
                # `v[i]`, `*v`) to a callee that frees its formal frees the SUB-OBJECT, not `v`.
                # The splice below keys the callee's lifetime effects onto `v`'s stream; without
                # this guard a helper freeing `&data->meta_hash` lands a phantom free on `data`
                # itself -- the interprocedural form of the C destructor-idiom double-free
                # (free the members via helpers, then free the container). This is the same
                # "object as written" rule the local free emission already applies; a sub-object
                # of `v` belongs to its own lifetime, so it must not contribute to `v`'s stream.
                if _freed_identity(a) != v:
                    continue
                sub = callee_param_stream(call, a)
                if sub:                                    # splice the callee's effects
                    for e in sub:                          # pinned to this caller's call site
                        stream.append((e["kind"], call["line"], call.get("node")))
                    continue
                # a dealloc's free is emitted once from fn["events"], keyed on the object AS
                # WRITTEN (free(p->field) frees the sub-object, not p). Re-emitting it here keyed
                # on the base root a["root"] puts a field-free back on the base pointer's stream --
                # a phantom double-free of the C destructor idiom (free the members, free the
                # container). So skip the free here; fn["events"] is its single, correctly-keyed
                # source. This loop emits only the pointer-as-arg USE.
                if norm.is_dealloc(call["callee"]) and a["pos"] == 0:
                    continue
                stream.append(("use", call["line"], call.get("node")))
        for ev in fn["events"]:
            if ev["var"] == v and ev["kind"] in ("free", "use", "escape"):
                stream.append((ev["kind"], ev["line"], ev.get("node")))
        seen, ordered = set(), []
        for k, ln, nd in sorted(stream, key=lambda x: x[1] or 0):
            if (k, ln, nd) in seen:
                continue
            seen.add((k, ln, nd))
            ordered.append({"kind": k, "line": ln, "node": nd})
        return ordered

    # alloc'd locals -> full lifecycle starting at the alloc site
    typestate = {v: lifetime_events_for(v, aline) for v, aline in alloc_line.items()}

    # freed locals with no detectable local alloc: still track their free/use lifecycle so a
    # double-free / use-after-free over a local is not lost when the alloc site is invisible --
    # e.g. the allocating assignment's value-flow edge was never emitted (a cast between the
    # call and the write drops it), or the pointer was obtained some other way. The frees alone
    # carry the typestate the matcher needs; the alloc only seeds ALLOCATED, which the automaton
    # does not require to flag a second free. Params are exported through param_typestate instead.
    covered = set(typestate) | params
    for ev in fn["events"]:
        v = ev["var"]
        if ev["kind"] in ("free", "use") and v not in covered:
            covered.add(v)
            evs = lifetime_events_for(v)
            if evs:
                typestate[v] = evs

    # dangling return values: a callee that returns a pointer it already freed
    # (returns_dangling) hands the caller an already-freed pointer. Seed a free at the call
    # site so this function's subsequent use of the assigned var is a use-after-free, and a
    # subsequent free is a double-free -- the interprocedural analogue of splicing a freed
    # param's lifecycle, but through the RETURN value instead of an argument.
    for a in fn.get("assigns", []):
        cn = a.get("callee")
        if cn and summaries.get(cn, {}).get("returns_dangling") and a["var"] not in typestate:
            typestate[a["var"]] = lifetime_events_for(
                a["var"], free_seed=(a["line"], a.get("node")))

    # freed params -> lifetime WITHOUT a local alloc, exported so a caller that allocates
    # then passes the pointer can splice these effects (path-sensitive UAF across the call)
    param_typestate = {}
    for p in params:
        if any(ev["var"] == p and ev["kind"] == "free" for ev in fn["events"]) \
           or p in frees:
            evs = lifetime_events_for(p)
            if evs:
                param_typestate[p] = evs

    # returns / ownership, composed through calls
    ret, ret_param = "value", None
    for r in fn["returns"]:
        if r["kind"] == "alloc" or (r["kind"] == "var" and r.get("prov") == "alloc"):
            ret = "alloc"
        elif r["kind"] == "call" and summaries.get(r["callee"], {}).get("returns") == "alloc":
            ret = "alloc"
        elif r["kind"] == "var" and r.get("prov") == "param" and ret != "alloc":
            ret, ret_param = "param", r["var"]

    # returns_dangling: does F return a pointer it has FREED and not re-alloc'd? A `may` fact
    # read off the END state of the pointer's lifecycle stream (freed, with no realloc reopening
    # it) -- deliberately NOT gated on the return statement's line, which the graph does not
    # report reliably for a cast-wrapped `return expr`. The caller-side reach from the callsite
    # to the use stays path-sensitive in the matcher, exactly as the param_typestate splice
    # does. This is the missing ownership term next to `alloc`.
    def _ends_freed(v):
        freed = False
        for e in typestate.get(v) or lifetime_events_for(v):
            if e["kind"] == "alloc":
                freed = False
            elif e["kind"] == "free":
                freed = True
        return freed

    returns_dangling = False
    for r in fn["returns"]:
        if r.get("kind") == "var" and _ends_freed(r["var"]):
            returns_dangling = True
        elif r.get("kind") == "call" \
                and summaries.get(r.get("callee"), {}).get("returns_dangling"):
            returns_dangling = True

    return {
        "name": name,
        "params": fn["params"],
        "taxonomy": fn["taxonomy"],
        "sink_flows": sink_flows,
        "sink_params": sink_params,
        "typestate": typestate,
        "param_typestate": param_typestate,
        "frees_params": frees,
        "returns": ret,
        "returns_param": ret_param,
        "returns_dangling": returns_dangling,
    }


def run(F, schedule):
    summaries = {}
    for group in schedule:
        members = group["members"]
        if not group["cyclic"]:
            summaries[members[0]] = summarize_one(members[0], F, summaries)
            continue
        # fixpoint for a recursive group: seed empty, iterate until stable
        for m in members:
            summaries[m] = {"name": m, "params": F[m]["params"], "taxonomy": F[m]["taxonomy"],
                            "sink_flows": [], "sink_params": {}, "typestate": {},
                            "param_typestate": {}, "frees_params": {}, "returns": "value",
                            "returns_param": None, "returns_dangling": False}
        for _ in range(len(members) + 3):
            snapshot = json.dumps({m: summaries[m] for m in members}, sort_keys=True)
            for m in members:
                summaries[m] = summarize_one(m, F, summaries)
            if json.dumps({m: summaries[m] for m in members}, sort_keys=True) == snapshot:
                break
    return summaries


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--graph", default="graph.json")
    ap.add_argument("--out", default="summaries.json")
    args = ap.parse_args()

    F, succ = load_order(args.graph)
    schedule = build_order(F, succ)
    summaries = run(F, schedule)

    with open(args.out, "w") as fh:
        json.dump(summaries, fh, indent=2)

    # readable view: functions whose parameters flow to a sink (the differential's raw material)
    print(f"summarized {len(summaries)} functions -> {args.out}\n")
    print("=== parameters that reach a sink (guarded? => the differential's input) ===")
    for name in sorted(summaries):
        sp = summaries[name]["sink_params"]
        if not sp:
            continue
        for param, recs in sorted(sp.items()):
            for r in recs:
                mark = "GUARDED " if r["guarded"] else "UNGUARDED"
                gtxt = (" [" + ", ".join(r["guards"]) + "]") if r["guards"] else ""
                print(f"  {name:14}({param:4}) -> {r['sink']:14} {mark}{gtxt}")

    print("\n=== free effects (calling F frees the given arg) ===")
    for name in sorted(summaries):
        fp = summaries[name]["frees_params"]
        if fp:
            print(f"  {name:16} {fp}")

    print("\n=== returns alloc (ownership handed to caller) ===")
    owners = [n for n in sorted(summaries) if summaries[n]["returns"] == "alloc"]
    print("  " + ", ".join(owners))


if __name__ == "__main__":
    main()
