#!/usr/bin/env python3
"""Graph -> F translation layer for the flow pass.

This does NOT parse, compile, or modify anything. It is a pure translator: it
reads an already-built, **enriched** Lachesis Kuzu graph (clang ran once, at
build time, to produce that graph) and projects the facts it already holds into
the compact per-function F IR the rest of the pass (order.py / traverse.py /
summarize.py) consumes. Every field below is looked up in the graph, never
computed from source text.

It replaces the old input stage -- the standalone clang parser
(parse.py, which re-ran ``clang -ast-dump``) and the minimal-graph builder
(variables.py). Same F out; the difference is where F comes from (a graph we
already have vs. a fresh reparse of the source).

Contract reproduced (the record ``order.load`` used to return, one per defined UDF):

    {name, file, line, taxonomy, is_source, params,
     udf_callees, ldf_callees, sink_ldf_callees, callers,
     calls[  {callee, line, is_sink, sink:{size_arg},
              args[{pos, var, value, root, provenance}],
              guards[{var, canon}]} ],
     events[{kind: alloc|free|escape, var, line}],
     assigns[{var, callee, line}],
     returns[{kind: alloc|var|call|value, var?, prov?, callee?}]}

Drop-in: ``load_graph(path)`` mirrors ``order.load`` and returns ``(F, succ)``.

Known gaps vs the old clang parser (honest, not silent):
  * memory.deref use-events for a standalone dereference (``return buf[0]`` after a
    free) are NOT emitted -- the reader does not stamp deref lifecycle nodes yet
    (the tier-2 blocker). Uses that pass through a call ARE recovered by summarize.
  * arg provenance is shallow: parameter / field / local / const, not the full
    origin walk (n <- r.count <- param r). Guard presence -- the differential's
    signal -- does not depend on it.
"""
import argparse
import json

from lachesis.nav.graph_store import GraphStore
from lachesis.nav.kuzu_index import materialize_graph
from lachesis.planner.unbounded_copy import BranchRegions

from . import atropos
from .normalize import normalizer


# --- small helpers ---------------------------------------------------------------
def _props(node):
    return (node or {}).get("properties") or {}


def _span(node):
    """(file, start_offset, end_offset) of a node, or None -- the shape BranchRegions wants."""
    p = _props(node)
    path = p.get("absolute_file") or p.get("file")
    s, e = p.get("start_offset"), p.get("end_offset")
    if not path or s is None or e is None:
        return None
    return (path, s, e)


def _by_offset(nodes):
    return sorted(nodes, key=lambda n: _props(n).get("start_offset") or 0)


def _prov(kind):
    """Map a value node's kind to the coarse provenance tag summarize reads."""
    if kind == "parameter":
        return "param"
    if kind == "property":
        return "field"
    return "local"


def _assigned_var(ix, call_id):
    """The variable a call result initializes: call --VFT--> ... --VFT--> variable.

    C emits ``buf = kmalloc(...)`` as call -> call-expression (value-preserving) ->
    variable (initializer/write), so a shallow forward VFT walk finds the pointer."""
    seen = set()
    frontier = [(call_id, 0)]
    while frontier:
        nid, d = frontier.pop(0)
        if nid in seen or d > 3:
            continue
        seen.add(nid)
        for e in ix.outgoing_of_kind(nid, "VALUE_FLOWS_TO"):
            tn = ix.nodes.get(e["target"])
            if tn is None:
                continue
            if tn.get("kind") == "variable":
                return tn.get("label")
            frontier.append((e["target"], d + 1))
    return None


def _arg_records(ix, call):
    """Ordered argument records for a call, resolved through argument_value_ids."""
    p = _props(call)
    av = p.get("argument_value_ids") or []
    out = []
    edges = sorted(ix.outgoing_of_kind(call["id"], "HAS_ARGUMENT"),
                   key=lambda e: _props(e).get("position") or 0)
    for e in edges:
        pos = _props(e).get("position")
        vid = av[pos] if (isinstance(pos, int) and pos < len(av)) else None
        vn = ix.nodes.get(vid) if vid else None
        if vn is not None:                       # resolves to a decl/value the arg carries
            root = vn.get("label")
            out.append({"pos": pos, "var": root, "value": root,
                        "root": root, "provenance": _prov(vn.get("kind"))})
        else:                                     # literal / unresolved expression
            an = ix.nodes.get(e["target"], {})
            out.append({"pos": pos, "var": None, "value": an.get("label"),
                        "root": None, "provenance": "const"})
    return out


def _guards_for(regions, fid, idents, span):
    """Guards active at a call site: {var, canon} for each arg-root a dominating
    size-testing branch names. Uses the same sound region-containment the reader's
    candidate enumerators use (guarded-region only; early-return guards read as none)."""
    if not idents or span is None:
        return []
    verdict = regions.classify(fid, idents, span)
    if verdict.get("status") != "guarded-region":
        return []
    out, seen = [], set()
    for reg in verdict.get("regions", ()):
        canon = reg.get("condition")
        for name in reg.get("names", ()):
            if (name, canon) in seen:
                continue
            seen.add((name, canon))
            out.append({"var": name, "canon": canon})
    return out


def _returns(ix, fid, alloc_vars, params, norm):
    """Return records: alloc-owned / param passthrough / call result / plain value."""
    out = []
    for rv in ix.sources(fid, "RETURNS_VALUE"):
        if rv.get("kind") == "call":
            out.append({"kind": "call", "callee": norm.canon_callee(_props(rv).get("callee")),
                        "line": _props(rv).get("start_line")})
            continue
        label = rv.get("label")
        line = _props(rv).get("start_line")
        if label in alloc_vars:
            out.append({"kind": "var", "prov": "alloc", "var": label, "line": line})
        elif label in params:
            out.append({"kind": "var", "prov": "param", "var": label, "line": line})
        else:
            out.append({"kind": "value", "line": line})
    return out


def _walk_function(ix, regions, sinks, norm, fnode):
    """Reconstruct one function's F IR from its owned graph nodes.

    Callee names are canonicalized through `norm` (the Atropos form oracle) as they leave the
    graph, so every downstream fact -- sink lookup, alloc/free events, summaries, skeletons --
    speaks one vocabulary. The graph node keeps its surface name; only this IR is rewritten."""
    fid = fnode["id"]
    params = [p.get("label") for p in _by_offset(ix.nodes_owned_by(fid, "parameter"))]
    param_set = set(params)
    calls, callees, events, assigns = [], [], [], []

    for c in _by_offset(ix.nodes_owned_by(fid, "call")):
        callee = norm.canon_callee(_props(c).get("callee"))
        if not callee:
            continue
        line = _props(c).get("start_line")
        callees.append(callee)
        args = _arg_records(ix, c)
        idents = {a["root"] for a in args if a["root"]}
        guards = _guards_for(regions, fid, idents, _span(c))
        cat = sinks.get(callee)
        rec = {"callee": callee, "line": line, "args": args, "guards": guards,
               "is_sink": cat is not None}
        if cat is not None:
            rec["sink"] = {"size_arg": cat.get("size_arg")}
        calls.append(rec)

        if norm.is_alloc(callee):
            var = _assigned_var(ix, c["id"])
            if var:
                events.append({"kind": "alloc", "var": var, "line": line})
                assigns.append({"var": var, "callee": callee, "line": line})
        if norm.is_dealloc(callee) and args and args[0]["root"]:
            events.append({"kind": "free", "var": args[0]["root"], "line": line})

    alloc_vars = {a["var"] for a in assigns}
    returns = _returns(ix, fid, alloc_vars, param_set, norm)
    for r in returns:                             # a returned alloc'd local escapes
        if r.get("kind") == "var" and r.get("prov") == "alloc":
            events.append({"kind": "escape", "var": r["var"], "line": r.get("line")})

    return {"name": fnode.get("label"),
            "file": _props(fnode).get("file"), "line": _props(fnode).get("start_line"),
            "params": params, "calls": calls, "events": events,
            "assigns": assigns, "returns": returns, "callees": callees}


def build_F(store, lang="c"):
    """Build the whole-graph F dict + succ (callee-edge) map from an enriched store.

    Reproduces order.load's return so the pass is input-source agnostic. Taxonomy /
    caller / source classification is the same class rule the old parser used."""
    ix = store.index
    graph = materialize_graph(ix)
    regions = BranchRegions(graph)
    sinks = atropos.sink_catalog(lang)
    sink_names = set(sinks)
    norm = normalizer(lang)                        # form oracle: canonicalize callee names

    fnodes = list(ix.nodes_of_kind("function", "method", "constructor"))
    defined = {f.get("label") for f in fnodes if not _props(f).get("declaration_only")}

    recs = {}
    for f in fnodes:
        if _props(f).get("declaration_only"):
            continue
        name = f.get("label")
        if not name or name in recs:              # first defined record wins (static dupes)
            continue
        recs[name] = _walk_function(ix, regions, sinks, norm, f)

    def is_lifecycle_or_sink(c):
        return c in sink_names or norm.is_alloc(c) or norm.is_dealloc(c)

    def reaches_sink(name, seen):
        if name in seen:
            return False
        seen.add(name)
        r = recs.get(name)
        if not r:
            return False
        for c in r["callees"]:
            if is_lifecycle_or_sink(c):
                return True
            if c in defined and reaches_sink(c, seen):
                return True
        return False

    callers = {n: set() for n in recs}
    for n, r in recs.items():
        for c in r["callees"]:
            if c in recs:
                callers[c].add(n)

    F = {}
    for n, r in recs.items():
        udf_callees = sorted({c for c in r["callees"] if c in recs})
        ldf_callees = sorted({c for c in r["callees"] if c not in recs})
        sink_ldf = sorted({c for c in ldf_callees if is_lifecycle_or_sink(c)})
        is_leaf = len(udf_callees) == 0
        if is_leaf and sink_ldf:
            taxo = "LS-UDF"
        elif is_leaf:
            taxo = "LUDF"
        elif reaches_sink(n, set()):
            taxo = "S-UDF"
        else:
            taxo = "UDF"
        F[n] = {
            "name": n, "file": r["file"], "line": r["line"],
            "taxonomy": taxo, "is_source": len(callers[n]) == 0,
            "params": r["params"],
            "udf_callees": udf_callees, "ldf_callees": ldf_callees,
            "sink_ldf_callees": sink_ldf, "callers": sorted(callers[n]),
            "calls": r["calls"], "events": r["events"],
            "assigns": r["assigns"], "returns": r["returns"],
        }

    succ = {n: [c for c in F[n]["udf_callees"] if c in F] for n in F}
    return F, succ


def load_graph(path, lang="c"):
    """Drop-in for order.load: open + enrich a Lachesis store, return (F, succ)."""
    store = GraphStore.load(path)
    store.ensure_dataflow_tier()                  # whole-graph value flow (cached beside store)
    return build_F(store, lang=lang)


def main():
    ap = argparse.ArgumentParser(description="dump the F IR built from a Lachesis graph")
    ap.add_argument("graph", help="path to a built Lachesis .kuzu store")
    ap.add_argument("--lang", default="c")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()
    F, succ = load_graph(args.graph, lang=args.lang)
    doc = {"functions": list(F.values())}
    if args.out:
        with open(args.out, "w") as fh:
            json.dump(doc, fh, indent=2)
    print(f"built F for {len(F)} defined function(s) from {args.graph}")
    by_tax = {}
    for r in F.values():
        by_tax[r["taxonomy"]] = by_tax.get(r["taxonomy"], 0) + 1
    print(f"  taxonomy: {by_tax}   sources: {sum(1 for r in F.values() if r['is_source'])}")


if __name__ == "__main__":
    main()
