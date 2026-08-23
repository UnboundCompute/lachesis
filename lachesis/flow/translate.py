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
from collections import defaultdict
import json
import re

from lachesis.nav.graph_store import GraphStore
from lachesis.nav.kuzu_index import materialize_graph
from lachesis.core.query import GraphIndex
from lachesis.planner.unbounded_copy import BranchRegions

from . import atropos
from .normalize import normalizer
from .source_discovery import discover_sources


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


def _stmt_line(node):
    """A reliable source line for a lifecycle event, robust to the macro-expansion begin-loc bug.

    A macro-expanded call (`curlx_free(p)` -> `free`) reports a bogus BEGIN location -- line 1,
    offset 0 -- while its END location stays pinned to the real use site. Ordering events by that
    bogus begin collapses every macro free to line 1, so it sorts before real uses on later lines
    and manufactures a use-after-free. The end location is correct, so fall back to it when the
    begin is the offset-0 sentinel (nothing real begins at offset 0 but the TU's first token)."""
    p = _props(node)
    if p.get("start_offset"):                        # non-zero begin: the real start line
        return p.get("start_line")
    return p.get("end_line") or p.get("start_line")  # macro sentinel -> the correct end line


def _prov(kind):
    """Map a value node's kind to the coarse provenance tag summarize reads."""
    if kind == "parameter":
        return "param"
    if kind == "property":
        return "field"
    return "local"


# --- intra-function control nesting ----------------------------------------------
# Loop/branch keywords a rule keys on. `else` is folded into `if` -- an else arm is the
# same branch construct, and the enclosing `if (...) {...} else {...}` statement already
# carries the `if` head, so the arm needs no separate token.
_CONTROL_KW = {"if", "for", "while", "switch", "do"}


def _leading_control(label):
    """The control keyword a statement node opens with (`for (...) {...}` -> 'for'), or None.
    A plain statement (`char *buf = ...;`) or a bare block (`{ ... }`) returns None."""
    if not label:
        return None
    m = re.match(r"\s*([A-Za-z_]\w*)", label)
    kw = m.group(1) if m else None
    if kw == "else":
        return "if"
    return kw if kw in _CONTROL_KW else None


class ControlNesting:
    """The ordered loop/branch structure enclosing a call, from AST containment.

    The C frontend's ``cfg-condition`` nodes carry the control keyword but no source span, and
    the loop-body region edge (``LOOP_TRUE``) is not always emitted -- so region containment
    cannot place a call inside its loop. The AST does: a call's ``AST_CHILD`` parent chain runs
    up through the ``statement`` nodes that enclose it, and those DO carry spans and the full
    control text. We read each enclosing statement's leading keyword; that is the nesting."""

    def __init__(self, graph):
        self._by_id = {n["id"]: n for n in graph.get("nodes", ())}
        self._parent = {}
        for e in graph.get("edges", ()):
            if e.get("kind") == "AST_CHILD":
                self._parent[e["target"]] = e["source"]   # child -> parent

    def enclosing(self, node_id):
        """Ordered control kinds around ``node_id``, outermost first (``['for']`` for a copy
        nested one loop deep). Empty when the call sits at function top level."""
        kinds, cur, seen = [], node_id, set()
        while cur in self._parent and cur not in seen:
            seen.add(cur)
            cur = self._parent[cur]
            n = self._by_id.get(cur)
            if n and n.get("kind") == "statement":
                kw = _leading_control(n.get("label"))
                if kw:
                    kinds.append(kw)
        kinds.reverse()                                    # outermost -> innermost
        return kinds


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


_SUBOBJECT = ("->", ".", "[", "*")


def _freed_identity(arg):
    """The lifetime identity of the object a `free(...)` releases -- the argument AS WRITTEN.

    `free(p)` frees the base pointer `p`; `free(p->field)` / `free(p[i])` / `free(*p)` frees a
    SUB-OBJECT with its own lifetime, distinct from `p`. Value-flow resolves all of these to the
    same base decl `p` (the `root`), which conflates the canonical C destructor idiom
    (free the members, then free the container) into a phantom double-free -- two frees on one
    identity. Keying the free on the written access path keeps the sub-object free off the base
    pointer's stream: a later `free(p)` no longer meets `free(p->field)` as a prior free of the
    SAME object, and a `use(p)` no longer reads as a use of freed memory. Two frees still collide
    (a real double-free) exactly when they free the same written expression."""
    expr, root = arg.get("expr"), arg["root"]
    if expr and expr != root and root in expr and any(s in expr for s in _SUBOBJECT):
        return expr
    return root


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
        # the argument AS WRITTEN (`p->field`, `p[i]`, `*p`) before value-flow resolves it to
        # its base decl -- the base loses the access path, which the lifetime identity needs.
        expr = (ix.nodes.get(e["target"], {}) or {}).get("label")
        if vn is not None:                       # resolves to a decl/value the arg carries
            root = vn.get("label")
            out.append({"pos": pos, "var": root, "value": root, "expr": expr,
                        "root": root, "provenance": _prov(vn.get("kind"))})
        else:                                     # literal / unresolved expression
            an = ix.nodes.get(e["target"], {})
            out.append({"pos": pos, "var": None, "value": an.get("label"), "expr": expr,
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
    """Return records: alloc-owned / param passthrough / call result / plain value.

    A `return expr` node is usually a cast/paren wrapper, not the variable itself, so when the
    surface label is not a known var we resolve through value-flow to the underlying variable
    (the same VFT walk `_assigned_var` uses). This exposes a freed-then-returned local as a
    `var` return so the summary can flag a dangling return -- without it, `return p` after
    `free(p)` reads as an anonymous value and the interprocedural use-after-free is invisible."""
    out = []
    for rv in ix.sources(fid, "RETURNS_VALUE"):
        if rv.get("kind") == "call":
            out.append({"kind": "call", "callee": norm.canon_callee(_props(rv).get("callee")),
                        "line": _props(rv).get("start_line")})
            continue
        line = _props(rv).get("start_line")
        label = rv.get("label")
        var = label if (label in alloc_vars or label in params) else _assigned_var(ix, rv["id"])
        if var in alloc_vars:
            out.append({"kind": "var", "prov": "alloc", "var": var, "line": line})
        elif var in params:
            out.append({"kind": "var", "prov": "param", "var": var, "line": line})
        elif var:
            out.append({"kind": "var", "prov": "local", "var": var, "line": line})
        else:
            out.append({"kind": "value", "line": line})
    return out


def _walk_function(ix, regions, nest, sinks, norm, fnode):
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
        line = _stmt_line(c)
        callees.append(callee)
        args = _arg_records(ix, c)
        idents = {a["root"] for a in args if a["root"]}
        guards = _guards_for(regions, fid, idents, _span(c))
        cat = sinks.get(callee)
        # the variable this call's result is assigned to (any callee, not just allocators), so
        # `x = udf(...)` is a first-class assign the summary can compose through -- an allocator
        # wrapper's `returns=alloc` seeds an alloc, a freed-return's `returns_dangling` seeds a
        # free. `alloc_dst` is the is_alloc-gated subset used for the alloc event and sink dst.
        assigned = _assigned_var(ix, c["id"])
        alloc_dst = assigned if norm.is_alloc(callee) else None
        rec = {"callee": callee, "line": line, "args": args, "guards": guards,
               "is_sink": cat is not None,
               "assigned": assigned,
               "node": c["id"],                             # graph node = CFG anchor for events
               "control": nest.enclosing(c["id"])}          # loop/branch nesting, outer->inner
        if cat is not None:
            size_arg = cat.get("size_arg")
            rec["sink"] = {"size_arg": size_arg}
            # the size/length operand as written (the arg at the size position), so a rule can
            # compare an alloc's size against a copy's size on the same path
            sa = next((a for a in args if a.get("pos") == size_arg), None) if size_arg is not None else None
            rec["size_expr"] = sa.get("value") if sa else None
            # the destination the sink writes/allocates -- the identity a two-node shape joins on
            # (alloc: the pointer the result is assigned to; copy/write: the first argument)
            rec["dst"] = alloc_dst if norm.is_alloc(callee) else (args[0].get("value") if args else None)
        calls.append(rec)

        # Interprocedural dispatch seam. A resolved indirect call (`obj->ops->fn()`, a
        # function-pointer field) carries a MAY_INVOKE edge to every handler bound to its
        # slot -- the widened seam. Emit one synthetic call record per resolved handler,
        # over THIS call's args, so the summary pass composes each handler's effects (above
        # all its free/lifetime signature) at this site. That is what lets a free reached
        # only through the seam land on the pointer's typestate stream, so a later use is a
        # cross-seam use-after-free and a second free a cross-seam double-free. May-
        # semantics: the union over handlers (freed if ANY handler frees) is the sound
        # over-approximation for the temporal lattice; the judge prunes the spurious arms.
        for mi in ix.outgoing_of_kind(c["id"], "MAY_INVOKE"):
            hnode = ix.nodes.get(mi["target"])
            hcallee = norm.canon_callee(hnode.get("label")) if hnode else None
            if not hcallee or hcallee == callee:
                continue
            callees.append(hcallee)
            hcat = sinks.get(hcallee)
            hrec = {"callee": hcallee, "line": line, "args": args, "guards": guards,
                    "is_sink": hcat is not None, "node": c["id"],
                    "control": rec["control"], "dispatch": "may-invoke"}
            if hcat is not None:
                hsize = hcat.get("size_arg")
                hrec["sink"] = {"size_arg": hsize}
                hsa = (next((a for a in args if a.get("pos") == hsize), None)
                       if hsize is not None else None)
                hrec["size_expr"] = hsa.get("value") if hsa else None
                hrec["dst"] = (assigned if norm.is_alloc(hcallee)
                               else (args[0].get("value") if args else None))
            calls.append(hrec)

        if assigned:
            assigns.append({"var": assigned, "callee": callee, "line": line, "node": c["id"]})
        if alloc_dst:
            events.append({"kind": "alloc", "var": alloc_dst, "line": line, "node": c["id"]})
        if norm.is_dealloc(callee) and args and args[0]["root"]:
            events.append({"kind": "free", "var": _freed_identity(args[0]), "line": line,
                           "node": c["id"]})

    alloc_vars = {a["var"] for a in assigns}
    returns = _returns(ix, fid, alloc_vars, param_set, norm)
    for r in returns:                             # a returned alloc'd local escapes
        if r.get("kind") == "var" and r.get("prov") == "alloc":
            events.append({"kind": "escape", "var": r["var"], "line": r.get("line")})

    return {"name": fnode.get("label"),
            "file": _props(fnode).get("file"), "line": _props(fnode).get("start_line"),
            "params": params, "calls": calls, "events": events,
            "assigns": assigns, "returns": returns, "callees": callees}


def build_F(store, lang="c", *, return_graph=False):
    """Build the whole-graph F dict + succ (callee-edge) map from an enriched store.

    Reproduces order.load's return so the pass is input-source agnostic. Taxonomy /
    caller / source classification is the same class rule the old parser used."""
    source_ix = store.index
    # Disk-backed stores need a columnar materialization for BranchRegions. Tests and
    # embedding callers can supply an already-materialized in-memory GraphStore; do not
    # assume its GraphIndex has Kuzu's private connection surface.
    graph = (store.graph if store.graph is not None
             else materialize_graph(source_ix))
    # Once a disk graph has been materialized, keep the complete projection on its
    # in-memory index.  Continuing to use ``source_ix`` here turned every helper in
    # ``_walk_function`` into another Kuzu query for each of thousands of functions.
    # The graph is a faithful snapshot taken after ensure_dataflow_tier(), so these
    # indexes have the same semantics and radically different access costs.
    # Flow translation only needs kind/adjacency/ownership access.  A full GraphStore
    # wrapper would retain navigation-only label/file buckets over the materialized
    # graph; the compact index defers those buckets until a caller explicitly asks.
    ix = source_ix if store.graph is not None else GraphIndex(graph, compact=True)
    regions = BranchRegions(graph)
    nest = ControlNesting(graph)                   # loop/branch nesting from AST containment
    sinks = atropos.sink_catalog(lang)
    sink_names = set(sinks)
    norm = normalizer(lang)                        # form oracle: canonicalize callee names
    source_methods = set(atropos.source_catalog(lang))

    fnodes = list(ix.nodes_of_kind("function", "method", "constructor"))
    defined = {f.get("label") for f in fnodes if not _props(f).get("declaration_only")}

    recs = {}
    for f in fnodes:
        if _props(f).get("declaration_only"):
            continue
        name = f.get("label")
        if not name or name in recs:              # first defined record wins (static dupes)
            continue
        recs[name] = _walk_function(ix, regions, nest, sinks, norm, f)

    def is_lifecycle_or_sink(c):
        return c in sink_names or norm.is_alloc(c) or norm.is_dealloc(c)

    # Compute the transitive caller closure once.  The old implementation launched a
    # depth-first walk from every function, allocating a fresh ``seen`` set each time;
    # on a large call graph that revisited the same shared callees O(functions) times.
    # A reverse walk from functions with a direct lifecycle/sink callee is equivalent,
    # including cyclic call components, and touches each recorded call edge at most
    # once.
    reverse_callers = defaultdict(set)
    sink_reachable = set()
    for name, record in recs.items():
        for callee in record["callees"]:
            if is_lifecycle_or_sink(callee):
                sink_reachable.add(name)
            elif callee in recs:
                reverse_callers[callee].add(name)
    pending = list(sink_reachable)
    while pending:
        callee = pending.pop()
        for caller in reverse_callers.get(callee, ()):
            if caller not in sink_reachable:
                sink_reachable.add(caller)
                pending.append(caller)

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
        elif n in sink_reachable:
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
            # Pass-2 source facts are retained separately from reachability.  A
            # callerless function is only a structural entry; an actual source call
            # is the operation from which Claus should launch.
            "source_calls": [
                {"callee": call["callee"], "line": call.get("line"), "node": call.get("node"),
                 "assigned": call.get("assigned"),
                 "args": [arg.get("pos") for arg in call.get("args", ())]}
                for call in r["calls"] if call.get("callee") in source_methods
            ],
            "source_reachable": bool(len(callers[n]) == 0 or
                                      any(call.get("callee") in source_methods
                                          for call in r["calls"])),
        }

    succ = {n: [c for c in F[n]["udf_callees"] if c in F] for n in F}
    discovery = discover_sources(F, succ, atropos.source_catalog(lang))
    by_function_bindings = {}
    for binding in discovery.bindings:
        by_function_bindings.setdefault(binding.caller, []).append({
            "callee": binding.callee, "call_node": binding.call_node,
            "formal_to_actual": list(binding.formal_to_actual),
            "return_to": binding.return_to,
        })
    for name, record in F.items():
        record["source_sites"] = [
            {"node": site.node, "callee": site.callee, "line": site.line,
             "arguments": list(site.arguments), "influenced_roots": list(site.influenced_roots),
             "kind": site.kind}
            for site in discovery.sites_for(name)
        ]
        record["seam_bindings"] = by_function_bindings.get(name, [])
        record["source_reachable"] = name in discovery.reachable_functions
    return (F, succ, graph) if return_graph else (F, succ)


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
