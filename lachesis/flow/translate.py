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

Known limitations vs a full object-state analysis (honest, not silent):
  * the compact F projection carries shallow provenance (parameter / field / local /
    const), not the full origin walk (n <- r.count <- param r); the native semantic
    graph receives richer declaration-rooted facts from the object substrate.
  * the generic non-native backend preserves the lifecycle and sink facts available in
    F, but does not invent frontend branch histories or heap aliases that were not
    emitted by that frontend.
"""
import argparse
from collections import Counter, defaultdict
import json
import re

from lachesis.nav.graph_store import GraphStore
from lachesis.planner.unbounded_copy import BranchRegions

from . import atropos
from .normalize import normalizer
from .source_discovery import discover_sources
from .coverage import CoverageScheduler
from lachesis.timeit import timeit


# --- small helpers ---------------------------------------------------------------
def _props(node):
    return (node or {}).get("properties") or {}


def _callee_name(node):
    """Frontend-neutral call spelling, including receiver methods."""
    p = _props(node)
    return (p.get("callee") or p.get("callee_name") or p.get("method_name")
            or node.get("label"))


def _header_node(ix, node_id):
    """Return the kind/label view needed by projection without a Kùzu fetch."""
    if node_id is None:
        return None
    if hasattr(ix, "_kind_by_id"):
        # Header nodes are read-only projection values.  Translation asks for the
        # same callee/argument/control headers repeatedly; rebuilding a dict and
        # copying its promoted properties on every lookup adds measurable Python
        # allocation pressure after the Kùzu fetches have been batched.
        cache = getattr(ix, "_translation_header_cache", None)
        if cache is None:
            cache = ix._translation_header_cache = {}
        cached = cache.get(node_id)
        if cached is not None:
            return cached
        kind = ix._kind_by_id.get(node_id)
        label = ix._label_by_id.get(node_id)
        node = {"id": node_id, "kind": kind, "label": label,
                "properties": dict(ix._header_by_id.get(node_id, {}))}
        cache[node_id] = node
        return node
    return ix.nodes.get(node_id)


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
        self._index = None if isinstance(graph, dict) else graph
        self._by_id = ({n["id"]: n for n in graph.get("nodes", ())}
                       if isinstance(graph, dict) else {})
        self._parent = {}
        self._headers = {}
        self._enclosing_cache = {}
        self._bulk_parent_kinds = frozenset()
        if isinstance(graph, dict):
            for e in graph.get("edges", ()):
                if e.get("kind") == "AST_CHILD":
                    self._parent[e["target"]] = e["source"]   # child -> parent
        elif hasattr(self._index, "ast_direct_parents"):
            target_kinds = ["call", "construct", "dynamic-behavior", "write"]
            # On large repositories, the next ancestor after a call is commonly
            # a statement. Prefetching that one additional level amortizes the
            # generic reverse-edge query; skip it on small fixtures where setup
            # would dominate.
            site_count = sum(len(self._index.by_kind.get(kind, ()))
                             for kind in target_kinds)
            if site_count > 10000:
                target_kinds.append("statement")
                # Calls are often nested through expression wrappers before reaching
                # the statement that carries the control keyword.  Prefetching this
                # intermediate parent column costs <1s on the libxml2 store and
                # avoids falling back to one reverse-edge query per site.
                target_kinds.append("expression")
            self._bulk_parent_kinds = frozenset(target_kinds)
            self._parent = self._index.ast_direct_parents(target_kinds)
            if hasattr(self._index, "node_headers"):
                self._headers = {
                    node["id"]: node
                    for node in self._index.node_headers(self._parent.values())
                }

    @timeit
    def enclosing(self, node_id):
        """Ordered control kinds around ``node_id``, outermost first (``['for']`` for a copy
        nested one loop deep). Empty when the call sits at function top level."""
        cached = self._enclosing_cache.get(node_id)
        if cached is not None:
            return list(cached)
        kinds, cur, seen = [], node_id, set()
        while cur not in seen:
            seen.add(cur)
            if self._index is None:
                if cur not in self._parent:
                    break
                cur = self._parent[cur]
                n = self._by_id.get(cur)
            else:
                if cur in self._parent:
                    cur = self._parent[cur]
                    n = self._headers.get(cur) or _header_node(self._index, cur)
                else:
                    # ``ast_direct_parents`` queried every AST child whose target
                    # kind is in this set.  A missing entry for such a node means
                    # it has no AST parent; asking Kùzu again through
                    # incoming_of_kind() only rediscovers that empty result.  A
                    # parent whose kind was not bulk-queried still uses the
                    # compatibility fallback below.
                    if (self._bulk_parent_kinds and
                            getattr(self._index, "_kind_by_id", {}).get(cur)
                            in self._bulk_parent_kinds):
                        break
                    parents = self._index.incoming_of_kind(cur, "AST_CHILD")
                    if not parents:
                        break
                    cur = parents[0]["source"]
                    n = self._index.nodes.get(cur)
            if n and n.get("kind") == "statement":
                kw = _leading_control(n.get("label"))
                if kw:
                    kinds.append(kw)
        kinds.reverse()                                    # outermost -> innermost
        # The returned list is never mutated by translation.  Store a tuple so
        # repeated projections share the value and callers cannot corrupt the cache.
        result = tuple(kinds)
        self._enclosing_cache[node_id] = result
        return kinds


@timeit
def _assigned_var(ix, call_id, value_edges=None):
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
        if value_edges is not None:
            edges = value_edges.get(nid, ())
        else:
            edges = ix.outgoing_of_kind(nid, "VALUE_FLOWS_TO")
        for e in edges:
            target_id = e if isinstance(e, str) else e["target"]
            if hasattr(ix, "_kind_by_id"):
                target_kind = ix._kind_by_id.get(target_id)
                target_label = ix._label_by_id.get(target_id)
                tn = {"kind": target_kind, "label": target_label}
            else:
                tn = ix.nodes.get(target_id)
            if tn is None or tn.get("kind") is None:
                continue
            if tn.get("kind") == "variable":
                return tn.get("label")
            # Call results can be assigned directly into a field or indexed
            # slot (`s->request = make_buffer(...)`). Preserve that expression
            # instead of discarding the receiver at the variable-only boundary;
            # Claus needs it to transfer return values and NULL facts across the
            # seam with field-sensitive identity.
            if tn.get("kind") == "expression":
                label = tn.get("label") or ""
                if any(marker in label for marker in _SUBOBJECT):
                    return label
            frontier.append((target_id, d + 1))
    return None


_SUBOBJECT = ("->", ".", "[", "*")


def _flow_node_needed(ix, node_id, kind=None, label=None):
    """Whether a lazy body node can contribute to the structural read stream."""
    kind = kind or ix._kind_by_id.get(node_id)
    if kind not in {"expression", "body", "read"}:
        return True
    label = label or ix._label_by_id.get(node_id) or ""
    return any(marker in str(label) for marker in _SUBOBJECT)


def _flow_header_node(node):
    """Make the read projection from promoted header fields only.

    Read events consume only ``kind``, spelling, and source line.  Inferring the
    accepted structural syntax from the spelling avoids inflating the large
    property tail for every expression node; ambiguous spellings are left out,
    which is safer than inventing a dereference.
    """
    label = str(node.get("label") or "")
    text = label.strip()
    syntax = None
    if "->" in label:
        syntax = "MemberExpr"
    elif "[" in label and "]" in label:
        syntax = "ArraySubscriptExpr"
    elif re.match(r"\s*\*", label):
        syntax = "UnaryOperator"
    elif re.search(r"[A-Za-z_]\w*\s*\.\s*[A-Za-z_]\w*", label):
        syntax = "MemberExpr"
    if syntax is None:
        return None
    properties = dict(node.get("properties") or {})
    properties["syntax_kind"] = syntax
    return {"id": node.get("id"), "kind": node.get("kind"),
            "label": node.get("label"), "properties": properties}


def _prefetched_owned(ix, owner_id, kind):
    """Read an already-prefetched owned-node slice without starting a query.

    Translation prefetches the small set of flow-bearing node kinds in one owner
    scan.  Calling the generic ``nodes_owned_by`` accessor afterwards can repeat a
    per-function warm-up for dynamic/write projections, defeating that prefetch.
    Keep the fallback for in-memory and third-party indexes.
    """
    prefetched = getattr(ix, "_translation_prefetched_kinds", ())
    if kind not in prefetched or not hasattr(ix, "_node_cache"):
        return ix.nodes_owned_by(owner_id, kind)
    out = []
    for node_id in ix.by_owner.get(owner_id, ()):
        if ix._kind_by_id.get(node_id) != kind:
            continue
        node = ix._node_cache.get(node_id)
        if node is not None:
            out.append(node)
    return tuple(out)


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


def _read_root(label, tracked):
    """Recover the base object from a frontend read spelling."""
    if not label:
        return None
    match = re.match(r"\s*(?:\*\s*)?([A-Za-z_]\w*)", str(label))
    root = match.group(1) if match else None
    return root if root in tracked else None


@timeit
def _arg_records(ix, call, argument_edges=None):
    """Ordered argument records for a call, resolved through argument_value_ids."""
    p = _props(call)
    av = p.get("argument_value_ids") or []
    out = []
    edges = sorted((argument_edges.get(call["id"], ())
                    if argument_edges is not None
                    else ix.outgoing_of_kind(call["id"], "HAS_ARGUMENT")),
                   key=lambda e: _props(e).get("position") or 0)
    for e in edges:
        pos = _props(e).get("position")
        vid = av[pos] if (isinstance(pos, int) and pos < len(av)) else None
        vn = _header_node(ix, vid) if vid else None
        # the argument AS WRITTEN (`p->field`, `p[i]`, `*p`) before value-flow resolves it to
        # its base decl -- the base loses the access path, which the lifetime identity needs.
        expr = (_header_node(ix, e["target"]) or {}).get("label")
        if vn is not None:                       # resolves to a decl/value the arg carries
            root = vn.get("label")
            out.append({"pos": pos, "var": root, "value": root, "expr": expr,
                        "root": root, "provenance": _prov(vn.get("kind"))})
        else:                                     # literal / unresolved expression
            an = _header_node(ix, e["target"]) or {}
            out.append({"pos": pos, "var": None, "value": an.get("label"), "expr": expr,
                        "root": None, "provenance": "const"})
    return out


def _expression_root(label):
    """Return the lexical root of a neutral expression, when one is visible."""
    match = re.match(r"\s*(?:[*&]\s*)*([A-Za-z_]\w*)", str(label or ""))
    return match.group(1) if match else None


def _catalog_sink(sinks, callee, call_props):
    """Look up a sink by canonical name, then by a simple module receiver.

    Python's AST frontend keeps ``os.makedirs`` as method ``makedirs`` plus
    receiver ``os``.  Atropos models the qualified library symbol, while
    receiver methods such as ``cursor.execute`` intentionally use the bare
    method key.  This neutral lookup preserves both forms without embedding a
    library-specific list in the flow layer.
    """
    direct = sinks.get(callee)
    if direct is not None:
        return direct, callee
    receiver = (call_props.get("receiver") or call_props.get("receiver_root")
                or call_props.get("receiver_value"))
    module = _expression_root(receiver)
    qualified = f"{module}.{callee}" if module and module != callee else None
    return (sinks.get(qualified), qualified) if qualified else (None, None)


@timeit
def _dynamic_property_writes(ix, regions, nest, fid):
    """Project computed member writes into the common sink vocabulary.

    Library sinks are represented by call-model rows, but a computed write such as
    ``target[key] = value`` has no callee to model.  Frontends already preserve this
    fact either as a T3 ``computed-property-write`` behavior (JS/TS) or as a write
    whose property path contains a dynamic segment (Python/C).  Keep the rule here,
    at the language-neutral boundary, so every frontend gets the same sink family.

    Literal member writes deliberately do not enter this projection: ``target.foo``
    is a named field, not an attacker-selected prototype key.
    """
    records, seen = [], set()

    def add(node, props, target, key_expression, key_node=None):
        target_props = _props(target)
        if not target or not target_props.get("dynamic"):
            return
        anchor = props.get("site_id") or props.get("evidenced_by") or node.get("id")
        dedupe = (anchor, props.get("target_id"), key_expression)
        if dedupe in seen:
            return
        seen.add(dedupe)
        key_label = (key_node or {}).get("label") if key_node else key_expression
        key_root = _expression_root(key_label)
        key_provenance = _prov((key_node or {}).get("kind")) if key_node else "local"
        span = _span(node)
        idents = {key_root} if key_root else set()
        guards = _guards_for(regions, fid, idents, span)
        record = {
            "callee": "__computed_property_write__",
            "line": _stmt_line(node),
            "args": [{"pos": 0, "var": key_root, "value": key_root or key_expression,
                      "expr": key_expression, "root": key_root,
                      "provenance": key_provenance}],
            "guards": guards,
            "guard_status": _guard_status_for(regions, fid, idents, span),
            "guard_predicates": tuple(g.get("canon") for g in guards if g.get("canon")),
            "is_sink": True,
            "sink_family": "prototype-pollution",
            "sink_arg": 0,
            "dynamic_property_write": True,
            "target_id": props.get("target_id"),
            "key_expression": key_expression,
            "dst": target.get("label"),
            "node": anchor,
            "control": nest.enclosing(anchor),
        }
        records.append(record)

    # TypeScript/JavaScript emits the key's value node and target path directly.
    for node in _by_offset(_prefetched_owned(ix, fid, "dynamic-behavior")):
        props = _props(node)
        if props.get("behavior_kind") != "computed-property-write":
            continue
        target = ix.nodes.get(props.get("target_id"))
        key_node = ix.nodes.get(props.get("key_value_id"))
        add(node, props, target, props.get("key_expression"), key_node)

    # Python, C, and any future frontend can use the shared write/property-path
    # contract without needing a frontend-specific behavior marker.
    for node in _by_offset(_prefetched_owned(ix, fid, "write")):
        props = _props(node)
        target = ix.nodes.get(props.get("target_id"))
        target_props = _props(target)
        segments = target_props.get("path_segments") or ()
        dynamic = [segment for segment in segments
                   if isinstance(segment, dict) and segment.get("dynamic")]
        if not dynamic:
            continue
        key_expression = dynamic[-1].get("key")
        add(node, props, target, key_expression)
    return records


def _expanded_macro_size(call, args, macro_defs, callee):
    """Recover an allocator's size expression when Clang lowered a macro call.

    The frontend graph preserves the macro definition and the call's argument
    values, but the lowered ``malloc`` node otherwise exposes only the final
    parameter (for example ``count``).  Expanding the recorded declarative macro
    body here keeps the fact language-neutral and avoids matching macro names or
    fixture text in the detector.
    """
    name = str(call.get("label") or "").strip()
    definition = macro_defs.get(name)
    if not definition or callee not in str(definition.get("body") or ""):
        return None
    body = str(definition.get("body") or "")
    parameters = tuple(definition.get("parameters") or ())
    substitutions = {
        parameter: str(args[index].get("expr") or args[index].get("value") or "")
        for index, parameter in enumerate(parameters)
        if index < len(args)
    }
    for parameter, replacement in substitutions.items():
        body = re.sub(rf"\b{re.escape(parameter)}\b", replacement, body)
    match = re.search(rf"\b{re.escape(callee)}\s*\((.*)\)", body)
    return match.group(1).strip() if match else None


@timeit
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


@timeit
def _guard_status_for(regions, fid, idents, span):
    """Return the Atropos guard-dimension status without collapsing it to a bool.

    ``guarded-region`` and ``fall-through`` are distinct semantic observations;
    the latter is the missing-bounds shape.  Keeping the status beside the typed
    guard list lets sink evaluators consume it without weakening lifetime/null
    guard handling.
    """
    if not idents or span is None:
        return "not-computed"
    return regions.classify(fid, idents, span).get("status", "not-computed")


@timeit
def _returns(ix, fid, alloc_vars, params, norm, value_edges=None,
             return_values=None):
    """Return records: alloc-owned / param passthrough / call result / plain value.

    A `return expr` node is usually a cast/paren wrapper, not the variable itself, so when the
    surface label is not a known var we resolve through value-flow to the underlying variable
    (the same VFT walk `_assigned_var` uses). This exposes a freed-then-returned local as a
    `var` return so the summary can flag a dangling return -- without it, `return p` after
    `free(p)` reads as an anonymous value and the interprocedural use-after-free is invisible."""
    out = []
    source_nodes = (return_values.get(fid, ()) if return_values is not None
                    else ix.sources(fid, "RETURNS_VALUE"))
    for rv in source_nodes:
        if rv.get("kind") == "call":
            out.append({"kind": "call", "callee": norm.canon_callee(_props(rv).get("callee")),
                        "line": _props(rv).get("start_line")})
            continue
        line = _props(rv).get("start_line")
        label = rv.get("label")
        var = (label if (label in alloc_vars or label in params)
               else _assigned_var(ix, rv["id"], value_edges))
        if var in alloc_vars:
            out.append({"kind": "var", "prov": "alloc", "var": var, "line": line})
        elif var in params:
            out.append({"kind": "var", "prov": "param", "var": var, "line": line})
        elif var:
            out.append({"kind": "var", "prov": "local", "var": var, "line": line})
        else:
            out.append({"kind": "value", "line": line})
    return out


@timeit
def _walk_function(ix, regions, nest, sinks, norm, fnode,
                   cfg_edges_by_source=None, macro_defs=None,
                   argument_edges=None, invoke_edges=None, value_edges=None,
                   return_values=None,
                   object_only=False, prewarmed=False):
    """Reconstruct one function's F IR from its owned graph nodes.

    Callee names are canonicalized through `norm` (the Atropos form oracle) as they leave the
    graph, so every downstream fact -- sink lookup, alloc/free events, summaries, skeletons --
    speaks one vocabulary. The graph node keeps its surface name; only this IR is rewritten."""
    fid = fnode["id"]
    disk_index = hasattr(ix, "nodes_owned_headers")
    owned_nodes = (ix.nodes_owned_headers(fid) if disk_index
                   else ix.nodes_owned_by(fid))
    owned_by_kind = defaultdict(list)
    for node in owned_nodes:
        owned_by_kind[node.get("kind")].append(node)

    # Kùzu property tails are fetched in batches.  The old disk path issued a
    # separate warm-up for each requested kind (calls, parameters, reads,
    # returns, ...), which multiplied query planning and decoding by the number
    # of functions.  Warm exactly the union of those same kinds once, then use
    # the cached nodes for every owned_of call.  Headers remain the source for
    # the broad body census, so unrelated node kinds are still not inflated.
    loaded_by_kind = None
    if disk_index:
        warm_kinds = {
            # Parameters are consumed only through their promoted label below.
            # Keep their cheap ownership headers instead of inflating the full
            # property tail for every function during the cold translation path.
            "call", "construct", "release",
            "dynamic-behavior", "write", "return",
        }
        warm_ids = [node_id for kind in warm_kinds
                    for node_id in ix.by_owner.get(fid, ())
                    if ix._kind_by_id.get(node_id) == kind and
                    _flow_node_needed(ix, node_id, kind)]
        if not prewarmed:
            ix._warm_nodes(warm_ids)
        loaded_by_kind = defaultdict(list)
        for node_id in warm_ids:
            node = ix.nodes.get(node_id)
            if node is not None:
                loaded_by_kind[node.get("kind")].append(node)
        for header in owned_nodes:
            if header.get("kind") in {"parameter", "read", "body", "expression"}:
                node = _flow_header_node(header)
                if header.get("kind") == "parameter":
                    # Parameter records need no syntax inference: their label is
                    # the only field consumed by the translation walk.
                    node = {"id": header.get("id"), "kind": "parameter",
                            "label": header.get("label"),
                            "properties": header.get("properties") or {}}
                if node is not None:
                    loaded_by_kind[node["kind"]].append(node)

    def owned_of(*kinds):
        if disk_index:
            return tuple(node for kind in kinds
                         for node in loaded_by_kind.get(kind, ()))
        return tuple(node for kind in kinds for node in owned_by_kind.get(kind, ()))

    body_node_count = sum(
        1 for node in owned_nodes
        if node.get("kind") not in {"cfg-entry", "cfg-exit", "cfg-merge", "cfg-condition"}
    )
    params = [p.get("label") for p in _by_offset(owned_of("parameter"))]
    param_set = set(params)
    calls, callees, events, assigns = [], [], [], []
    if macro_defs is None:
        macro_defs = {node.get("label"): _props(node)
                      for node in ix.nodes_of_kind("macro") if node.get("label")}

    for c in _by_offset(owned_of("call", "construct")):
        callee = norm.canon_callee(_callee_name(c))
        if not callee:
            continue
        line = _stmt_line(c)
        callees.append(callee)
        args = _arg_records(ix, c, argument_edges)
        cp = _props(c)
        idents = {a["root"] for a in args if a["root"]}
        guards = _guards_for(regions, fid, idents, _span(c))
        guard_status = _guard_status_for(regions, fid, idents, _span(c))
        cat, catalog_name = _catalog_sink(sinks, callee, cp)
        # the variable this call's result is assigned to (any callee, not just allocators), so
        # `x = udf(...)` is a first-class assign the summary can compose through -- an allocator
        # wrapper's `returns=alloc` seeds an alloc, a freed-return's `returns_dangling` seeds a
        # free. `alloc_dst` is the is_alloc-gated subset used for the alloc event and sink dst.
        assigned = _assigned_var(ix, c["id"], value_edges)
        alloc_dst = assigned if norm.is_acquire(callee) else None
        rec = {"callee": callee, "line": line, "args": args, "guards": guards,
               "guard_status": guard_status,
               "guard_predicates": tuple(g.get("canon") for g in guards if g.get("canon")),
               "is_sink": cat is not None,
               "sink_name": catalog_name,
               # Keep the catalog's semantic kind on the F record.  `is_sink`
               # alone is not enough for the language-neutral matcher/security
               # projections: it used to make every non-prototype Python sink
               # visible only as an untyped call.
               "sink_family": cat.get("family") if cat is not None else None,
               "assigned": assigned,
               # Managed-language lifecycle methods place the resource on the
               # receiver, not in an argument slot. Preserve that neutral
               # identity for the semantic graph; C-style calls leave it absent.
               "receiver": (cp.get("receiver") or cp.get("receiver_root")
                            or cp.get("receiver_value")),
               "node": c["id"],                             # graph node = CFG anchor for events
               "control": nest.enclosing(c["id"])}          # loop/branch nesting, outer->inner
        if cat is not None:
            size_arg = cat.get("size_arg")
            rec["sink"] = {"size_arg": size_arg}
            # the size/length operand as written (the arg at the size position), so a rule can
            # compare an alloc's size against a copy's size on the same path
            sa = next((a for a in args if a.get("pos") == size_arg), None) if size_arg is not None else None
            rec["size_expr"] = sa.get("value") if sa else None
            if norm.is_alloc(callee):
                expanded = _expanded_macro_size(c, args, macro_defs, callee)
                if expanded:
                    rec["size_expr"] = expanded
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
        may_invoke = (invoke_edges.get(c["id"], ()) if invoke_edges is not None
                      else ix.outgoing_of_kind(c["id"], "MAY_INVOKE"))
        for mi in may_invoke:
            hnode = _header_node(ix, mi["target"])
            hcallee = norm.canon_callee(hnode.get("label")) if hnode else None
            if not hcallee or hcallee == callee:
                continue
            callees.append(hcallee)
            hcat = sinks.get(hcallee)
            hrec = {"callee": hcallee, "line": line, "args": args, "guards": guards,
                    "guard_status": guard_status,
                    "guard_predicates": tuple(g.get("canon") for g in guards if g.get("canon")),
                    "is_sink": hcat is not None,
                    "sink_name": hcallee if hcat is not None else None,
                    "sink_family": hcat.get("family") if hcat is not None else None,
                    "node": c["id"],
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
            events.append({"kind": "alloc", "family": ("memory.alloc" if norm.lang == "c"
                           else "lifecycle.acquire"),
                           "var": alloc_dst, "line": line, "node": c["id"]})
        # realloc is a release of the old generation and an acquire of the returned
        # generation.  Keep both facts in the structural stream; the matcher remains
        # completely unaware of the concrete allocator spelling.
        release_arg = args[0] if args and args[0].get("root") else None
        if norm.is_release(callee) or norm.is_realloc(callee):
            receiver_id = cp.get("receiver_value_id") or cp.get("receiver_symbol_id")
            if release_arg is None and receiver_id:
                receiver = _header_node(ix, receiver_id) or {}
                receiver_label = receiver.get("label") or cp.get("receiver")
                if receiver_label:
                    release_arg = {"root": receiver_label, "expr": receiver_label}
            if release_arg is None or not release_arg.get("root"):
                release_arg = None
        if release_arg:
            events.append({"kind": "free", "family": ("memory.free" if norm.lang == "c"
                           else "lifecycle.release"),
                           "var": _freed_identity(release_arg), "line": line,
                           "node": c["id"], "callee": callee})

    dynamic_writes = _dynamic_property_writes(ix, regions, nest, fid)
    calls.extend(dynamic_writes)
    callees.extend(record["callee"] for record in dynamic_writes)

    alloc_vars = {a["var"] for a in assigns}
    tracked_vars = set()
    tracked_vars.update(a["var"] for a in assigns
                        if norm.is_acquire(a.get("callee"))
                        or a.get("callee") in atropos.source_catalog(norm.lang))
    tracked_vars.update(e["var"] for e in events if e["kind"] in ("alloc", "free"))
    # Explicit frontend release nodes (Python `del`/context exit) are also
    # evidence that their target is a tracked resource.  Collect them before
    # scanning reads so a subsequent member/index access is in scope.
    for n in owned_of("release"):
        target = ix.nodes.get((_props(n)).get("target_id")) or {}
        root = _read_root(target.get("label") or n.get("label"), set(params))
        if root:
            tracked_vars.add(root)
    if norm.lang == "c":
        for n in owned_nodes:
            p = _props(n)
            syntax = p.get("syntax_kind") or n.get("kind")
            label = n.get("label") or ""
            if syntax == "CXXDeleteExpr" or str(label).lstrip().startswith("delete"):
                root = _read_root(label, set(params))
                if root:
                    tracked_vars.add(root)
    # Expression-level reads are the structural use alphabet for all frontends.
    # They are emitted only when the base is already tracked by an acquisition,
    # release, or source; ordinary object/property reads never enter the stream.
    for n in owned_of("read", "body", "expression"):
        p = _props(n)
        syntax = p.get("syntax_kind") or n.get("kind")
        label = n.get("label") or p.get("expression")
        if syntax not in {"MemberExpr", "ArraySubscriptExpr", "UnaryOperator",
                          "property-path", "read", "index", "member"}:
            continue
        root = _read_root(label, tracked_vars)
        if root and any(mark in str(label) for mark in ("->", ".", "[", "*")):
            events.append({"kind": "use", "family": ("memory.deref" if norm.lang == "c"
                           else "lifecycle.use"), "var": root,
                           "line": p.get("start_line"), "node": n.get("id")})
    for n in owned_of("release"):
        p = _props(n)
        target = ix.nodes.get(p.get("target_id")) or {}
        root = _read_root(target.get("label") or n.get("label"), tracked_vars)
        if root:
            events.append({"kind": "free", "family": ("memory.free" if norm.lang == "c"
                           else "lifecycle.release"), "var": root,
                           "line": p.get("release_line") or p.get("start_line"),
                           "node": n.get("id"),
                           "callee": p.get("release_method")})
    # Clang represents delete/delete[] as an expression rather than a call.
    # It is still a catalogue release and must enter the same structural stream.
    if norm.lang == "c":
        for n in owned_nodes:
            p = _props(n)
            syntax = p.get("syntax_kind") or n.get("kind")
            label = n.get("label") or ""
            if syntax != "CXXDeleteExpr" and not str(label).lstrip().startswith("delete"):
                continue
            root = _read_root(label, tracked_vars)
            if root:
                events.append({"kind": "free", "family": "memory.free", "var": root,
                               "line": p.get("start_line"), "node": n.get("id"),
                               "callee": "delete"})
    returns = _returns(ix, fid, alloc_vars, param_set, norm, value_edges, return_values)
    for r in returns:                             # a returned alloc'd local escapes
        if r.get("kind") == "var" and r.get("prov") == "alloc":
            events.append({"kind": "escape", "var": r["var"], "line": r.get("line")})

    # Preserve the neutral control-flow overlay for consumers that do not have
    # the C declaration-rooted object substrate.  The semantic graph can use
    # these typed sibling edges without re-reading frontend-specific AST facts.
    cfg_edge_kinds = ("CFG_NEXT", "TRUE_BRANCH", "FALSE_BRANCH", "LOOP_BACK",
                      "EXCEPTION_BRANCH", "SWITCH_CASE")
    owned_ids = {node.get("id") for node in owned_nodes}
    cfg_successors = defaultdict(list)
    cfg_nodes = set()
    if cfg_edges_by_source is None:
        cfg_edges_by_source = defaultdict(list)
        for edge in ix.edges_of_kind(*cfg_edge_kinds):
            cfg_edges_by_source[edge.get("source")].append(edge)
    for source in owned_ids:
        for edge in cfg_edges_by_source.get(source, ()):
            target = edge.get("target")
            if target not in owned_ids:
                continue
            kind = ix.semantic_edge_kind(edge) or edge.get("kind")
            cfg_successors[source].append({
                "target": target,
                "kind": kind,
                "predicate": (_header_node(ix, source) or {}).get("label"),
                "properties": edge.get("properties") or {},
            })
            cfg_nodes.update((source, target))
    cfg = None
    if cfg_nodes:
        entries = [node.get("id") for node in owned_nodes
                   if node.get("id") in cfg_nodes and node.get("kind") == "cfg-entry"]
        cfg = {
            "nodes": tuple(sorted(cfg_nodes)),
            "entry": entries[0] if entries else None,
            "succ": {source: tuple(sorted(edges, key=lambda item: (
                item.get("kind") or "", item.get("target") or "")))
                      for source, edges in cfg_successors.items()},
        }

    return {"name": fnode.get("label"),
            "file": _props(fnode).get("file"), "line": _props(fnode).get("start_line"),
            # Frontends with linkage metadata can distinguish an exported
            # declaration from a file-local helper.  Missing metadata is treated
            # as externally visible for non-C frontends, whose module/export
            # rules are represented elsewhere in the graph.
            "externally_visible": (_props(fnode).get("storage_class") != "static"),
            "params": params, "calls": calls, "events": events,
            "assigns": assigns, "returns": returns, "callees": callees,
            "body_node_count": body_node_count, "cfg": cfg}


@timeit
def build_F(store, lang="c", *, return_graph=False, object_only=False):
    """Build the whole-graph F dict + succ (callee-edge) map from an enriched store.

    Reproduces order.load's return so the pass is input-source agnostic. Taxonomy /
    caller / source classification is the same class rule the old parser used."""
    source_ix = store.index
    # Disk-backed stores need a columnar materialization for BranchRegions. Tests and
    # embedding callers can supply an already-materialized in-memory GraphStore; do not
    # assume its GraphIndex has Kuzu's private connection surface.
    # Keep disk-backed Pass 3 lazy.  Materializing the complete Kùzu graph here
    # inflates every property blob before the flow pass can select its function
    # slice, dominating both cold startup time and peak RSS on large repositories.
    # The Kùzu index implements the same navigation surface needed by translation.
    graph = store.graph if store.graph is not None else source_ix
    # Once a disk graph has been materialized, keep the complete projection on its
    # in-memory index.  Continuing to use ``source_ix`` here turned every helper in
    # ``_walk_function`` into another Kuzu query for each of thousands of functions.
    # The graph is a faithful snapshot taken after ensure_dataflow_tier(), so these
    # indexes have the same semantics and radically different access costs.
    # Flow translation only needs kind/adjacency/ownership access.  A full GraphStore
    # wrapper would retain navigation-only label/file buckets over the materialized
    # graph; the compact index defers those buckets until a caller explicitly asks.
    ix = source_ix if store.graph is not None else source_ix
    regions = BranchRegions(graph)
    nest = ControlNesting(graph)                   # loop/branch nesting from AST containment
    sinks = atropos.sink_catalog(lang)
    sink_names = set(sinks)
    norm = normalizer(lang)                        # form oracle: canonicalize callee names
    source_methods = set(atropos.source_catalog(lang))
    cfg_edge_kinds = ("CFG_NEXT", "TRUE_BRANCH", "FALSE_BRANCH", "LOOP_BACK",
                      "EXCEPTION_BRANCH", "SWITCH_CASE")
    cfg_edges_by_source = defaultdict(list)
    for edge in ix.edges_of_kind(*cfg_edge_kinds):
        cfg_edges_by_source[edge.get("source")].append(edge)
    macro_defs = {node.get("label"): _props(node)
                  for node in ix.nodes_of_kind("macro") if node.get("label")}

    prewarmed_flow_nodes = False
    definition_ids = None
    if hasattr(ix, "node_headers"):
        callable_ids = [nid for kind in ("function", "method", "constructor")
                        for nid in ix.by_kind.get(kind, ())]
        callable_headers = {node["id"]: node
                            for node in ix.node_headers(callable_ids)}
        if hasattr(ix, "metadata_by_kind"):
            for node_id, metadata in ix.metadata_by_kind(
                    ("function", "method", "constructor")).items():
                header = callable_headers.get(node_id)
                if header is not None:
                    header["properties"] = {
                        **header.get("properties", {}), **metadata}

        def has_body(owner_id):
            # Declaration-only callables in the C graph own only the synthetic
            # entry/exit pair.  Their ownership headers are intentionally cheap
            # and may not have a promoted kind for overlay-derived CFG nodes,
            # so use both kind and the stable entry/exit labels.
            owned = ix.by_owner.get(owner_id, ())
            if not owned:
                return False
            for node_id in owned:
                cached = getattr(ix, "_node_cache", {}).get(node_id) or {}
                kind = (ix._kind_by_id.get(node_id) or
                        cached.get("kind"))
                label = (ix._label_by_id.get(node_id) or
                         cached.get("label") or "")
                if kind not in {None, "cfg-entry", "cfg-exit"}:
                    return True
                if not (str(label).startswith("entry:") or
                        str(label).startswith("exit:")):
                    return True
            return False

        flow_kinds = {
            "parameter", "call", "construct", "release",
            "dynamic-behavior", "write", "return",
        }
        # ``parameter`` is header-only in Translation.  It remains in the
        # definition/body census above, but does not need a full Kùzu payload.
        translation_warm_kinds = flow_kinds - {"parameter"}

        # ``object_only`` is retained as an API compatibility switch, but the
        # default projection must keep every body-bearing callable so caller
        # closure and source discovery remain exact.  The filter only removes
        # declaration-only stubs that the old path discarded after inflating
        # their full properties.
        all_definition_ids = [nid for nid in callable_ids if has_body(nid)]
        full_definition_ids = {
            owner_id for owner_id in all_definition_ids
            if any(ix._kind_by_id.get(node_id) in flow_kinds
                   for node_id in ix.by_owner.get(owner_id, ()))
        }
        definition_ids = [nid for nid in all_definition_ids if nid in full_definition_ids]
        ix._warm_nodes(ix.by_kind.get("macro", ()))
        fnodes = []
        for nid in all_definition_ids:
            node = callable_headers[nid]
            if node is not None:
                fnodes.append(node)

        # Warm the exact node kinds consumed by _walk_function once for the
        # whole definition set.  _warm_nodes bounds each Kùzu IN-list at 5,000,
        # so this remains predictable while avoiding one query plan per
        # function.  The per-function implementation still constructs its
        # owned-kind views from the cache, preserving all selection semantics.
        if hasattr(ix, "_warm_nodes_by_owner"):
            ix._warm_nodes_by_owner(definition_ids, translation_warm_kinds)
            # The dynamic/write projection below must consume this cache directly;
            # otherwise its generic owner accessor can issue one warm-up per
            # function after this scan has already completed.
            ix._translation_prefetched_kinds = frozenset(translation_warm_kinds)
        else:
            flow_ids = {
                node_id for owner_id in definition_ids
                for node_id in ix.by_owner.get(owner_id, ())
                if ix._kind_by_id.get(node_id) in translation_warm_kinds and
                _flow_node_needed(ix, node_id)
            }
            ix._warm_nodes(flow_ids)
        prewarmed_flow_nodes = True
        full_definition_set = set(full_definition_ids)
    else:
        fnodes = list(ix.nodes_of_kind("function", "method", "constructor"))
        full_definition_set = {f.get("id") for f in fnodes}
    # These relations are intentionally left lazy: the full VALUE_FLOWS_TO
    # relation is much larger than the call slice, so globally indexing it would
    # trade round trips for a larger-than-Pass-2 resident graph.
    argument_edges = (ix.argument_edges_by_source()
                      if hasattr(ix, "argument_edges_by_source") else None)
    invoke_edges = (ix.invoke_edges_by_source()
                    if hasattr(ix, "invoke_edges_by_source") else None)
    value_edges = (ix.value_targets_by_source()
                   if hasattr(ix, "value_targets_by_source") else None)
    return_values = (ix.return_value_sources_by_target()
                     if hasattr(ix, "return_value_sources_by_target") else None)
    defined = {f.get("label") for f in fnodes if not _props(f).get("declaration_only")}

    # Python permits many methods with the same surface name (`extract`, `close`,
    # `execute`, ...).  The old name-keyed projection silently discarded every
    # definition after the first one, which could erase the only source/sink body
    # in a class hierarchy.  Preserve a stable qualified identity when the frontend
    # gives us a class owner; retain the old spelling for unique functions and for
    # non-class callables so existing language-neutral consumers remain compatible.
    non_declared_name_counts = Counter(
        f.get("label") for f in fnodes
        if f.get("label") and not _props(f).get("declaration_only")
    )

    def function_key(fnode):
        name = fnode.get("label")
        props = _props(fnode)
        owner_id = props.get("owner_id")
        owner = (_header_node(ix, owner_id) if owner_id else None)
        if owner and owner.get("kind") == "class" and owner.get("label"):
            return f"{owner['label']}.{name}"
        if non_declared_name_counts.get(name, 0) > 1:
            return f"{name}@{props.get('absolute_file') or props.get('file')}:{props.get('start_line')}"
        return name

    def lightweight_record(fnode):
        """Header-only IR for functions with no flow-bearing owned nodes."""
        fid = fnode.get("id")
        if hasattr(ix, "nodes_owned_headers"):
            owned = ix.nodes_owned_headers(fid)
            params = [node.get("label") for node in _by_offset(owned)
                      if node.get("kind") == "parameter"]
            body_count = sum(1 for node in owned if node.get("kind") not in
                             {"cfg-entry", "cfg-exit", "cfg-merge", "cfg-condition"})
        else:
            owned, params, body_count = (), [], 0
        owned_ids = {node.get("id") for node in owned}
        cfg_successors = defaultdict(list)
        cfg_nodes = set()
        for source in owned_ids:
            for edge in cfg_edges_by_source.get(source, ()):
                target = edge.get("target")
                if target not in owned_ids:
                    continue
                kind = ix.semantic_edge_kind(edge) or edge.get("kind")
                cfg_successors[source].append({
                    "target": target, "kind": kind,
                    "predicate": ix._label_by_id.get(source)
                    if hasattr(ix, "_label_by_id") else None,
                    "properties": edge.get("properties") or {},
                })
                cfg_nodes.update((source, target))
        cfg = None
        if cfg_nodes:
            entries = [node.get("id") for node in owned
                       if node.get("id") in cfg_nodes and node.get("kind") == "cfg-entry"]
            cfg = {
                "nodes": tuple(sorted(cfg_nodes)),
                "entry": entries[0] if entries else None,
                "succ": {source: tuple(sorted(edges, key=lambda item: (
                    item.get("kind") or "", item.get("target") or "")))
                          for source, edges in cfg_successors.items()},
            }
        props = _props(fnode)
        return {"name": fnode.get("label"), "file": props.get("file"),
                "line": props.get("start_line"), "externally_visible": True,
                "params": params, "calls": [], "events": [], "assigns": [],
                "returns": [], "callees": [], "body_node_count": body_count,
                "cfg": cfg}

    recs = {}
    for f in fnodes:
        if _props(f).get("declaration_only"):
            continue
        name = function_key(f)
        if not name or name in recs:
            continue
        if f.get("id") in full_definition_set:
            recs[name] = _walk_function(ix, regions, nest, sinks, norm, f,
                                        cfg_edges_by_source, macro_defs,
                                        argument_edges, invoke_edges, value_edges,
                                        return_values,
                                        object_only, prewarmed_flow_nodes)
        else:
            recs[name] = lightweight_record(f)
        recs[name]["name"] = name

    def is_lifecycle_or_sink(c):
        return c in sink_names or norm.is_acquire(c) or norm.is_release(c) or norm.is_realloc(c)

    # Compute the transitive caller closure once.  The old implementation launched a
    # depth-first walk from every function, allocating a fresh ``seen`` set each time;
    # on a large call graph that revisited the same shared callees O(functions) times.
    # A reverse walk from functions with a direct lifecycle/sink callee is equivalent,
    # including cyclic call components, and touches each recorded call edge at most
    # once.
    reverse_callers = defaultdict(set)
    sink_reachable = set()
    for name, record in recs.items():
        for call in record["calls"]:
            callee = call.get("callee")
            if call.get("sink_family") or is_lifecycle_or_sink(callee):
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
            "externally_visible": r.get("externally_visible", True),
            "taxonomy": taxo, "is_source": len(callers[n]) == 0,
            "params": r["params"],
            "udf_callees": udf_callees, "ldf_callees": ldf_callees,
            "sink_ldf_callees": sink_ldf, "callers": sorted(callers[n]),
            "calls": r["calls"], "events": r["events"],
            "assigns": r["assigns"], "returns": r["returns"],
            "body_node_count": r.get("body_node_count", 0),
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
    # A function-valued argument is an indirect call-graph edge even when the
    # immediate callee is a callback formal (``callback(value)``). Preserve it
    # in the generic successor relation so source discovery, coverage cones,
    # object slicing, and Claus all include the eventual target. This relies on
    # canonical function identities already present in F; no callback names or
    # language-specific conventions are embedded here.
    for caller, record in F.items():
        for call in record.get("calls", ()):
            callee = call.get("callee")
            callee_record = F.get(callee)
            if callee_record is None:
                continue
            formals = tuple(callee_record.get("params", ()))
            for argument in call.get("args", ()):
                position = argument.get("pos")
                actual = argument.get("root")
                if (isinstance(position, int) and position < len(formals)
                        and actual in F and actual != callee):
                    succ[caller].append(actual)
        succ[caller] = sorted(set(succ[caller]))
    discovery = discover_sources(F, succ, atropos.source_catalog(lang))
    coverage = CoverageScheduler(F, succ).plan()
    coverage_by_target = {region.target: region for region in coverage.regions}
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
        root_provenance = discovery.provenance_by_function.get(name, ())
        record["source_provenance"] = (
            root_provenance[0] if len(root_provenance) == 1 else
            "mixed" if root_provenance else "unreachable")
        record["source_influenced_roots"] = discovery.influenced_roots.get(name, ())
        region = coverage_by_target.get(name)
        record["coverage_sources"] = region.sources if region else ()
        record["coverage_functions"] = region.functions if region else ()
        record["coverage_state_keys"] = region.state_keys if region else ()
        record["coverage_unresolved"] = name in coverage.uncovered_functions
    # build_F already paid for this exact plan to annotate the projected records.
    # Keep it on the live GraphStore so run_pass can reuse it instead of planning
    # the same (F, succ) graph a second time in the same request.
    try:
        store._pass3_coverage_cache = (F, succ, coverage)
    except AttributeError:
        pass
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
