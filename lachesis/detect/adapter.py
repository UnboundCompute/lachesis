"""Turn one Lachesis graph into detection leads across all three evaluator classes.

This is the only graph-specific code in the package. It operates on ONE representation --
the canonical ``{nodes, edges}`` dict the planner also consumes -- so the taint half and
the capacity half meet on the same ids with no cross-view bookkeeping. The graph is
obtained once via ``from_store``: ``materialize_graph`` rebuilds the dict from the store,
and atropos enrichment folds in the per-argument ``atropos-model`` sink vocabulary on top
of the ``generic-security-roles`` sinks the compiler already stamped.

Two sink vocabularies live on the one graph, each read in its natural shape:

  * ``generic-security-roles`` (``fact_origin == "compiler"``) -- coarse roles baked into
    every enriched store (filesystem/database/response/process/...). These are the
    REACHABILITY population: a role bridges to a catalog kind, and taint reaching any of
    the sink's argument expressions fires the reachability evaluator. This is the tested
    path and it needs no capacity.

  * ``atropos-model`` (``fact_origin == "atropos-model"``) -- precise per-argument kinds
    added by enrichment (buffer-write/buffer-size, weak-crypto, ...). Each such sink names
    its own ``value_id``, so its fact is read directly: ``tainted`` is whether the flood
    reached that value, ``value_bound`` is the planner's capacity verdict for it (see
    ``capacity.py``), and the sink's kind selects reachability / relational / presence.

The interprocedural taint flood is shared by both: seed every parameter a catalogued
source marks, then propagate forward over the flow edges. A union of both front-ends'
taint encodings is still sound; each graph populates the edges it uses.
"""
import collections

from lachesis.detect import substrate
from lachesis.detect.capacity import capacity_bounds
from lachesis.detect.catalog import DetectionCatalogUnavailable, load_detector


# The forward edges the interprocedural taint flood walks from a source-marked parameter.
# Two front-ends encode taint flow differently, so the flood unions both encodings -- a
# union of sound taint edges is still sound, and each graph populates the ones it uses:
#   VALUE_FLOWS_TO            intra-procedural value flow (assignment, use)  [C computes]
#   ARGUMENT_BINDS_PARAMETER  actual argument -> callee formal (taint crosses in) [C]
#   RETURNS_VALUE             return value flow (taint crosses a call out)   [C]
#   TAINT_FLOWS_TO            the front-end's own taint relation             [Python seeds]
_FLOW_EDGES = ("VALUE_FLOWS_TO", "ARGUMENT_BINDS_PARAMETER", "RETURNS_VALUE", "TAINT_FLOWS_TO")


class LachesisGraph:
    """A detection view over one materialized (optionally atropos-enriched) graph dict."""

    def __init__(self, graph, bind_summary=None, detector=None):
        self.graph = graph
        self.nodes = graph.get("nodes", ())
        self.by_id = {n["id"]: n for n in self.nodes}
        self._edges_by_kind = collections.defaultdict(list)
        for e in graph.get("edges", ()):
            self._edges_by_kind[e["kind"]].append((e["source"], e["target"]))
        # The recipe + sink-role bridge are pure data in the atropos catalog. Load the
        # default (generic-security-roles) unless a caller injects a Detector.
        self.detector = detector if detector is not None else load_detector()
        # value_id -> value_bound, delegated whole to the planner's capacity proof. Empty
        # when the graph carries no atropos-model memory sinks (no relational evidence).
        self._bounds = capacity_bounds(graph, bind_summary)

    @classmethod
    def from_store(cls, store_dir, detector=None):
        """Load a store, materialize it, and fold in the atropos-model sink vocabulary.

        The materialized graph already carries the ``generic-security-roles`` sinks and
        every flow edge, so reachability works even if enrichment is unavailable; the
        ``atropos-model`` sinks (relational / presence) are added when an atropos checkout
        with the binder is present, and their absence degrades soundly to reachability.
        """
        from lachesis.integrations.atropos.enrich import atropos_enrich
        from lachesis.nav.graph_store import GraphStore
        from lachesis.nav.kuzu_index import materialize_graph

        graph = materialize_graph(GraphStore.load(store_dir).index)
        summary = {}
        try:
            graph, summary = atropos_enrich(graph, complete_dataflow=False)
        except (DetectionCatalogUnavailable, FileNotFoundError, RuntimeError):
            pass  # no binder/atropos: keep the un-enriched graph, reachability still runs
        return cls(graph, summary, detector=detector)

    # -- taint --------------------------------------------------------------------------
    def _seeds(self):
        """Parameters a catalogued source taints (source -[TAINT_SOURCE]-> parameter)."""
        return {t for _s, t in self._edges_by_kind.get("TAINT_SOURCE", ())}

    def _tainted_nodes(self):
        """Every node the flood reaches from a source-marked parameter (a fixpoint BFS)."""
        adj = collections.defaultdict(list)
        for kind in _FLOW_EDGES:
            for s, t in self._edges_by_kind.get(kind, ()):
                adj[s].append(t)
        seen = set(self._seeds())
        stack = list(seen)
        while stack:
            for nxt in adj.get(stack.pop(), ()):
                if nxt not in seen:
                    seen.add(nxt)
                    stack.append(nxt)
        return seen

    # -- generic-security-roles sinks (reachability) ------------------------------------
    def _role_sink_arguments(self, sink_nodes):
        """Map each argument expression of a compiler-stamped role sink to its sink.

        A ``sink -[TAINT_SINK]-> target`` edge lands on a node whose shape depends on the
        front-end: C targets a ``call`` node (arguments are its HAS_ARGUMENT children),
        Python targets the argument ``value`` node itself (taint may arrive one value-flow
        hop upstream). A ``call-value`` target is treated as both.
        """
        sink_by_id = {n["id"]: n for n in sink_nodes}
        target_sink = {}
        for s, t in self._edges_by_kind.get("TAINT_SINK", ()):
            sink = sink_by_id.get(s)
            if sink is not None:
                target_sink[t] = sink
        target_kind = {t: (self.by_id.get(t) or {}).get("kind") for t in target_sink}
        # C targets a `call` node (args via HAS_ARGUMENT); Python targets the `value` node
        # itself. A `call-value` target is both, so it appears in both branches below.
        value_targets = {t for t, k in target_kind.items() if k in ("value", "call-value")}

        def tag(sink):
            props = sink.get("properties") or {}
            return (sink["id"], sink.get("label"), props.get("sink_kind"))

        args = {}
        # C shape: call -> HAS_ARGUMENT -> argument expression.
        for s, t in self._edges_by_kind.get("HAS_ARGUMENT", ()):
            sink = target_sink.get(s)
            if sink is not None:
                args[t] = tag(sink)
        # Python shape: the value target itself is the argument expression.
        for t in value_targets:
            args[t] = tag(target_sink[t])
        # Python shape: taint may reach one intra-procedural hop upstream of the value.
        if value_targets:
            pred = collections.defaultdict(set)
            for s, t in self._edges_by_kind.get("VALUE_FLOWS_TO", ()):
                if t in value_targets:
                    pred[t].add(s)
            for t in value_targets:
                for p in pred.get(t, ()):
                    args.setdefault(p, tag(target_sink[t]))
        return args

    def _reachability_leads(self, sink_nodes, tainted):
        """Reachability leads from the compiler-stamped role sinks (one per fired sink)."""
        reached = {}  # sink_id -> [label, sink_kind, any-arg-tainted]
        for arg_id, (sink_id, label, sink_kind) in self._role_sink_arguments(sink_nodes).items():
            hit = arg_id in tainted
            prev = reached.get(sink_id)
            reached[sink_id] = [label, sink_kind, (prev[2] if prev else False) or hit]

        out = []
        for sink_id, (label, sink_kind, is_tainted) in reached.items():
            kind = self.detector.bridge(sink_kind)
            if kind is None:
                continue  # a role the catalog has no kind for yet
            fact = substrate.substrate(kind, tainted=is_tainted, value_bound=None, guarded=False)
            fired = self.detector.evaluate(kind, fact)
            if fired:
                out.append({"sink": sink_id, "label": label, "sink_kind": sink_kind,
                            "kind": kind, "evaluator": fired, "location": None,
                            "vocabulary": "generic-security-roles"})
        return out

    def _site(self, callsite_id):
        """The (call expression, ``file:line``) of a callsite, for an actionable lead.

        The atropos-model sink's own label is just its role name; the callsite it marks
        carries the faithful call spelling and location, so a lead points at real source.
        """
        call = self.by_id.get(callsite_id or "")
        if not call:
            return None, None
        props = call.get("properties") or {}
        loc_file = props.get("absolute_file") or props.get("file")
        line = props.get("start_line")
        location = f"{loc_file}:{line}" if loc_file and line is not None else loc_file
        return call.get("label"), location

    # -- atropos-model sinks (reachability + relational + presence) ----------------------
    def _model_leads(self, sink_nodes, tainted):
        """Leads from the precise atropos-model sinks: each names its own ``value_id``, so
        its fact is read directly. ``value_bound`` comes from the planner's capacity proof;
        the sink's kind (buffer-write, weak-crypto, ...) selects its evaluator, so one pass
        yields reachability, relational and presence leads without special-casing a class.
        """
        out = []
        for node in sink_nodes:
            props = node.get("properties") or {}
            kind = props.get("sink_kind")  # already a catalog kind for this vocabulary
            if kind is None or self.detector.kind_evaluator.get(kind) is None:
                continue
            value_id = props.get("value_id")
            fact = substrate.substrate(
                kind,
                tainted=value_id in tainted,
                value_bound=self._bounds.get(value_id),
                guarded=False,
            )
            fired = self.detector.evaluate(kind, fact)
            if fired:
                site, location = self._site(props.get("callsite_id"))
                out.append({"sink": node["id"], "label": site or node.get("label"),
                            "sink_kind": kind, "kind": kind, "evaluator": fired,
                            "location": location, "value_id": value_id,
                            "vocabulary": "atropos-model"})
        return out

    # -- leads --------------------------------------------------------------------------
    def leads(self):
        """Every sink occurrence whose substrate fact fires its evaluator, across both
        vocabularies and all three classes. Reachability comes from the coarse role sinks
        and from any atropos-model injection kind; relational and presence come from the
        atropos-model memory/config kinds."""
        tainted = self._tainted_nodes()
        role_sinks, model_sinks = [], []
        for n in self.nodes:
            if n.get("kind") != "sink":
                continue
            origin = (n.get("properties") or {}).get("fact_origin")
            (model_sinks if origin == "atropos-model" else role_sinks).append(n)
        return (self._reachability_leads(role_sinks, tainted)
                + self._model_leads(model_sinks, tainted))


def report(graph, bind_summary=None, detector=None, evaluator=None, kind=None):
    """A grouped lead report over one materialized+enriched graph, for a tool surface.

    Returns ``{census, leads}``: the census counts every fired lead by evaluator and by
    kind (over the WHOLE graph, never the filtered view, so coverage is honest), while
    ``leads`` is the rows, optionally narrowed to one ``evaluator`` or ``kind``. Callers
    that already hold a stamped graph (the MCP server reuses the candidate bundle's) pass
    it in, so the expensive materialize+enrich happens once.
    """
    import collections

    all_leads = LachesisGraph(graph, bind_summary, detector=detector).leads()
    by_ev = collections.Counter(ld["evaluator"] for ld in all_leads)
    by_kind = collections.Counter(ld["kind"] for ld in all_leads)
    rows = all_leads
    if evaluator is not None:
        rows = [ld for ld in rows if ld["evaluator"] == evaluator]
    if kind is not None:
        rows = [ld for ld in rows if ld["kind"] == kind]
    return {"census": {"by_evaluator": dict(by_ev), "by_kind": dict(by_kind),
                       "total": len(all_leads)},
            "leads": rows}


def leads(store_dir):
    """Convenience: open a store, enrich it, and return its detection leads."""
    return LachesisGraph.from_store(store_dir).leads()


if __name__ == "__main__":
    import sys

    found = leads(sys.argv[1])
    print(f"{len(found)} lead(s) in {sys.argv[1]}")
    for ld in sorted(found, key=lambda d: (d["evaluator"], d["sink_kind"] or "", d["label"] or "")):
        print(f"  [{ld['evaluator']:12}] {ld['sink_kind']}->{ld['kind']}  {ld['label']}")
