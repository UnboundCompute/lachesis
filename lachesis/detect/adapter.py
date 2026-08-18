"""Translate a Lachesis enriched kuzu graph into detection leads via the substrate.

This is the only graph-specific code in the package. It does three things:

  1. TAINT FLOOD -- seed every parameter a catalogued source marks, then propagate
     forward over the graph's interprocedural flow edges (intra-procedural value flow,
     actual->formal argument binding, and return-value flow). A sink argument the flood
     reaches is attacker-influenced. The graph ships a native taint relation too, but it
     is not seeded from the source catalog, so reachability is computed here rather than
     read off the graph.

  2. SINK RESOLUTION -- read each sink node's `sink_kind` and translate that vocabulary
     into the substrate's kind (see SINK_KIND_BRIDGE).

  3. EVALUATE -- present {kind, tainted, value_bound, guarded} for each sink occurrence
     to `substrate.evaluate`, which routes it through the evaluator its kind selects.

Everything after step 1's edge set is graph-neutral: point the adapter at a different
backend by re-implementing the handful of `KuzuGraphIndex` reads used here.
"""
import collections

from lachesis.nav.kuzu_index import KuzuGraphIndex
from lachesis.detect import substrate


# The enriched graph marks sinks with a `generic-security-roles` vocabulary that is
# coarser than the atropos per-argument kinds the substrate speaks. This is
# catalog-to-catalog DATA, not a hardcoded family: every role that denotes a
# taint-reachability sink maps to the atropos kind the substrate routes. Roles the
# enrichment model does not carry (size/memory, weak crypto) simply never appear on
# these graphs; supporting one is a new row here, not engine code.
SINK_KIND_BRIDGE = {
    "filesystem-write": "path-traversal",
    "filesystem-read":  "path-traversal",
    "database":         "sql-injection",
    "response":         "xss",
    "process":          "command-injection",
    "dynamic-code":     "code-injection",
    "deserialize":      "deserialization",
}

# The forward edges the interprocedural taint flood walks from a source-marked parameter:
#   VALUE_FLOWS_TO            intra-procedural value flow (assignment, use)
#   ARGUMENT_BINDS_PARAMETER  actual argument -> callee formal (taint crosses a call in)
#   RETURNS_VALUE             return value flow (taint crosses a call out)
_FLOW_EDGES = ("VALUE_FLOWS_TO", "ARGUMENT_BINDS_PARAMETER", "RETURNS_VALUE")


class LachesisGraph:
    """A read view over one enriched kuzu store, opened lightweight (no full load)."""

    def __init__(self, store_dir):
        self.index = KuzuGraphIndex(store_dir)

    # -- taint --------------------------------------------------------------------------
    def _seeds(self):
        """Parameters a catalogued source taints (source -[TAINT_SOURCE]-> parameter)."""
        return {e["target"] for e in self.index.flow_edges(["TAINT_SOURCE"])}

    def _flow_adjacency(self):
        """Forward adjacency for the taint flood over the interprocedural flow edges."""
        adj = collections.defaultdict(list)
        for e in self.index.flow_edges(list(_FLOW_EDGES)):
            adj[e["source"]].append(e["target"])
        return adj

    def _tainted_nodes(self):
        """Every node the flood reaches from a source-marked parameter (a fixpoint BFS)."""
        adj = self._flow_adjacency()
        seen = set(self._seeds())
        stack = list(seen)
        while stack:
            node = stack.pop()
            for nxt in adj.get(node, ()):
                if nxt not in seen:
                    seen.add(nxt)
                    stack.append(nxt)
        return seen

    # -- sinks --------------------------------------------------------------------------
    def _sink_arguments(self):
        """Map each sink-call argument expression to (sink_id, sink_label, sink_kind).

        sink -[TAINT_SINK]-> call ; call -[HAS_ARGUMENT]-> argument-expression.
        """
        sink_node = {s["id"]: s for s in self.index.nodes_of_kind("sink")}
        call_to_sink = {}
        for e in self.index.flow_edges(["TAINT_SINK"]):
            s = sink_node.get(e["source"])
            if s is not None:
                call_to_sink[e["target"]] = s
        args = {}
        for e in self.index.flow_edges(["HAS_ARGUMENT"]):
            s = call_to_sink.get(e["source"])
            if s is None:
                continue
            props = s.get("properties", {}) or {}
            args[e["target"]] = (s["id"], s.get("label"), props.get("sink_kind"))
        return args

    # -- leads --------------------------------------------------------------------------
    def leads(self):
        """Every sink occurrence whose substrate fact fires its evaluator.

        One lead per (sink, evaluator). `tainted` is whether the flood reached any of the
        sink's argument expressions; `value_bound`/`guarded` are left unmodelled for the
        reachability class (they carry no obligation there) and are refinements for the
        relational/presence classes a richer sink model would surface.
        """
        tainted = self._tainted_nodes()
        sink_args = self._sink_arguments()

        reached = {}  # sink_id -> (label, sink_kind, any-arg-tainted)
        for arg_id, (sink_id, label, sink_kind) in sink_args.items():
            hit = arg_id in tainted
            prev = reached.get(sink_id)
            reached[sink_id] = (label, sink_kind, (prev[2] if prev else False) or hit)

        out = []
        for sink_id, (label, sink_kind, is_tainted) in reached.items():
            kind = SINK_KIND_BRIDGE.get(sink_kind)
            if kind is None:
                continue  # a sink role the substrate has no evaluator for yet
            fact = substrate.substrate(kind, tainted=is_tainted,
                                       value_bound=None, guarded=False)
            fired = substrate.evaluate(kind, fact)
            if fired:
                out.append({"sink": sink_id, "label": label, "sink_kind": sink_kind,
                            "kind": kind, "evaluator": fired})
        return out


def leads(store_dir):
    """Convenience: open a store and return its detection leads."""
    return LachesisGraph(store_dir).leads()


if __name__ == "__main__":
    import sys
    store = sys.argv[1]
    found = leads(store)
    print(f"{len(found)} lead(s) in {store}")
    for ld in sorted(found, key=lambda d: (d["evaluator"], d["label"] or "")):
        print(f"  [{ld['evaluator']}] {ld['sink_kind']}->{ld['kind']}  {ld['label']}")
