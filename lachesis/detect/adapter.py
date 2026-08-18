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
from lachesis.detect.catalog import load_detector


# The enriched graph marks sinks with a `generic-security-roles` vocabulary that is
# coarser than the atropos per-argument kinds the recipe speaks. That translation is
# DATA in the atropos catalog (detection/sink-roles.json), loaded via `load_detector`;
# supporting another front-end vocabulary is a new file there, not a change here.

# The forward edges the interprocedural taint flood walks from a source-marked parameter.
# Two front-ends encode taint flow differently, so the flood unions both encodings -- a
# union of sound taint edges is still sound, and each graph populates the ones it uses:
#   VALUE_FLOWS_TO            intra-procedural value flow (assignment, use)  [C computes]
#   ARGUMENT_BINDS_PARAMETER  actual argument -> callee formal (taint crosses in) [C]
#   RETURNS_VALUE             return value flow (taint crosses a call out)   [C]
#   TAINT_FLOWS_TO            the front-end's own taint relation             [Python seeds]
# The C export leaves TAINT_FLOWS_TO unseeded from the source catalog, so reachability is
# COMPUTED from the first three; the Python export seeds TAINT_FLOWS_TO directly and leaves
# the argument-binding edges as EDGE-kinds the first three don't fully cover. Unioning
# reaches curl's C sinks and flask's/requests' Python sinks with one code path.
_FLOW_EDGES = ("VALUE_FLOWS_TO", "ARGUMENT_BINDS_PARAMETER", "RETURNS_VALUE", "TAINT_FLOWS_TO")


class LachesisGraph:
    """A read view over one enriched kuzu store, opened lightweight (no full load)."""

    def __init__(self, store_dir, detector=None):
        self.index = KuzuGraphIndex(store_dir)
        # The recipe + sink-role bridge come from the atropos catalog. Load the default
        # (generic-security-roles) unless a caller injects a Detector (tests, other vocabs).
        self.detector = detector if detector is not None else load_detector()

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
        """Map each sink argument expression to (sink_id, sink_label, sink_kind).

        A `sink -[TAINT_SINK]-> target` edge lands on a node whose shape depends on the
        front-end, so both are handled:

          * C shape -- the target is a `call` node; its arguments are the HAS_ARGUMENT
            children (`call -[HAS_ARGUMENT]-> argument-expression`).
          * Python shape -- the target IS the argument `value` node; taint may arrive one
            intra-procedural hop upstream, so its VALUE_FLOWS_TO predecessors count as the
            argument too.

        A `call-value` target is treated as both. Each argument node inherits its sink's
        id/label/kind; the flood need only touch any one of a sink's arguments.
        """
        sink_node = {s["id"]: s for s in self.index.nodes_of_kind("sink")}

        # sink target node -> the sink that marks it, plus that target's node kind.
        target_sink = {}
        for e in self.index.flow_edges(["TAINT_SINK"]):
            s = sink_node.get(e["source"])
            if s is not None:
                target_sink[e["target"]] = s
        target_kind = {}
        for tid in target_sink:
            n = self.index._node(tid)
            target_kind[tid] = n.get("kind") if n else None

        call_targets = {t for t, k in target_kind.items() if k in ("call", "call-value")}
        value_targets = {t for t, k in target_kind.items() if k in ("value", "call-value")}

        def tag(s):
            props = s.get("properties", {}) or {}
            return (s["id"], s.get("label"), props.get("sink_kind"))

        args = {}
        # C shape: call -> HAS_ARGUMENT -> argument expression.
        for e in self.index.flow_edges(["HAS_ARGUMENT"]):
            s = target_sink.get(e["source"])
            if s is not None:
                args[e["target"]] = tag(s)
        # Python shape: the value target itself is the argument expression.
        for t in value_targets:
            args[t] = tag(target_sink[t])
        # Python shape: taint may reach one intra-procedural hop upstream of the value.
        if value_targets:
            pred = collections.defaultdict(set)
            for e in self.index.flow_edges(["VALUE_FLOWS_TO"]):
                if e["target"] in value_targets:
                    pred[e["target"]].add(e["source"])
            for t in value_targets:
                for p in pred.get(t, ()):
                    args.setdefault(p, tag(target_sink[t]))
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
            kind = self.detector.bridge(sink_kind)
            if kind is None:
                continue  # a sink role the catalog has no kind/evaluator for yet
            fact = substrate.substrate(kind, tainted=is_tainted,
                                       value_bound=None, guarded=False)
            fired = self.detector.evaluate(kind, fact)
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
