#!/usr/bin/env python3
"""CFG projection for the flow pass -- the substrate the path-sensitive typestate matcher
walks, pulled once out of the reader's control-flow tier so the matcher never re-reads the
graph.

Two plain artifacts:
  succ      node -> set(node)   the control-flow successor edges (branch/loop/merge included)
  resolve   node -> node        the nearest CFG-participating ancestor-or-self of an event's
                                anchor node, so an event pinned to a call node is placed on
                                whatever unit the reader's CFG actually sequences (the call
                                itself where calls carry CFG edges, else the enclosing
                                statement/block) -- robust to either granularity.

Everything a temporal shape query needs to be path-sensitive (two frees on mutually-exclusive
branches never meet; a free across a loop back-edge does) comes from these two.
"""
from collections import defaultdict
from lachesis.timeit import timeit

# the reader's control-flow edge kinds (control_flow overlay). MERGES_AT joins branch tails
# so a post-branch use sees the union of both arms; LOOP_BACK carries the back-edge that makes
# a free reachable from itself.
_CFG_EDGES = ("CFG_NEXT", "TRUE_BRANCH", "FALSE_BRANCH", "LOOP_BACK",
              "SWITCH_CASE", "EXCEPTION_BRANCH", "RUNS_FINALLY", "MERGES_AT")


@timeit
def cfg_bundle(store):
    """Build {"succ", "resolve"} from an opened store whose dataflow tier is ensured."""
    idx = store.index
    succ = defaultdict(set)
    for e in idx.edges_of_kind(*_CFG_EDGES):
        succ[e["source"]].add(e["target"])

    # nodes that actually participate in the CFG (as a source or a target of any edge)
    cfg_nodes = set(succ)
    for ts in succ.values():
        cfg_nodes.update(ts)

    ast_parent = {}
    for e in idx.edges_of_kind("AST_CHILD"):
        ast_parent[e["target"]] = e["source"]

    resolved = {}

    def resolve(nid):
        """The nearest ancestor-or-self of `nid` that participates in the CFG."""
        if nid in resolved:
            return resolved[nid]
        cur, chain = nid, []
        while cur is not None:
            chain.append(cur)
            if cur in cfg_nodes:
                break
            cur = ast_parent.get(cur)
        target = cur if cur is not None else nid
        for c in chain:
            resolved[c] = target
        return target

    return {"succ": dict(succ), "resolve": resolve}
