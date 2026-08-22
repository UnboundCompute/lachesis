from __future__ import annotations

import unittest

from .communities import Communities
from .graph_store import GraphStore
from .report import build_report


def node(node_id, kind, label, file=None, line=None, **properties):
    return {"id": node_id, "kind": kind, "label": label,
            "properties": {"file": file, "start_line": line, **properties}}


def edge(kind, source, target, **properties):
    properties.setdefault("confidence", "exact")
    return {"kind": kind, "source": source, "target": target, "properties": properties}


def _fn(node_id, label, file, line):
    return node(node_id, "function", label, file, line)


class CommunitiesTests(unittest.TestCase):
    def _two_cluster_store(self):
        # Two call-cliques (K4 each: a1..a4, b1..b4) joined by one weak bridge. The bridge
        # is placed at the highest-sorted node of each clique (a4<->b4) on purpose: label
        # propagation updates nodes in id order, so each clique reaches internal consensus
        # before its bridge endpoint updates, and the single cross-edge cannot pull the two
        # subsystems into one blob. (Bridging at the *first* node instead lets the smallest
        # tie-break label cascade across — the known small-graph fragility of raw LPA.)
        nodes = [
            node("fa", "file", "a.py", "pkg/a.py", 1, provenance="application"),
            node("fb", "file", "b.py", "pkg/b.py", 1, provenance="application"),
        ]
        alpha = ["a1", "a2", "a3", "a4"]
        beta = ["b1", "b2", "b3", "b4"]
        for i, nid in enumerate(alpha):
            nodes.append(_fn(nid, f"alpha_{i}", "pkg/a.py", 10 + i))
        for i, nid in enumerate(beta):
            nodes.append(_fn(nid, f"beta_{i}", "pkg/b.py", 10 + i))
        edges = []
        for clique in (alpha, beta):
            for i in range(len(clique)):
                for j in range(i + 1, len(clique)):
                    edges.append(edge("CALLS", clique[i], clique[j]))
        edges.append(edge("CALLS", "a4", "b4"))  # the one cross-cluster edge
        return GraphStore({"nodes": nodes, "edges": edges})

    def test_finds_the_two_call_cliques(self):
        comm = Communities(self._two_cluster_store().gl)
        result = comm.summary(min_size=2)
        self.assertEqual(2, result["communities"])
        members = {frozenset(m["name"] for m in p["members"])
                   for p in result["partitions"]}
        self.assertIn(frozenset({"alpha_0", "alpha_1", "alpha_2", "alpha_3"}), members)
        self.assertIn(frozenset({"beta_0", "beta_1", "beta_2", "beta_3"}), members)
        # A clean split of two cliques by one bridge is strongly modular.
        self.assertGreater(result["modularity"], 0.3)

    def test_partition_is_deterministic(self):
        store = self._two_cluster_store()
        first = Communities(store.gl).summary()
        second = Communities(store.gl).summary()
        self.assertEqual(first["partitions"], second["partitions"])

    def test_dispatch_family_excluded_by_default(self):
        # A MAY_INVOKE (indirect dispatch) edge must not fuse clusters by default, but
        # must when the caller opts into dispatch — the C-function-pointer escape hatch.
        nodes = [
            node("fa", "file", "a.py", "pkg/a.py", 1, provenance="application"),
            _fn("a1", "alpha_one", "pkg/a.py", 10),
            _fn("a2", "alpha_two", "pkg/a.py", 20),
            _fn("z", "zeta", "pkg/a.py", 90),
        ]
        edges = [
            edge("CALLS", "a1", "a2"),
            # A resolved dispatch edge, so the confidence floor keeps it — isolating the
            # dispatch-family gate from the separate conservative-confidence gate.
            edge("MAY_INVOKE", "a2", "z", confidence="high"),
        ]
        store = GraphStore({"nodes": nodes, "edges": edges})
        default = Communities(store.gl)
        # 'z' is reached only by dispatch, so by default it never enters the graph.
        self.assertNotIn("z", default._adj)
        withd = Communities(store.gl, include_dispatch=True)
        self.assertIn("z", withd._adj)

    def test_connector_hub_is_lifted_out(self):
        # 24 leaf functions all calling one hub: the hub is a near-universal connector
        # and must be lifted out before partitioning, not left to glue everything.
        nodes = [node("fa", "file", "a.py", "pkg/a.py", 1, provenance="application"),
                 _fn("hub", "hub", "pkg/a.py", 1)]
        edges = []
        for i in range(24):
            nodes.append(_fn(f"f{i}", f"leaf_{i}", "pkg/a.py", 100 + i))
            edges.append(edge("CALLS", f"f{i}", "hub"))
        store = GraphStore({"nodes": nodes, "edges": edges})
        result = Communities(store.gl).summary()
        self.assertGreaterEqual(result["connectors_removed"], 1)
        self.assertIn("hub", {m["name"] for m in result["connectors"]})

    def test_report_renders_the_sections(self):
        text = build_report(self._two_cluster_store(), title="fixture")
        self.assertIn("# Architecture report — fixture", text)
        self.assertIn("Start here — the spine", text)
        self.assertIn("Function clusters — by the call graph", text)
        # A real cluster label from the fixture should appear in the clusters section.
        self.assertTrue("alpha" in text or "beta" in text)


if __name__ == "__main__":
    unittest.main()
