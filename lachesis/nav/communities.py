"""Subsystem partitioning of the union call graph.

`hubs` answers "what is the spine?" — the most central functions. The next question a
reader asks about an unfamiliar codebase is "what are its *parts*?": which functions
cluster into a subsystem that talks to itself more than to the rest of the tree. That is
community detection, and it is what turns a flat call graph into an architecture.

The graph is the SAME undirected union call graph `hubs` ranks over (direct `CALLS` plus
the indirect-dispatch family), so a community is a set of functions that call each other,
independent of any file/package/directory layout — the structure the code *has*, not the
structure someone filed it under.

The algorithm is label propagation (Raghavan et al.): dependency-free, near-linear, and
the standard choice when a heavyweight modularity optimiser is not on the dependency list.
It is made deterministic here — a fixed node order and smallest-id tie-breaking — so the
same graph always yields the same partition, which a demo and a golden test both need. The
result's modularity is computed and returned so the partition's quality is legible rather
than asserted.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lachesis.nav.graphlib import GraphLib, CALLABLE_KINDS
from lachesis.nav.symbol_index import (
    CALL_EDGES, INDIRECT_CALL_EDGES, _caller_decl, _file_provenance, _is_external,
)


class Communities:
    """Label-propagation partition of function declarations over the union call graph."""

    # Confidence tiers kept when partitioning. `hubs` ranks over EVERY edge because
    # over-approximation only inflates a degree it already trusts; a partition is the
    # opposite — a single conservative name-dispatch edge (every `.get(...)` resolving to
    # one `get` declaration) becomes a false super-hub that glues unrelated subsystems
    # into one blob. So communities keep only resolved calls (exact/high) by default and
    # drop the conservative/low over-approximation that destroys structure.
    _RESOLVED = frozenset({"exact", "high"})

    def __init__(self, gl: GraphLib, include_external: bool = False,
                 include_tests: bool = False, include_conservative: bool = False,
                 include_dispatch: bool = False, hub_fraction: float = 0.05,
                 max_rounds: int = 100) -> None:
        self.gl = gl
        self._prov = _file_provenance(gl)
        self._include_external = include_external
        self._include_tests = include_tests
        self._include_conservative = include_conservative
        self._include_dispatch = include_dispatch
        self._hub_fraction = hub_fraction
        self._max_rounds = max_rounds
        # Undirected adjacency over caller-decl <-> callee, weighted by distinct pairs.
        self._adj: dict[str, dict[str, int]] = {}
        self._degree: dict[str, int] = {}
        self._connectors: list[str] = []
        self._connector_degree: dict[str, int] = {}
        self._label_of: dict[str, int] = {}
        self._build_graph()
        self._suppress_connectors()
        self._propagate()

    # ------------------------------------------------------------------ graph
    def _decl_of_source(self, edge: dict) -> dict | None:
        src = self.gl.nodes.get(edge.get("source"))
        if src is None:
            return None
        return _caller_decl(self.gl, src) or src

    def _keep_id(self, node_id: str) -> bool:
        node = self.gl.nodes.get(node_id)
        if node is None:
            return False
        # Only real function declarations are subsystem members. Call-context (k-CFA)
        # pseudo-nodes and other non-callable endpoints ride the call edges but are not
        # functions, so they must never appear as members — same filter `hubs` applies.
        if node.get("kind") not in CALLABLE_KINDS:
            return False
        if self.gl.prop(node, "declaration_only"):
            return False
        file, _, _ = self.gl.loc(node)
        if not self._include_external and _is_external(file, self._prov):
            return False
        if not self._include_tests:
            from lachesis.nav.symbol_index import _is_test
            if _is_test(file):
                return False
        return True

    def _edge_resolved(self, edge: dict) -> bool:
        if self._include_conservative:
            return True
        conf = (edge.get("properties") or {}).get("confidence")
        # Keep resolved calls; also keep an edge that simply carries no confidence stamp
        # (direct compiler CALLS are always exact, and a missing stamp is not evidence of
        # over-approximation), but drop anything explicitly conservative/low/unresolved.
        return conf is None or conf in self._RESOLVED

    def _link(self, a: str, b: str) -> None:
        if a == b:
            return
        self._adj.setdefault(a, {})
        self._adj.setdefault(b, {})
        self._adj[a][b] = self._adj[a].get(b, 0) + 1
        self._adj[b][a] = self._adj[b].get(a, 0) + 1

    def _build_graph(self) -> None:
        gl = self.gl
        # Distinct caller-decl -> callee pairs over the union graph, same dedup as hubs.
        # Partition over PRECISE structural calls by default. `hubs` ranks over the union
        # graph including the indirect-dispatch family, because for centrality an
        # over-approximated edge only inflates a degree. A partition is the opposite: on a
        # duck-typed tree, `.label()` / `.get()` resolve by NAME to every method of that
        # name (a known attribute-dispatch blind spot), and those MAY_INVOKE / CONTEXT_CALLS
        # edges outnumber the exact calls several-to-one and fuse every subsystem into one
        # blob. So dispatch is opt-in (`--include-dispatch`), earned on C function-pointer
        # trees where indirect dispatch *is* the real control flow.
        families = [CALL_EDGES]
        if self._include_dispatch:
            families.append(INDIRECT_CALL_EDGES)
        pairs: set[tuple[str, str]] = set()
        for kinds in families:
            for edge in gl.index.edges_of_kind(*kinds):
                if not self._edge_resolved(edge):
                    continue
                target = edge.get("target")
                caller = self._decl_of_source(edge)
                if caller is None or not target:
                    continue
                pairs.add((caller["id"], target))
        for caller_id, callee_id in pairs:
            if self._keep_id(caller_id) and self._keep_id(callee_id):
                self._link(caller_id, callee_id)
        self._recompute_degree()

    def _recompute_degree(self) -> None:
        self._degree = {nid: sum(nbrs.values()) for nid, nbrs in self._adj.items()}

    def _suppress_connectors(self) -> None:
        """Remove near-universal connector nodes before partitioning.

        A callee reached by a large fraction of the whole tree carries no subsystem
        signal: whether it is a genuine cross-cutting utility (a logger, an allocator)
        or a name-dispatch over-approximation (every `.get(...)` resolving to one `get`
        declaration — a known attribute-dispatch blind spot), keeping it collapses every
        subsystem it touches into one blob. So it is lifted out of the graph, reported
        separately, and the partition is computed over what remains. `hub_fraction <= 0`
        disables this.
        """
        n = len(self._adj)
        if self._hub_fraction <= 0 or n < 20:
            return
        threshold = self._hub_fraction * n
        connectors = [nid for nid, deg in self._degree.items() if deg > threshold]
        if not connectors:
            return
        drop = set(connectors)
        self._connector_degree = {nid: self._degree[nid] for nid in drop}
        for nid in drop:
            for other in self._adj.get(nid, {}):
                self._adj.get(other, {}).pop(nid, None)
            self._adj.pop(nid, None)
        # Report connectors most-connected first (by their pre-removal degree).
        self._connectors = sorted(drop, key=lambda i: -self._connector_degree.get(i, 0))
        self._recompute_degree()

    # -------------------------------------------------------------- algorithm
    def _propagate(self) -> None:
        # Seed every node with a unique label; order deterministically so the run is
        # reproducible (a bug hunt and a golden test both depend on stable partitions).
        order = sorted(self._adj)
        label = {nid: i for i, nid in enumerate(order)}
        for _ in range(self._max_rounds):
            changed = False
            for nid in order:
                nbrs = self._adj[nid]
                if not nbrs:
                    continue
                # Tally neighbour-label weight; adopt the heaviest, smallest-id on ties.
                weight: dict[int, int] = {}
                for other, w in nbrs.items():
                    lbl = label[other]
                    weight[lbl] = weight.get(lbl, 0) + w
                best = max(weight.items(), key=lambda kv: (kv[1], -kv[0]))[0]
                if label[nid] != best:
                    label[nid] = best
                    changed = True
            if not changed:
                break
        self._label_of = label

    def modularity(self) -> float:
        """Newman-Girvan modularity of the partition over the undirected graph."""
        m2 = sum(self._degree.values())  # == 2m (each edge counted from both ends)
        if m2 == 0:
            return 0.0
        q = 0.0
        for nid, nbrs in self._adj.items():
            li = self._label_of[nid]
            ki = self._degree[nid]
            for other, w in nbrs.items():
                if self._label_of[other] != li:
                    continue
                q += w - (ki * self._degree[other]) / m2
        return q / m2

    # ----------------------------------------------------------------- output
    def partitions(self, n: int = 20, members: int = 8, min_size: int = 2) -> list[dict]:
        """The communities, largest first, each summarised for a reader.

        Each row is one subsystem: its size, its highest-degree members (the local
        spine, so it reads like a labelled part rather than a bag of ids), the files it
        spans, and its cohesion (internal vs. outgoing edges).
        """
        groups: dict[int, list[str]] = {}
        for nid, lbl in self._label_of.items():
            groups.setdefault(lbl, []).append(nid)

        rows: list[dict] = []
        for lbl, ids in groups.items():
            if len(ids) < max(1, min_size):
                continue
            ids.sort(key=lambda i: (-self._degree.get(i, 0), self._name(i).lower()))
            internal = external = 0
            files: dict[str, int] = {}
            for nid in ids:
                for other, w in self._adj[nid].items():
                    if self._label_of[other] == lbl:
                        internal += w
                    else:
                        external += w
                f, _, _ = self.gl.loc(self.gl.nodes.get(nid))
                if f:
                    files[f] = files.get(f, 0) + 1
            top_files = sorted(files.items(), key=lambda kv: (-kv[1], kv[0]))
            rows.append({
                "id": lbl,
                "label": self._name(ids[0]),
                "size": len(ids),
                "internal_edges": internal // 2,  # each internal edge counted twice
                "external_edges": external,
                "cohesion": round((internal / (internal + external)), 3)
                            if (internal + external) else 0.0,
                "files": [f for f, _ in top_files[:members]],
                "members": [self._member(nid) for nid in ids[:members]],
            })
        rows.sort(key=lambda r: (-r["size"], -r["internal_edges"], r["label"].lower()))
        # Renumber ids 0..k-1 in display order so the surface is stable and readable.
        for i, r in enumerate(rows[:max(0, n)]):
            r["id"] = i
        return rows[:max(0, n)]

    def summary(self, n: int = 20, members: int = 8, min_size: int = 2) -> dict:
        parts = self.partitions(n=n, members=members, min_size=min_size)
        placed = sum(len(g) for g in self._group_sizes(min_size))
        return {
            "nodes": len(self._adj),
            "communities": len([g for g in self._group_sizes(min_size)]),
            "modularity": round(self.modularity(), 4),
            "shown": len(parts),
            "placed_nodes": placed,
            "connectors": [self._member(nid) for nid in self._connectors[:members]],
            "connectors_removed": len(self._connectors),
            "partitions": parts,
        }

    def _group_sizes(self, min_size: int) -> list[list[str]]:
        groups: dict[int, list[str]] = {}
        for nid, lbl in self._label_of.items():
            groups.setdefault(lbl, []).append(nid)
        return [ids for ids in groups.values() if len(ids) >= max(1, min_size)]

    def _name(self, node_id: str) -> str:
        node = self.gl.nodes.get(node_id)
        return self.gl.label(node) if node else node_id

    def _member(self, node_id: str) -> dict:
        node = self.gl.nodes.get(node_id)
        file, line, _ = self.gl.loc(node) if node else (None, None, None)
        return {
            "node_id": node_id,
            "name": self._name(node_id),
            "handle": f"{file}:{line}" if file and line else None,
            "file": file,
            "line": line,
            # A suppressed connector is out of `_degree`; fall back to its pre-removal one.
            "degree": self._degree.get(node_id) or self._connector_degree.get(node_id, 0),
        }


def _parser():
    import argparse
    p = argparse.ArgumentParser(
        description="Partition the union call graph into subsystems (communities).")
    p.add_argument("graph", help="path to the graph JSON")
    p.add_argument("-n", type=int, default=20, help="how many communities to show")
    p.add_argument("--members", type=int, default=8, help="members/files listed per community")
    p.add_argument("--min-size", type=int, default=2, help="drop communities smaller than this")
    p.add_argument("--overlay", help="optional overlay graph JSON")
    p.add_argument("--include-external", action="store_true")
    p.add_argument("--include-tests", action="store_true")
    p.add_argument("--include-dispatch", action="store_true",
                   help="also partition over the indirect-dispatch family (function "
                        "pointers / ops-structs / attribute dispatch); earned on C "
                        "function-pointer trees, noisy on duck-typed Python/TS")
    p.add_argument("--include-conservative", action="store_true",
                   help="also partition over conservative/low-confidence dispatch edges "
                        "(default: resolved calls only, which gives cleaner subsystems)")
    p.add_argument("--hub-fraction", type=float, default=0.05,
                   help="lift out connector nodes reached by more than this fraction of "
                        "the tree before partitioning (0 disables; default 0.05)")
    p.add_argument("--json", action="store_true")
    return p


def main(argv: list[str]) -> int:
    import json
    from lachesis.nav.graph_store import GraphStore
    args = _parser().parse_args(argv)
    gl = GraphStore.load(args.graph, overlay_path=args.overlay).ensure_dataflow_tier().gl
    comm = Communities(gl, include_external=args.include_external,
                       include_tests=args.include_tests,
                       include_conservative=args.include_conservative,
                       include_dispatch=args.include_dispatch,
                       hub_fraction=args.hub_fraction)
    result = comm.summary(n=args.n, members=args.members, min_size=args.min_size)
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0
    print(f"{result['communities']} communities over {result['nodes']} functions  "
          f"(modularity {result['modularity']})")
    if result["connectors_removed"]:
        names = ", ".join(f"{m['name']} ({m['degree']})" for m in result["connectors"])
        print(f"  cross-cutting connectors lifted out ({result['connectors_removed']}): {names}")
    for r in result["partitions"]:
        print(f"\n  #{r['id']}  {r['label']}  "
              f"({r['size']} funcs, cohesion {r['cohesion']}, "
              f"{r['internal_edges']} internal / {r['external_edges']} out)")
        for m in r["members"]:
            print(f"      {m['degree']:4}  {m['name']}  {m['handle'] or ''}")
        if r["files"]:
            print(f"      files: {', '.join(r['files'])}")
    if not result["partitions"]:
        print("(no communities — graph has no call edges)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
