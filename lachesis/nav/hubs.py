"""Centrality-ranked cold-start over the union call graph.

The MCP surface's old cold-start door (`guards_top`) ranks by *guard signal* — a
security notion. When the goal is to *understand* an unfamiliar subsystem, the first
question is "what is the spine?", and the answer is centrality: the functions with the
most callers + callees. This engine ranks function declarations by degree over the SAME
union call graph `callers`/`callees` traverse (direct `CALLS` + the indirect-dispatch
family), so on C/kernel — where function-pointer / ops-struct dispatch *is* the control
flow — the spine surfaces instead of staying invisible.

Language-agnostic: degree is computed from schema edge kinds, and the entry-point flags
(`exported` / `dispatch_target` / `callback`) are derived from schema relationships, not
from any vendor / interface / package literal.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lachesis.nav.graphlib import GraphLib, CALLABLE_KINDS
from lachesis.nav.symbol_index import (
    CALL_EDGES, INDIRECT_CALL_EDGES, _caller_decl, _file_provenance, _is_external,
)

# Edges that register a function to be run later (callback / deferred work). A function
# that is a target here is an entry point reached by the runtime, not by a direct caller.
CALLBACK_EDGES = ("REGISTERS_CALLBACK", "PASSES_CALLBACK", "SCHEDULES")


class Hubs:
    """Degree ranking of function declarations over the union call graph."""

    def __init__(self, gl: GraphLib, include_external: bool = False,
                 include_tests: bool = False) -> None:
        self.gl = gl
        self._prov = _file_provenance(gl)
        self._include_external = include_external
        self._include_tests = include_tests
        self._fan_in: dict[str, int] = {}
        self._fan_out: dict[str, int] = {}
        self._flags: dict[str, list[str]] = {}
        self._build()

    def _decl_of_source(self, edge: dict) -> dict | None:
        """Declaration that owns an edge's source (call-site / call-context / decl)."""
        src = self.gl.nodes.get(edge.get("source"))
        if src is None:
            return None
        return _caller_decl(self.gl, src) or src

    def _build(self) -> None:
        gl = self.gl
        # Unique caller-decl -> callee pairs over the union graph (dedup so a function
        # called from ten call-sites counts its callee once, matching callees() dedup).
        pairs: set[tuple[str, str]] = set()
        for kinds in (CALL_EDGES, INDIRECT_CALL_EDGES):
            for edge in gl.index.edges_of_kind(*kinds):
                target = edge.get("target")
                caller = self._decl_of_source(edge)
                if caller is None or not target:
                    continue
                pairs.add((caller["id"], target))
        for caller_id, callee_id in pairs:
            self._fan_out[caller_id] = self._fan_out.get(caller_id, 0) + 1
            self._fan_in[callee_id] = self._fan_in.get(callee_id, 0) + 1

        exported = gl.exported_ids
        callback_targets = {e.get("target") for e in gl.index.edges_of_kind(*CALLBACK_EDGES)}
        dispatch_targets = {e.get("target") for e in gl.index.edges_of_kind(*INDIRECT_CALL_EDGES)}
        for node in gl.index.nodes_of_kind(*CALLABLE_KINDS):
            nid = node["id"]
            flags: list[str] = []
            if nid in exported:
                flags.append("exported")
            if nid in dispatch_targets:
                flags.append("dispatch_target")  # reached via function-pointer / runtime dispatch
            if nid in callback_targets:
                flags.append("callback")          # registered / scheduled to run later
            if flags:
                self._flags[nid] = flags

    def _keep(self, node: dict) -> bool:
        file, _, _ = self.gl.loc(node)
        if not self._include_external and _is_external(file, self._prov):
            return False
        if not self._include_tests:
            from lachesis.nav.symbol_index import _is_test
            if _is_test(file):
                return False
        return True

    def top(self, n: int = 20) -> list[dict]:
        """The n highest-degree function declarations — the subsystem's spine."""
        rows: list[dict] = []
        for node in self.gl.index.nodes_of_kind(*CALLABLE_KINDS):
            nid = node["id"]
            if not self._keep(node):
                continue
            # A bodyless prototype (header/forward decl) is not part of the spine —
            # after cross-TU linking its call edges live on the definition twin, so
            # exclude it from the centrality ranking rather than showing a 0-edge stub.
            if self.gl.prop(node, "declaration_only"):
                continue
            fan_in = self._fan_in.get(nid, 0)
            fan_out = self._fan_out.get(nid, 0)
            degree = fan_in + fan_out
            if degree == 0:
                continue
            file, line, _ = self.gl.loc(node)
            rows.append({
                "node_id": nid,
                "name": self.gl.label(node),
                "handle": f"{file}:{line}" if file and line else None,
                "file": file,
                "line": line,
                "fan_in": fan_in,
                "fan_out": fan_out,
                "degree": degree,
                "flags": self._flags.get(nid, []),
            })
        rows.sort(key=lambda r: (-r["degree"], -r["fan_in"], r["name"].lower()))
        return rows[:max(0, n)]


def _parser():
    import argparse
    p = argparse.ArgumentParser(description="Centrality-ranked cold-start (union call graph).")
    p.add_argument("graph", help="path to the graph JSON")
    p.add_argument("-n", type=int, default=20, help="how many hubs to show")
    p.add_argument("--overlay", help="optional overlay graph JSON")
    p.add_argument("--include-external", action="store_true")
    p.add_argument("--include-tests", action="store_true")
    p.add_argument("--json", action="store_true")
    return p


def main(argv: list[str]) -> int:
    import json
    from lachesis.nav.graph_store import GraphStore
    args = _parser().parse_args(argv)
    # Load through GraphStore so an overlay's derived edges (extra dispatch context)
    # are folded into the same union graph the MCP `hubs` tool ranks over.
    gl = GraphStore.load(args.graph, overlay_path=args.overlay).ensure_dataflow_tier().gl
    rows = Hubs(gl, include_external=args.include_external,
                include_tests=args.include_tests).top(args.n)
    if args.json:
        print(json.dumps(rows, indent=2, ensure_ascii=False))
        return 0
    for r in rows:
        flags = f"  [{', '.join(r['flags'])}]" if r["flags"] else ""
        print(f"{r['degree']:4}  (in {r['fan_in']:>3} / out {r['fan_out']:>3})  "
              f"{r['name']}  {r['handle'] or ''}{flags}")
    if not rows:
        print("(no hubs — graph has no call edges)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
