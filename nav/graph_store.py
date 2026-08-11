#!/usr/bin/env python3
"""Load-once store + the shared labeled-path shape every reasoning move returns.

This is the seam the whole reasoning layer (and, last, the MCP server) sits on:

  * **load once** — the canonical graph is parsed a single time into `GraphLib`
    (`GraphIndex` adjacency + `by_kind`/`by_label`/`by_file`/`by_owner`), the name
    index is built once, and the **sidecar overlay** (`overlay.py`) is merged in
    memory so derived `guard_signal` / `GUARDED` / `role` signals are queryable
    right alongside the base facts. The store on disk is never rewritten.

  * **one output shape** — `path_shape(nodes, edges)` renders any traversal result
    into the same labeled-path envelope so every move (`flow`, `reaches`,
    `siblings`, `guards`, …) speaks one language to the agent:
      - nodes: `{id, name, kind, file, line}`  (named + `file:line` anchored)
      - edges: `{src, tgt, kind, via, reason, role, confidence, fact_origin}`
    `via`/`reason`/`role` explain *why* the hop exists; `confidence`/`fact_origin`
    carry the graph's built-in provenance straight through to the answer.

Query scoping by `owner_function_id` (`scope_owner`) gives cheap function-local
slices without a re-parse.

  python3 nav/graph_store.py graph.kuzu --stat
  python3 nav/graph_store.py graph.kuzu --resolve verifySignature
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from nav.graphlib import GraphLib
from nav import symbol_index as si
from nav.overlay import Overlay, sidecar_path


def node_view(node: dict) -> dict:
    """The `{id, name, kind, file, line}` projection every shape node uses."""
    props = node.get("properties") or {}
    return {
        "id": node.get("id"),
        "name": node.get("label"),
        "kind": node.get("kind"),
        "file": props.get("file"),
        "line": props.get("start_line"),
    }


def edge_view(edge: dict) -> dict:
    """The `{src, tgt, kind, via, reason, role, confidence, fact_origin}` projection.

    `kind` is the *semantic* kind (an `EXPANDS_TO` wrapper is unwrapped to its
    `via` relationship), while the raw `via`/`reason`/`role` and provenance ride
    along untouched so the caller sees exactly why a hop is in the path."""
    props = edge.get("properties") or {}
    kind = edge.get("kind")
    if kind == "EXPANDS_TO":
        kind = props.get("via") or kind
    return {
        "src": edge.get("source"),
        "tgt": edge.get("target"),
        "kind": kind,
        "via": props.get("via"),
        "reason": props.get("reason") or props.get("transition"),
        "role": props.get("role"),
        "confidence": props.get("confidence"),
        "fact_origin": props.get("fact_origin"),
    }


class GraphStore:
    """Everything a reasoning move needs, loaded once and shared."""

    def __init__(self, graph: dict, overlay: Overlay | None = None,
                 graph_path: str | None = None) -> None:
        self.overlay = overlay or Overlay()
        # merge derived signals in memory; the canonical dict is left untouched
        merged = self.overlay.apply_to(graph) if overlay else graph
        self.graph = merged
        self.gl = GraphLib(merged)
        self.index = self.gl.index
        self.graph_path = graph_path
        self._entries: list[dict] | None = None

    @classmethod
    def from_graphlib(cls, gl: GraphLib, graph_path: str | None = None,
                      overlay: Overlay | None = None) -> "GraphStore":
        """Build a store around an already-constructed ``GraphLib`` (the disk-backed
        store path), bypassing the dict merge an in-memory graph needs. The overlay is
        folded into the index itself rather than into a dict, so nothing materializes."""
        self = cls.__new__(cls)
        self.overlay = overlay or Overlay()
        self.graph = None
        self.gl = gl
        self.index = gl.index
        self.graph_path = graph_path
        self._entries = None
        return self

    @classmethod
    def load(cls, graph_path: str, overlay_path: str | None = None) -> "GraphStore":
        """Open a Kùzu store directory. The disk-backed index satisfies the same
        accessor surface as the in-RAM one, so ``GraphLib`` and every nav tool are
        unchanged, and nothing loads the whole graph into memory."""
        from Lachesis.kuzu_store import is_kuzu_dir
        from nav.kuzu_index import KuzuGraphIndex
        if not is_kuzu_dir(graph_path):
            raise ValueError(
                f"{graph_path} is not a Lachesis graph store; build one with "
                f"`lachesis-analyze <source_dir> {graph_path}`"
            )
        index = KuzuGraphIndex(graph_path)
        ov_path = Path(overlay_path) if overlay_path else sidecar_path(graph_path)
        overlay = Overlay.load(ov_path)
        index.attach_overlay(overlay)
        return cls.from_graphlib(GraphLib.from_index(index), graph_path=graph_path,
                                 overlay=overlay)

    # -- name entry / teleport ----------------------------------------------

    @property
    def entries(self) -> list[dict]:
        if self._entries is None:
            self._entries = si.build_index(self.gl)
        return self._entries

    def resolve(self, name: str) -> list[dict]:
        """Name -> candidate index entries (exact first, else fuzzy)."""
        return si._resolve(self.gl, self.entries, name)

    def node(self, node_id: str) -> dict | None:
        return self.gl.nodes.get(node_id)

    # -- scoping -------------------------------------------------------------

    def scope_owner(self, owner_id: str) -> tuple[dict, ...]:
        """Cheap function-local slice: nodes owned by a function (no re-parse)."""
        return self.index.nodes_owned_by(owner_id)

    # -- the one output shape ------------------------------------------------

    def path_shape(self, nodes, edges, *, manifest: dict | None = None) -> dict:
        """Render nodes/edges into the shared labeled-path envelope.

        `nodes` may be node dicts or ids; `edges` are edge dicts. Node order is
        preserved (a witness path stays in path order); duplicates collapse."""
        seen: set[str] = set()
        out_nodes: list[dict] = []
        for n in nodes:
            node = self.node(n) if isinstance(n, str) else n
            if not node:
                continue
            nid = node.get("id")
            if nid in seen:
                continue
            seen.add(nid)
            out_nodes.append(node_view(node))
        out_edges = [edge_view(e) for e in edges]
        env = {"nodes": out_nodes, "edges": out_edges,
               "counts": {"nodes": len(out_nodes), "edges": len(out_edges)}}
        if manifest:
            env["manifest"] = manifest
        return env

    def stat(self) -> dict:
        return {
            "graph": self.graph_path,
            "nodes": len(self.gl.nodes),
            "edges": sum(len(v) for v in self.index.outgoing.values()),
            "names_indexed": len(self.entries),
            "overlay": self.overlay.summary(),
        }


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="load-once reasoning store + path-shape")
    p.add_argument("graph")
    p.add_argument("--overlay", help="override the sidecar overlay path")
    p.add_argument("--stat", action="store_true", help="graph + overlay stats")
    p.add_argument("--resolve", metavar="NAME", help="resolve a name to node(s)")
    return p


def main(argv: list[str]) -> int:
    args = _parser().parse_args(argv)
    store = GraphStore.load(args.graph, overlay_path=args.overlay)
    if args.resolve:
        hits = store.resolve(args.resolve)
        print(json.dumps(hits, indent=2, ensure_ascii=False))
        return 0
    print(json.dumps(store.stat(), indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
