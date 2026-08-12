#!/usr/bin/env python3
"""The sidecar overlay — where derived reasoning signals live, off the canonical graph.

The user's decision (locked): derived signals are **non-invasive**. The canonical
Lachesis graph (`graph.kuzu`) is never rewritten; everything this reasoning layer
*infers* — per-function `guard_signal` (Fix 2), first-class `GUARDED`/`UNGUARDED`
edges (0 in the base graph), `CALLS` callee security-roles (Fix 4) — is written to
a companion JSON next to the graph and merged back in memory at load time. This
matches the `lachesis/core/overlays/` convention (an overlay is a `GraphDelta` of
derived nodes/edges), but stays a plain sidecar file so nothing in `lachesis/` has
to change.

Shape on disk::

    {
      "overlay_id": "nav-reasoning",
      "source": "graph.kuzu",
      "node_props": { "<node id>": { "guard_signal": {...} }, ... },
      "edge_props": { "<edge key>": { "role": "verify" }, ... },
      "derived_edges": [ { "source","target","kind","properties" }, ... ],
      "derived_nodes": [ { "id","kind","label","properties" }, ... ]
    }

`node_props`/`edge_props` are *merges* onto pre-existing graph elements (they never
mutate the file — `graph_store` applies them to the in-memory copy). `derived_*`
are brand-new elements this layer materializes (e.g. a `GUARDED` edge that has no
counterpart in the base graph).

  python3 nav/overlay.py graph.kuzu --show           # summarize an existing sidecar
  python3 nav/overlay.py graph.kuzu --init            # write an empty sidecar
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

OVERLAY_ID = "nav-reasoning"
# derived edge kinds this layer is allowed to materialize (kept explicit so a typo
# never silently invents an edge kind the movers then query for and never find).
DERIVED_EDGE_KINDS = frozenset({"GUARDED", "UNGUARDED"})


def sidecar_path(graph_path: str | Path) -> Path:
    """The overlay file that pairs with a graph: `foo.kuzu` -> `foo.nav-overlay.json`."""
    p = Path(graph_path)
    return p.with_name(p.stem + ".nav-overlay.json")


def edge_key(edge: dict) -> str:
    """A stable key for an existing edge so `edge_props` can address it.

    Canonical edges have no id; (source, target, kind) identifies them for the
    property merges this layer needs (e.g. tagging a `CALLS` edge with a role)."""
    return f"{edge.get('source')}\t{edge.get('target')}\t{edge.get('kind')}"


class Overlay:
    """A mutable sidecar of derived signals, additive over a canonical graph."""

    def __init__(self, source: str | None = None) -> None:
        self.source = source
        self.node_props: dict[str, dict] = {}
        self.edge_props: dict[str, dict] = {}
        self.derived_edges: list[dict] = []
        self.derived_nodes: list[dict] = []

    # -- construction --------------------------------------------------------

    def set_node_prop(self, node_id: str, key: str, value) -> None:
        self.node_props.setdefault(node_id, {})[key] = value

    def set_edge_prop(self, edge: dict, key: str, value) -> None:
        self.edge_props.setdefault(edge_key(edge), {})[key] = value

    def add_derived_edge(self, source: str, target: str, kind: str,
                         properties: dict | None = None) -> None:
        if kind not in DERIVED_EDGE_KINDS:
            raise ValueError(f"undeclared derived edge kind {kind!r} "
                             f"(add it to DERIVED_EDGE_KINDS first)")
        self.derived_edges.append({
            "source": source, "target": target, "kind": kind,
            "properties": properties or {},
        })

    def add_derived_node(self, node: dict) -> None:
        self.derived_nodes.append(node)

    # -- persistence ---------------------------------------------------------

    def to_dict(self) -> dict:
        return {
            "overlay_id": OVERLAY_ID,
            "source": self.source,
            "node_props": self.node_props,
            "edge_props": self.edge_props,
            "derived_edges": self.derived_edges,
            "derived_nodes": self.derived_nodes,
        }

    def write(self, path: str | Path) -> Path:
        path = Path(path)
        path.write_text(json.dumps(self.to_dict(), indent=2, ensure_ascii=False),
                        encoding="utf-8")
        return path

    @classmethod
    def from_dict(cls, doc: dict) -> "Overlay":
        ov = cls(source=doc.get("source"))
        ov.node_props = dict(doc.get("node_props") or {})
        ov.edge_props = dict(doc.get("edge_props") or {})
        ov.derived_edges = list(doc.get("derived_edges") or [])
        ov.derived_nodes = list(doc.get("derived_nodes") or [])
        return ov

    @classmethod
    def load(cls, path: str | Path) -> "Overlay":
        path = Path(path)
        if not path.exists():
            return cls()
        return cls.from_dict(json.loads(path.read_text(encoding="utf-8")))

    # -- application (in memory only — never touches the canonical file) -----

    def apply_to(self, graph: dict) -> dict:
        """Return the graph with derived nodes/edges/props merged in (new dict).

        The canonical `graph` argument is not mutated; a shallow-copied dict with
        extended `nodes`/`edges` lists is returned so the on-disk file stays
        byte-identical while the in-memory reasoning surface is enriched.
        """
        nodes = list(graph.get("nodes", []))
        edges = list(graph.get("edges", []))

        if self.node_props:
            # position map, not `nodes.index(node)`: this runs over whole-repo graphs,
            # where a linear scan per overlaid node is quadratic.
            position = {n["id"]: i for i, n in enumerate(nodes)}
            for node_id, props in self.node_props.items():
                idx = position.get(node_id)
                if idx is None:
                    continue
                node = nodes[idx]
                merged = dict(node.get("properties") or {})
                merged.update(props)
                # replace the node with a copy carrying merged props (no mutation
                # of the original dict the caller may still hold)
                nodes[idx] = {**node, "properties": merged}

        if self.edge_props:
            for i, edge in enumerate(edges):
                extra = self.edge_props.get(edge_key(edge))
                if not extra:
                    continue
                merged = dict(edge.get("properties") or {})
                merged.update(extra)
                edges[i] = {**edge, "properties": merged}

        nodes.extend(self.derived_nodes)
        edges.extend(self.derived_edges)
        return {**graph, "nodes": nodes, "edges": edges}

    def summary(self) -> dict:
        from collections import Counter
        return {
            "overlay_id": OVERLAY_ID,
            "source": self.source,
            "node_props": len(self.node_props),
            "edge_props": len(self.edge_props),
            "derived_edges": len(self.derived_edges),
            "derived_edge_kinds": dict(Counter(e["kind"] for e in self.derived_edges)),
            "derived_nodes": len(self.derived_nodes),
        }


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="nav reasoning sidecar overlay")
    p.add_argument("graph")
    p.add_argument("--show", action="store_true", help="summarize the paired sidecar")
    p.add_argument("--init", action="store_true", help="write an empty sidecar")
    p.add_argument("--path", help="override the sidecar path")
    return p


def main(argv: list[str]) -> int:
    args = _parser().parse_args(argv)
    path = Path(args.path) if args.path else sidecar_path(args.graph)
    if args.init:
        ov = Overlay(source=Path(args.graph).name)
        ov.write(path)
        print(f"wrote empty overlay -> {path}", file=sys.stderr)
        return 0
    ov = Overlay.load(path)
    print(json.dumps(ov.summary(), indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
