"""Split an enriched graph into the part a compiler can rebuild and the part it cannot.

A store does not have to hold everything it can answer with. Three layers come out of a
build and only two of them are worth keeping on disk:

``SPINE``
    Files, modules, declarations, scopes, call sites — the skeleton. A frontend emits it
    again from the same source in seconds, so it is cheap to recompute, but it is also
    what answers "find this symbol" and "who calls this" without starting a compiler, so
    it is kept resident anyway.
``BODY``
    Everything inside a function: values, identifiers, expressions, reads, writes,
    statements, arguments. The bulk of the graph, and entirely a function of the source.
``SEMANTIC``
    What enrichment derived — taint, roles, contexts, ecosystem facts. Nothing but this
    codebase knows it, and rederiving it costs an order of magnitude more than a compile.

So: store spine and semantic, drop bodies, recompile at load, and rejoin by
content-addressed id. The ids are the load-bearing wall — a node's id is a digest of what
it is and where it lives, so a stored semantic edge that points into a body finds its
endpoint again in a fresh compile of the same source, without anything being written down
to connect them.

This module is only the vocabulary of that split: which nodes are spine, and which edges a
store has to carry because nothing will regenerate them. It reads graphs and returns
graphs, and knows nothing about Kuzu, files, or loading.
"""
from __future__ import annotations

import itertools
import json
from typing import Dict, List, Set, Tuple

from .types import CodeGraph, GraphEdge, GraphNode

#: Node kinds that stay resident. Deliberately holds not one intra-body kind: everything
#: here either declares a name, scopes one, or names a file, and the whole set is the part
#: of the graph that is meaningful with the bodies gone.
#:
#: `external-module` is here because a dependency you cannot name is not a symbol table:
#: without it every `import x from "y"` loses its target and a file's dependency list comes
#: back empty. That one was found by probing the tool surface, not by reasoning about
#: kinds, which is the honest reason to distrust this list until it has been probed again
#: after a frontend adds a kind.
SPINE_NODE_KINDS = frozenset({
    "file", "module", "package", "namespace",
    "function", "method", "class", "interface", "record", "enum", "struct",
    "definition", "declaration", "variable", "parameter", "field", "property",
    "symbol", "binding", "import", "export", "type", "typedef",
    "call", "route", "sink",
    "external-module", "scope", "module-initializer", "constructor",
    "type-parameter", "macro", "decorator", "static-initializer",
})

SPINE = "SPINE"
SEMANTIC = "SEMANTIC"
BODY = "BODY"


def partition_of(node: GraphNode) -> str:
    """Which of the three layers one node belongs to.

    A node with no ``frontend_id`` was minted by enrichment rather than read out of a
    snapshot, so it is semantic by construction rather than by kind. That is what keeps
    the rule honest when an overlay invents a kind this module has never heard of: a new
    semantic kind is classified correctly the day it appears, and only a new *compiler*
    kind needs `SPINE_NODE_KINDS` to be revisited.
    """
    if not (node.get("properties") or {}).get("frontend_id"):
        return SEMANTIC
    return SPINE if node.get("kind") in SPINE_NODE_KINDS else BODY


def edge_identity(edge: GraphEdge) -> Tuple[str, str, str, str]:
    """The tuple that makes two edges the same edge.

    Properties are part of it. Two ``CALLS`` edges can join the same pair of nodes and
    mean different things — different call sites, different lines — and enrichment can add
    an edge that shares kind and endpoints with a compiler edge and differs only in what it
    records. Keying on endpoints alone files those as "the compiler will regenerate this",
    and then nothing does.
    """
    return (
        edge["kind"], edge["source"], edge["target"],
        json.dumps(edge.get("properties") or {}, sort_keys=True),
    )


def resident_ids(graph: CodeGraph) -> Set[str]:
    """The ids of every node that survives the split."""
    return {n["id"] for n in graph.get("nodes", []) if partition_of(n) != BODY}


def reduce_graph(core: CodeGraph, enriched: CodeGraph) -> CodeGraph:
    """The graph to store: spine and semantic nodes, plus every edge worth carrying.

    Which edges those are is decided by provenance, not by whether both endpoints are
    resident. Anything already in ``core`` is free at load because the compiler emits it
    again; everything enrichment added has to be carried because nothing else knows it.
    Deciding provenance by inspecting an edge's endpoints instead — "it runs body to body,
    so a compiler must have made it" — loses precisely the enrichment edges that matter,
    since a taint edge is body to body by nature. Asking ``core`` directly cannot make that
    mistake.

    Core edges between two resident nodes are kept as well. They are recomputable, so this
    is redundancy rather than necessity, and it buys a store that still answers
    "who calls this" with no compiler in the room.

    Many of the returned edges have an endpoint that is not in the returned nodes. That is
    the design, not an oversight: those endpoints come back from the recompile.
    """
    keep = resident_ids(enriched)
    core_edges = {edge_identity(e) for e in core.get("edges", [])}
    carried: List[GraphEdge] = [
        e for e in enriched.get("edges", []) if edge_identity(e) not in core_edges
    ]
    carried.extend(
        e for e in core.get("edges", [])
        if e["source"] in keep and e["target"] in keep
    )
    return {
        "nodes": [n for n in enriched.get("nodes", []) if n["id"] in keep],
        "edges": carried,
    }


def partition_counts(graph: CodeGraph) -> Dict[str, int]:
    """How many nodes of each layer a graph holds, for reporting a store's shape."""
    counts = {SPINE: 0, SEMANTIC: 0, BODY: 0}
    for node in graph.get("nodes", []):
        counts[partition_of(node)] += 1
    return counts


def join_graphs(fresh: CodeGraph, stored: CodeGraph) -> CodeGraph:
    """Overlay a stored layer onto a freshly compiled graph.

    ``fresh`` wins on anything it produces: it is the ground truth for this source tree
    right now, and the store may have been written against an older one. The store
    contributes exactly what a compiler cannot.

    A stored edge whose endpoint neither side supplies is dropped. On a store built from
    the same source that is the empty set; on a stale store it is the honest expression of
    a semantic fact that no longer has anything to attach to.
    """
    nodes: Dict[str, GraphNode] = {n["id"]: n for n in fresh.get("nodes", [])}
    for node in stored.get("nodes", []):
        nodes.setdefault(node["id"], node)

    seen: Set[Tuple[str, str, str, str]] = set()
    edges: List[GraphEdge] = []
    for edge in itertools.chain(fresh.get("edges", []), stored.get("edges", [])):
        if edge["source"] not in nodes or edge["target"] not in nodes:
            continue
        key = edge_identity(edge)
        if key in seen:
            continue
        seen.add(key)
        edges.append(edge)
    return {"nodes": list(nodes.values()), "edges": edges}
