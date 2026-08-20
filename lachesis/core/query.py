"""Small indexes for overlays and ecosystem models over canonical graphs."""
from __future__ import annotations

from collections import defaultdict
from typing import Iterable, Optional

from ..indices import EXPORTS, build_callsite_index, build_decl_index, exported_ids


def _bucket_order(item: dict) -> tuple:
    """The order every bucket is kept in, node or edge.

    One key serves both because the two field sets do not overlap: a node answers to
    ``id`` and nothing else, an edge to ``kind``/``source``/``target``.
    """
    return (
        item.get("id", ""), item.get("kind", ""),
        item.get("source", ""), item.get("target", ""),
    )


class GraphIndex:
    """Six lookups over a canonical graph, each sorted the first time it is read.

    Population is eager and cheap. Sorting is neither, and it is what dominates: an
    index over the enriched graph spends most of its construction ordering buckets, and
    an overlay reads one or two of the six. The enrich path never reads ``by_label``,
    ``by_file`` or ``by_owner`` at all, yet paid to order them once per overlay, on a
    graph that grows as the overlays run. Sorting on first read charges each caller only
    for what it asks about, and charges it once.

    This is not a weaker guarantee. Every bucket a caller can observe is ordered exactly
    as before, since the only way to reach one is through the property that orders it.

    Buckets *are* written to after construction, by ``absorb``, which is what lets one
    index follow a fold instead of being rebuilt per overlay. A sort cannot go stale
    across that, because ``absorb`` re-orders exactly the buckets it appended to, and
    only among the collections a caller has already read. See ``absorb`` for why the
    resulting order is the same one a rebuild would have produced.
    """

    _COLLECTIONS = ("by_kind", "by_label", "by_file", "by_owner", "outgoing", "incoming")

    def __init__(self, graph: dict, *, compact: bool = False) -> None:
        self._compact = compact
        self.nodes = {node["id"]: node for node in graph.get("nodes", [])}
        active = ("by_kind", "outgoing", "incoming") if compact else self._COLLECTIONS
        self._buckets = {name: defaultdict(list) for name in active}
        for node in self.nodes.values():
            self._file_node(node)
        for edge in graph.get("edges", []):
            self._file_edge(edge)

    def _file_node(self, node: dict) -> None:
        self._buckets["by_kind"][node.get("kind")].append(node)
        if "by_label" not in self._buckets:
            return
        self._buckets["by_label"][node.get("label")].append(node)
        properties = node.get("properties", {})
        path = properties.get("absolute_file") or properties.get("file")
        if path:
            self._buckets["by_file"][path].append(node)
        owner = properties.get("owner_function_id") or properties.get("function_id")
        if owner:
            self._buckets["by_owner"][owner].append(node)

    def _file_edge(self, edge: dict) -> None:
        self._buckets["outgoing"][edge["source"]].append(edge)
        self._buckets["incoming"][edge["target"]].append(edge)

    def absorb(self, nodes: Iterable[dict], edges: Iterable[dict]) -> None:
        """Take in the facts one overlay added, so this index keeps describing the fold.

        Every overlay in a registry fold used to build its own index over a graph that
        grows as the fold proceeds, so the eighth overlay paid to index the first seven's
        output from scratch. Following the fold instead costs each overlay its own delta.

        The order a caller observes is the order a rebuild would have produced, and for
        two different reasons. Node buckets are keyed by a unique id, so ``_bucket_order``
        is a total order over them and insertion order cannot survive the sort. Edge
        buckets can tie -- two edges may agree on kind, source and target and differ only
        in properties -- and there the tie is broken by position, so what matters is that
        edges arrive here in the same sequence a rebuilt index would have walked them.
        They do: a rebuild reads ``GraphAccumulator.view()``, whose edge list is a stable
        sort of seed-then-delta-by-delta arrival, which is exactly the sequence the fold
        hands to ``absorb``.

        Only collections that have already been read need re-ordering, and only at the
        keys this call touched. An unread collection is left alone because ``__getattr__``
        has not sorted it yet and will sort all of it on first read.
        """
        touched: dict[str, set] = {name: set() for name in self._COLLECTIONS}
        for node in nodes:
            if node["id"] in self.nodes:
                continue
            self.nodes[node["id"]] = node
            self._file_node(node)
            properties = node.get("properties", {})
            touched["by_kind"].add(node.get("kind"))
            touched["by_label"].add(node.get("label"))
            path = properties.get("absolute_file") or properties.get("file")
            if path:
                touched["by_file"].add(path)
            owner = properties.get("owner_function_id") or properties.get("function_id")
            if owner:
                touched["by_owner"].add(owner)
        for edge in edges:
            self._file_edge(edge)
            touched["outgoing"].add(edge["source"])
            touched["incoming"].add(edge["target"])
        for name, keys in touched.items():
            if not keys or name not in self._buckets:
                continue
            bucket = self._buckets[name]
            for key in keys:
                bucket[key].sort(key=_bucket_order)
        self._drop_indices()

    def decl_index(self, name: str | None = None):
        """Declarations by name — the same map a Kùzu store persists as ``DeclIndex``.

        Built from ``lachesis.indices``, so this and the store answer the same question
        with the same code and the parity test covers both for free. Held after the
        first call, because resolution asks this once per call site and building it
        walks every node.
        """
        if "_decl_index" not in self.__dict__:
            self._decl_index = build_decl_index(
                self.nodes.values(), exported_ids(self.edges_of_kind(EXPORTS)))
        return self._decl_index if name is None \
            else tuple(self._decl_index.get(name, ()))

    def callsite_index(self, name: str | None = None):
        """Call sites by the name they call — the store's ``CallsiteIndex``."""
        if "_callsite_index" not in self.__dict__:
            self._callsite_index = build_callsite_index(self.nodes.values())
        return self._callsite_index if name is None \
            else tuple(self._callsite_index.get(name, ()))

    def _drop_indices(self) -> None:
        """Forget the name indices, because the graph they described just grew.

        Overlays add call sites and MAY_INVOKE edges, so an index memoized before a
        fold and read after it would be a confident answer about an older graph — the
        one failure mode worth more than the rebuild it costs to avoid.
        """
        self.__dict__.pop("_decl_index", None)
        self.__dict__.pop("_callsite_index", None)

    def has_kind(self, *kinds: str) -> bool:
        """Whether any node of these kinds exists, without ordering anything.

        ``applies`` is a predicate, and a predicate that reaches for ``by_kind`` through
        the sorting property charges a whole sort to answer a yes/no question -- for
        every overlay in the fold, including the ones that then decline to run.
        """
        return any(self._buckets["by_kind"].get(kind) for kind in kinds)

    def __getattr__(self, name: str):
        """Order a bucket on its first mention and then get out of the way.

        ``__getattr__`` runs only when normal lookup fails, so binding the ordered
        collection onto the instance here means this is consulted once per collection
        per index. Everything after that is a plain attribute read, which matters
        because ``targets`` and ``outgoing_of_kind`` reach for ``outgoing`` inside loops
        that run millions of times per enrich; a property would tax every one of them.
        """
        if name not in self._COLLECTIONS:
            raise AttributeError(
                f"{type(self).__name__!r} object has no attribute {name!r}"
            )
        collection = self._buckets.get(name)
        if collection is None:
            # Compact enrichment indexes defer navigation-only node buckets until
            # a caller actually asks for one. This preserves the public API while
            # avoiding three extra references per node during pass 3.
            collection = defaultdict(list)
            if name == "by_label":
                for node in self.nodes.values():
                    collection[node.get("label")].append(node)
            elif name == "by_file":
                for node in self.nodes.values():
                    properties = node.get("properties", {})
                    path = properties.get("absolute_file") or properties.get("file")
                    if path:
                        collection[path].append(node)
            elif name == "by_owner":
                for node in self.nodes.values():
                    properties = node.get("properties", {})
                    owner = properties.get("owner_function_id") or properties.get("function_id")
                    if owner:
                        collection[owner].append(node)
            else:
                raise AttributeError(
                    f"{type(self).__name__!r} has no bucket {name!r}"
                )
            self._buckets[name] = collection
        for values in collection.values():
            values.sort(key=_bucket_order)
        setattr(self, name, collection)
        return collection

    def nodes_of_kind(self, *kinds: str) -> Iterable[dict]:
        return (
            node for kind in kinds for node in self.by_kind.get(kind, ())
        )

    def degrees(self) -> dict:
        """``{node_id: outgoing + incoming}`` for every node that has an edge.

        Trivial here -- the adjacency is already in memory and this is two dict walks.
        It exists so callers can ask one question instead of branching on which index
        they hold: the Kùzu side answers the same question with two aggregate scans
        rather than two queries per node, and that difference is seconds.

        Read straight out of ``_buckets`` because the order within a bucket cannot
        change its length, and going through the sorting ``__getattr__`` would charge a
        full sort of every adjacency list to compute a count.
        """
        degree: dict = {}
        for bucket in ("outgoing", "incoming"):
            for node_id, edges in self._buckets[bucket].items():
                degree[node_id] = degree.get(node_id, 0) + len(edges)
        return degree

    def nodes_named(self, label: str) -> tuple[dict, ...]:
        return tuple(self.by_label.get(label, ()))

    def nodes_in_file(self, path: str) -> tuple[dict, ...]:
        return tuple(self.by_file.get(path, ()))

    def nodes_owned_by(self, owner_id: str, *kinds: str) -> tuple[dict, ...]:
        """The nodes a declaration owns, optionally narrowed to some kinds first.

        The narrowing buys nothing here -- the nodes are already dicts in memory and the
        filter is the same either way. It exists because on the Kùzu side the kind is
        known before the node is fetched, so passing it lets that index skip fetching
        the body nodes a caller was only going to discard.
        """
        owned = self.by_owner.get(owner_id, ())
        if kinds:
            accepted = frozenset(kinds)
            return tuple(node for node in owned if node.get("kind") in accepted)
        return tuple(owned)

    @staticmethod
    def semantic_edge_kind(edge: dict) -> str | None:
        """Return the relationship represented by a tier drill edge.

        Frontend snapshots serialize cross-tier structural facts as
        ``EXPANDS_TO`` and retain their canonical relationship in ``via``.
        Overlays should not need to know which tiers happened to contain the
        endpoints, so query matching treats that value as the semantic kind.
        """
        if edge.get("kind") == "EXPANDS_TO":
            return edge.get("properties", {}).get("via") or "EXPANDS_TO"
        return edge.get("kind")

    def edges_of_kind(self, *edge_kinds: str) -> Iterable[dict]:
        accepted = frozenset(edge_kinds)
        for edges in self.outgoing.values():
            for edge in edges:
                if edge.get("kind") in accepted or self.semantic_edge_kind(edge) in accepted:
                    yield edge

    def flow_edges(self, kinds) -> list[dict]:
        """All edges whose *semantic* kind is in ``kinds`` — the single adjacency
        source ``Reachability._build`` consumes. Filtering here (instead of inline in
        the BFS) lets a disk-backed index answer it with one query while the JSON index
        keeps today's exact iteration order (``outgoing`` insertion order, inner lists
        pre-sorted), so the value-flow closure is unchanged."""
        accepted = frozenset(kinds)
        return [
            edge
            for edges in self.outgoing.values()
            for edge in edges
            if self.semantic_edge_kind(edge) in accepted
        ]

    def targets(self, source: str, *edge_kinds: str) -> Iterable[dict]:
        accepted = frozenset(edge_kinds)
        for edge in self.outgoing.get(source, []):
            if (edge.get("kind") in accepted or self.semantic_edge_kind(edge) in accepted) \
                    and edge.get("target") in self.nodes:
                yield self.nodes[edge["target"]]

    def sources(self, target: str, *edge_kinds: str) -> Iterable[dict]:
        accepted = frozenset(edge_kinds)
        for edge in self.incoming.get(target, []):
            if (edge.get("kind") in accepted or self.semantic_edge_kind(edge) in accepted) \
                    and edge.get("source") in self.nodes:
                yield self.nodes[edge["source"]]

    def outgoing_of_kind(self, source: str, *edge_kinds: str) -> tuple[dict, ...]:
        accepted = frozenset(edge_kinds)
        return tuple(
            edge for edge in self.outgoing.get(source, ())
            if edge.get("kind") in accepted or self.semantic_edge_kind(edge) in accepted
        )

    def incoming_of_kind(self, target: str, *edge_kinds: str) -> tuple[dict, ...]:
        accepted = frozenset(edge_kinds)
        return tuple(
            edge for edge in self.incoming.get(target, ())
            if edge.get("kind") in accepted or self.semantic_edge_kind(edge) in accepted
        )

    def first_target(self, source: str, *edge_kinds: str) -> Optional[dict]:
        return next(iter(self.targets(source, *edge_kinds)), None)

    def package_inventory(self) -> frozenset[str]:
        return frozenset(
            node.get("properties", {}).get("package_name") or node.get("label")
            for node in self.nodes_of_kind("package")
            if node.get("properties", {}).get("package_name") or node.get("label")
        )
