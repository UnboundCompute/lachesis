"""Explicit Phase-1/Phase-3 boundary for semantic Claus fragments.

The original production path assembled fragments and selected source roots in one
large function.  This small store is intentionally boring: it gives callers a
stable place to cache and inspect a completed graph while keeping graph matching
downstream.  A future fragment serializer can replace the in-memory value without
changing the pipeline contract.
"""
from __future__ import annotations

from dataclasses import dataclass, field, fields, is_dataclass
from enum import Enum
import hashlib
import json
import os
from collections import defaultdict
from pathlib import Path
import tempfile
from typing import Any, Mapping

from .semantic_graph import SkeletonGraph
from lachesis.timeit import timeit


@dataclass
class FragmentStore:
    """Subsumption-keyed in-memory store for built semantic graphs."""

    _graphs: dict[tuple[Any, ...], SkeletonGraph] = field(default_factory=dict)
    _coverage_graphs: dict[
        tuple[Any, ...], list[tuple[frozenset[tuple], SkeletonGraph]]
    ] = field(default_factory=dict)
    covered_states: set[tuple[str, str]] = field(default_factory=set)
    covered_contexts: set[tuple[str, str, str]] = field(default_factory=set)
    _fingerprint_cache: dict[int, tuple[Any, str]] = field(default_factory=dict,
                                                          repr=False)

    @staticmethod
    def _coverage_key(coverage) -> tuple[tuple[str, str], ...]:
        if coverage is None:
            return ()
        if hasattr(coverage, "state_keys"):
            return tuple(sorted(tuple(key) for key in coverage.state_keys))
        if hasattr(coverage, "to_dict"):
            coverage = coverage.to_dict()
        return tuple(sorted(
            tuple(key) for key in coverage.get("state_keys", ())
        ))

    @staticmethod
    def _context_key(coverage) -> tuple[tuple[str, str, str], ...]:
        if coverage is None:
            return ()
        if hasattr(coverage, "context_keys"):
            return tuple(sorted(tuple(key) for key in coverage.context_keys))
        if hasattr(coverage, "to_dict"):
            coverage = coverage.to_dict()
        return tuple(sorted(tuple(key) for key in coverage.get("context_keys", ())))

    @classmethod
    def _coverage_signature(cls, coverage) -> frozenset[tuple]:
        return frozenset(
            [("state",) + key for key in cls._coverage_key(coverage)]
            + [("context",) + key for key in cls._context_key(coverage)]
        )

    def _fingerprint(self, value: Any) -> str:
        """Stable content identity for semantic inputs rebuilt by each pass."""
        # A single Pass 3 request validates the same large F-IR, summaries, and
        # state-artifact objects during snapshot restore, cache lookup, and put.
        # Keep the object alive alongside its digest so repeated validation does
        # not recursively normalize and JSON-encode millions of values.
        cache_key = id(value)
        cached = self._fingerprint_cache.get(cache_key)
        if cached is not None and cached[0] is value:
            return cached[1]

        def normalize(item):
            # State artifacts contain AbstractState/AnalysisResult instances whose
            # default repr includes insertion-ordered dicts and unordered sets.  The
            # same semantic analysis can therefore produce a different cache key
            # when summaries are rebuilt in another process.  Normalize the small
            # value protocol used by the analysis instead of falling back to repr.
            if item is None or isinstance(item, (str, int, float, bool)):
                return item
            if isinstance(item, Enum):
                return {"__enum__": f"{type(item).__qualname__}:{item.value}"}
            if isinstance(item, Mapping):
                if all(isinstance(key, str) for key in item):
                    return {"__mapping__": {
                        key: normalize(val) for key, val in item.items()
                    }}
                pairs = [(normalize(key), normalize(val))
                         for key, val in item.items()]
                pairs.sort(key=lambda pair: json.dumps(pair[0], sort_keys=True,
                                                        separators=(",", ":"),
                                                        default=str))
                return {"__mapping__": pairs}
            if isinstance(item, (set, frozenset)):
                values = [normalize(val) for val in item]
                if all(isinstance(val, (str, int, float, bool)) or val is None
                       for val in item):
                    values.sort(key=lambda val: (type(val).__name__, repr(val)))
                    return {"__set__": values}
                values.sort(key=lambda val: json.dumps(val, sort_keys=True,
                                                        separators=(",", ":"),
                                                        default=str))
                return {"__set__": values}
            if isinstance(item, (list, tuple)):
                return {"__tuple__": [normalize(val) for val in item]}
            if is_dataclass(item):
                return {"__type__": type(item).__qualname__,
                        "fields": {field.name: normalize(getattr(item, field.name))
                                   for field in fields(item)}}
            attrs = getattr(item, "__dict__", None)
            if attrs is not None:
                return {"__type__": type(item).__qualname__,
                        "attrs": normalize(attrs)}
            return {"__type__": type(item).__qualname__, "value": repr(item)}

        try:
            encoded = json.dumps(normalize(value), sort_keys=True,
                                 separators=(",", ":"))
        except (TypeError, ValueError):
            encoded = repr(value)
        digest = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
        self._fingerprint_cache[cache_key] = (value, digest)
        return digest

    def key(self, functions: Mapping[str, Mapping], lang: str, graph: Any = None,
            summaries: Any = None, coverage=None, reach_summaries: Any = None,
            state_artifacts: Any = None) -> tuple[Any, ...]:
        return self._base_key(functions, lang, graph, summaries, reach_summaries,
                              state_artifacts) + (
            self._coverage_key(coverage), self._context_key(coverage))

    def _base_key(self, functions: Mapping[str, Mapping], lang: str, graph: Any,
                  summaries: Any, reach_summaries: Any,
                  state_artifacts: Any = None) -> tuple[Any, ...]:
        graph_key = (self._fingerprint(graph)
                     if isinstance(graph, (dict, list, tuple)) else id(graph))
        return (lang, graph_key, self._fingerprint(functions),
                self._fingerprint(summaries),
                self._fingerprint(reach_summaries),
                self._fingerprint(state_artifacts))

    def get(self, functions: Mapping[str, Mapping], lang: str, graph: Any = None,
            summaries: Any = None, coverage=None, reach_summaries: Any = None,
            state_artifacts: Any = None):
        exact = self._graphs.get(self.key(functions, lang, graph, summaries, coverage,
                                           reach_summaries, state_artifacts))
        if exact is not None:
            return exact
        requested = self._coverage_signature(coverage)
        if not requested:
            return None
        base = self._base_key(functions, lang, graph, summaries, reach_summaries,
                              state_artifacts)
        # Reuse only a true source/state superset under identical semantic inputs.
        candidates = self._coverage_graphs.get(base, ())
        supersets = [(len(states), value) for states, value in candidates
                     if requested <= states]
        if supersets:
            return min(supersets, key=lambda item: item[0])[1]

        # Pass 3 may materialize source cones incrementally.  A collection of
        # partial graphs under the same semantic inputs is a valid cache hit if
        # their state sets cover the request; requiring one graph to be a
        # superset would throw away already-built regions and restart Claus.
        remaining = set(requested)
        selected: list[tuple[frozenset[tuple], SkeletonGraph]] = []
        available = list(candidates)
        while remaining and available:
            index, (states, value) = max(
                enumerate(available),
                key=lambda item: len(item[1][0] & remaining))
            gain = states & remaining
            if not gain:
                break
            selected.append((states, value))
            remaining -= gain
            available.pop(index)
        if remaining or not selected:
            return None
        graphs = [value for _states, value in selected]
        if len(graphs) == 1:
            return graphs[0]
        if all(isinstance(value, SkeletonGraph) for value in graphs):
            try:
                return self._merge_graphs(graphs)
            except ValueError:
                # A partial cache entry must never make Pass 3 fail.  The
                # caller will rebuild under the same semantic key, preserving
                # correctness when independently materialized fragments carry
                # incompatible structure.
                return None
        return None

    @staticmethod
    def _merge_graphs(graphs: list[SkeletonGraph]) -> SkeletonGraph:
        """Union compatible cached fragments without changing graph identity.

        Each graph was built from the same base cache key, so duplicate node ids
        represent the same semantic fact.  A conflicting duplicate is rejected
        rather than silently preferring one source-state projection.
        """
        merged = SkeletonGraph()
        for graph in graphs:
            if merged.language is None:
                merged.language = graph.language
            elif graph.language is not None and merged.language != graph.language:
                raise ValueError("incompatible cached graph languages")
            for node_id, node in graph.nodes.items():
                existing = merged.nodes.get(node_id)
                if existing is None:
                    merged.add_node(node_id, node.event, fragment=node.fragment,
                                    **node.metadata)
                elif (existing.event != node.event or
                      existing.fragment != node.fragment or
                      existing.metadata != node.metadata):
                    raise ValueError(f"incompatible cached node: {node_id}")
            for source, edges in graph.edges.items():
                for edge in edges:
                    if edge not in merged.edges.setdefault(source, []):
                        merged.edges[source].append(edge)
            for name, fragment in graph.fragments.items():
                existing = merged.fragments.get(name)
                if existing is None:
                    merged.add_fragment(name, fragment.entry, fragment.exits, fragment.params)
                elif (existing.entry != fragment.entry or
                      existing.params != fragment.params):
                    raise ValueError(f"incompatible cached fragment: {name}")
                else:
                    existing.exits.update(fragment.exits)
            merged.source_reachable.update(graph.source_reachable)
            merged.coverage.update(graph.coverage)
        merged.validate()
        return merged

    def put(self, functions: Mapping[str, Mapping], lang: str, graph: Any,
            semantic_graph: SkeletonGraph, summaries: Any = None,
            coverage=None, reach_summaries: Any = None,
            state_artifacts: Any = None) -> SkeletonGraph:
        self._graphs[self.key(functions, lang, graph, summaries, coverage,
                              reach_summaries, state_artifacts)] = semantic_graph
        base = self._base_key(functions, lang, graph, summaries, reach_summaries,
                              state_artifacts)
        states = self._coverage_signature(coverage)
        entries = self._coverage_graphs.setdefault(base, [])
        entries[:] = [(known, value) for known, value in entries
                      if known != states]
        entries.append((states, semantic_graph))
        return semantic_graph

    def mark_covered(self, state_keys) -> None:
        self.covered_states.update(tuple(key) for key in state_keys)

    def mark_contexts_covered(self, context_keys) -> None:
        self.covered_contexts.update(tuple(key) for key in context_keys)

    def uncovered(self, state_keys):
        return tuple(sorted(set(tuple(key) for key in state_keys) - self.covered_states))

    def uncovered_contexts(self, context_keys):
        return tuple(sorted(set(tuple(key) for key in context_keys) - self.covered_contexts))

    def coverage_snapshot(self) -> dict[str, list[list[str]]]:
        """Return a JSON-safe ledger of materialized source states and contexts."""
        return {
            "covered_states": [list(key) for key in sorted(self.covered_states)],
            "covered_contexts": [list(key) for key in sorted(self.covered_contexts)],
        }

    def snapshot(self) -> dict[str, Any]:
        """Export reusable semantic fragments and their coverage ledger.

        The snapshot contains no cache key guesswork: callers must provide the
        current semantic inputs to :meth:`restore_snapshot`, which recomputes
        the base key before accepting a fragment.  This prevents a graph from a
        different source revision or language from being treated as covered.
        """
        entries = []
        for base, candidates in self._coverage_graphs.items():
            for states, graph in candidates:
                if not isinstance(graph, SkeletonGraph):
                    continue
                state_keys = [list(key[1:]) for key in states if key and key[0] == "state"]
                context_keys = [list(key[1:]) for key in states if key and key[0] == "context"]
                entries.append({
                    "base_key": list(base),
                    "state_keys": state_keys,
                    "context_keys": context_keys,
                    "graph": graph.to_dict(),
                })
        return {"version": 1, "coverage": self.coverage_snapshot(),
                "fragments": entries}

    def restore_snapshot(self, payload: Mapping[str, Any], functions: Mapping[str, Mapping],
                         lang: str, graph: Any = None, summaries: Any = None,
                         reach_summaries: Any = None, state_artifacts: Any = None) -> int:
        """Restore only fragments matching the supplied semantic input identity.

        Returns the number of accepted fragments.  Invalid or incompatible
        fragments are rejected by the same graph validation and cache-key path
        used for live Claus builds; a stale snapshot is therefore a cache miss,
        never a source of fabricated coverage.
        """
        accepted = 0
        expected_base = self._base_key(functions, lang, graph, summaries,
                                       reach_summaries, state_artifacts)
        for entry in payload.get("fragments", ()) or ():
            # A persisted graph is useful only when its semantic-input identity
            # matches this restore session.  Never re-key an arbitrary stale
            # graph under the current program merely because its shape loads.
            if tuple(entry.get("base_key", ())) != expected_base:
                continue
            try:
                semantic = SkeletonGraph.from_dict(entry["graph"])
                coverage = {"state_keys": entry.get("state_keys", ()),
                            "context_keys": entry.get("context_keys", ())}
                self.put(functions, lang, graph, semantic, summaries, coverage,
                         reach_summaries, state_artifacts)
                # A matching semantic fingerprint proves only that the
                # snapshot was built from the same inputs.  It does not prove
                # that the serialized graph still contains every source-rooted
                # path it claims to cover. Reuse the live materialization
                # checks so a truncated or hand-edited sidecar cannot create a
                # false convergence result.
                materialized_states = Claus._materialized_states(
                    semantic, coverage["state_keys"])
                materialized_contexts = Claus._materialized_contexts(
                    semantic, coverage["context_keys"])
                self.mark_covered(materialized_states)
                self.mark_contexts_covered(materialized_contexts)
            except (KeyError, TypeError, ValueError):
                continue
            accepted += 1
        return accepted

    def save_snapshot(self, path: str | os.PathLike[str]) -> None:
        """Atomically write the reusable fragment snapshot to ``path``."""
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        handle = tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=destination.parent,
            prefix=f".{destination.name}.", suffix=".tmp", delete=False)
        temporary = Path(handle.name)
        try:
            with handle:
                json.dump(self.snapshot(), handle, sort_keys=True,
                          separators=(",", ":"))
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, destination)
        finally:
            if temporary.exists():
                temporary.unlink()

    def load_snapshot(self, path: str | os.PathLike[str], functions: Mapping[str, Mapping],
                      lang: str, graph: Any = None, summaries: Any = None,
                      reach_summaries: Any = None, state_artifacts: Any = None) -> int:
        """Load a sidecar snapshot, returning zero for absent/invalid data."""
        try:
            with Path(path).open(encoding="utf-8") as handle:
                payload = json.load(handle)
            if payload.get("version") != 1:
                return 0
            return self.restore_snapshot(payload, functions, lang, graph,
                                         summaries, reach_summaries, state_artifacts)
        except (OSError, TypeError, ValueError, json.JSONDecodeError):
            return 0

    def restore_coverage(self, snapshot: Mapping[str, Any]) -> None:
        """Restore only coverage facts; graph materialization remains independently verified."""
        for key in snapshot.get("covered_states", ()):
            if len(key) == 2:
                self.covered_states.add((str(key[0]), str(key[1])))
        for key in snapshot.get("covered_contexts", ()):
            if len(key) == 3:
                self.covered_contexts.add((str(key[0]), str(key[1]), str(key[2])))

    def pending(self, plan):
        """Return the next deterministic source-rooted regions still uncovered."""
        return plan.pending_regions(self.covered_states, self.covered_contexts)


class Claus:
    """Source-rooted Phase-3 driver over the existing semantic emitter."""

    def __init__(self, store: FragmentStore | None = None):
        self.fragments = store or FragmentStore()

    @staticmethod
    def _reachable_fragments(graph: SkeletonGraph, starts) -> set[str]:
        """Return fragments reachable by the matcher-compatible pushdown walk.

        Coverage commonly contains many target/source pairs sharing the same source.
        Walking the graph once per pair repeats the same call/return traversal; this
        keeps the full stack state in the visited key while sharing the result across
        all targets in that source cone.
        """
        queue = [(entry, ()) for entry in starts]
        seen = set(queue)
        reachable = set()
        while queue:
            node, stack = queue.pop()
            current = graph.nodes.get(node)
            if current is None:
                continue
            if current.fragment is not None:
                reachable.add(current.fragment)
            for edge in graph.edges.get(node, ()):
                next_stack = stack
                if edge.kind == "call":
                    if edge.return_to is None:
                        continue
                    next_stack = stack + (edge.return_to,)
                elif edge.kind == "return":
                    if not stack or edge.target != stack[-1]:
                        continue
                    next_stack = stack[:-1]
                state = (edge.target, next_stack)
                if state not in seen:
                    seen.add(state)
                    queue.append(state)
        return reachable

    @staticmethod
    @timeit(name="fragment_store.Claus._materialized_states")
    def _materialized_states(graph: SkeletonGraph, state_keys) -> list[tuple[str, str]]:
        """Keep only source states with a concrete graph path to their target.

        A fragment's existence is not enough evidence for a coverage state: the same
        function can be reached from several external roots with different object
        bindings.  The current graph representation does not yet serialize the full
        abstract state on each edge, but it does preserve source fragments and seam
        edges.  Requiring source-to-target reachability is therefore the strongest
        honest accounting available at this boundary and avoids claiming disconnected
        source cones were analysed.
        """
        materialized = []
        grouped: dict[str, list[tuple[str, str]]] = defaultdict(list)
        for key in state_keys:
            if len(key) != 2:
                continue
            target, source = key
            if source not in graph.fragments or target not in graph.fragments:
                continue
            grouped[source].append((target, source))
        for source, keys in grouped.items():
            source_fragment = graph.fragments[source]
            launch_nodes = sorted(
                node_id for node_id in graph.source_reachable
                if graph.nodes.get(node_id) is not None
                and graph.nodes[node_id].fragment == source)
            starts = launch_nodes or [source_fragment.entry]
            non_self = [key for key in keys if key[0] != source]
            if non_self:
                reachable = Claus._reachable_fragments(graph, starts)
                materialized.extend(key for key in non_self if key[0] in reachable)
            if launch_nodes or not graph.source_reachable:
                materialized.extend(key for key in keys if key[0] == source)
        return materialized

    @staticmethod
    @timeit(name="fragment_store.Claus._materialized_contexts")
    def _materialized_contexts(graph: SkeletonGraph, context_keys):
        """Prove source-site contexts using the same pushdown walk as states."""
        materialized = []
        grouped: dict[tuple[str, str], list[tuple[str, str, str]]] = defaultdict(list)
        for key in context_keys:
            if len(key) != 3:
                continue
            target, source, context = key
            if source not in graph.fragments or target not in graph.fragments:
                continue
            grouped[(source, context)].append((target, source, context))
        for (source, context), keys in grouped.items():
            source_fragment = graph.fragments[source]
            if context == "__entry__":
                starts = [source_fragment.entry]
            else:
                launch_nodes = [
                    node_id for node_id in graph.source_reachable
                    if graph.nodes.get(node_id) is not None
                    and graph.nodes[node_id].fragment == source
                ]
                explicit = [
                    node_id for node_id in launch_nodes
                    if str(graph.nodes[node_id].metadata.get("source_site", ""))
                    == str(context)
                ]
                if explicit:
                    starts = sorted(explicit)
                elif any("source_site" in graph.nodes[node_id].metadata
                         for node_id in launch_nodes):
                    starts = []
                else:
                    starts = sorted(node_id for node_id in launch_nodes if context in node_id)
                if not starts:
                    continue
            reachable = Claus._reachable_fragments(graph, starts)
            materialized.extend(key for key in keys if key[0] in reachable)
        return materialized

    @timeit(name="fragment_store.Claus._record_coverage")
    def _record_coverage(self, graph: SkeletonGraph, coverage) -> SkeletonGraph:
        """Attach honest coverage accounting to both fresh and cached graphs."""
        if coverage is None:
            return graph
        graph.coverage = coverage.to_dict() if hasattr(coverage, "to_dict") else dict(coverage)
        planned_keys = [tuple(key) for region in graph.coverage.get("regions", [])
                        for key in region.get("state_keys", [])]
        planned_contexts = [tuple(key) for region in graph.coverage.get("regions", [])
                            for key in region.get("context_keys", [])]
        # A plan describes work that should be attempted; it is not proof that
        # the graph contains it.  Reuse the same pushdown-aware materialization
        # check for cache hits and freshly emitted graphs.
        materialized = self._materialized_states(graph, planned_keys)
        materialized_contexts = self._materialized_contexts(graph, planned_contexts)
        self.fragments.mark_covered(materialized)
        self.fragments.mark_contexts_covered(materialized_contexts)
        pending = tuple(sorted(set(planned_keys) - set(materialized)))
        pending_contexts = tuple(sorted(set(planned_contexts) - set(materialized_contexts)))
        graph.coverage.update({
            "covered_states": [list(key) for key in sorted(self.fragments.covered_states)],
            "covered_contexts": [list(key) for key in sorted(self.fragments.covered_contexts)],
            "uncovered_states": [list(key) for key in pending],
            "uncovered_contexts": [list(key) for key in pending_contexts],
            "converged": not pending and not pending_contexts,
        })
        return graph

    @timeit
    def build(self, store, functions, successors, *, lang="c", graph=None, summaries=None,
              coverage=None, reach_summaries=None, state_artifacts=None, cfgs=None):
        cached = self.fragments.get(functions, lang, graph, summaries, coverage,
                                    reach_summaries, state_artifacts)
        if cached is not None:
            return self._record_coverage(cached, coverage)
        # A complete cache miss must rebuild the full semantic input.  When a
        # source-rooted plan is only partially materialized, however, hand the
        # emitter the deterministic pending cones so Claus can grow the cache
        # incrementally instead of rewalking every function.  The full
        # ``functions`` mapping remains part of the cache identity; only the
        # current materialization work item is narrowed.
        work_functions = None
        if coverage is not None and hasattr(coverage, "pending_regions"):
            pending = coverage.pending_regions(
                self.fragments.covered_states,
                self.fragments.covered_contexts,
            )
            if pending:
                work_functions = {
                    name
                    for region in pending
                    for name in (*region.sources, *region.functions)
                }
        from .emit import build_semantic_graph
        built = build_semantic_graph(store, functions, successors, lang=lang,
                                     graph=graph, summaries=summaries,
                                     reach_summaries=reach_summaries,
                                     state_artifacts=state_artifacts, cfgs=cfgs,
                                     work_functions=work_functions)
        self._record_coverage(built, coverage)
        return self.fragments.put(functions, lang, graph, built, summaries, coverage,
                                  reach_summaries, state_artifacts)
