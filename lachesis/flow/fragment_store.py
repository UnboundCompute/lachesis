"""Explicit Phase-1/Phase-3 boundary for semantic Claus fragments.

The original production path assembled fragments and selected source roots in one
large function.  This small store is intentionally boring: it gives callers a
stable place to cache and inspect a completed graph while keeping graph matching
downstream.  A future fragment serializer can replace the in-memory value without
changing the pipeline contract.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from .semantic_graph import SkeletonGraph


@dataclass
class FragmentStore:
    """Subsumption-keyed in-memory store for built semantic graphs."""

    _graphs: dict[tuple[Any, ...], SkeletonGraph] = field(default_factory=dict)
    covered_states: set[tuple[str, str]] = field(default_factory=set)

    def key(self, functions: Mapping[str, Mapping], lang: str, graph: Any = None,
            summaries: Any = None) -> tuple[Any, ...]:
        return (lang, id(graph), id(summaries), tuple(sorted(functions)))

    def get(self, functions: Mapping[str, Mapping], lang: str, graph: Any = None,
            summaries: Any = None):
        return self._graphs.get(self.key(functions, lang, graph, summaries))

    def put(self, functions: Mapping[str, Mapping], lang: str, graph: Any,
            semantic_graph: SkeletonGraph, summaries: Any = None) -> SkeletonGraph:
        self._graphs[self.key(functions, lang, graph, summaries)] = semantic_graph
        return semantic_graph

    def mark_covered(self, state_keys) -> None:
        self.covered_states.update(tuple(key) for key in state_keys)

    def uncovered(self, state_keys):
        return tuple(sorted(set(tuple(key) for key in state_keys) - self.covered_states))


class Claus:
    """Source-rooted Phase-3 driver over the existing semantic emitter."""

    def __init__(self, store: FragmentStore | None = None):
        self.fragments = store or FragmentStore()

    def build(self, store, functions, successors, *, lang="c", graph=None, summaries=None,
              coverage=None):
        cached = self.fragments.get(functions, lang, graph, summaries)
        if cached is not None:
            return cached
        from .emit import build_semantic_graph
        built = build_semantic_graph(store, functions, successors, lang=lang,
                                     graph=graph, summaries=summaries)
        if coverage is not None:
            built.coverage = coverage.to_dict() if hasattr(coverage, "to_dict") else dict(coverage)
            self.fragments.mark_covered(
                built.coverage.get("regions", [])
                and [key for region in built.coverage["regions"]
                     for key in region.get("state_keys", [])]
                or ())
        return self.fragments.put(functions, lang, graph, built, summaries)
