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

    def key(self, functions: Mapping[str, Mapping], lang: str, graph: Any = None,
            summaries: Any = None, coverage=None) -> tuple[Any, ...]:
        return (lang, id(graph), id(summaries), tuple(sorted(functions)),
                self._coverage_key(coverage))

    def get(self, functions: Mapping[str, Mapping], lang: str, graph: Any = None,
            summaries: Any = None, coverage=None):
        return self._graphs.get(self.key(functions, lang, graph, summaries, coverage))

    def put(self, functions: Mapping[str, Mapping], lang: str, graph: Any,
            semantic_graph: SkeletonGraph, summaries: Any = None,
            coverage=None) -> SkeletonGraph:
        self._graphs[self.key(functions, lang, graph, summaries, coverage)] = semantic_graph
        return semantic_graph

    def mark_covered(self, state_keys) -> None:
        self.covered_states.update(tuple(key) for key in state_keys)

    def uncovered(self, state_keys):
        return tuple(sorted(set(tuple(key) for key in state_keys) - self.covered_states))

    def pending(self, plan):
        """Return the next deterministic source-rooted regions still uncovered."""
        return plan.pending_regions(self.covered_states)


class Claus:
    """Source-rooted Phase-3 driver over the existing semantic emitter."""

    def __init__(self, store: FragmentStore | None = None):
        self.fragments = store or FragmentStore()

    def build(self, store, functions, successors, *, lang="c", graph=None, summaries=None,
              coverage=None):
        cached = self.fragments.get(functions, lang, graph, summaries, coverage)
        if cached is not None:
            return cached
        from .emit import build_semantic_graph
        built = build_semantic_graph(store, functions, successors, lang=lang,
                                     graph=graph, summaries=summaries)
        if coverage is not None:
            built.coverage = coverage.to_dict() if hasattr(coverage, "to_dict") else dict(coverage)
            state_keys = [key for region in built.coverage.get("regions", [])
                          for key in region.get("state_keys", [])]
            self.fragments.mark_covered(state_keys)
            pending = self.fragments.uncovered(state_keys)
            built.coverage.update({
                "covered_states": [list(key) for key in sorted(self.fragments.covered_states)],
                "uncovered_states": [list(key) for key in pending],
                "converged": not pending,
            })
        return self.fragments.put(functions, lang, graph, built, summaries, coverage)
