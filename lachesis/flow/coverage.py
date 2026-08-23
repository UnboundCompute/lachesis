"""Deterministic source-rooted coverage scheduling for Pass 3.

The scheduler is deliberately independent of vulnerability patterns.  It answers
which externally reachable source cones must be explored to cover a selected
function, and records a stable state key that Claus can cache.
"""
from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Iterable, Mapping


@dataclass(frozen=True)
class CoverageRegion:
    target: str
    sources: tuple[str, ...]
    functions: tuple[str, ...]
    state_keys: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class CoveragePlan:
    regions: tuple[CoverageRegion, ...]
    covered_functions: frozenset[str]
    uncovered_functions: frozenset[str]

    def for_target(self, target: str) -> CoverageRegion | None:
        return next((region for region in self.regions if region.target == target), None)

    def to_dict(self) -> dict:
        return {
            "regions": [{"target": region.target, "sources": list(region.sources),
                         "functions": list(region.functions),
                         "state_keys": [list(key) for key in region.state_keys]}
                        for region in self.regions],
            "covered_functions": sorted(self.covered_functions),
            "uncovered_functions": sorted(self.uncovered_functions),
        }


class CoverageScheduler:
    """Backtrack from unresolved functions, then explore each source cone forward."""

    def __init__(self, functions: Mapping[str, Mapping], successors: Mapping[str, Iterable[str]]):
        self.functions = functions
        self.successors = {name: tuple(sorted(callee for callee in successors.get(name, ())
                                             if callee in functions))
                           for name in functions}
        reverse: dict[str, set[str]] = defaultdict(set)
        for caller, callees in self.successors.items():
            for callee in callees:
                reverse[callee].add(caller)
        self.reverse = {name: tuple(sorted(reverse.get(name, ()))) for name in functions}

    def _source_functions(self) -> tuple[str, ...]:
        sources = [name for name, record in self.functions.items()
                   if record.get("source_sites") or record.get("source_calls")]
        if sources:
            return tuple(sorted(sources))
        return tuple(sorted(name for name, record in self.functions.items()
                            if not record.get("callers")))

    def _backward_cone(self, target: str) -> set[str]:
        seen = {target}
        queue = deque([target])
        while queue:
            current = queue.popleft()
            for caller in self.reverse.get(current, ()):
                if caller not in seen:
                    seen.add(caller)
                    queue.append(caller)
        return seen

    def _forward_cone(self, source: str) -> set[str]:
        seen = {source}
        queue = deque([source])
        while queue:
            current = queue.popleft()
            for callee in self.successors.get(current, ()):
                if callee not in seen:
                    seen.add(callee)
                    queue.append(callee)
        return seen

    def plan(self, targets: Iterable[str] | None = None) -> CoveragePlan:
        selected = sorted(set(targets) if targets is not None else self.functions)
        source_functions = set(self._source_functions())
        regions = []
        covered = set()
        for target in selected:
            if target not in self.functions:
                continue
            backward = self._backward_cone(target)
            sources = tuple(sorted(source_functions & backward))
            # A callerless structural root is a valid deterministic fallback when
            # no catalog source lies on the backward cone.
            if not sources:
                sources = tuple(sorted(name for name in backward
                                       if not self.reverse.get(name)))
            forward = set()
            for source in sources:
                forward.update(self._forward_cone(source) & backward)
            if not forward and target in backward:
                forward.add(target)
            state_keys = tuple((function, source)
                               for source in sources for function in sorted(forward))
            regions.append(CoverageRegion(target, sources, tuple(sorted(forward)), state_keys))
            covered.update(forward)
        return CoveragePlan(tuple(regions), frozenset(covered),
                            frozenset(set(self.functions) - covered))

