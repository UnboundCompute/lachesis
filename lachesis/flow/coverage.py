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

    @property
    def state_keys(self) -> tuple[tuple[str, str], ...]:
        """All source-rooted semantic states this plan requires, deterministically."""
        return tuple(sorted({key for region in self.regions for key in region.state_keys}))

    def pending_regions(self, covered_states: Iterable[tuple[str, str]] = ()) -> tuple[CoverageRegion, ...]:
        """Return regions whose source/state work has not been materialized yet.

        Coverage is keyed by ``(function, source)`` rather than by a function
        name alone: the same function may need separate exploration under
        different externally reachable object states.  This is the worklist
        boundary consumed by Claus/fragment stores.
        """
        covered = {tuple(key) for key in covered_states}
        return tuple(region for region in self.regions
                     if any(tuple(key) not in covered for key in region.state_keys))

    def converged(self, covered_states: Iterable[tuple[str, str]] = ()) -> bool:
        """Whether every planned source-rooted state has been materialized."""
        covered = {tuple(key) for key in covered_states}
        return all(tuple(key) in covered for key in self.state_keys)

    def to_dict(self) -> dict:
        return {
            "regions": [{"target": region.target, "sources": list(region.sources),
                         "functions": list(region.functions),
                         "state_keys": [list(key) for key in region.state_keys]}
                        for region in self.regions],
            "covered_functions": sorted(self.covered_functions),
            "uncovered_functions": sorted(self.uncovered_functions),
            "state_keys": [list(key) for key in self.state_keys],
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
            # Keep each source cone separate.  Unioning the cones first and then
            # pairing that union with every source invents impossible states when
            # two external roots reach different parts of the same backward cone
            # (for example, ``(callee, source_a)`` where only source_b reaches the
            # callee).  Pass 3 coverage is source-rooted, so the state key must
            # preserve that relation all the way into Claus's cache.
            forward_by_source = {
                source: self._forward_cone(source) & backward
                for source in sources
            }
            if not any(forward_by_source.values()) and target in backward:
                # A target with no graph successor from its selected structural
                # root remains an explicit unresolved state rather than silently
                # disappearing from the plan.
                fallback_source = sources[0] if sources else target
                forward_by_source.setdefault(fallback_source, set()).add(target)
            forward = set().union(*forward_by_source.values()) if forward_by_source else set()
            state_keys = tuple(
                (function, source)
                for source in sources
                for function in sorted(forward_by_source.get(source, ()))
            )
            regions.append(CoverageRegion(target, sources, tuple(sorted(forward)), state_keys))
            covered.update(forward)
        return CoveragePlan(tuple(regions), frozenset(covered),
                            frozenset(set(self.functions) - covered))
