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
    context_keys: tuple[tuple[str, str, str], ...] = ()


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

    @property
    def context_keys(self) -> tuple[tuple[str, str, str], ...]:
        """Source-site-rooted contexts required by the region."""
        return tuple(sorted({key for region in self.regions for key in region.context_keys}))

    def pending_regions(self, covered_states: Iterable[tuple[str, str]] = (),
                        covered_contexts: Iterable[tuple[str, str, str]] | None = None) -> tuple[CoverageRegion, ...]:
        """Return regions whose source/state work has not been materialized yet.

        Coverage is keyed by ``(function, source)`` rather than by a function
        name alone: the same function may need separate exploration under
        different externally reachable object states.  This is the worklist
        boundary consumed by Claus/fragment stores.
        """
        covered = {tuple(key) for key in covered_states}
        contexts = ({tuple(key) for key in covered_contexts}
                    if covered_contexts is not None else None)
        return tuple(region for region in self.regions
                     if (any(tuple(key) not in covered for key in region.state_keys)
                         or (contexts is not None
                             and any(tuple(key) not in contexts for key in region.context_keys))))

    def converged(self, covered_states: Iterable[tuple[str, str]] = (),
                  covered_contexts: Iterable[tuple[str, str, str]] | None = None) -> bool:
        """Whether every planned source-rooted state has been materialized."""
        covered = {tuple(key) for key in covered_states}
        contexts = ({tuple(key) for key in covered_contexts}
                    if covered_contexts is not None else None)
        return (all(tuple(key) in covered for key in self.state_keys)
                and (contexts is None
                     or all(tuple(key) in contexts for key in self.context_keys)))

    def to_dict(self) -> dict:
        return {
            "regions": [{"target": region.target, "sources": list(region.sources),
                         "functions": list(region.functions),
                         "state_keys": [list(key) for key in region.state_keys],
                         "context_keys": [list(key) for key in region.context_keys]}
                        for region in self.regions],
            "covered_functions": sorted(self.covered_functions),
            "uncovered_functions": sorted(self.uncovered_functions),
            "state_keys": [list(key) for key in self.state_keys],
            "context_keys": [list(key) for key in self.context_keys],
        }


class CoverageScheduler:
    """Backtrack from unresolved functions, then explore each source cone forward."""

    def __init__(self, functions: Mapping[str, Mapping], successors: Mapping[str, Iterable[str]]):
        self.functions = functions
        normalized = {
            name: set(callee for callee in successors.get(name, ())
                      if callee in functions)
            for name in functions
        }
        # A callback target is a real source-rooted edge even when the
        # frontend's direct call graph records only the callback formal. Keep
        # this normalization at the scheduler boundary so every frontend and
        # every direct CoverageScheduler caller gets the same reachability
        # semantics as the semantic emitter.
        for caller, record in functions.items():
            for call in record.get("calls", ()):
                callee = call.get("callee")
                callee_record = functions.get(callee)
                if callee_record is None:
                    continue
                formals = tuple(callee_record.get("params", ()))
                for argument in call.get("args", ()):
                    position = argument.get("pos")
                    actual = argument.get("root")
                    if (isinstance(position, int) and position < len(formals)
                            and actual in functions and actual != callee):
                        normalized[caller].add(actual)
        self.successors = {
            name: tuple(sorted(callees)) for name, callees in normalized.items()
        }
        reverse: dict[str, set[str]] = defaultdict(set)
        for caller, callees in self.successors.items():
            for callee in callees:
                reverse[callee].add(caller)
        self.reverse = {name: tuple(sorted(reverse.get(name, ()))) for name in functions}

    def _source_functions(self) -> tuple[str, ...]:
        # Catalogued source sites and structural roots are both external launch
        # candidates.  A project can legitimately contain both: for example,
        # one entry point may read through a known library source while another
        # public entry has no catalogued source call at all.  Returning only the
        # catalogued set would silently make the second entry unreachable to
        # Pass 3 whenever the catalog is non-empty.
        sources = {
            name for name, record in self.functions.items()
            if record.get("source_sites") or record.get("source_calls")
        }
        # The successor relation is the scheduler's normalized whole-program
        # graph. Do not infer roots from an optional frontend ``callers`` field:
        # frontends are allowed to omit it, and treating every such function as
        # external would invent source states for callees that are reachable only
        # through another function.
        sources.update(name for name in self.functions
                       if not self.reverse.get(name))
        return tuple(sorted(sources))

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

    def _source_contexts(self, source: str) -> tuple[str, ...]:
        sites = self.functions.get(source, {}).get("source_sites", ())
        contexts = []
        for site in sites:
            token = site.get("node") or (
                f"{site.get('callee') or 'source'}@{site.get('line') or 0}")
            contexts.append(str(token))
        return tuple(sorted(set(contexts))) or ("__entry__",)

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
            context_keys = tuple(
                (function, source, context)
                for source in sources
                for context in self._source_contexts(source)
                for function in sorted(forward_by_source.get(source, ()))
            )
            regions.append(CoverageRegion(target, sources, tuple(sorted(forward)),
                                          state_keys, context_keys))
            covered.update(forward)
        return CoveragePlan(tuple(regions), frozenset(covered),
                            frozenset(set(self.functions) - covered))
