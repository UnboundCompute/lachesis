"""Phase-3 source discovery for the frozen flow skeleton.

Pass 2 gives us enriched function records and call argument identities.  This module performs
the small, explicit Phase-3 operation that was previously hidden inside ``is_source``: identify
external source sites, retain formal-to-actual bindings at every call seam, and expose the
source roots that Claus should launch from.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Mapping


@dataclass(frozen=True)
class SourceSite:
    function: str
    node: str | None
    callee: str | None
    line: int | None
    arguments: tuple[int | str, ...] = ()
    influenced_roots: tuple[str, ...] = ()
    kind: str = "external-input"


@dataclass(frozen=True)
class SeamBinding:
    caller: str
    callee: str
    call_node: str | None
    formal_to_actual: tuple[tuple[str, str], ...] = ()
    return_to: str | None = None


@dataclass
class SourceDiscovery:
    sites: tuple[SourceSite, ...] = ()
    bindings: tuple[SeamBinding, ...] = ()
    launch_nodes: dict[str, tuple[str, ...]] = field(default_factory=dict)
    reachable_functions: set[str] = field(default_factory=set)
    influenced_roots: dict[str, tuple[str, ...]] = field(default_factory=dict)

    def sites_for(self, function: str) -> tuple[SourceSite, ...]:
        return tuple(site for site in self.sites if site.function == function)


def discover_sources(F: Mapping[str, Mapping], succ: Mapping[str, Iterable[str]],
                    source_methods: Mapping[str, object] | Iterable[str] = ()) -> SourceDiscovery:
    """Discover source roots and formal/actual seam bindings from the enriched F IR.

    A source catalog entry is a callsite source.  When no catalog entry exists for a project,
    callerless functions remain structural launch roots for backwards-compatible coverage; they
    are marked as uninfluenced rather than pretending that every parameter is tainted.
    """
    methods = set(source_methods.keys()) if isinstance(source_methods, Mapping) else set(source_methods)
    sites: list[SourceSite] = []
    bindings: list[SeamBinding] = []
    launches: dict[str, list[str]] = {}
    influenced: dict[str, set[str]] = {function: set() for function in F}

    for caller, record in F.items():
        for call in record.get("calls", ()):
            callee = call.get("callee")
            args = tuple(arg for arg in call.get("args", ()) if arg.get("root"))
            formal_to_actual = []
            callee_record = F.get(callee, {})
            formals = tuple(callee_record.get("params", ()))
            for arg in args:
                pos = arg.get("pos")
                if isinstance(pos, int) and pos < len(formals):
                    formal_to_actual.append((str(formals[pos]), str(arg["root"])))
            if callee in F:
                bindings.append(SeamBinding(
                    caller=caller, callee=callee, call_node=call.get("node"),
                    formal_to_actual=tuple(formal_to_actual),
                    return_to=call.get("assigned")))
            if callee not in methods:
                continue
            roots = [call.get("assigned")]
            roots.extend(arg.get("root") for arg in args)
            roots = tuple(sorted({str(root) for root in roots if root}))
            influenced[caller].update(roots)
            spec = source_methods.get(callee) if isinstance(source_methods, Mapping) else None
            kind = spec.get("kind", "external-input") if isinstance(spec, Mapping) else "external-input"
            site = SourceSite(caller, call.get("node"), callee, call.get("line"),
                              tuple(arg.get("pos") for arg in args), roots, kind)
            sites.append(site)
            if call.get("node"):
                launches.setdefault(caller, []).append(call["node"])

    # Structural entries are a fallback only. Catalog-backed source sites remain the preferred
    # launch points and carry influence roots for Tier 1 ranking.
    for function, record in F.items():
        if function in launches:
            continue
        if not record.get("callers"):
            launches[function] = ["__entry__"]

    reachable = set(launches)
    work = list(reachable)
    while work:
        function = work.pop()
        for callee in succ.get(function, ()):
            if callee in F and callee not in reachable:
                reachable.add(callee)
                work.append(callee)

    # Propagate source influence through actual/formal seams and returned values.
    # Reachability is intentionally computed independently above: a reachable
    # callee may still have no influenced root and must remain Tier 2 coverage.
    changed = True
    while changed:
        changed = False
        for caller, record in F.items():
            for call in record.get("calls", ()):
                callee = call.get("callee")
                if callee not in F:
                    continue
                formals = tuple(F[callee].get("params", ()))
                for arg in call.get("args", ()):
                    actual = arg.get("root")
                    pos = arg.get("pos")
                    if actual in influenced.get(caller, set()) and isinstance(pos, int) and pos < len(formals):
                        formal = str(formals[pos])
                        if formal not in influenced[callee]:
                            influenced[callee].add(formal)
                            changed = True
                if call.get("assigned") and influenced.get(callee):
                    assigned = str(call["assigned"])
                    if assigned not in influenced[caller]:
                        influenced[caller].add(assigned)
                        changed = True

    return SourceDiscovery(tuple(sites), tuple(bindings),
                           {name: tuple(nodes) for name, nodes in launches.items()}, reachable,
                           {name: tuple(sorted(roots)) for name, roots in influenced.items()})
