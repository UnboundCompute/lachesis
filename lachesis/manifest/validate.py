"""Check a manifest's *facts* against the graph — the anti-gaming keystone.

Every ``[project]`` entry is a statement about the code, so it can be checked where
the graph can see the truth.  This module resolves each declared symbol and sorts it
into three honest buckets:

* **validated** — the symbol is defined in the graph, with the expected kind.  The
  fact is grounded.
* **external** — the graph knows the symbol only as a declaration with no body
  (a cross-TU or library function).  It *cannot* be verified — which is exactly what
  the manifest exists to supply — so it is accepted quietly but counted.
* **warning** — the symbol does not resolve at all, or resolves only to the wrong
  kind (a ``free`` name that is actually a variable, a ``typedef`` target that is not
  a type).  This is the typo / stale-manifest signal.

The distinction between *external* and *warning* is what keeps the check honest: a
name the graph has never heard of is a probable mistake; a name it knows but cannot
open is a legitimate declared fact.  Only warnings are surfaced as problems.

Scope of P2: existence and kind.  The deeper semantic contradiction — "you declared
this frees, but its body never frees" — needs the object solver's per-function
effects and is checked in P3, where those effects are already computed.  Access-path
facts (``frees = ["arg0.data"]``, ``noalias``) and non-symbol facts (build flags,
source roots) are not symbol lookups and are left to their consuming stages.

Depends only on ``store.resolve(name) -> list[entry]``; any object exposing that
works (the real :class:`GraphStore`, or a stub in tests).
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .schema import Manifest

FUNCTION_KINDS = frozenset({"function", "method"})
TYPE_KINDS = frozenset({"struct", "union", "enum", "class", "typedef", "type", "interface"})


class Status(str, Enum):
    VALIDATED = "validated"
    EXTERNAL = "external"
    WARNING = "warning"


@dataclass(frozen=True)
class FactCheck:
    """The outcome of checking one declared symbol against the graph."""

    location: str      # dotted manifest location, e.g. "project.memory.free"
    symbol: str        # the declared name
    status: Status
    detail: str        # human-readable explanation

    def __str__(self) -> str:
        mark = {Status.VALIDATED: "✓", Status.EXTERNAL: "~", Status.WARNING: "!"}
        return f"  {mark[self.status]} {self.location} '{self.symbol}' — {self.detail}"


@dataclass
class ManifestReport:
    """The verdict over every symbol a manifest declares."""

    checks: tuple[FactCheck, ...] = ()

    @property
    def validated(self) -> tuple[FactCheck, ...]:
        return tuple(c for c in self.checks if c.status is Status.VALIDATED)

    @property
    def external(self) -> tuple[FactCheck, ...]:
        return tuple(c for c in self.checks if c.status is Status.EXTERNAL)

    @property
    def warnings(self) -> tuple[FactCheck, ...]:
        return tuple(c for c in self.checks if c.status is Status.WARNING)

    @property
    def ok(self) -> bool:
        """True when no declared fact contradicts the graph."""
        return not self.warnings

    def format(self) -> str:
        if not self.checks:
            return "manifest: no symbol facts to validate"
        lines = [
            f"manifest validation: {len(self.validated)} grounded, "
            f"{len(self.external)} external (unverifiable), "
            f"{len(self.warnings)} warning(s)"
        ]
        # warnings first — they are what a reader must act on
        for c in (*self.warnings, *self.external, *self.validated):
            lines.append(str(c))
        return "\n".join(lines)


# --------------------------------------------------------------------------- #
def _exact(store, name: str) -> list[dict]:
    """Candidates whose name matches *name* exactly (resolve() also fuzzes)."""
    return [e for e in store.resolve(name) if e.get("name") == name]


def _classify(store, name: str, kinds: frozenset[str]) -> tuple[Status, str]:
    cands = _exact(store, name)
    if not cands:
        return Status.WARNING, "no such symbol in the graph (typo or stale?)"

    typed = [e for e in cands if e.get("kind") in kinds]
    if not typed:
        found = sorted({str(e.get("kind")) for e in cands})
        want = "function" if kinds is FUNCTION_KINDS else "type"
        return Status.WARNING, f"resolves only to kind(s) {found}, expected a {want}"

    defined = [e for e in typed if not e.get("declaration_only")]
    if defined:
        e = defined[0]
        where = f"{e.get('file')}:{e.get('line')}" if e.get("file") else "graph"
        return Status.VALIDATED, f"defined ({e.get('kind')}) at {where}"

    # known to the graph but only as a bodiless declaration — the manifest's job
    return Status.EXTERNAL, "declared-only in graph (no body to verify)"


def _check(store, checks: list, location: str, name: str, kinds: frozenset[str]) -> None:
    status, detail = _classify(store, name, kinds)
    checks.append(FactCheck(location=location, symbol=name, status=status, detail=detail))


def validate_manifest(manifest: Manifest, store) -> ManifestReport:
    """Resolve every declared symbol in *manifest* against *store*."""
    p = manifest.project
    checks: list[FactCheck] = []

    for name in p.memory.alloc:
        _check(store, checks, "project.memory.alloc", name, FUNCTION_KINDS)
    for name in p.memory.free:
        _check(store, checks, "project.memory.free", name, FUNCTION_KINDS)
    for name in p.surface.entrypoints:
        _check(store, checks, "project.surface.entrypoints", name, FUNCTION_KINDS)
    for u in p.surface.untrusted:
        _check(store, checks, "project.surface.untrusted", u.fn, FUNCTION_KINDS)
    for name in p.trust.sanitizers:
        _check(store, checks, "project.trust.sanitizers", name, FUNCTION_KINDS)
    for fc in p.functions:
        _check(store, checks, "project.functions", fc.name, FUNCTION_KINDS)
    for field, handler in p.dispatch.items():
        # the seam target must be a real function; the "struct.field" key is a
        # structural fact checked more deeply once the seam binder consumes it.
        _check(store, checks, f"project.dispatch[{field}]", handler, FUNCTION_KINDS)
    for alias, struct in p.typedefs.items():
        _check(store, checks, f"project.typedefs[{alias}]", struct, TYPE_KINDS)

    return ManifestReport(checks=tuple(checks))


def validate_contract_effects(manifest: Manifest, summaries) -> ManifestReport:
    """Warn when a body-visible function contract claims a free the solver never saw.

    Opaque functions are intentionally absent from ``summaries`` and remain unverifiable.
    For a visible body we keep the check conservative: any observed free effect satisfies
    the declaration.  Exact access-path equivalence is a deeper claim than the current
    summary representation can prove reliably.
    """
    checks = []
    for contract in manifest.project.functions:
        if not contract.frees or contract.name not in summaries:
            continue
        alternatives = summaries.get(contract.name) or ()
        observed = any(
            getattr(getattr(effect, "kind", None), "value",
                    getattr(effect, "kind", None)) == "free"
            for alternative in alternatives for effect in alternative
        )
        if not observed:
            checks.append(FactCheck(
                location=f"project.functions.{contract.name}.frees",
                symbol=contract.name,
                status=Status.WARNING,
                detail="contract declares a free, but the analyzed body has no free effect",
            ))
    return ManifestReport(checks=tuple(checks))
