"""Typed shape of a ``lachesis.toml`` project manifest.

A manifest is a per-target file, checked in beside the code, that declares *facts
about the project* so the analysis pipeline runs deterministically instead of
guessing.  Two blocks:

* ``project`` — facts about the code.  Every entry is a true statement that can, in
  principle, be checked against the graph (see :mod:`lachesis.manifest.validate`).
  Split into a *core* tier (things any maintainer knows: source layout, build
  variant, alloc/free vocabulary, trust boundaries) and an *advanced* tier (expert
  facts about hard internals: function contracts, aliasing, dispatch seams).
* ``analysis`` — run configuration (engine, caps, graph path).  Applied, not
  validated; every cap that drops coverage is reported by the runner.

The dataclasses here are pure data with no graph dependency; the loader
(:mod:`lachesis.manifest.loader`) builds them from parsed TOML and the rest of the
pipeline consumes them.  Leaf *facts* are frozen (hashable, comparable); the
container blocks are plain dataclasses so defaults compose cleanly.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Ownership(str, Enum):
    """What a function's return value obliges the caller to do."""

    OWNED = "owned"        # caller receives ownership and must free
    BORROWED = "borrowed"  # caller must NOT free (aliases live state)
    UNKNOWN = "unknown"


# --------------------------------------------------------------------------- #
# core tier — facts any maintainer can state in five minutes
# --------------------------------------------------------------------------- #
@dataclass
class Source:
    """Where the project's own code lives, and what to skip."""

    roots: tuple[str, ...] = ()
    exclude: tuple[str, ...] = ()


@dataclass
class Build:
    """The variant actually shipped, so the right branches are analyzed."""

    config: tuple[str, ...] = ()               # active #ifdef / feature flags
    include: tuple[str, ...] = ()              # header search paths
    defines: dict[str, object] = field(default_factory=dict)  # macro -> value


@dataclass
class Memory:
    """The project's allocation vocabulary (its custom alloc/free wrappers)."""

    alloc: tuple[str, ...] = ()
    free: tuple[str, ...] = ()


@dataclass(frozen=True)
class UntrustedInput:
    """A point where attacker-controlled data enters the program."""

    fn: str            # function that introduces the input
    at: str            # "return" | "argN" | a parameter name


@dataclass
class Surface:
    """Where execution starts and where the outside world touches the program."""

    entrypoints: tuple[str, ...] = ()
    untrusted: tuple[UntrustedInput, ...] = ()


@dataclass
class Trust:
    """Things the project has already made safe."""

    sanitizers: tuple[str, ...] = ()           # inputs through here are validated


# --------------------------------------------------------------------------- #
# advanced tier — expert facts about hard internals (all optional)
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class FunctionContract:
    """A behavioural summary a maintainer supplies for an opaque/cross-TU function.

    ``frees``/``allocs``/``uses`` are access paths rooted at a parameter, e.g.
    ``"arg0"`` or ``"arg0.data"``.  ``returns`` records return ownership.
    """

    name: str
    frees: tuple[str, ...] = ()
    allocs: tuple[str, ...] = ()
    uses: tuple[str, ...] = ()
    returns: Ownership = Ownership.UNKNOWN


@dataclass
class AliasFacts:
    """Heap facts the points-to model is too conservative to derive."""

    # each group is a set of access paths declared NOT to alias one another
    noalias: tuple[tuple[str, ...], ...] = ()


@dataclass
class ProjectFacts:
    """The ``[project]`` block: facts about the code, core + advanced tiers."""

    name: str = ""
    language: str = "c"
    # core
    source: Source = field(default_factory=Source)
    build: Build = field(default_factory=Build)
    memory: Memory = field(default_factory=Memory)
    surface: Surface = field(default_factory=Surface)
    trust: Trust = field(default_factory=Trust)
    # advanced
    functions: tuple[FunctionContract, ...] = ()
    alias: AliasFacts = field(default_factory=AliasFacts)
    dispatch: dict[str, str] = field(default_factory=dict)   # "struct.field" -> handler
    typedefs: dict[str, str] = field(default_factory=dict)   # alias -> concrete struct


# --------------------------------------------------------------------------- #
# run configuration — applied, not validated
# --------------------------------------------------------------------------- #
@dataclass
class AnalysisConfig:
    """The ``[analysis]`` block: how to run, not what the code is."""

    engine: str | None = None                  # lifetime engine, e.g. "object"
    graph: str | None = None                   # path to a prebuilt .kuzu, if any
    disjunct_cap: int | None = None            # object-state disjunct ceiling
    timeout_per_fn: float | None = None        # seconds; None = engine default


@dataclass
class Manifest:
    """A parsed ``lachesis.toml``: project facts plus run configuration."""

    project: ProjectFacts = field(default_factory=ProjectFacts)
    analysis: AnalysisConfig = field(default_factory=AnalysisConfig)
    path: str | None = None                    # source file, for diagnostics

    @property
    def is_empty(self) -> bool:
        """True when neither block declares anything (a no-op manifest)."""
        p, a = self.project, self.analysis
        return (
            not (p.name or p.source.roots or p.build.config or p.memory.alloc
                 or p.memory.free or p.surface.entrypoints or p.surface.untrusted
                 or p.trust.sanitizers or p.functions or p.alias.noalias
                 or p.dispatch or p.typedefs)
            and a == AnalysisConfig()
        )
