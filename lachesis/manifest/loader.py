"""Load and validate a ``lachesis.toml`` manifest.

Parsing is deliberately strict: an unknown key or a wrong-typed value raises
:class:`ManifestError` naming the offending path.  A manifest is a *facts* file that
silently changes what the analysis sees, so a typo (``fre`` for ``free``) must fail
loudly rather than drop a fact without a trace.

TOML is read with the standard library ``tomllib`` (Python 3.11+); on 3.10 the
``tomli`` backport is used if installed.  The import is lazy so that importing this
package never forces a 3.11 floor on the rest of lachesis — only *using* a manifest
does.
"""
from __future__ import annotations

from pathlib import Path

from .schema import (
    AliasFacts,
    AnalysisConfig,
    Build,
    FunctionContract,
    Manifest,
    Memory,
    Ownership,
    ProjectFacts,
    Source,
    Surface,
    Trust,
    UntrustedInput,
)

MANIFEST_NAME = "lachesis.toml"


class ManifestError(ValueError):
    """A manifest that is present but malformed (unknown key, wrong type, ...)."""


# --------------------------------------------------------------------------- #
# TOML backend (lazy)
# --------------------------------------------------------------------------- #
def _read_toml(path: Path) -> dict:
    try:
        import tomllib as _toml  # py3.11+
    except ModuleNotFoundError:  # pragma: no cover - exercised on 3.10 only
        try:
            import tomli as _toml  # backport
        except ModuleNotFoundError:
            raise ManifestError(
                "reading a manifest needs Python 3.11+ (stdlib tomllib) or the "
                "'tomli' backport on 3.10; neither is importable"
            )
    try:
        with open(path, "rb") as fh:
            return _toml.load(fh)
    except OSError as exc:
        raise ManifestError(f"cannot read {path}: {exc}") from exc
    except Exception as exc:  # tomllib.TOMLDecodeError and friends
        raise ManifestError(f"{path}: invalid TOML: {exc}") from exc


# --------------------------------------------------------------------------- #
# small typed extractors (all raise ManifestError with the dotted key path)
# --------------------------------------------------------------------------- #
def _reject_unknown(table: dict, allowed: set[str], where: str) -> None:
    extra = sorted(set(table) - allowed)
    if extra:
        raise ManifestError(
            f"{where}: unknown key(s) {extra}; allowed: {sorted(allowed)}"
        )


def _table(value, where: str) -> dict:
    if not isinstance(value, dict):
        raise ManifestError(f"{where}: expected a table, got {type(value).__name__}")
    return value


def _str(value, where: str) -> str:
    if not isinstance(value, str):
        raise ManifestError(f"{where}: expected a string, got {type(value).__name__}")
    return value


def _str_list(value, where: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
        raise ManifestError(f"{where}: expected a list of strings")
    return tuple(value)


def _int(value, where: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ManifestError(f"{where}: expected an integer, got {type(value).__name__}")
    return value


def _duration_seconds(value, where: str) -> float:
    """Accept a number of seconds or a string like ``"30s"`` / ``"5m"``."""
    if isinstance(value, bool):
        raise ManifestError(f"{where}: expected a duration, got a boolean")
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        units = {"s": 1.0, "m": 60.0, "h": 3600.0, "ms": 0.001}
        text = value.strip()
        for suffix, scale in sorted(units.items(), key=lambda kv: -len(kv[0])):
            if text.endswith(suffix):
                try:
                    return float(text[: -len(suffix)]) * scale
                except ValueError:
                    break
        try:
            return float(text)
        except ValueError:
            pass
    raise ManifestError(f"{where}: expected a duration (seconds or '30s'/'5m')")


# --------------------------------------------------------------------------- #
# block parsers
# --------------------------------------------------------------------------- #
def _parse_source(t: dict) -> Source:
    _reject_unknown(t, {"roots", "exclude"}, "project.source")
    return Source(
        roots=_str_list(t.get("roots", []), "project.source.roots"),
        exclude=_str_list(t.get("exclude", []), "project.source.exclude"),
    )


def _parse_build(t: dict) -> Build:
    _reject_unknown(t, {"config", "include", "defines"}, "project.build")
    defines = _table(t.get("defines", {}), "project.build.defines")
    return Build(
        config=_str_list(t.get("config", []), "project.build.config"),
        include=_str_list(t.get("include", []), "project.build.include"),
        defines=dict(defines),
    )


def _parse_memory(t: dict) -> Memory:
    _reject_unknown(t, {"alloc", "free"}, "project.memory")
    return Memory(
        alloc=_str_list(t.get("alloc", []), "project.memory.alloc"),
        free=_str_list(t.get("free", []), "project.memory.free"),
    )


def _parse_surface(t: dict) -> Surface:
    _reject_unknown(t, {"entrypoints", "untrusted"}, "project.surface")
    raw = t.get("untrusted", [])
    if not isinstance(raw, list):
        raise ManifestError("project.surface.untrusted: expected an array of tables")
    untrusted = []
    for i, item in enumerate(raw):
        where = f"project.surface.untrusted[{i}]"
        item = _table(item, where)
        _reject_unknown(item, {"fn", "at"}, where)
        if "fn" not in item or "at" not in item:
            raise ManifestError(f"{where}: requires both 'fn' and 'at'")
        untrusted.append(
            UntrustedInput(fn=_str(item["fn"], f"{where}.fn"),
                           at=_str(item["at"], f"{where}.at"))
        )
    return Surface(
        entrypoints=_str_list(t.get("entrypoints", []), "project.surface.entrypoints"),
        untrusted=tuple(untrusted),
    )


def _parse_trust(t: dict) -> Trust:
    _reject_unknown(t, {"sanitizers"}, "project.trust")
    return Trust(sanitizers=_str_list(t.get("sanitizers", []), "project.trust.sanitizers"))


def _parse_functions(t: dict) -> tuple[FunctionContract, ...]:
    out = []
    for name, spec in t.items():
        where = f"project.functions.{name}"
        spec = _table(spec, where)
        _reject_unknown(spec, {"frees", "allocs", "uses", "returns"}, where)
        ret_raw = spec.get("returns", "unknown")
        try:
            returns = Ownership(_str(ret_raw, f"{where}.returns"))
        except ValueError:
            raise ManifestError(
                f"{where}.returns: expected one of "
                f"{[o.value for o in Ownership]}, got {ret_raw!r}"
            )
        out.append(
            FunctionContract(
                name=name,
                frees=_str_list(spec.get("frees", []), f"{where}.frees"),
                allocs=_str_list(spec.get("allocs", []), f"{where}.allocs"),
                uses=_str_list(spec.get("uses", []), f"{where}.uses"),
                returns=returns,
            )
        )
    return tuple(out)


def _parse_alias(t: dict) -> AliasFacts:
    _reject_unknown(t, {"noalias"}, "project.alias")
    raw = t.get("noalias", [])
    if not isinstance(raw, list):
        raise ManifestError("project.alias.noalias: expected a list of groups")
    groups = tuple(
        _str_list(g, f"project.alias.noalias[{i}]") for i, g in enumerate(raw)
    )
    return AliasFacts(noalias=groups)


def _parse_str_map(t: dict, where: str) -> dict[str, str]:
    out = {}
    for k, v in t.items():
        out[k] = _str(v, f"{where}.{k}")
    return out


def _parse_project(t: dict) -> ProjectFacts:
    allowed = {"name", "language", "source", "build", "memory", "surface", "trust",
               "functions", "alias", "dispatch", "typedefs"}
    _reject_unknown(t, allowed, "project")
    return ProjectFacts(
        name=_str(t.get("name", ""), "project.name"),
        language=_str(t.get("language", "c"), "project.language"),
        source=_parse_source(_table(t.get("source", {}), "project.source")),
        build=_parse_build(_table(t.get("build", {}), "project.build")),
        memory=_parse_memory(_table(t.get("memory", {}), "project.memory")),
        surface=_parse_surface(_table(t.get("surface", {}), "project.surface")),
        trust=_parse_trust(_table(t.get("trust", {}), "project.trust")),
        functions=_parse_functions(_table(t.get("functions", {}), "project.functions")),
        alias=_parse_alias(_table(t.get("alias", {}), "project.alias")),
        dispatch=_parse_str_map(_table(t.get("dispatch", {}), "project.dispatch"),
                                "project.dispatch"),
        typedefs=_parse_str_map(_table(t.get("typedefs", {}), "project.typedefs"),
                                "project.typedefs"),
    )


def _parse_analysis(t: dict) -> AnalysisConfig:
    allowed = {"engine", "graph", "disjunct_cap", "timeout_per_fn"}
    _reject_unknown(t, allowed, "analysis")
    return AnalysisConfig(
        engine=_str(t["engine"], "analysis.engine") if "engine" in t else None,
        graph=_str(t["graph"], "analysis.graph") if "graph" in t else None,
        disjunct_cap=(_int(t["disjunct_cap"], "analysis.disjunct_cap")
                      if "disjunct_cap" in t else None),
        timeout_per_fn=(_duration_seconds(t["timeout_per_fn"], "analysis.timeout_per_fn")
                        if "timeout_per_fn" in t else None),
    )


# --------------------------------------------------------------------------- #
# public API
# --------------------------------------------------------------------------- #
def parse_manifest(data: dict, *, path: str | None = None) -> Manifest:
    """Build a :class:`Manifest` from an already-parsed TOML mapping."""
    _reject_unknown(data, {"project", "analysis"}, "<manifest>")
    return Manifest(
        project=_parse_project(_table(data.get("project", {}), "project")),
        analysis=_parse_analysis(_table(data.get("analysis", {}), "analysis")),
        path=path,
    )


def load_manifest(path) -> Manifest:
    """Read, parse and validate the ``lachesis.toml`` at *path*."""
    path = Path(path)
    return parse_manifest(_read_toml(path), path=str(path))


def discover_manifest(start=".") -> Path | None:
    """Walk up from *start* (a file or directory) to the nearest ``lachesis.toml``."""
    p = Path(start).resolve()
    if p.is_file():
        p = p.parent
    for directory in (p, *p.parents):
        candidate = directory / MANIFEST_NAME
        if candidate.is_file():
            return candidate
    return None


def load_or_discover(start=".") -> Manifest | None:
    """Load the manifest nearest *start*, or ``None`` if there is none."""
    found = discover_manifest(start)
    return load_manifest(found) if found is not None else None
