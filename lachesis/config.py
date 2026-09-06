"""Project configuration for lachesis (``lachesis.yml``).

A single optional file that controls what a build ingests, how large a graph or
an export may grow, where the atropos catalog lives, and the runtime knobs that
are otherwise reachable only through ``LACHESIS_*`` environment variables. It is
discovered by walking up from the analysed source tree (and the current working
directory), or named explicitly with ``--config``.

Precedence, highest first: an explicit CLI flag, then the matching environment
variable, then this file, then the built-in default. A repository that ships a
``lachesis.yml`` therefore changes the defaults for everyone who builds it, while
a one-off flag or env var still wins for a single run.

Two deliberate departures from "no file means no change":

* Non-product code — tests, examples, docs, fixtures, benchmarks, vendored
  trees, and their common synonyms — is excluded from a build **by default**,
  with or without a config file. A tree is understood by its product source; the
  scaffolding around it drowns the projection and the architecture ranking. Set
  ``build.exclude: []`` (or list an ``build.include`` allow-list) to bring any of
  it back.

* The parser is loaded lazily. PyYAML is imported only when a config file is
  actually found, so the stdlib-only core is unaffected for anyone who never
  writes one. A file that is present but unparseable because PyYAML is missing is
  a hard, explained error rather than a silent skip.

The schema is intentionally broad and forward-looking: every knob that today is
a CLI flag or an ``LACHESIS_*`` variable has a home here, grouped by the stage it
controls (``build``, ``export``, ``runtime``, ``atropos``). Unknown keys are
reported, not fatal, so a newer config file stays loadable by an older reader.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional, Sequence

# The names looked for when walking up the tree, in order of preference. The
# dotfile form is accepted so a repo can keep the file out of the way.
CONFIG_FILENAMES = ("lachesis.yml", "lachesis.yaml", ".lachesis.yml", ".lachesis.yaml")

# The built-in "non-product" exclusion set. A path is non-product when any of its
# directory segments is one of these scaffolding names, or when its basename is a
# test module, a vendored dependency, a generated/minified artifact, or a build
# config. Matching is on path *segments* and basenames, never on substrings, so
# product files whose name merely contains a keyword — ``testing.py``,
# ``templating.py``, ``documentation.py`` — are kept. Validated against the pallets
# /flask tree: of 83 .py files it drops exactly the 41 tests + 17 examples + 1 doc
# and keeps all 24 ``src/flask`` modules.
#
# The set is deliberately language-agnostic — it classifies *paths*, so one rule
# covers Python, TypeScript, JavaScript and C at once. It is the same default a
# review confirmed the graph itself must honor (not only the bundle export): a
# code-property graph over an application has no business modelling a vendored
# dependency, a build output tree, or a generated bundle — a bug found inside one
# is not actionable in the analysed repo, and the noise drowns the product signal
# for comprehension and for security triage alike. Dependencies (``node_modules``,
# ``vendor``, ``third_party``, ``site-packages``), build/CI tooling (``scripts``),
# generated output (``dist``), minified/declaration/build-config artifacts
# (``*.min.js``, ``*.d.ts``, ``*.config.js``) are therefore all dropped by default.
# Any of it is recoverable with an explicit ``build.include`` allow-list or by
# clearing ``build.exclude`` — the opt-in escape hatch for deliberately auditing a
# dependency.
#
# Kept as a single compiled regex (rather than a glob list) because it is the
# default applied on every build and both the builder and the exporter consult
# it; the user-facing ``build.exclude`` list is expressed as globs and compiled
# on top of this.
_NONPRODUCT_SEGMENTS = (
    r"tests?", r"testing", r"__tests__", r"specs?",
    r"examples?", r"samples?", r"demos?",
    r"docs?", r"documentation",
    r"benchmarks?", r"bench", r"perf",
    r"fixtures?", r"testdata", r"test[_-]?data", r"__mocks__", r"mocks",
    r"vendor", r"vendored", r"third[_-]?party", r"node_modules", r"site-packages",
    r"\.tox", r"\.nox", r"\.venv", r"venv",
    r"dist", r"scripts",
)
_NONPRODUCT_BASENAMES = (
    r"conftest\.py",
    r"test_[^/]*\.py", r"[^/]*_test\.py",
    r"[^/]*\.spec\.[a-z]+", r"[^/]*\.test\.[a-z]+",
    # Generated / vendored / build-config artifacts: a minified bundle, a
    # TypeScript declaration file, and the common ``*.config.js`` build configs
    # (rollup/webpack/vite/babel/jest/…) are outputs and scaffolding, not source.
    r"[^/]*\.min\.[a-z0-9]+",
    r"[^/]*\.d\.ts",
    r"[^/]*\.config\.(?:js|cjs|mjs|ts)",
)
NONPRODUCT_RE = re.compile(
    r"(?:^|/)(?:" + "|".join(_NONPRODUCT_SEGMENTS) + r")(?:/|$)"
    r"|(?:^|/)(?:" + "|".join(_NONPRODUCT_BASENAMES) + r")$",
    re.IGNORECASE,
)


# Every ``LACHESIS_*`` variable the codebase reads, so a ``runtime:`` block can set
# any of them from the file with the same precedence a shell export would have. A key
# outside this set is still applied (a newer reader may know a variable this one does
# not), but it is reported as a warning so a typo is visible rather than silent. Kept
# here, next to the parser, deliberately: it is the single list a reviewer checks when
# a new env var is introduced. ``ATROPOS_ROOT`` is included though it lacks the prefix
# because the atropos resolver reads it and the ``atropos.root`` knob maps onto it.
KNOWN_RUNTIME_ENV = frozenset({
    "ATROPOS_ROOT",
    "LACHESIS_ATROPOS_TIMINGS", "LACHESIS_BIN", "LACHESIS_BIND_SIDECAR",
    "LACHESIS_BIND_SIDECAR_MAX_MB", "LACHESIS_BLESS", "LACHESIS_C_CHUNK_FILES",
    "LACHESIS_C_JOBS", "LACHESIS_CACHE_DIR", "LACHESIS_CFLAGS", "LACHESIS_COLUMNAR",
    "LACHESIS_COMPILE_COMMANDS", "LACHESIS_CONCEPT_CACHE", "LACHESIS_CORPUS_ROOT",
    "LACHESIS_DEFER_TRANSLATION_FACTS", "LACHESIS_EMIT_PROOFS", "LACHESIS_EMIT_TOKENS",
    "LACHESIS_ENRICH_AT_BUILD", "LACHESIS_ENRICH_SHARDS", "LACHESIS_EQUALITY_HARNESS",
    "LACHESIS_EQUALITY_TIER", "LACHESIS_FORMAT", "LACHESIS_FRONTEND_JOBS",
    "LACHESIS_GRAPH", "LACHESIS_HARD_STOP", "LACHESIS_HOME",
    "LACHESIS_INCLUDE_DEP_TYPES", "LACHESIS_INCLUDE_DIRS_FILE", "LACHESIS_INPROCESS",
    "LACHESIS_ISOLATE_NATIVE", "LACHESIS_KUZU_BATCH", "LACHESIS_KUZU_BPS",
    "LACHESIS_KUZU_BUFFER_POOL_SIZE", "LACHESIS_KUZU_CHECKPOINT_THRESHOLD",
    "LACHESIS_KUZU_LOW_MEMORY", "LACHESIS_KUZU_MAX_DB_SIZE",
    "LACHESIS_KUZU_QUERY_THREADS", "LACHESIS_MAX_DEPENDENCY_FILES",
    "LACHESIS_MCP_PROFILE", "LACHESIS_MEMORY_BUDGET_MB", "LACHESIS_NATIVE_ATROPOS_LIB",
    "LACHESIS_NATIVE_LIFETIME_LIB", "LACHESIS_NO_PROGRESS", "LACHESIS_PASS2_TIMINGS",
    "LACHESIS_PROFILE", "LACHESIS_ROOTS_FILE", "LACHESIS_SEMANTIC_SHARDS",
    "LACHESIS_SHARD_DIR", "LACHESIS_SHARD_ID", "LACHESIS_SHARD_ROOT",
    "LACHESIS_SOURCE_MAP", "LACHESIS_SOURCE_ROOT", "LACHESIS_STREAM_BATCH_ROWS",
    "LACHESIS_TIER_VALIDATION", "LACHESIS_TIMEIT", "LACHESIS_TIMEIT_REPORT",
    "LACHESIS_TIMINGS", "LACHESIS_TRACEBACK", "LACHESIS_TS_MAX_OLD_SPACE_MB",
    "LACHESIS_TS_STACK_KB",
})


def is_nonproduct(relpath: str) -> bool:
    """Whether a repo-relative path is scaffolding rather than product source.

    The default build- and export-time filter. Operates on the forward-slashed
    repo-relative form (``display_path`` in the frontend), so it is independent of
    where the tree lives on disk.
    """
    return NONPRODUCT_RE.search(relpath.replace(os.sep, "/")) is not None


def _glob_to_regex(pattern: str) -> re.Pattern[str]:
    """Translate a path glob to an anchored regex.

    Supports ``**`` (any run of characters including ``/``), ``*`` (any run within
    a single path segment), and ``?`` (one non-separator character). A bare name
    like ``tests`` matches that segment anywhere in the path, so ``tests`` and
    ``tests/**`` and ``**/tests/**`` all do the intuitive thing.
    """
    pattern = pattern.strip().replace(os.sep, "/")
    out: list[str] = []
    i, n = 0, len(pattern)
    while i < n:
        c = pattern[i]
        if c == "*":
            if i + 1 < n and pattern[i + 1] == "*":
                out.append(".*")
                i += 2
                # A trailing ``/`` after ``**`` may match nothing.
                if i < n and pattern[i] == "/":
                    out.append("/?")
                    i += 1
                continue
            out.append("[^/]*")
            i += 1
            continue
        if c == "?":
            out.append("[^/]")
        elif c == "/":
            out.append("/")
        else:
            out.append(re.escape(c))
        i += 1
    body = "".join(out)
    # A bare segment name (no separators, no wildcards) matches that segment
    # wherever it appears in the path.
    if "/" not in pattern and "*" not in pattern and "?" not in pattern:
        return re.compile(r"(?:^|/)" + body + r"(?:/|$)")
    return re.compile(r"^" + body + r"$")


@dataclass(frozen=True)
class PathFilter:
    """A compiled exclude/include decision over repo-relative paths.

    ``include`` is an allow-list that wins over ``exclude`` (and over the built-in
    non-product default), so a specific example can be kept without disabling the
    whole default. ``use_nonproduct_default`` folds the built-in scaffolding set
    into the exclusion; the loader clears it when the user sets ``exclude`` to an
    explicit list so that ``exclude: []`` genuinely means "compile everything".
    """

    exclude: tuple[re.Pattern[str], ...] = ()
    include: tuple[re.Pattern[str], ...] = ()
    use_nonproduct_default: bool = True

    def excluded(self, relpath: str) -> bool:
        rel = relpath.replace(os.sep, "/")
        if any(p.search(rel) for p in self.include):
            return False
        if any(p.search(rel) for p in self.exclude):
            return True
        if self.use_nonproduct_default and is_nonproduct(rel):
            return True
        return False

    def keep(self, relpath: str) -> bool:
        return not self.excluded(relpath)


@dataclass(frozen=True)
class BuildConfig:
    """What a build ingests and how large it may grow."""

    paths: PathFilter = field(default_factory=PathFilter)
    max_files: Optional[int] = None      # cap on files compiled; None = no cap
    max_nodes: Optional[int] = None      # cap on graph node count; None = no cap
    prune_tokens: Optional[bool] = None  # None defers to the CLI default (--prune)
    timeout_seconds: Optional[int] = None
    frontend_jobs: Optional[int] = None
    memory_budget_mb: Optional[int] = None


@dataclass(frozen=True)
class ExportConfig:
    """Bounds and toggles on the comprehension bundle projection."""

    max_nodes: Optional[int] = None       # projection budget
    max_entrypoints: Optional[int] = None
    include_tests: bool = False           # Dense-mode opt-in; default off
    paths: PathFilter = field(default_factory=PathFilter)


@dataclass(frozen=True)
class AtroposConfig:
    """Where the atropos catalog lives and which of it is active."""

    root: Optional[str] = None            # replaces $ATROPOS_ROOT / resolver default
    enabled: bool = True
    native_lib: Optional[str] = None      # $LACHESIS_NATIVE_ATROPOS_LIB
    timings: Optional[bool] = None        # $LACHESIS_ATROPOS_TIMINGS
    languages: Optional[tuple[str, ...]] = None   # None = all present
    kinds: Optional[tuple[str, ...]] = None       # enable-list of sink kinds
    flow_patterns: Optional[tuple[str, ...]] = None  # enable-list of pattern ids


@dataclass(frozen=True)
class Config:
    """A resolved configuration. ``source`` is the file it came from, if any."""

    build: BuildConfig = field(default_factory=BuildConfig)
    export: ExportConfig = field(default_factory=ExportConfig)
    atropos: AtroposConfig = field(default_factory=AtroposConfig)
    runtime: Mapping[str, Any] = field(default_factory=dict)
    source: Optional[str] = None
    warnings: tuple[str, ...] = ()


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

def find_config(start: Optional[str] = None) -> Optional[Path]:
    """The nearest config file at or above ``start`` (default: cwd).

    Walks upward to the filesystem root, returning the first match. A build points
    ``start`` at the analysed source directory so the tree's own config is found
    even when the build is launched from elsewhere.
    """
    base = Path(start or os.getcwd()).resolve()
    for directory in (base, *base.parents):
        for name in CONFIG_FILENAMES:
            candidate = directory / name
            if candidate.is_file():
                return candidate
    return None


def _load_yaml(path: Path) -> dict[str, Any]:
    """Parse a config file, importing PyYAML lazily.

    A present-but-unparseable file is an error a user needs to see, so a missing
    parser is raised with an actionable message rather than swallowed.
    """
    try:
        import yaml  # type: ignore
    except ImportError as exc:  # pragma: no cover - environment-dependent
        raise ConfigError(
            f"{path} is present but PyYAML is not installed. Install it with "
            f"`pip install lachesis-cpg[config]` (or `pip install pyyaml`), or "
            f"remove the file to fall back to defaults."
        ) from exc
    try:
        data = yaml.safe_load(path.read_text()) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path} is not valid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"{path} must be a mapping at the top level, got {type(data).__name__}.")
    return data


class ConfigError(Exception):
    """A config file exists but cannot be honored."""


# ---------------------------------------------------------------------------
# Parsing / resolution
# ---------------------------------------------------------------------------

def _compile_globs(patterns: Iterable[str]) -> tuple[re.Pattern[str], ...]:
    return tuple(_glob_to_regex(str(p)) for p in patterns)


def _path_filter(section: Mapping[str, Any], warnings: list[str], where: str) -> PathFilter:
    exclude = section.get("exclude")
    include = section.get("include", []) or []
    if exclude is None:
        # Key absent: keep the non-product default, no explicit patterns.
        return PathFilter(
            include=_compile_globs(include),
            use_nonproduct_default=True,
        )
    if not isinstance(exclude, list) or not isinstance(include, list):
        warnings.append(f"{where}: `exclude`/`include` must be lists; ignoring.")
        return PathFilter(use_nonproduct_default=True)
    # An explicit exclude list replaces the default set. `exclude: []` therefore
    # means "compile everything", which is the intuitive reading.
    return PathFilter(
        exclude=_compile_globs(exclude),
        include=_compile_globs(include),
        use_nonproduct_default=False,
    )


def _as_int(value: Any, where: str, warnings: list[str]) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        warnings.append(f"{where}: expected an integer, got {value!r}; ignoring.")
        return None


def _as_bool(value: Any, where: str, warnings: list[str]) -> Optional[bool]:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    warnings.append(f"{where}: expected true/false, got {value!r}; ignoring.")
    return None


def _as_str_tuple(value: Any) -> Optional[tuple[str, ...]]:
    if value is None:
        return None
    if isinstance(value, str):
        return (value,)
    if isinstance(value, list):
        return tuple(str(v) for v in value)
    return None


def parse(data: Mapping[str, Any], source: Optional[str] = None) -> Config:
    """Turn a raw config mapping into a resolved, typed ``Config``.

    Tolerant by design: a malformed field is dropped with a warning rather than
    failing the build, and unknown top-level sections are reported so a config
    written for a newer reader still loads.
    """
    warnings: list[str] = []
    known = {"build", "export", "atropos", "runtime"}
    for key in data:
        if key not in known:
            warnings.append(f"unknown top-level section {key!r}; ignoring.")

    build_raw = data.get("build") or {}
    export_raw = data.get("export") or {}
    atropos_raw = data.get("atropos") or {}
    runtime_raw = data.get("runtime") or {}

    build = BuildConfig(
        paths=_path_filter(build_raw, warnings, "build"),
        max_files=_as_int(build_raw.get("max_files"), "build.max_files", warnings),
        max_nodes=_as_int(build_raw.get("max_nodes"), "build.max_nodes", warnings),
        prune_tokens=_as_bool(build_raw.get("prune_tokens"), "build.prune_tokens", warnings),
        timeout_seconds=_as_int(build_raw.get("timeout_seconds"), "build.timeout_seconds", warnings),
        frontend_jobs=_as_int(build_raw.get("frontend_jobs"), "build.frontend_jobs", warnings),
        memory_budget_mb=_as_int(build_raw.get("memory_budget_mb"), "build.memory_budget_mb", warnings),
    )
    export = ExportConfig(
        max_nodes=_as_int(export_raw.get("max_nodes"), "export.max_nodes", warnings),
        max_entrypoints=_as_int(export_raw.get("max_entrypoints"), "export.max_entrypoints", warnings),
        include_tests=bool(_as_bool(export_raw.get("include_tests"), "export.include_tests", warnings) or False),
        paths=_path_filter(export_raw, warnings, "export") if ("exclude" in export_raw or "include" in export_raw) else build.paths,
    )
    atropos = AtroposConfig(
        root=atropos_raw.get("root"),
        enabled=bool(_as_bool(atropos_raw.get("enabled"), "atropos.enabled", warnings) if atropos_raw.get("enabled") is not None else True),
        native_lib=atropos_raw.get("native_lib"),
        timings=_as_bool(atropos_raw.get("timings"), "atropos.timings", warnings),
        languages=_as_str_tuple(atropos_raw.get("languages")),
        kinds=_as_str_tuple(atropos_raw.get("kinds")),
        flow_patterns=_as_str_tuple(atropos_raw.get("flow_patterns")),
    )
    if runtime_raw and not isinstance(runtime_raw, dict):
        warnings.append("runtime: expected a mapping of LACHESIS_* variables; ignoring.")
        runtime_raw = {}
    runtime: dict[str, Any] = {}
    for key, value in (runtime_raw or {}).items():
        name = str(key)
        if name not in KNOWN_RUNTIME_ENV:
            warnings.append(
                f"runtime.{name}: not a known LACHESIS_* variable; applying anyway."
            )
        runtime[name] = value

    return Config(
        build=build,
        export=export,
        atropos=atropos,
        runtime=runtime,
        source=source,
        warnings=tuple(warnings),
    )


def _env_str(value: Any) -> str:
    """Render a config value the way a shell export would carry it."""
    if isinstance(value, bool):
        return "1" if value else "0"
    return str(value)


def apply_runtime_env(config: Config) -> None:
    """Fold config-declared runtime knobs into ``os.environ``.

    Every key of the ``runtime:`` block is a ``LACHESIS_*`` variable, and the atropos
    root/native-lib/timings map onto the environment variables their resolver reads.
    ``setdefault`` is deliberate: an inherited environment variable still wins over the
    file, which is the documented precedence (flag > env > file > default). Idempotent,
    and safe to call before any pipeline import — nothing here imports the pipeline.
    """
    for name, value in (config.runtime or {}).items():
        os.environ.setdefault(str(name), _env_str(value))
    atropos = config.atropos
    if atropos.root:
        os.environ.setdefault("ATROPOS_ROOT", str(atropos.root))
    if atropos.native_lib:
        os.environ.setdefault("LACHESIS_NATIVE_ATROPOS_LIB", str(atropos.native_lib))
    if atropos.timings is not None:
        os.environ.setdefault("LACHESIS_ATROPOS_TIMINGS", _env_str(atropos.timings))


def load(start: Optional[str] = None, explicit: Optional[str] = None) -> Config:
    """Discover and parse the config, or return the all-default ``Config``.

    ``explicit`` (a ``--config`` path) is honored verbatim and must exist;
    otherwise the tree is searched from ``start``. When no file is found the
    returned ``Config`` is all-defaults — which still excludes non-product code,
    because that default lives in ``PathFilter`` itself, not in the file.
    """
    if explicit:
        path = Path(explicit).resolve()
        if not path.is_file():
            raise ConfigError(f"--config {explicit} does not exist.")
    else:
        path = find_config(start)
    if path is None:
        return Config()
    return parse(_load_yaml(path), source=str(path))
