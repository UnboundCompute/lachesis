"""The eager-vs-lazy equality harness: what the nav tools answered, frozen.

The lazy-resolution work replaces eager whole-graph enrichment with resolution done on
demand. The one thing that must not happen is a tool answering with *less* than it used
to -- ``callers(X)`` returning ``[]`` because resolution has not run yet is the failure a
vulnerability hunter cannot detect and cannot tolerate. Every other kind of regression
announces itself; that one looks exactly like a clean codebase.

So this records what the eager path answers, for real tools on a real graph, and every
later phase diffs against it. The comparison is deliberately **asymmetric**: a row in the
golden that is missing from the actual answer is always a failure, because that is the
regression this exists to catch. A row in the actual answer that is not in the golden is
also a failure by default -- it means something moved and nobody said so -- but it is
downgradeable per tool through ``ALLOWED_EXTRA_ROWS``, with a comment naming the phase
that justifies it.

The corpus is pinned to a git revision, and that is not incidental. Arachne analyzes
itself, so a baseline recorded over the working tree makes the corpus and the analyzer
the same files: editing this module shifts the line numbers the golden recorded, and the
resulting failures are indistinguishable from the regressions the harness exists to
catch. ``git:<rev>`` exports the commit to a directory named after it, so later phases
change the analyzer while the thing being analyzed stays byte for byte -- and at the same
absolute path, which the C and TypeScript frontends stamp into ids -- what it was.

Running it:

    LACHESIS_BLESS=1 python3 -m lachesis.nav.checks --bless git:HEAD:lachesis
    LACHESIS_EQUALITY_HARNESS=golden python3 -m pytest lachesis/nav/checks.py

``golden`` means "the corpus the baseline was recorded over", which is the revision the
golden pins rather than whatever ``HEAD`` has since become. A plain directory or a built
Kùzu store also works as a target, for a quick local run; the pinned form is the one to
record a baseline over.

Blessing refuses to run without ``LACHESIS_BLESS=1`` set. That is not ceremony: an agent
that can regenerate the baseline it is being judged against is not being judged, and the
cheapest way to make a failing harness pass is to re-bless it.
"""
from __future__ import annotations

import argparse
import gzip
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import List, Sequence, Tuple

from ._navharness import NavCall, norm, rows_of, run_nav, scalars_of


#: Bumped when the calls, the seed rule or the row projection change, so an old golden
#: is rejected rather than compared against a harness that no longer means the same
#: thing by "the same call".
HARNESS_VERSION = 3

GOLDEN_DIR = Path(__file__).resolve().parent / "goldens"
GOLDEN_PATH = GOLDEN_DIR / "eager_baseline.json.gz"

#: How many seeds overall, and how many per language, so all three frontends are
#: represented even when one dominates the degree ranking.
SEED_LIMIT = 12
SEED_PER_LANGUAGE = 4

#: Tools allowed to answer with rows the golden does not have, and why. An entry is a
#: phase saying out loud that it changed an answer; the asymmetry is the point, so
#: nothing here weakens the ``missing`` half, which stays a hard failure for every tool.
ALLOWED_EXTRA_ROWS: dict = {
    # Phase 3 wired the resolution tier into these two. They gain rows two ways: the
    # union over every homonym a name means (the golden recorded one arbitrary winner),
    # and the ladder deciding call sites the eager frontends left undecided. `callees`
    # additionally grows an `unresolved` field, which is a field the golden has no
    # counterpart for at all.
    "callers": "Phase 3: homonym union + resolver-decided rows",
    "callees": "Phase 3: homonym union + resolver-decided rows, plus `unresolved`",
}

#: Fields that are additive by construction, on any tool, and why. These are not rows
#: about the graph -- they are the answer describing how it was arrived at -- so their
#: presence displaces nothing and their absence from the golden is expected rather than
#: suspicious. Listed by name so a *third* new field still has to justify itself.
ADDED_FIELDS = {
    # Phase 3: which seeds a name collapsed to. Every tool that takes one seed grew it.
    "homonyms": "Phase 3: the seeds a name was resolved between",
    # Phase 3, invariant 2: the call sites `callees` could not decide, as themselves.
    "unresolved": "Phase 3: undecidable call sites, reported rather than omitted",
}

#: ``hubs`` is a ranking, not a set, so it is compared by membership plus how well the
#: order survived. Below this the ranking has changed character even if the members did
#: not, which is the §10 measurement.
HUBS_RANK_FLOOR = 0.9

_EXTENSION_LANGUAGE = {
    ".c": "c", ".h": "c", ".py": "python", ".pyi": "python",
    ".ts": "typescript", ".tsx": "typescript", ".js": "typescript",
    ".jsx": "typescript", ".mjs": "typescript", ".cjs": "typescript",
}


def _language_of(file: str | None) -> str:
    return _EXTENSION_LANGUAGE.get(Path(file or "").suffix.lower(), "other")


#: A corpus pinned to a git revision: ``git:<rev>`` or ``git:<rev>:<subpath>``.
GIT_TARGET = re.compile(r"^git:([^:]+)(?::(.+))?$")


def _corpus_root() -> Path:
    """Where exported corpora live. Outside the repository, because they are not it."""
    root = Path(
        os.environ.get("LACHESIS_CORPUS_ROOT") or Path.home() / ".lachesis" / "corpora",
    )
    root.mkdir(parents=True, exist_ok=True)
    return root


def resolve_corpus(target: str, repo: str | None = None):
    """Turn a ``git:<rev>`` target into a checked-out directory, and say which revision.

    This is the difference between a harness that works and one that cannot. Arachne
    analyzes itself, so pointing the harness at the working tree makes the corpus and
    the analyzer the same files: every edit to this very module shifts the line numbers
    the golden recorded, and the baseline fails for reasons that have nothing to do with
    resolution. A harness has to hold the corpus fixed and vary only the code doing the
    analysis, so the corpus is exported from a commit and the commit is written into the
    golden. Later phases re-export the same commit and compare like against like.

    The export goes to a fixed directory named after the revision rather than to a fresh
    temporary one, and that is load-bearing twice over. The C and TypeScript frontends
    stamp absolute paths into node ids and into result rows, so a corpus that moved
    between two runs would produce a different ``graph_content_hash`` and different rows
    for the same code -- the comparison would be permanently stuck in identity-relaxed
    mode and every TypeScript row would read as changed. Naming the directory after the
    commit makes the corpus reproducible on disk, not just in content, and re-exporting
    the same revision is then free.

    Returns ``(directory, revision, holder)``; ``revision`` is ``None`` for a plain path
    target, which stays supported for a quick local run against a tree or a built store.
    ``holder`` is always ``None`` here -- the export is cached deliberately, not owned.
    """
    match = GIT_TARGET.match(target or "")
    if not match:
        return target, None, None
    rev, subpath = match.group(1), match.group(2) or ""
    repo = repo or str(Path(__file__).resolve().parents[2])
    resolved = subprocess.run(
        ["git", "-C", repo, "rev-parse", rev],
        capture_output=True, text=True, check=True,
    ).stdout.strip()
    root = _corpus_root() / resolved
    if not root.is_dir():
        export = subprocess.run(
            ["git", "-C", repo, "archive", "--format=tar", resolved]
            + ([subpath] if subpath else []),
            capture_output=True, check=True,
        )
        # Extract beside the destination and rename into place, so an export killed
        # halfway leaves nothing a later run would mistake for a complete corpus.
        scratch = Path(tempfile.mkdtemp(dir=str(_corpus_root())))
        subprocess.run(["tar", "-x", "-C", str(scratch)], input=export.stdout, check=True)
        try:
            os.replace(scratch, root)
        except OSError:
            if not root.is_dir():
                raise
            shutil.rmtree(scratch, ignore_errors=True)
    return str(root / subpath) if subpath else str(root), resolved, None


def open_store(target: str):
    """A store for ``target``, which may be a built Kùzu store or a source tree.

    Taking either is what lets the harness run against the tree it is guarding without
    the caller having to remember to build first, while still being pointable at a store
    that is already built when the build is the expensive part.
    """
    from lachesis.kuzu_store import is_kuzu_dir, write_kuzu_graph
    from lachesis.nav.graph_store import GraphStore

    if is_kuzu_dir(target):
        return GraphStore.load(target), None
    from lachesis.pipeline import run_project

    holder = tempfile.TemporaryDirectory()
    frontend_out = os.path.join(holder.name, "frontends")
    store_dir = os.path.join(holder.name, "store")
    graph, snapshots = run_project(target, frontend_out)
    write_kuzu_graph(graph, snapshots, store_dir, prune=False, enriched=True)
    # The holder is returned so the caller keeps it alive; a store whose directory has
    # been reclaimed fails deep inside Kùzu with a message about a missing file.
    return GraphStore.load(store_dir), holder


def _pinned(target: str, revision: str | None) -> str | None:
    match = GIT_TARGET.match(target or "")
    if not match or revision is None:
        return None
    subpath = match.group(2)
    return f"git:{revision}:{subpath}" if subpath else f"git:{revision}"


def corpus_target(golden: dict, requested: str) -> str:
    """What to actually open, given what the caller asked for.

    ``LACHESIS_EQUALITY_HARNESS=golden`` means "whatever corpus the baseline was
    recorded over". Without it the pinned revision has to be copied out of the golden
    and pasted into an environment variable by hand at every phase, and the failure mode
    of getting that wrong is a wall of differences that look like regressions.
    """
    if requested != "golden":
        return requested
    pinned = golden.get("corpus", {}).get("pinned")
    if not pinned:
        raise SystemExit(
            "the golden was recorded over an unpinned target, so there is no corpus "
            "to reuse; name a target explicitly",
        )
    return pinned


def open_corpus(target: str):
    """``(store, directory, revision, holders)`` for a target of any supported form.

    The holders are temporary directories the caller must keep alive and then clean up,
    innermost first -- the store lives inside a directory that the corpus export may own.
    """
    directory, revision, corpus_holder = resolve_corpus(target)
    store, store_holder = open_store(directory)
    holders = [holder for holder in (store_holder, corpus_holder) if holder is not None]
    return store, directory, revision, holders


def close_corpus(holders) -> None:
    for holder in holders:
        holder.cleanup()


def graph_identity(store) -> str:
    """The hash that says whether two runs are looking at the same graph.

    Phase 1 changes Python call-site node ids without changing a source byte, so this is
    the tripwire that tells the harness to stop comparing ids and compare the id-free
    projection instead. Preferred from the store manifest, which already carries it;
    computed only when it does not, because computing it walks every edge.
    """
    from lachesis.kuzu_store import graph_content_hash, read_store_manifest

    path = getattr(store, "_core_path", None)
    if path:
        recorded = read_store_manifest(path).get("core_content_hash")
        if recorded:
            return recorded
    from lachesis.nav.kuzu_index import materialize_graph

    graph = materialize_graph(store.index)
    return graph_content_hash(graph["nodes"], graph["edges"])


def pick_seeds(store) -> List[dict]:
    """Derive the seeds from the graph, never from a hand-written list.

    A hand-listed seed that stops resolving turns into a vacuous pass: the harness keeps
    comparing, and keeps comparing nothing. Derived seeds cannot do that, because the
    harness asserts every one of them resolves, and a seed set that shrank is itself the
    failure.

    ``store.entries`` is already totally ordered, and carries the degree the ranking
    needs. Top-k overall would be dominated by whichever language contributes the most
    code, so a per-language quota runs alongside it and all three frontends are
    represented in the baseline.
    """
    candidates = [
        entry for entry in store.entries
        if entry["kind"] in {"function", "method", "constructor"}
        and not entry.get("is_test")
        and not entry.get("declaration_only")
        and entry.get("name") and entry.get("file")
    ]
    candidates.sort(key=lambda e: (
        -e.get("degree", 0), e["name"], e["file"] or "", e.get("line") or 0,
    ))
    chosen: List[dict] = []
    seen: set = set()
    per_language: dict = {}
    # The per-language quota first, so a language that contributes little code is still
    # in the baseline; then the overall ranking fills whatever is left.
    for entry in candidates:
        language = _language_of(entry["file"])
        if per_language.get(language, 0) >= SEED_PER_LANGUAGE:
            continue
        per_language[language] = per_language.get(language, 0) + 1
        seen.add(entry["node_id"])
        chosen.append(entry)
    for entry in candidates:
        if len(chosen) >= SEED_LIMIT + len(per_language) * SEED_PER_LANGUAGE:
            break
        if entry["node_id"] not in seen:
            seen.add(entry["node_id"])
            chosen.append(entry)
    chosen.sort(key=lambda e: (e["name"], e["file"] or "", e.get("line") or 0))
    return chosen


def tree_roots(target: str, store) -> Tuple[str, ...]:
    """Every spelling of the tree root that could appear in an answer.

    One is not enough. macOS puts temporary and cache directories behind a ``/private``
    symlink, so a frontend that resolved the path it was handed and one that did not
    stamp two different absolute strings for the same file, and a single-prefix strip
    silently leaves half of them machine-specific.
    """
    roots = [_tree_root(target, store)]
    # The analyzer's own checkout, because it leaks into the answers: TypeScript
    # resolves the standard library out of arachne's ``node_modules``, so results carry
    # a path that has nothing to do with the corpus and everything to do with where
    # somebody happens to keep this repository.
    roots.append(str(Path(__file__).resolve().parents[2]))
    forms = {
        form
        for root in roots if root
        for form in (root, os.path.realpath(root).rstrip("/"),
                     os.path.abspath(root).rstrip("/"))
    }
    # Longest first, so a root that is a prefix of another never strips the wrong one.
    return tuple(sorted((form for form in forms if form), key=len, reverse=True))


def _tree_root(target: str, store) -> str:
    """Where the analyzed tree lives on this machine, so labels can stop saying it.

    The C frontend stamps absolute resolved paths while Python stamps repo-relative
    ones, so a mixed-language graph has no shared textual prefix to derive -- a common
    prefix over the two collapses to nothing, and the labels stay machine-specific. The
    tree root is the one thing that actually explains the absolute half, and both a
    source-dir target and a store manifest know it.

    Python's paths are already relative and pass through untouched, which is what makes
    stripping safe: it removes a location, never a path that meant something.
    """
    if target and os.path.isdir(target) and not _is_store(target):
        return os.path.realpath(target).rstrip("/")
    from lachesis.kuzu_store import read_store_manifest

    path = getattr(store, "_core_path", None)
    recorded = read_store_manifest(path).get("source_dir") if path else None
    return os.path.realpath(recorded).rstrip("/") if recorded else ""


def _is_store(target: str) -> bool:
    from lachesis.kuzu_store import is_kuzu_dir

    return is_kuzu_dir(target)


def _relative(path: str | None, prefixes: Sequence[str]) -> str:
    if isinstance(prefixes, str):
        # A bare string iterates by character, so every startswith fails and nothing is
        # stripped -- and the harness then reports every absolute-path row as changed,
        # which reads exactly like the regression it exists to find. Refuse instead.
        raise TypeError("prefixes is a sequence of roots, not one root")
    if not path:
        return ""
    for prefix in prefixes:
        if prefix and path.startswith(prefix + "/"):
            return path[len(prefix) + 1:]
    return path


def _label(tool: str, seed: dict, prefixes: Sequence[str] = ()) -> str:
    at = f"{_relative(seed.get('file'), prefixes)}:{seed.get('line')}"
    return f"{tool}:{seed['name']}@{at}"


def build_calls(seeds: Sequence[dict], prefixes: Sequence[str] = ()) -> List[NavCall]:
    """Every call the baseline records, labelled by what it asked rather than by index.

    Positional labels would silently re-pair calls with answers the moment the seed rule
    changes; a label naming the symbol and its location cannot.
    """
    calls: List[NavCall] = [
        ("hubs", "hubs", {"n": 40}),
        ("guards_top", "guards_top", {"n": 40}),
    ]
    for seed in seeds:
        name = seed["name"]
        for tool, args in (
            ("search", {"name": name}),
            ("callers", {"name": name}),
            ("callees", {"name": name}),
            ("read_body", {"name": name}),
            ("flow", {"seed": name}),
            ("sources_of", {"sink": name}),
            ("points_to", {"value": name}),
            ("aliases", {"value": name}),
            ("guards", {"fn": name}),
            ("call_roles", {"fn": name}),
            ("siblings", {"sym": name}),
        ):
            calls.append((_label(tool, seed, prefixes), tool, args))
    # Consecutive pairs rather than the full cross product: reaches is the most
    # expensive tool here and n^2 of it would dominate the run without adding a kind of
    # evidence the n pairs do not already give.
    for left, right in zip(seeds, seeds[1:]):
        calls.append((
            f"reaches:{left['name']}->{right['name']}", "reaches",
            {"src": left["name"], "sink": right["name"]},
        ))
    for file in sorted({seed["file"] for seed in seeds if seed.get("file")}):
        calls.append((
            f"open_file:{_relative(file, prefixes)}", "open_file", {"file": file},
        ))
        folder = file.rsplit("/", 1)[0] if "/" in file else file
        calls.append((
            f"open_folder:{_relative(folder, prefixes)}", "open_folder", {"root": folder},
        ))
    # Labels must be unique or later calls overwrite earlier answers in the result dict.
    return list({label: (label, tool, args) for label, tool, args in calls}.values())


def collect(store, calls: Sequence[NavCall], prefixes: Sequence[str] = ()) -> dict:
    """Answer every call and strip the checkout's own location out of the answers.

    Paths appear in ``file``, ``at`` and ``handle`` fields all over the results, and an
    absolute one records where the recording machine happened to keep the tree. Note
    what this cannot fix: the C frontend hashes the absolute path into node ids, so a
    golden read on a different checkout will differ by ``graph_content_hash`` and the
    comparison drops to identity-relaxed -- which is the right answer there anyway.
    """
    return {
        label: _strip_prefix(norm(payload), prefixes)
        for label, payload in run_nav(store, calls).items()
    }


def _strip_prefix(value, prefixes: Sequence[str]):
    if not prefixes:
        return value
    if isinstance(value, str):
        return _relative(value, prefixes)
    if isinstance(value, list):
        return [_strip_prefix(item, prefixes) for item in value]
    if isinstance(value, dict):
        return {key: _strip_prefix(item, prefixes) for key, item in value.items()}
    return value


# -- comparison ---------------------------------------------------------------------

#: The fields a row is identified by when node ids can no longer be trusted. Phase 1
#: changes ids without changing meaning, so during that phase this is what "the same
#: row" means. Anything not listed is content, not identity.
RELAXED_FIELDS = ("name", "file", "line", "at", "via", "resolved", "kind")


def _row_key(row: dict, relaxed: bool):
    if not relaxed:
        return json.dumps(row, sort_keys=True, default=str)
    return json.dumps(
        {field: row.get(field) for field in RELAXED_FIELDS if field in row},
        sort_keys=True, default=str,
    )


def _tool_of(label: str) -> str:
    return label.split(":", 1)[0]


#: A ``stable_id``: ``v2:<owner>:<namespace>:<kind>:<20 hex>``. Matched whole, so a body
#: of source text that happens to open with those two characters is not mistaken for one.
_STABLE_ID = re.compile(r"^v2:[^:]*:[^:]*:[^:]*:[0-9a-f]{20}$")


def _mask_ids(value):
    """Replace node ids with a placeholder, wherever they are nested.

    Identity-relaxed mode drops ``node_id`` out of a row's key, but ids also appear as
    scalars -- ``manifest.seed``, ``manifest.src``, ``function.node_id`` -- and those
    would fail every call during Phase 1 for the one reason the phase says to forgive.
    Masking rather than deleting keeps the *shape* under comparison: a field that stops
    carrying an id at all still shows up as a difference.
    """
    if isinstance(value, str):
        return "<id>" if _STABLE_ID.match(value) else value
    if isinstance(value, list):
        return [_mask_ids(item) for item in value]
    if isinstance(value, dict):
        return {key: _mask_ids(item) for key, item in value.items()}
    return value


def spearman(golden: Sequence, actual: Sequence) -> float:
    """Rank correlation over the items the two rankings share.

    ``hubs`` answers a ranking, so set equality says nothing about whether the ranking
    survived, and exact equality says nothing about whether a one-place swap matters.
    §10 asks for this number specifically.
    """
    shared = [item for item in golden if item in actual]
    if len(shared) < 2:
        return 1.0
    golden_rank = {item: index for index, item in enumerate(golden)}
    actual_rank = {item: index for index, item in enumerate(actual)}
    n = len(shared)
    total = sum(
        (golden_rank[item] - actual_rank[item]) ** 2 for item in shared
    )
    return 1.0 - (6.0 * total) / (n * (n * n - 1))


def _scalar_problems(label: str, golden, actual, relaxed: bool) -> List[str]:
    """The non-row half of one answer, compared whole.

    Fields that are rows on *either* side are left out entirely: a field that went from
    rows to an empty list is already reported by the row comparison, in the words that
    describe what actually happened, and reporting it twice makes the second sentence
    look like a second regression.
    """
    golden_scalars, actual_scalars = scalars_of(golden), scalars_of(actual)
    rows = set(rows_of(golden)) | set(rows_of(actual))
    if relaxed:
        golden_scalars = _mask_ids(golden_scalars)
        actual_scalars = _mask_ids(actual_scalars)
    problems: List[str] = []
    for field in sorted(set(golden_scalars) | set(actual_scalars)):
        if field in rows:
            continue
        if field in ADDED_FIELDS and field not in golden_scalars:
            # A row-bearing field that happened to answer empty here. `rows_of` drops
            # empty lists, so `unresolved: []` arrives as a scalar and would be reported
            # as a new field on exactly the calls where it has nothing to say.
            continue
        if field not in actual_scalars:
            problems.append(f"{label}.{field}: the golden has this field, the run does not")
        elif field not in golden_scalars:
            problems.append(f"{label}.{field}: the run answers a field the golden does not")
        elif golden_scalars[field] != actual_scalars[field]:
            was = json.dumps(golden_scalars[field], sort_keys=True, default=str)
            now = json.dumps(actual_scalars[field], sort_keys=True, default=str)
            problems.append(f"{label}.{field}: was {was[:160]} and is now {now[:160]}")
    return problems


def compare(golden: dict, actual: dict, relaxed: bool) -> List[str]:
    """Every way the two disagree, as sentences. Empty means they agree."""
    problems: List[str] = []
    for label in sorted(golden):
        if label not in actual:
            problems.append(f"{label}: the golden has this call and the run does not")
    for label in sorted(golden.keys() & actual.keys()):
        tool = _tool_of(label)
        golden_rows = rows_of(golden[label])
        actual_rows = rows_of(actual[label])
        problems += _scalar_problems(label, golden[label], actual[label], relaxed)
        if tool == "hubs":
            # A ranking, so membership and order are two separate questions and only
            # the first is a set comparison.
            golden_names = [row.get("name") for row in golden_rows.get("hubs", ())]
            actual_names = [row.get("name") for row in actual_rows.get("hubs", ())]
            missing = [name for name in golden_names if name not in set(actual_names)]
            if missing:
                problems.append(f"{label}: dropped from the ranking: {missing[:5]}")
                continue
            score = spearman(golden_names, actual_names)
            if score < HUBS_RANK_FLOOR:
                problems.append(
                    f"{label}: rank correlation {score:.3f} is below {HUBS_RANK_FLOOR}",
                )
            continue
        for field in sorted(golden_rows):
            golden_keys = {_row_key(row, relaxed) for row in golden_rows[field]}
            actual_keys = {
                _row_key(row, relaxed) for row in actual_rows.get(field, ())
            }
            missing = golden_keys - actual_keys
            if not actual_keys:
                # The regression this harness exists for, so it gets its own sentence
                # rather than being reported as "every row is missing".
                problems.append(
                    f"{label}.{field}: answered {len(golden_keys)} row(s) before and "
                    f"answers none now",
                )
            elif missing:
                problems.append(
                    f"{label}.{field}: {len(missing)} row(s) the golden has and the "
                    f"run lost -- e.g. {sorted(missing)[0][:200]}",
                )
        for field in sorted(set(actual_rows) - set(golden_rows)):
            if field not in ADDED_FIELDS and tool not in ALLOWED_EXTRA_ROWS:
                problems.append(
                    f"{label}.{field}: the run answers a field the golden does not have",
                )
        for field in sorted(set(actual_rows) & set(golden_rows)):
            if tool in ALLOWED_EXTRA_ROWS:
                continue
            extra = (
                {_row_key(row, relaxed) for row in actual_rows[field]}
                - {_row_key(row, relaxed) for row in golden_rows[field]}
            )
            if extra:
                problems.append(
                    f"{label}.{field}: {len(extra)} row(s) the run added and the "
                    f"golden does not have -- e.g. {sorted(extra)[0][:200]}",
                )
    return problems


# -- golden i/o ---------------------------------------------------------------------

def write_golden(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    scratch = path.with_suffix(path.suffix + ".partial")
    with gzip.open(scratch, "wt", encoding="utf-8") as handle:
        json.dump(payload, handle, sort_keys=True, indent=1)
    # Replace rather than write in place: a baseline torn by a crash would otherwise be
    # a file that reads as valid until the gzip trailer.
    os.replace(scratch, path)


def read_golden(path: Path) -> dict:
    with gzip.open(path, "rt", encoding="utf-8") as handle:
        return json.load(handle)


def bless(target: str, path: Path = GOLDEN_PATH) -> dict:
    from lachesis.kuzu_store import STORE_FORMAT_VERSION

    store, directory, revision, holders = open_corpus(target)
    try:
        seeds = pick_seeds(store)
        if not seeds:
            raise SystemExit(f"no seed symbols found in {target}; nothing to bless")
        prefixes = tree_roots(directory, store)
        calls = build_calls(seeds, prefixes)
        payload = {
            "harness_version": HARNESS_VERSION,
            "store_format_version": STORE_FORMAT_VERSION,
            "corpus": {
                "target": target, "revision": revision,
                # The target with the symbolic revision resolved. ``git:HEAD:lachesis``
                # names a different tree next week; this names the tree that was read.
                "pinned": _pinned(target, revision),
            },
            "graph_content_hash": graph_identity(store),
            "seeds": [{
                "name": seed.get("name"), "kind": seed.get("kind"),
                "file": _relative(seed.get("file"), prefixes), "line": seed.get("line"),
            } for seed in seeds],
            "results": collect(store, calls, prefixes),
        }
    finally:
        close_corpus(holders)
    write_golden(path, payload)
    return payload


# -- the test -----------------------------------------------------------------------

class ComparisonTests(unittest.TestCase):
    """The comparison itself, which the full run is too slow to be the only test of.

    A harness whose compare step is only exercised by the run it gates is a harness
    nobody finds out is broken until it has already passed something it should not
    have -- and every one of these cases is a way it could pass vacuously.
    """

    #: A tool with no ``ALLOWED_EXTRA_ROWS`` entry, so the default asymmetry is what is
    #: under test here. Deliberately not `callers`: Phase 3 allow-listed that one, and a
    #: self-test that shares a name with a real entry stops testing the default the
    #: moment a phase claims the name.
    TOOL = "flow"

    def _answer(self, rows) -> dict:
        return {"of": "f", "nodes": rows}

    def _label(self) -> str:
        return f"{self.TOOL}:f@a.c:1"

    def test_a_lost_row_is_a_failure(self) -> None:
        golden = {self._label(): self._answer([{"name": "a"}, {"name": "b"}])}
        actual = {self._label(): self._answer([{"name": "a"}])}
        problems = compare(golden, actual, relaxed=False)
        self.assertEqual(1, len(problems), problems)
        self.assertIn("the run lost", problems[0])

    def test_an_emptied_answer_says_so_in_its_own_words(self) -> None:
        golden = {self._label(): self._answer([{"name": "a"}])}
        actual = {self._label(): self._answer([])}
        problems = compare(golden, actual, relaxed=False)
        self.assertEqual(1, len(problems), problems)
        self.assertIn("answers none now", problems[0])

    def test_an_added_row_is_a_failure_unless_a_phase_allowed_it(self) -> None:
        golden = {self._label(): self._answer([{"name": "a"}])}
        actual = {self._label(): self._answer([{"name": "a"}, {"name": "b"}])}
        self.assertTrue(compare(golden, actual, relaxed=False))
        try:
            ALLOWED_EXTRA_ROWS[self.TOOL] = "self-test"
            self.assertEqual([], compare(golden, actual, relaxed=False))
        finally:
            ALLOWED_EXTRA_ROWS.pop(self.TOOL, None)

    def test_a_missing_call_is_a_failure(self) -> None:
        golden = {self._label(): self._answer([{"name": "a"}])}
        self.assertTrue(compare(golden, {}, relaxed=False))

    def test_relaxed_mode_forgives_the_id_and_nothing_else(self) -> None:
        golden = {self._label(): self._answer([
            {"name": "a", "file": "a.c", "node_id": "v2:old"},
        ])}
        renamed_id = {self._label(): self._answer([
            {"name": "a", "file": "a.c", "node_id": "v2:new"},
        ])}
        renamed_row = {self._label(): self._answer([
            {"name": "z", "file": "a.c", "node_id": "v2:old"},
        ])}
        self.assertTrue(compare(golden, renamed_id, relaxed=False))
        self.assertEqual([], compare(golden, renamed_id, relaxed=True))
        self.assertTrue(compare(golden, renamed_row, relaxed=True))

    def test_a_field_the_golden_lacks_is_a_failure_unless_it_is_an_added_one(self) -> None:
        """``ADDED_FIELDS`` is the narrower of the two escape hatches, so it is worth
        checking that it is actually narrow: one named field passes and its neighbour
        in the same answer does not."""
        golden = {self._label(): self._answer([{"name": "a"}])}
        actual = {self._label(): {**self._answer([{"name": "a"}]),
                                  "homonyms": [{"node_id": "v2:x"}]}}
        self.assertEqual([], compare(golden, actual, relaxed=False))
        invented = {self._label(): {**self._answer([{"name": "a"}]),
                                    "hunches": [{"node_id": "v2:x"}]}}
        problems = compare(golden, invented, relaxed=False)
        self.assertEqual(1, len(problems), problems)
        self.assertIn("hunches", problems[0])

    def test_an_added_field_is_forgiven_when_it_answers_empty_too(self) -> None:
        """The case that actually bit. ``rows_of`` drops empty lists, so an added field
        with nothing to say arrives at the *scalar* comparison instead of the row one —
        and gets reported as a new field on exactly the calls where it found nothing."""
        golden = {self._label(): self._answer([{"name": "a"}])}
        actual = {self._label(): {**self._answer([{"name": "a"}]), "unresolved": []}}
        self.assertEqual([], compare(golden, actual, relaxed=False))

    def test_every_row_bearing_field_is_compared_not_just_the_first(self) -> None:
        """``flow`` answers ``nodes`` and ``edges``; losing either has to show."""
        golden = {"flow:f@a.c:1": {
            "nodes": [{"id": "n1"}], "edges": [{"kind": "VALUE_FLOWS_TO"}],
        }}
        actual = {"flow:f@a.c:1": {"nodes": [{"id": "n1"}], "edges": []}}
        problems = compare(golden, actual, relaxed=False)
        self.assertEqual(1, len(problems), problems)
        self.assertIn("edges", problems[0])

    def test_hubs_is_compared_as_a_ranking(self) -> None:
        order = [{"name": name} for name in "abcdefghij"]
        golden = {"hubs": {"hubs": order}}
        self.assertEqual([], compare(golden, {"hubs": {"hubs": order}}, False))
        # One member gone is a membership failure, whatever the order.
        problems = compare(golden, {"hubs": {"hubs": order[1:]}}, False)
        self.assertIn("dropped from the ranking", problems[0])
        # Same members, reversed, is a ranking failure.
        problems = compare(golden, {"hubs": {"hubs": order[::-1]}}, False)
        self.assertIn("rank correlation", problems[0])

    def test_spearman_reads_as_a_correlation(self) -> None:
        order = list("abcdefghij")
        self.assertAlmostEqual(1.0, spearman(order, order))
        self.assertAlmostEqual(-1.0, spearman(order, order[::-1]))

    def test_rows_of_ignores_fields_that_are_not_rows(self) -> None:
        self.assertEqual(
            {"hits": [{"name": "a"}]},
            rows_of({"query": "a", "total": 1, "tokens": ["a"],
                     "hits": [{"name": "a"}]}),
        )

    def test_an_answer_with_no_rows_at_all_is_still_compared(self) -> None:
        """``read_body`` and ``guards`` answer no rows; they must not compare to nothing."""
        golden = {"read_body:f@a.c:1": {"name": "f", "body": "int f(void) { return 1; }"}}
        actual = {"read_body:f@a.c:1": {"name": "f", "body": "int f(void) { return 2; }"}}
        problems = compare(golden, actual, relaxed=False)
        self.assertEqual(1, len(problems), problems)
        self.assertIn("body", problems[0])
        self.assertEqual([], compare(golden, golden, relaxed=False))

    def test_a_changed_count_or_manifest_is_a_failure(self) -> None:
        golden = {"flow:f@a.c:1": {
            "counts": {"nodes": 9, "edges": 4}, "nodes": [{"id": "n1"}],
        }}
        actual = {"flow:f@a.c:1": {
            "counts": {"nodes": 1, "edges": 0}, "nodes": [{"id": "n1"}],
        }}
        problems = compare(golden, actual, relaxed=False)
        self.assertEqual(1, len(problems), problems)
        self.assertIn("counts", problems[0])

    def test_a_field_that_lost_its_rows_is_reported_once_not_twice(self) -> None:
        """It is a row field on one side and a scalar on the other; one sentence."""
        golden = {"flow:f@a.c:1": {"nodes": [{"id": "n1"}]}}
        actual = {"flow:f@a.c:1": {"nodes": []}}
        problems = compare(golden, actual, relaxed=False)
        self.assertEqual(1, len(problems), problems)
        self.assertIn("answers none now", problems[0])

    def test_relaxed_mode_masks_ids_nested_in_scalars(self) -> None:
        """``manifest.seed`` is an id, and Phase 1 changes ids without changing meaning."""
        old = "v2:frontend:cpython-ast:function:" + "0" * 20
        new = "v2:frontend:cpython-ast:function:" + "1" * 20
        golden = {"flow:f@a.py:1": {"manifest": {"move": "flow", "seed": old}}}
        actual = {"flow:f@a.py:1": {"manifest": {"move": "flow", "seed": new}}}
        self.assertTrue(compare(golden, actual, relaxed=False))
        self.assertEqual([], compare(golden, actual, relaxed=True))
        # The move is not an id, so relaxed mode still sees it change.
        moved = {"flow:f@a.py:1": {"manifest": {"move": "sources_of", "seed": new}}}
        self.assertTrue(compare(golden, moved, relaxed=True))

    def test_masking_leaves_a_body_that_merely_looks_like_an_id_alone(self) -> None:
        body = "v2:frontend:x:y:0123456789abcdef0123 is what this function returns"
        self.assertEqual({"body": body}, _mask_ids({"body": body}))

    def test_a_pinned_corpus_exports_the_commit_and_not_the_working_tree(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            os.environ["LACHESIS_CORPUS_ROOT"] = root
            try:
                directory, revision, holder = resolve_corpus("git:HEAD:lachesis")
                self.assertIsNone(holder)
                self.assertEqual(40, len(revision), revision)
                self.assertTrue(os.path.isfile(os.path.join(directory, "pipeline.py")))
                # The point of the pin: what lands in the corpus is the commit, so an
                # uncommitted edit cannot move the target the golden compares against.
                repo = str(Path(__file__).resolve().parents[2])
                committed = subprocess.run(
                    ["git", "-C", repo, "show", f"{revision}:lachesis/core/query.py"],
                    capture_output=True, text=True, check=True,
                ).stdout
                self.assertEqual(
                    committed, Path(directory, "core", "query.py").read_text(),
                )
                # Same revision, same directory -- which is what keeps the absolute
                # paths the C and TypeScript frontends stamp stable between runs.
                self.assertEqual(directory, resolve_corpus("git:HEAD:lachesis")[0])
            finally:
                os.environ.pop("LACHESIS_CORPUS_ROOT", None)

    def test_stripping_handles_every_spelling_of_the_root(self) -> None:
        roots = ("/private/var/corpus", "/var/corpus")
        self.assertEqual("a/b.ts", _relative("/private/var/corpus/a/b.ts", roots))
        self.assertEqual("a/b.ts", _relative("/var/corpus/a/b.ts", roots))
        self.assertEqual("core/query.py", _relative("core/query.py", roots))
        self.assertEqual("/elsewhere/x.c", _relative("/elsewhere/x.c", roots))
        with self.assertRaises(TypeError):
            _relative("/var/corpus/a/b.ts", "/var/corpus")

    def test_a_plain_path_target_stays_supported_and_unpinned(self) -> None:
        self.assertEqual((".", None, None), resolve_corpus("."))

    def test_golden_as_a_target_means_the_corpus_the_golden_pins(self) -> None:
        golden = {"corpus": {"target": "git:HEAD:lachesis", "revision": "abc",
                             "pinned": "git:abc:lachesis"}}
        self.assertEqual("git:abc:lachesis", corpus_target(golden, "golden"))
        self.assertEqual("./lachesis", corpus_target(golden, "./lachesis"))
        with self.assertRaises(SystemExit):
            corpus_target({"corpus": {}}, "golden")

    def test_blessing_refuses_without_the_environment_variable(self) -> None:
        previous = os.environ.pop("LACHESIS_BLESS", None)
        try:
            with self.assertRaises(SystemExit):
                main(["--bless", "."])
        finally:
            if previous is not None:
                os.environ["LACHESIS_BLESS"] = previous


TARGET = os.environ.get("LACHESIS_EQUALITY_HARNESS")


@unittest.skipUnless(
    TARGET and GOLDEN_PATH.exists(),
    "set LACHESIS_EQUALITY_HARNESS=<source-or-store> and bless a golden first",
)
class EagerLazyEqualityTests(unittest.TestCase):
    """Today's answers against the recorded ones, row by row."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.golden = read_golden(GOLDEN_PATH)
        cls.store, cls.directory, cls.revision, cls._holders = open_corpus(
            corpus_target(cls.golden, TARGET),
        )
        # The golden's own seeds, not this store's. `pick_seeds` ranks by degree, and
        # degree is a property of the graph rather than of the corpus: a store whose
        # overlay tier was never folded has strictly lower degrees, so re-deriving picks
        # a *different* seed set and the comparison reports every call the two sets do
        # not share as "the golden has this call and the run does not". That reads as a
        # catastrophic regression and is in fact two seed lists disagreeing about which
        # functions are interesting. The recorded seeds keep the question fixed while
        # the code answering it varies, which is the whole point of a baseline.
        #
        # A seed the store can no longer resolve is still a failure -- see
        # `test_every_recorded_seed_still_resolves`; it just fails as itself now.
        cls.calls = build_calls(
            cls.golden["seeds"], tree_roots(cls.directory, cls.store),
        )

    @classmethod
    def tearDownClass(cls) -> None:
        close_corpus(cls._holders)

    #: Answered once and shared: three hundred nav calls is minutes, and two tests
    #: asking different questions of the same answers must not pay for it twice.
    _answers: dict | None = None

    def _actual(self) -> dict:
        cls = type(self)
        if cls._answers is None:
            cls._answers = collect(
                self.store, self.calls, tree_roots(self.directory, self.store),
            )
        return cls._answers

    def test_the_golden_was_recorded_by_this_harness(self) -> None:
        self.assertEqual(
            HARNESS_VERSION, self.golden["harness_version"],
            "the golden predates a change to the calls, the seed rule or the row "
            "projection, so re-bless it rather than comparing across the change",
        )

    def test_the_corpus_is_the_one_the_golden_was_recorded_over(self) -> None:
        """Same analyzer, same corpus -- otherwise the comparison means nothing.

        Arachne analyzes itself, so a golden recorded over the working tree drifts
        every time this file is edited, and the failures that produces look exactly
        like the regressions the harness exists to catch. Pinning the corpus to a
        commit is what separates "resolution changed" from "somebody saved a file".
        """
        recorded = self.golden.get("corpus", {}).get("revision")
        if recorded is None:
            self.skipTest("golden was recorded over an unpinned target")
        self.assertEqual(
            recorded, self.revision,
            "run the harness against the revision the golden names -- "
            "LACHESIS_EQUALITY_HARNESS=golden does exactly that",
        )

    def test_every_recorded_seed_still_resolves(self) -> None:
        """A seed that stopped resolving is the failure, not a reason to drop it."""
        seeds = pick_seeds(self.store)
        for recorded in self.golden["seeds"]:
            self.assertIsNotNone(
                self.store.resolve(recorded["name"]),
                f"{recorded['name']} ({recorded['file']}) no longer resolves",
            )
        self.assertGreaterEqual(
            len(seeds), len(self.golden["seeds"]),
            "the derived seed set shrank, which is itself a regression",
        )

    def test_the_nav_tools_answer_what_they_answered(self) -> None:
        relaxed = self.golden["graph_content_hash"] != graph_identity(self.store)
        if relaxed:
            # Phase 1 changes node ids without changing a source byte, so identity has
            # to be re-established from meaning. Everything else about the comparison,
            # including its asymmetry, is unchanged.
            print("graph hash differs: comparing in identity-relaxed mode",
                  file=sys.stderr)
        problems = compare(self.golden["results"], self._actual(), relaxed)
        self.assertEqual([], problems, "\n".join(problems))

    def test_every_returned_node_id_is_well_formed_and_distinct(self) -> None:
        """What identity-relaxed mode still gets to assert about ids.

        Relaxed mode stops comparing ids against the golden, which would otherwise let
        Phase 1 ship two declarations that collapsed onto one id. Within a single
        answer, distinctness is still checkable, and it is exactly the property the
        homonym work must not break.
        """
        actual = self._actual()
        for label in sorted(actual):
            if _tool_of(label) not in {"search", "callers", "callees"}:
                continue
            for field, rows in sorted(rows_of(actual[label]).items()):
                ids = [row["node_id"] for row in rows if row.get("node_id")]
                self.assertEqual(
                    len(ids), len(set(ids)), f"{label}.{field}: repeated node_id",
                )
                for node_id in ids:
                    self.assertIsNotNone(
                        self.store.node(node_id),
                        f"{label}.{field}: {node_id} is not in the graph",
                    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bless", metavar="TARGET",
                        help="record the baseline from this source tree or Kùzu store")
    parser.add_argument("--out", default=str(GOLDEN_PATH),
                        help="where to write it (defaults to the shipped golden)")
    args = parser.parse_args(argv)
    if not args.bless:
        parser.error("nothing to do; pass --bless <source-or-store>")
    if os.environ.get("LACHESIS_BLESS") != "1":
        parser.error(
            "refusing to bless without LACHESIS_BLESS=1. The baseline is what the "
            "harness is judged against, and the cheapest way to make a failing "
            "harness pass is to regenerate it."
        )
    payload = bless(args.bless, Path(args.out))
    print(f"blessed {len(payload['results'])} calls over {len(payload['seeds'])} "
          f"seeds -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
