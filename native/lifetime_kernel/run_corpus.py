"""End-to-end FP/FN regression runner for the native lifetime matcher.

Compiles the C fixtures in this directory into one graph, runs the temporal
census, and checks every COMPLETE lifetime finding against a manifest that
declares, per fixture family:

  * the positive control `<family>_bug`  -- must raise exactly the target family
    (and, being single-defect by construction, nothing else); and
  * the negative control `<family>_clean` -- must raise NOTHING.

The overriding invariant is *no false positive on any clean control*: a COMPLETE
temporal finding anywhere inside a `*_clean` (or `*_idiom_clean`) body fails the
run outright.  Families the reader cannot yet confirm end to end are declared
`known_fn` -- their bug control is asserted to raise nothing today, so the day
the reader learns them this runner flips to red and the expectation is updated
deliberately rather than drifting silently.

Each fixture is a single translation unit written to exhibit exactly one defect:
allocations in a bug that targets some *other* family are guarded (to suppress an
incidental null-deref) and freed (to suppress an incidental leak), so the target
family is the only COMPLETE finding its bug body can produce.

Runnable directly (`python run_corpus.py`, exit code 0/1) or importable: the
pytest wrapper in ``lachesis/planner/test_lifetime_corpus.py`` calls
``run(...)``.  One graph is built per invocation, into a caller-supplied scratch
directory that the caller deletes -- no graph artifact outlives the run.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

CORPUS_DIR = Path(__file__).resolve().parent / "corpus"
REPO_ROOT = CORPUS_DIR.parents[2]

# Per-fixture expectation.  `family` is the temporal family the bug control must
# raise; `status` is "detected" (reader confirms it today) or "known_fn" (a
# documented false-negative: the bug control raises nothing yet).
MANIFEST = {
    "double_free.c":            ("double-free",          "detected"),
    "use_after_free.c":         ("use-after-free",       "detected"),
    "leak.c":                   ("leak",                 "detected"),
    "null_deref.c":             ("null-deref",           "detected"),
    "use_after_return.c":       ("use-after-return",     "detected"),
    # dangling-use (free through an alias, then use) is reported under the
    # use-after-free family by the current reader.
    "dangling_use.c":           ("use-after-free",       "detected"),
    "realloc_failure_leak.c":   ("realloc-failure-leak", "detected"),
    "uninitialized_use.c":      ("uninitialized-use",    "known_fn"),
    "unchecked_return_deref.c": ("unchecked-return-deref", "known_fn"),
    "aggregate_copy_alias.c":   ("double-free",          "detected"),
}


def _family_of(constructor: str) -> str:
    # constructor ids look like "mem.lifetime.double-free"; keep the leaf.
    return str(constructor).rsplit(".", 1)[-1]


def _clean_start_line(source: str) -> int:
    """1-based line where the negative-control function begins.

    Every fixture holds a `*_bug` first and a `*_clean`/`*_idiom_clean` second;
    the returned line splits bug (below it) from clean (at or after it).
    """
    for i, line in enumerate(source.splitlines(), start=1):
        if re.match(r"^\S.*\b\w*clean\s*\(", line):
            return i
    return 1 << 30  # no clean control -> nothing is "in the clean region"


def _build_graph(graph_path: Path) -> None:
    subprocess.run(
        ["lachesis", "build", str(CORPUS_DIR), str(graph_path), "--timeout", "3600"],
        check=True, capture_output=True, text=True,
    )


def _complete_temporal_findings(graph_path: Path):
    """[(basename, line, family)] for every COMPLETE lifetime finding."""
    os.environ.setdefault("ATROPOS_ROOT", str(REPO_ROOT.parent / "atropos"))
    from lachesis.session import Analysis

    analysis = Analysis.open(str(graph_path))
    res = analysis.candidates(temporal=True, detail="full", limit=1000)
    out = []
    for group in res.get("groups") or [res]:
        constructor = str(group.get("constructor", ""))
        if not constructor.startswith("mem.lifetime."):
            continue
        family = _family_of(constructor)
        for row in group.get("candidates", []):
            if row.get("completeness") != "COMPLETE":
                continue
            obs = row.get("observations") or {}
            path = obs.get("file") or ""
            line = obs.get("line")
            if line is None:
                continue
            out.append((os.path.basename(path), int(line), family))
    return out


def run(graph_path: Path, *, verbose: bool = True) -> list[str]:
    """Build, census, adjudicate.  Returns a list of failure strings (empty=pass)."""
    _build_graph(graph_path)
    findings = _complete_temporal_findings(graph_path)

    clean_start = {
        name: _clean_start_line((CORPUS_DIR / name).read_text())
        for name in MANIFEST
    }
    by_file: dict[str, list[tuple[int, str]]] = {name: [] for name in MANIFEST}
    stray: list[tuple[str, int, str]] = []
    for name, line, family in findings:
        if name in by_file:
            by_file[name].append((line, family))
        else:
            stray.append((name, line, family))

    failures: list[str] = []
    for name, (want_family, status) in MANIFEST.items():
        rows = by_file[name]
        split = clean_start[name]
        clean_hits = [(ln, fam) for ln, fam in rows if ln >= split]
        bug_hits = [(ln, fam) for ln, fam in rows if ln < split]

        # (1) the load-bearing invariant: clean controls raise nothing.
        for ln, fam in clean_hits:
            failures.append(
                f"FALSE POSITIVE: {name}:{ln} raised '{fam}' inside the clean control")

        bug_families = {fam for _, fam in bug_hits}
        if status == "detected":
            # (2a) the target family fires...
            if want_family not in bug_families:
                failures.append(
                    f"FALSE NEGATIVE: {name} bug did not raise '{want_family}' "
                    f"(raised {sorted(bug_families) or 'nothing'})")
            # (2b) ...and, single-defect by construction, nothing else does.
            extra = bug_families - {want_family}
            if extra:
                failures.append(
                    f"UNEXPECTED: {name} bug raised extra families {sorted(extra)}")
        else:  # known_fn -- documents a false-negative that must stay honest.
            if want_family in bug_families:
                failures.append(
                    f"FN CLOSED (update manifest to 'detected'): {name} bug now "
                    f"raises '{want_family}'")
            if bug_families:
                failures.append(
                    f"UNEXPECTED: {name} known-fn bug raised {sorted(bug_families)}")

    for name, ln, fam in stray:
        failures.append(f"STRAY finding in unlisted file {name}:{ln} ('{fam}')")

    if verbose:
        print(f"[corpus] {len(findings)} COMPLETE temporal findings over "
              f"{len(MANIFEST)} fixtures")
        for name in MANIFEST:
            rows = sorted(by_file[name])
            print(f"  {name:<26} {MANIFEST[name][1]:<9} -> {rows}")
        if failures:
            print("\n[corpus] FAILURES:")
            for f in failures:
                print("  -", f)
        else:
            print("[corpus] PASS: all TPs present, all clean controls silent")
    return failures


def _main() -> int:
    import tempfile, shutil
    scratch = Path(tempfile.mkdtemp(prefix="corpus-"))
    graph = scratch / "corpus.kuzu"
    try:
        sys.path.insert(0, str(REPO_ROOT))
        failures = run(graph)
        return 1 if failures else 0
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(_main())
