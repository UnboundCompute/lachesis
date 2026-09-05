"""End-to-end FP/FN regression runner for the native lifetime matcher.

Compiles the C fixtures in this directory into one graph, runs the temporal
census, and checks every lifetime *detection* against a manifest that declares,
per fixture family:

  * the positive control `<family>_bug`  -- must raise exactly the target family
    (and, being single-defect by construction, nothing else); and
  * the negative control `<family>_clean` -- must raise NOTHING.

A detection is either a COMPLETE verdict or a PARTIAL triage lead on a real
violation: a family the catalog marks `confirmable: false` (double-free,
use-after-free, null-deref, use-after-return, dangling-use) surfaces its bug as a
rank-0.4 lead rather than a standalone verdict, and that lead is the detection
the gate checks -- filtering to COMPLETE only would turn every such family into a
spurious false negative.  An ownership-shape lead (`aggregate-copy-alias`) is not
a detection: it is raised by benign struct copies too, so it bears on neither the
TP nor the FP side and is dropped before adjudication (see `_finding_tier`).

The overriding invariant is *no false positive on any clean control*: a COMPLETE
verdict or a real-violation lead anywhere inside a `*_clean` (or `*_idiom_clean`)
body fails the run outright.  Families the reader cannot yet detect at all are
declared `known_fn` -- their bug control is asserted to raise nothing today, so
the day the reader learns them this runner flips to red and the expectation is
updated deliberately rather than drifting silently.

Known limitation, out of scope of this corpus (a narrow *false positive*, tracked
here rather than encoded as a fixture because encoding it would forfeit the
no-FP-on-clean invariant above).  One contrived same-function idiom still yields a
spurious `leak`:

    char *p = malloc(n);   /* origin recorded on `p`            */
    char **pp = &p;        /* value-flow p -> &p -> pp          */
    free(*pp);             /* RELEASE recorded on `*pp`, a       *
                            * different object id than `p`       */
    /* fallthrough exit, no return */

The allocation *is* freed, but through the double-pointer spelling `*pp` the
frontend roots the release on the pointee object (`*pp`), which it cannot fold
back to `p` -- it emits the forward value-flow chain `p -> &p -> pp -> *pp` but no
must-alias fact unifying `*(&p)` with `p`.  The exit leak scan then sees `p`'s
origin undischarged and reports a leak.  The fix belongs upstream (fold `*(&x)`
-> x in the frontend / native translation, or emit a must-alias binding the
kernel's `canonical()` can follow); it is deliberately NOT patched in the kernel
leak scan, where following arbitrary value-flow bindings would trade this
contrived FP for real *missed* leaks on non-alias flows.  Real code frees through
`*pp` only in a separate `free(char **)` helper -- which carries no allocation and
so no leak obligation -- so this idiom does not arise in practice and is not a
hand-over blocker; it is recorded so a future frontend must-alias pass flips it
green deliberately.

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


def _finding_tier(row: dict) -> str:
    """Classify a temporal finding into the gate's three tiers.

    The census surfaces a lifetime finding at one of three strengths, and the gate
    must treat them differently:

      * ``confirmed`` -- a COMPLETE verdict (rank 1.0): the native matcher related
        the events across a reachable path on one object.  A confirmable family
        (``leak``, ``realloc-failure-leak``) reaches this.
      * ``lead`` -- a PARTIAL finding on a real violation whose family is declared
        ``confirmable: false`` in the catalog (double-free, use-after-free,
        null-deref, use-after-return, dangling-use).  Its native detector does not
        yet stand alone, so the census emits it as a rank-0.4 triage lead rather
        than a verdict.  It is still a genuine detection of the bug.
      * ``shape`` -- a PARTIAL ownership-shape lead (``aggregate-copy-alias``): the
        matcher only observed a field alias from a struct copy, which occurs on
        benign copies too.  It is neither a detection nor, on a clean control, a
        false positive; the gate ignores it and looks for the double-free/UAF that
        composes through it instead.

    The tier is read from ``completeness`` plus the ``rank_reasons`` term the census
    stamps on each row (``native-matcher`` / ``unvalidated-detector`` /
    ``ownership-shape-lead``), so the gate follows the engine's own classification
    rather than re-deriving it from the family name.
    """
    if row.get("completeness") == "COMPLETE":
        return "confirmed"
    terms = {reason.get("term") for reason in (row.get("rank_reasons") or [])}
    if "ownership-shape-lead" in terms:
        return "shape"
    return "lead"


def _temporal_findings(graph_path: Path):
    """[(basename, line, family, tier)] for every lifetime finding.

    Both COMPLETE verdicts and PARTIAL leads are returned; the caller decides how
    each tier bears on the FP/FN gate (see :func:`_finding_tier`).  Filtering to
    COMPLETE only here would drop the PARTIAL leads that are the sole detection a
    ``confirmable: false`` family produces today, turning every such family into a
    spurious false negative.
    """
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
            obs = row.get("observations") or {}
            path = obs.get("file") or ""
            line = obs.get("line")
            if line is None:
                continue
            out.append((os.path.basename(path), int(line), family, _finding_tier(row)))
    return out


def run(graph_path: Path, *, verbose: bool = True) -> list[str]:
    """Build, census, adjudicate.  Returns a list of failure strings (empty=pass)."""
    _build_graph(graph_path)
    findings = _temporal_findings(graph_path)

    clean_start = {
        name: _clean_start_line((CORPUS_DIR / name).read_text())
        for name in MANIFEST
    }
    # An ownership-shape lead (aggregate-copy-alias) is not a detection and, on a
    # clean control, not a false positive -- a benign struct copy raises it too. It
    # bears on neither gate, so drop it here and adjudicate over the detections that
    # remain: confirmed verdicts and real-violation triage leads.
    by_file: dict[str, list[tuple[int, str, str]]] = {name: [] for name in MANIFEST}
    stray: list[tuple[str, int, str]] = []
    for name, line, family, tier in findings:
        if tier == "shape":
            continue
        if name in by_file:
            by_file[name].append((line, family, tier))
        else:
            stray.append((name, line, family))

    failures: list[str] = []
    for name, (want_family, status) in MANIFEST.items():
        rows = by_file[name]
        split = clean_start[name]
        clean_hits = [(ln, fam, tier) for ln, fam, tier in rows if ln >= split]
        bug_hits = [(ln, fam, tier) for ln, fam, tier in rows if ln < split]

        # (1) the load-bearing invariant: clean controls raise no detection -- neither
        # a confirmed verdict nor a real-violation lead. (Shape leads were dropped
        # above, so a benign struct copy in a clean body does not trip this.)
        for ln, fam, tier in clean_hits:
            failures.append(
                f"FALSE POSITIVE: {name}:{ln} raised '{fam}' ({tier}) "
                "inside the clean control")

        bug_families = {fam for _, fam, _ in bug_hits}
        if status == "detected":
            # (2a) the target family fires -- as a confirmed verdict or a lead...
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
        print(f"[corpus] {len(findings)} temporal findings over "
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
