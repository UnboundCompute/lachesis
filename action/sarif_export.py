#!/usr/bin/env python3
"""Export Lachesis security findings as SARIF 2.1.0.

v1. This is a thin, dependency-free renderer: it drives the existing
`lachesis-query` CLI (nothing private, no new engine) and maps the
source-to-sink paths and guard verdicts it already computes onto SARIF
results that GitHub code scanning renders inline on a PR.

    python3 action/sarif_export.py graph.kuzu -o lachesis.sarif

It reads one query when the engine supports it:
  * `security-paths` -> every reachable path's guard verdict, source, and sink
                        location in a single graph load (one process, not N).
Older engines that lack the batch command fall back to `overview` +
per-path `security-path` calls, which is correct but pays a graph reload each.

Findings are anchored at the sink call site, carry the tainted flow as a SARIF
codeFlow, and are leveled by guard status:
  UNGUARDED + guarded sibling exists -> error   (a real guard differential)
  UNGUARDED                          -> warning
  GUARDED                            -> note

Design notes for the next pass (kept deliberately simple for v1):
  * Rules are minted on demand; tune ids/help text later.
  * `--changed-files` does a post-hoc path filter. True seed-scoping
    (analyze only the changed cone) is a core-engine feature, not here.
  * Everything comes from public query output, so this stays OSS-clean.
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import os
import subprocess
import sys
from typing import Any, Dict, List, Optional

SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
INFO_URI = "https://github.com/UnboundCompute/lachesis"

# Guard status -> (ruleId, SARIF level, one-line rule description)
RULES: Dict[str, Dict[str, str]] = {
    "unguarded-differential": {
        "id": "lachesis/unguarded-sink-differential",
        "level": "error",
        "desc": "Untrusted input reaches a sink with no authorization check, "
                "while a sibling function guards the identical sink.",
    },
    "unguarded": {
        "id": "lachesis/unguarded-sink",
        "level": "warning",
        "desc": "Untrusted input reaches a sink with no authorization check on the path.",
    },
    "guarded": {
        "id": "lachesis/guarded-sink",
        "level": "note",
        "desc": "Untrusted input reaches a sink, but the path passes an authorization check.",
    },
    "reachable": {
        "id": "lachesis/reachable-sink",
        "level": "warning",
        "desc": "Untrusted input reaches a sink; guard status could not be determined.",
    },
}


def run_query(query_cmd: List[str], graph: str, *args: str) -> Dict[str, Any]:
    out = subprocess.check_output(
        [*query_cmd, "--format", "json", graph, *args],
        text=True,
    )
    return json.loads(out)


def classify(guard: Dict[str, Any]) -> str:
    status = (guard.get("status") or "").upper()
    if status == "UNGUARDED":
        return "unguarded-differential" if guard.get("differential_siblings") else "unguarded"
    if status == "GUARDED":
        return "guarded"
    return "reachable"


def rel_uri(path: Optional[str], repo_root: Optional[str]) -> Optional[str]:
    """Normalize a file path to a repo-root-relative POSIX uri for SARIF."""
    if not path:
        return None
    if os.path.isabs(path) and repo_root:
        try:
            path = os.path.relpath(path, repo_root)
        except ValueError:
            pass
    return path.replace(os.sep, "/").lstrip("./") or path


def step_location(step: Dict[str, Any]) -> Dict[str, Optional[Any]]:
    loc = (step.get("locator") or {}).get("location") or {}
    # Prefer the absolute path so rel_uri can rebase it on the repo root; this keeps
    # SARIF uris repo-root-relative even when `source` is a subdirectory (the query's
    # own `file` is relative to the analyzed source dir, not the repo root).
    return {
        "file": loc.get("absolute_file") or loc.get("file"),
        "line": loc.get("start_line"),
    }


def sarif_location(uri: Optional[str], line: Optional[int], message: Optional[str] = None) -> Dict[str, Any]:
    region: Dict[str, Any] = {}
    if line:
        region["startLine"] = int(line)
    phys: Dict[str, Any] = {"artifactLocation": {"uri": uri or "<unknown>"}}
    if region:
        phys["region"] = region
    out: Dict[str, Any] = {"physicalLocation": phys}
    if message:
        out["message"] = {"text": message}
    return out


def build_result(
    path_query: Dict[str, Any],
    detail: Dict[str, Any],
    repo_root: Optional[str],
) -> Optional[Dict[str, Any]]:
    summary = detail.get("summary") or {}
    guard = summary.get("guard") or {}
    steps = (detail.get("sections") or {}).get("path") or []
    if not steps:
        return None

    kind = classify(guard)
    rule = RULES[kind]

    label = path_query.get("label") or detail.get("focus", {}).get("label") or "tainted flow"
    handler = guard.get("handler_label") or "handler"
    sinks = ", ".join(guard.get("sink_names") or []) or "sink"
    siblings = ", ".join(guard.get("differential_siblings") or [])

    # Anchor at the sink (last path step); fall back to the guard's handler location.
    sink_loc = step_location(steps[-1])
    sink_uri = rel_uri(sink_loc["file"], repo_root)
    sink_line = sink_loc["line"]
    if not sink_uri:
        sink_uri = rel_uri(guard.get("file"), repo_root)
        sink_line = guard.get("line")
    if not sink_uri:
        # Nothing to anchor the finding to; SARIF requires a valid uri, so skip it
        # rather than emit an invalid "<unknown>" location.
        return None

    msg = f"Tainted flow reaches `{sinks}` in `{handler}` — {(guard.get('status') or 'REACHABLE')}. Flow: {label}."
    if siblings:
        msg += f" Sibling `{siblings}` guards the same sink (guard differential)."
    confidence = guard.get("confidence")
    if confidence:
        msg += f" [confidence: {confidence}]"

    # Full flow as a SARIF codeFlow so the PR view can walk source -> sink.
    thread_locs = []
    for st in steps:
        sl = step_location(st)
        uri = rel_uri(sl["file"], repo_root)
        if not uri:
            # A step with no resolvable file would emit an invalid uri; skip it.
            continue
        thread_locs.append({
            "location": sarif_location(
                uri, sl["line"],
                f"{st.get('kind', 'step')}: {st.get('label', '')}".strip(),
            )
        })

    result: Dict[str, Any] = {
        "ruleId": rule["id"],
        "level": rule["level"],
        "message": {"text": msg},
        "locations": [sarif_location(sink_uri, sink_line)],
        "partialFingerprints": {"lachesisPathId": path_query["id"]},
    }
    if thread_locs:
        result["codeFlows"] = [{"threadFlows": [{"locations": thread_locs}]}]
    return result


def collect_paths(query_cmd: List[str], graph: str) -> List[Dict[str, Any]]:
    """Return [{path_query, detail}] for every reachable path.

    Prefers the batch `security-paths` query: it loads and materializes the graph
    once, so N findings cost one graph load instead of N. Falls back to per-path
    `security-path` calls when the installed engine predates the batch command
    (the Action may install an older `lachesis-ref`).
    """
    try:
        batch = run_query(query_cmd, graph, "security-paths")
        entries = batch.get("paths")
        if entries is not None:
            return [
                {"pq": {"id": e.get("id"), "label": e.get("label")},
                 "detail": e.get("detail") or {}}
                for e in entries
            ]
    except (subprocess.CalledProcessError, json.JSONDecodeError):
        pass  # older engine: fall back below
    overview = run_query(query_cmd, graph, "overview")
    security = (overview.get("manifest") or {}).get("security") or {}
    return [
        {"pq": pq, "detail": run_query(query_cmd, graph, "security-path", pq["id"])}
        for pq in (security.get("path_queries") or [])
    ]


def build_sarif(
    graph: str,
    query_cmd: List[str],
    repo_root: Optional[str],
    changed: Optional[set],
    excluded: Optional[List[str]] = None,
) -> Dict[str, Any]:
    results: List[Dict[str, Any]] = []
    used_rules: Dict[str, Dict[str, str]] = {}
    for entry in collect_paths(query_cmd, graph):
        res = build_result(entry["pq"], entry["detail"], repo_root)
        if res is None:
            continue
        uri = res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        if changed is not None and uri not in changed:
            continue
        if is_excluded(uri, excluded):
            continue
        results.append(res)
        for meta in RULES.values():
            if meta["id"] == res["ruleId"]:
                used_rules[meta["id"]] = meta

    rules = [
        {
            "id": meta["id"],
            "name": meta["id"].split("/")[-1].replace("-", " ").title().replace(" ", ""),
            "shortDescription": {"text": meta["desc"]},
            "defaultConfiguration": {"level": meta["level"]},
            "helpUri": INFO_URI,
        }
        for meta in used_rules.values()
    ]

    return {
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "Lachesis",
                "informationUri": INFO_URI,
                "rules": rules,
            }},
            "results": results,
        }],
    }


def load_changed(args: argparse.Namespace) -> Optional[set]:
    raw: List[str] = []
    if args.changed_from_file:
        with open(args.changed_from_file) as fh:
            raw.extend(fh.read().split())
    for chunk in args.changed_files or []:
        raw.extend(chunk.replace(",", " ").split())
    if not raw:
        return None
    return {p.replace(os.sep, "/").lstrip("./") for p in raw if p.strip()}


def load_excluded(args: argparse.Namespace) -> List[str]:
    """Normalize the --exclude patterns to repo-root-relative POSIX form."""
    raw: List[str] = []
    for chunk in args.exclude or []:
        raw.extend(chunk.replace(",", " ").split())
    return [p.replace(os.sep, "/").lstrip("./").rstrip("/") for p in raw if p.strip()]


def is_excluded(uri: str, patterns: Optional[List[str]]) -> bool:
    """True if a finding's file uri sits under, equals, or globs an excluded path.

    A bare directory (``a/b/fixtures``) drops everything beneath it; a glob
    (``**/fixtures/**``, ``*.min.js``) is matched with fnmatch. This is a report
    filter — the excluded code is still analyzed, its findings just aren't emitted.
    """
    if not patterns:
        return False
    for pat in patterns:
        if uri == pat or uri.startswith(pat + "/") or fnmatch.fnmatch(uri, pat):
            return True
    return False


def main() -> int:
    ap = argparse.ArgumentParser(description="Render Lachesis security findings as SARIF 2.1.0.")
    ap.add_argument("graph", help="path to the .kuzu store built by lachesis-analyze")
    ap.add_argument("-o", "--output", default="-", help="SARIF output file (default: stdout)")
    ap.add_argument("--repo-root", default=os.environ.get("GITHUB_WORKSPACE") or os.getcwd(),
                    help="root the SARIF uris are relative to (default: $GITHUB_WORKSPACE or cwd)")
    ap.add_argument("--query-cmd", default="python3 -m lachesis.cli.query",
                    help="how to invoke the query CLI (default: 'python3 -m lachesis.cli.query')")
    ap.add_argument("--changed-files", action="append",
                    help="only report findings in these files (repeatable / comma-separated)")
    ap.add_argument("--changed-from-file", help="read the changed-file list from this path")
    ap.add_argument("--exclude", action="append",
                    help="drop findings under these paths/globs, e.g. a fixtures or "
                         "vendor dir (repeatable / comma-separated)")
    args = ap.parse_args()

    query_cmd = args.query_cmd.split()
    changed = load_changed(args)
    excluded = load_excluded(args)
    sarif = build_sarif(args.graph, query_cmd, args.repo_root, changed, excluded)

    text = json.dumps(sarif, indent=2)
    n = len(sarif["runs"][0]["results"])
    if args.output == "-":
        print(text)
    else:
        with open(args.output, "w") as fh:
            fh.write(text)
    print(f"lachesis: wrote {n} finding(s) to {args.output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
