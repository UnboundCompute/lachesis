"""Pseudo-function skeletons: a function's sink landscape in its control skeleton.

A function that touches a critical sink is judged by *which* sinks it reaches and
*under what control* -- the branch that guards a write, the loop that repeats it.
This module strips each enclosing function down to exactly that: every catalogued
sink (across every family -- memory, os, file, logical, ...) shown in place, plus
the branch/loop structure that scopes them, with all other lines elided. The result
is the sink map of the function -- what it can do that matters, and the conditionals
and loops around each one -- so orientation is a single local read.

Slice criterion (keep the sinks and the control that scopes them):
  keep (1) every catalogued sink line, with *every* candidate on it (all families,
  not just one -- a line like ``fread(dst, n, 1, f)`` carries several obligations
  and all are shown), (2) every control predicate -- branches and loops
  (if/else/for/while/switch/case/do) and the flow edges inside them
  (return/break/continue/goto), so no guard or iteration is lost, and (3) the braces
  that carry nesting. Drop everything else. Provenance of a sink's operands (reaching
  defs, allocation site, destination capacity) is a drill-down -- it lives in
  candidate_detail / sources_of, not here; the skeleton is the map, not the trace.

Candidates are sourced from the live registry (every family), never a frozen
ledger -- so a rebuilt graph reskeletonizes without a re-freeze.
"""
from __future__ import annotations

import os
import re
from collections import defaultdict

# The control skeleton: branch and loop headers, plus the flow edges inside them
# (a `continue`/`return` in a guard is what tells reject from fall-through), plus
# brace-only lines so nesting survives the elision.
CTRL = re.compile(r'^\s*(if|else|for|while|switch|case|default|do|goto|return|break|continue)\b')
BRACE = re.compile(r'^\s*[{}]+\s*;?\s*$')


def candidates_by_function(registry) -> dict[str, list[dict]]:
    """Group every candidate, across every family, by enclosing function id.

    Enumerates the whole taxonomy (`registry.selected()`); results memoize inside
    the registry, so repeated skeleton calls pay the enumeration once.
    """
    byfunc: dict[str, list[dict]] = defaultdict(list)
    for key in registry.selected():
        try:
            rows = registry._result(key).get("candidates", [])
        except Exception:
            continue  # one bad family must not sink the whole grouping
        for row in rows:
            fid = (row.get("handles") or {}).get("enclosing_function_id")
            if fid:
                byfunc[fid].append(row)
    return byfunc


def _span(gl, fid: str):
    node = gl.nodes.get(fid)
    if not node:
        return None
    props = node.get("properties", {})
    path = props.get("absolute_file") or props.get("file")
    sl, el = props.get("start_line"), props.get("end_line")
    if not path or not sl or not el:
        return None
    return path, sl, el, node.get("label")


def _stmt_end(src: list[str], ln: int) -> int:
    """Extend a kept sink statement forward across continuation lines up to its ';'."""
    end = ln
    while end - 1 < len(src) and ';' not in src[end - 1] and '{' not in src[end - 1]:
        if end - ln > 6:
            break
        end += 1
    return end


def _sink_annotation(row: dict) -> str:
    """One annotation line for a single candidate sitting on a sink line.

    Co-locates the three facts that decide the obligation: the size expression, the
    destination-capacity status, and the guard dominance (`fall-through` = a size
    guard exists but the sink is reached around it; `guarded-region` = the sink is
    inside it; `none-observed` = no size guard at all). Every candidate on the line
    gets its own line -- nothing is clobbered by a line-mate.
    """
    obs = row.get("observations", {})
    inf = row.get("inferences", {})
    cap = (inf.get("destination_capacity") or {}).get("status", "?")
    dom = (inf.get("conditions", {}).get("dominance") or {}).get("status", "?")
    fam = row.get("constructor") or "?"
    cid = (row.get("candidate_id") or "")[:14]
    size = obs.get("size_expression")
    rank = row.get("rank")
    rank_s = f" rank={rank:.2f}" if isinstance(rank, (int, float)) else ""
    return f"<== SINK [{fam}] size=({size}) cap={cap} dom={dom}{rank_s}  {cid}"


def render_function(gl, fid: str, cands: list[dict],
                    keep_candidate_ids: set[str] | None = None) -> dict | None:
    """Render one enclosing function to a sink-and-control skeleton. Returns a dict
    with the text and a structured sink roster, or None when source is unavailable.

    ``keep_candidate_ids`` is an optional pure-rendering subset filter: when given,
    only candidates whose ``candidate_id`` is in the set are drawn (the rest are
    elided like any other non-kept line). This is what lets a caller show *not every
    catalogued sink but only the ones that survived some external judgement* -- e.g.
    a taint pass -- without the renderer itself knowing or deciding what survives.
    The subset is supplied; the skeleton stays a pure renderer.
    """
    sp = _span(gl, fid)
    if not sp:
        return None
    path, sl, el, name = sp
    text = gl._read_file(path)
    if text is None:
        return None
    src = text.splitlines()

    scoped = keep_candidate_ids is not None
    total_before = len(cands)
    if scoped:
        cands = [r for r in cands if r.get("candidate_id") in keep_candidate_ids]

    # line -> every candidate on it (all families). A dict-of-lists, never a scalar,
    # so two obligations sharing a line both survive -- the clobber that used to hide
    # the higher-signal candidate behind a line-mate is gone.
    sinks_at: dict[int, list[dict]] = defaultdict(list)
    for row in cands:
        ln = row.get("observations", {}).get("line")
        if ln is not None:
            sinks_at[ln].append(row)
    # lead each line with its highest-rank obligation, not whichever was enumerated last
    for ln in sinks_at:
        sinks_at[ln].sort(key=lambda r: -(r.get("rank") or 0.0))

    keep: set[int] = set()
    for ln in range(sl, el + 1):
        if ln - 1 >= len(src):
            break
        t = src[ln - 1]
        if ln == sl or ln in sinks_at or CTRL.match(t) or BRACE.match(t):
            keep.add(ln)
    # a sink call can wrap across lines -- keep its continuation through the ';'
    for ln in list(keep):
        if ln in sinks_at:
            for k in range(ln, _stmt_end(src, ln) + 1):
                keep.add(k)

    base = os.path.basename(path)
    total_sinks = sum(len(v) for v in sinks_at.values())
    header = f"{name}   {base}:{sl}-{el}   [{total_sinks} sink(s) over {len(sinks_at)} site(s)]"
    if scoped:
        header += f"   [taint-scoped: {total_sinks} of {total_before} survived]"
    out = [header, "=" * 78]
    elided = 0
    for ln in range(sl, el + 1):
        if ln - 1 >= len(src):
            break
        if ln in keep:
            if elided:
                out.append(f"          :  {elided} line(s) elided")
                elided = 0
            out.append(f"  {ln:5d}| {src[ln - 1].rstrip()}")
            for row in sinks_at.get(ln, []):
                out.append(f"          {_sink_annotation(row)}")
        else:
            elided += 1
    if elided:
        out.append(f"          :  {elided} line(s) elided")

    sinks = [{
        "candidate_id": r.get("candidate_id"),
        "family": r.get("constructor"),
        "domain": r.get("domain"),
        "line": r.get("observations", {}).get("line"),
        "callee": r.get("observations", {}).get("callee"),
        "size_expression": r.get("observations", {}).get("size_expression"),
        "rank": r.get("rank"),
    } for r in cands]
    return {
        "function": name,
        "function_id": fid,
        "file": path,
        "start_line": sl,
        "end_line": el,
        "sink_count": len(cands),
        "sink_sites": len(sinks_at),
        "kept_lines": len(keep),
        "total_lines": el - sl + 1,
        "scoped": scoped,
        "sinks_before_scope": total_before if scoped else None,
        "sinks": sinks,
        "text": "\n".join(out),
    }


def skeleton_for_function(gl, registry, fid: str,
                          keep_candidate_ids: set[str] | None = None) -> dict:
    """Skeleton for a function node id, with all its sinks (every family).

    ``keep_candidate_ids`` is forwarded to :func:`render_function` as a pure
    subset filter -- give it the candidate ids that survived taint to get a
    skeleton scoped to just those, or leave it None for the full sink map.
    """
    cands = candidates_by_function(registry).get(fid, [])
    if not cands:
        node = gl.nodes.get(fid)
        if node is None:
            return {"error": f"unknown function id: {fid}"}
        return {"error": f"no candidates enclosed by {fid}", "function": node.get("label")}
    rendered = render_function(gl, fid, cands, keep_candidate_ids=keep_candidate_ids)
    if rendered is None:
        return {"error": f"could not render function: {fid}"}
    return rendered


def skeleton_for_candidate(gl, registry, candidate_id: str) -> dict:
    """Skeleton for the function that encloses a given candidate."""
    row = registry.detail(candidate_id).get("candidate")
    if not row:
        return {"error": f"unknown candidate: {candidate_id}"}
    fid = (row.get("handles") or {}).get("enclosing_function_id")
    if not fid:
        return {"error": f"candidate has no enclosing function: {candidate_id}"}
    result = skeleton_for_function(gl, registry, fid)
    result["focus_candidate"] = candidate_id
    return result
