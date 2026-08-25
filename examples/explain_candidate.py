#!/usr/bin/env python3
"""Explain one candidate in a single call -- the whole adjudication chain composed.

Judging a lead used to be a five-tool ritual, threaded by hand and copying node ids between
calls: census -> candidates -> candidate_detail -> sources_of -> read_body, identical for every
case. ``Analysis.explain`` composes that into one structured result: the obligation and where it
lands, the guard the enclosing function does (or does not) place over it, the bounded reverse
value-flow cone into the sink, and the enclosing function's source read inline. Provenance and
guard are evidence, never verdicts -- an empty cone is "nothing observed under this tier", not
"unreachable".

Run it:

    # explain the first structural candidate the graph carries
    python examples/explain_candidate.py ~/.lachesis/graphs/fixture_p3.kuzu

    # explain a specific candidate id (from `lachesis candidates` / the candidates tool)
    python examples/explain_candidate.py ~/.lachesis/graphs/curl.kuzu --id obl_0e994e4f22b6

    # explain whatever sink sits at a source position (a diff line, a stack frame)
    python examples/explain_candidate.py ~/.lachesis/graphs/curl.kuzu --at tree.c:185
"""
from __future__ import annotations

import argparse
import sys

import lachesis


def _first_candidate_id(analysis: "lachesis.Analysis") -> str | None:
    """The first structural candidate the graph carries -- a sensible default subject so the
    example runs with no id in hand. Structural (temporal off) keeps it fast and unbounded-safe."""
    for group in analysis.candidates(temporal=False, limit=200)["groups"]:
        if group.get("candidates"):
            return group["candidates"][0]["candidate_id"]
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("graph", help="path to a built .kuzu graph (~ is expanded)")
    parser.add_argument("--id", metavar="CANDIDATE_ID", help="the candidate to explain")
    parser.add_argument("--at", metavar="FILE:LINE", help="locate the sink by source position")
    parser.add_argument("--temporal", action="store_true",
                        help="evaluate the temporal families too (slower; forces the tier)")
    parser.add_argument("--hard-stop", type=float, default=None, metavar="SECONDS",
                        help="wall-clock budget for the temporal path (0 = unbounded)")
    args = parser.parse_args()

    analysis = lachesis.Analysis.open(args.graph)
    common = {"temporal": args.temporal, "hard_stop": args.hard_stop}

    if args.at:
        file, _, line = args.at.rpartition(":")
        if not file or not line.isdigit():
            parser.error("--at expects FILE:LINE, e.g. tree.c:185")
        result = analysis.explain_sink(file, int(line), **common)
    else:
        candidate_id = args.id or _first_candidate_id(analysis)
        if not candidate_id:
            print("no candidates in this graph (nothing structural to explain)", file=sys.stderr)
            return 1
        result = analysis.explain(candidate_id, **common)

    if "error" in result:
        print(result["error"], file=sys.stderr)
        if result.get("note"):
            print(f"  note: {result['note']}", file=sys.stderr)
        return 1

    sink = result["sink"]
    print(f"{result['candidate_id']}  [{result['constructor']}]  rank={result['rank']}")
    print(f"  obligation : {result['obligation']}")
    print(f"  sink       : {sink['callee']} at {sink['file']}:{sink['line']}")
    if sink.get("site"):
        print(f"               {sink['site']}")

    guard = result["guard"]
    dominance = (guard.get("dominance") or {}).get("status", "unknown")
    print(f"  guard      : conditions={guard.get('status')}, size-dominance={dominance}")

    provenance = result["provenance"]
    print(f"  provenance : reached={provenance.get('reached')} "
          f"shown={provenance.get('shown')} truncated={provenance.get('truncated')}")
    for source in provenance.get("sources", [])[:8]:
        where = f"{source.get('file')}:{source.get('line')}" if source.get("file") else "?"
        print(f"                <- {source.get('name')}  ({where})")

    source = result.get("source") or {}
    if source.get("body"):
        print(f"  source     : {source.get('name')} "
              f"({source.get('file')}:{source.get('start_line')}-{source.get('end_line')})")

    if result.get("other_matches"):
        print(f"  other sinks at this line: {', '.join(result['other_matches'])}")
    if not result.get("temporal_evaluated"):
        print("  (temporal families not evaluated on this run -- an absent double-free/UAF here "
              "reads as 'not evaluated', never 'clean')")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
