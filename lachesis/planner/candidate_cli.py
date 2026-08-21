#!/usr/bin/env python3
"""CLI for exhaustive, verdict-free obligation candidates."""
from __future__ import annotations

import argparse
import json
import sys

from lachesis.integrations.atropos.enrich import atropos_enrich
from lachesis.cache import _version
from lachesis.nav.graph_store import GraphStore
from lachesis.nav.kuzu_index import materialize_graph
from lachesis.planner.registry import default_candidate_registry


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lachesis-candidates",
        description="enumerate Atropos-backed obligations without judging safety")
    parser.add_argument("--version", action="version", version=_version())
    parser.add_argument("graph", help="path to a Lachesis .kuzu store")
    parser.add_argument("--constructor", default="memory.copy.capacity")
    parser.add_argument("--domain")
    parser.add_argument("--language")
    parser.add_argument("--limit", type=int, default=40)
    parser.add_argument("--cursor")
    parser.add_argument("--detail", choices=("brief", "compact", "full"), default="compact")
    parser.add_argument("--candidate-id", help="return one full candidate capsule")
    parser.add_argument("--census", action="store_true",
                        help="return counts and coverage frontiers instead of rows")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(sys.argv[1:] if argv is None else argv)
    store = GraphStore.load(args.graph)
    stamped, summary = atropos_enrich(
        materialize_graph(store.index), complete_dataflow=False)
    if not summary.get("applied"):
        print(json.dumps({
            "applied": False, "reason": summary.get("reason"),
            "hint": "set ATROPOS_ROOT or place an Atropos checkout beside Lachesis",
        }, indent=2))
        return 2

    registry = default_candidate_registry(stamped, summary)
    if args.candidate_id:
        result = registry.detail(args.candidate_id)
    elif args.census:
        result = registry.census(args.constructor)
    else:
        result = registry.candidates(
            constructor=args.constructor, domain=args.domain, language=args.language,
            limit=args.limit, cursor=args.cursor, detail=args.detail)
    # Census carries the full per-language `unbound` rosters; the list/detail
    # paths keep the status counts only, so a page stays bounded (mirrors the
    # MCP server's _atropos_envelope split).
    per_language = summary.get("per_language", {})
    if not args.census:
        per_language = {lang: {k: v for k, v in stats.items() if k != "unbound"}
                        for lang, stats in per_language.items()}
    result["atropos"] = {
        "root": summary.get("atropos_root"),
        "languages": summary.get("languages", []),
        "bind": per_language,
    }
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 1 if result.get("error") else 0


if __name__ == "__main__":
    raise SystemExit(main())
