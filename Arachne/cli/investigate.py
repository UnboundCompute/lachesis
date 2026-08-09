#!/usr/bin/env python3
"""Run the lightweight Arachne LLM investigation loop over a canonical graph."""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

FIXTURE_ROOT = Path(__file__).resolve().parents[2]
RAVEN_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(FIXTURE_ROOT))
sys.path.insert(0, str(RAVEN_ROOT))

from Arachne.cli.query import load_graph
from Arachne.reasoning import InvestigationAgent, ReasoningQuery


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("graph", help="canonical project graph JSON")
    result.add_argument("--focus-id", help="optional exact canonical node ID")
    result.add_argument("--max-steps", type=int, default=8)
    result.add_argument("--slice-budget-tokens", type=int, default=2_500)
    result.add_argument("--model", help="Gemini model override passed to llmseam")
    result.add_argument("--bedrock-model", help="Bedrock model override passed to llmseam")
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        graph, metadata = load_graph(args.graph)
        query = ReasoningQuery(graph, project_metadata=metadata)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(json.dumps({"status": "INVALID_GRAPH", "error": str(error)}))
        return 2

    import llmseam

    llm = llmseam.make(
        model=args.model, max_calls=max(1, args.max_steps),
        bedrock_model=args.bedrock_model,
    )
    if not llmseam.is_live(llm):
        print(json.dumps({
            "schema_version": 1,
            "status": "LLM_UNAVAILABLE",
            "finding": None,
            "error": "llmseam did not find a configured live provider",
        }, indent=2))
        return 0

    from core.llm.base import LLMRequest

    agent = InvestigationAgent(
        query, llm, max_steps=args.max_steps,
        slice_budget_tokens=args.slice_budget_tokens,
        request_factory=LLMRequest,
    )
    try:
        result = asyncio.run(agent.run(args.focus_id))
    except KeyError as error:
        print(json.dumps({"status": "INVALID_FOCUS", "error": str(error)}))
        return 2
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
