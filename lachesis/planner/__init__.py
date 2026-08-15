"""The planner: graph facts in, ranked investigation capsules out.

`nav/` is the verdict-free retrieval surface — it answers questions and never
decides anything. The planner is the layer that *does* decide, under one rule:

    the graph owns "don't miss", the judge owns "don't false-positive"

The obligation registry is stricter than the legacy differential planner: it
enumerates every observable Atropos attachment and never suppresses a site or emits
a safe/unsafe state. Its capsules are facts and bounded inferences for a downstream
judge. The older differential constructor retains its documented suppression model.
"""

from .registry import CandidateRegistry, default_candidate_registry

__all__ = ["CandidateRegistry", "default_candidate_registry"]
