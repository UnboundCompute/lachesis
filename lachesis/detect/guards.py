"""The guard-aware evaluators' ``guard`` dimension, delegated to the planner's dominance.

detect computes the TAINT half of a lead; it does not compute control-flow dominance. That
half already exists, publicly, in the candidate registry: every obligation candidate carries
``inferences.conditions.dominance`` -- the planner's four-state answer to "where does this sink
sit relative to a branch that tests its variable?" (``guarded-region`` / ``fall-through`` /
``none-observed`` / not-computed). It is computed once, soundly, from the graph's branch-region
substrate. This module is the seam that projects it onto the substrate's ``guard`` dimension so
the guard-aware evaluators (``relational`` suppression, ``missing-guard``) can read it.

Like ``capacity.py`` it IMPORTS the analysis and never reimplements dominance. The join is by
node id: each candidate keys its obligation values (``handles.obligation_value_ids``), the same
canonical ids the taint flood floods over. A value absent from the returned map simply has no
guard evidence, and its ``guard`` stays ``None``.

Reuse over recompute: a caller that already holds an enumerated ``CandidateRegistry`` (the MCP
server's cached bundle) passes it in, so the guard status is read off the cached candidates with
no second enumeration. Given only a graph, a registry is built.
"""


# Only the two decided states carry a signal the evaluators act on. ``none-observed`` (no
# validating branch in the function) and ``undecided`` / ``not-computed`` are no evidence, so
# their values stay absent from the map (guard == None).
_DECIDED = ("guarded-region", "fall-through")


def _iter_candidates(registry):
    """Every candidate the registry enumerates, paging each constructor's full rows."""
    for meta in registry.constructors:
        cursor = None
        while True:
            page = registry.candidates(constructor=meta["id"], detail="full",
                                       limit=200, cursor=cursor)
            for row in page.get("candidates", ()):
                yield row
            cursor = page.get("next_cursor")
            if not cursor:
                break


def guard_status(stamped_graph, bind_summary=None, registry=None):
    """Map each obligation value id to its guard dominance status.

    Returns ``{value_id: "guarded-region" | "fall-through"}``; ids with no decided dominance
    are absent. ``fall-through`` dominates ``guarded-region`` when a value appears in more than
    one obligation -- the site that escapes its guard is the lead, so the anomaly is surfaced
    rather than masked by a sibling that happens to be checked.
    """
    if registry is None:
        from lachesis.planner.registry import default_candidate_registry
        registry = default_candidate_registry(stamped_graph, bind_summary or {})

    status: dict[str, str] = {}
    for row in _iter_candidates(registry):
        dominance = (((row.get("inferences") or {}).get("conditions") or {})
                     .get("dominance") or {}).get("status")
        if dominance not in _DECIDED:
            continue
        for vid in (row.get("handles") or {}).get("obligation_value_ids", ()):
            if not vid:
                continue
            if dominance == "fall-through" or status.get(vid) is None:
                status[vid] = dominance
    return status
