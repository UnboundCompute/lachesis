"""The relational evaluator's `value_bound`, delegated to the planner's capacity proof.

detect computes the TAINT half of a lead; it does not compute object sizes. The
capacity half already exists, publicly, in ``lachesis.planner``: ``MemoryCopyCapacity``
enumerates every atropos-model memory-copy sink and resolves -- soundly, object-size
only -- whether a copy's length exceeds its destination's fixed capacity. It leaves
``input_reachability: not-queried`` because the planner is taint-blind. The two halves
are complementary and share no code: the planner never asks "is this attacker-
influenced", detect never computes a capacity. This module is the seam that joins them.
It IMPORTS the planner (never reimplements object-size) and projects its capacity status
onto the substrate's ``value_bound`` so a relational lead can fire exactly where detect's
taint MEETS the planner's exceeds/unproven capacity.

The join is by node id: the planner keys each obligation by the store's canonical value
ids (``handles.obligation_value_ids``), and ``materialize_graph`` decodes ids back to
that same canonical space -- so a value id here is the same value id the taint flood
floods over. A value id absent from the returned map simply has no capacity evidence,
and its ``value_bound`` stays ``None`` (the relational evaluator then does not fire).
"""
from lachesis.planner.unbounded_copy import MemoryCopyCapacity


# The planner's object-size status -> the substrate's value_bound. Only three statuses
# carry a bound; the rest ("unknown", "capacity-known-in-elements") are no evidence.
#
#   exceeds-capacity            a literal copy provably overwrites a known fixed capacity
#   capacity-known-size-unknown fixed capacity, size is a non-literal (open) expression
#     -> both read as "unbounded": the length is not proven within the buffer. Gated by
#        taint in the evaluator, so neither alone is a lead -- only an unbounded length an
#        attacker can influence is.
#   within-capacity             a literal copy provably fits -> "bounded" (suppresses)
_STATUS_BOUND = {
    "exceeds-capacity": "unbounded",
    "capacity-known-size-unknown": "unbounded",
    "within-capacity": "bounded",
}


def capacity_bounds(stamped_graph, bind_summary=None):
    """Map each memory-copy obligation value id to its ``value_bound``.

    Runs the planner's capacity enumeration over an atropos-model-stamped graph and
    projects each candidate's ``destination_capacity.status`` onto the substrate bound.
    Returns ``{value_id: "unbounded" | "bounded"}``; ids with no capacity evidence are
    absent. ``unbounded`` dominates ``bounded`` when a value appears in more than one
    obligation -- any single copy that can overflow leaves the value relationally open.
    """
    bounds: dict[str, str] = {}
    result = MemoryCopyCapacity(stamped_graph, bind_summary or {}).enumerate()
    for cand in result.get("candidates", ()):
        status = ((cand.get("inferences") or {}).get("destination_capacity") or {}).get("status")
        bound = _STATUS_BOUND.get(status)
        if bound is None:
            continue
        for vid in (cand.get("handles") or {}).get("obligation_value_ids", ()):
            if not vid:
                continue
            if bounds.get(vid) != "unbounded":
                bounds[vid] = bound
    return bounds
