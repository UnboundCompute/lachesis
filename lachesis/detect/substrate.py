"""Data-driven detection core.

CLASS-first, not language-first: a sink argument's *kind* (from the atropos catalog --
`command-injection`, `alloc-size`, `weak-crypto`, ...) selects the detection recipe.
Adding a new sink kind to the catalog that maps to an existing evaluator adds a whole
detection category with ZERO engine code. A genuinely new evaluation primitive is the
only thing that needs code -- that is the closed-evaluator-set promise.

Three layers, kept separable so each can graduate to its destination:

  (a) PATTERN DATA  -- the `kind -> evaluator` table. Pure data, and it now lives
                       where it belongs: the atropos catalog (detection/evaluators.json),
                       loaded by `catalog.py` and PASSED IN to `evaluate` here. This
                       module holds none of it, so a new catalogued kind that maps to an
                       existing evaluator adds a category with no change to this file.
  (b) EVALUATORS    -- a CLOSED set of generic predicates over the substrate. This is
                       the one thing that IS code: reachability / relational / presence
                       today; typestate and differential are the next primitives (need
                       an effect catalog + object id).
  (c) SUBSTRATE     -- the neutral fact a sink occurrence presents to a pattern:
                       {kind, tainted, value_bound, guarded}. Every bug is a predicate
                       over these dimensions (op/effect, object reachability, value,
                       control).

The recipe (a) is data and is injected; the evaluators (b) and substrate (c) are the
closed, graph- and catalog-neutral core. This module imports nothing and does no I/O,
so it is testable with a synthetic recipe table.
"""


# ---- (c) SUBSTRATE -------------------------------------------------------------------------
def substrate(sink_kind, tainted, value_bound, guarded):
    """The dimensions every pattern predicates over, built once per sink occurrence:
      kind        -- the op / effect identity (atropos sink-arg kind)
      tainted     -- does an attacker-controlled value reach this arg (from the tainter)
      value_bound -- "unbounded" | "bounded" | None (None = arg carries no length obligation)
      guarded     -- is there a control guard on the value at the sink
    """
    return {"kind": sink_kind, "tainted": bool(tainted),
            "value_bound": value_bound, "guarded": bool(guarded)}


# ---- (b) EVALUATORS (closed set) -----------------------------------------------------------
def _reachability(fact):
    """Injection / traversal: an attacker-controlled value reaching the sink arg IS the lead.
    No bound obligation exists on the arg, so taint alone fires (command/sql/xss/ssrf/...)."""
    return fact["tainted"]


def _relational(fact):
    """Size / memory: the delivered length must be BOTH attacker-influenced AND unbounded vs
    the buffer capacity. Either alone is normal (a bounded tainted length, an unbounded
    constant). No taint -> no lead."""
    return fact["tainted"] and fact["value_bound"] == "unbounded"


def _presence(fact):
    """Configuration weakness (weak crypto, insecure TLS, predictable temp file): the CALL
    ITSELF is the defect regardless of taint. Fires on presence -- taint is not consulted."""
    return True


EVALUATORS = {
    "reachability": _reachability,
    "relational":   _relational,
    "presence":     _presence,
}


# ---- (a) PATTERN DATA: injected, not held here ---------------------------------------------
# The `kind -> evaluator` recipe is DATA in the atropos catalog (detection/evaluators.json).
# `catalog.py` loads it and callers pass it in as `kind_evaluator` -- a plain
# {kind: evaluator-name} dict. This module intentionally holds no copy: the "add knowledge
# without code" seam is a row in atropos, never an edit here.


def evaluate(sink_kind, fact, kind_evaluator):
    """Route a substrate fact through the evaluator its kind selects, per the recipe table.
    Returns the evaluator name if the pattern fires, else None (kind absent from the recipe,
    or the predicate is not satisfied)."""
    ev = kind_evaluator.get(sink_kind)
    if ev is None:
        return None
    return ev if EVALUATORS[ev](fact) else None


def is_call_level(sink_kind, kind_evaluator):
    """Occurrence granularity of a kind, read off the recipe. Presence-class kinds are
    CALL-level: the defect is that the sink is CALLED (weak crypto, insecure TLS), so it must
    be collected per-call and fires even with constant arguments. Every other class is
    ARG-level: the occurrence is a (call, argument) pair carrying a value the taint/bound
    predicates read. Adding a new presence KIND needs no code; only a new occurrence
    granularity would."""
    return kind_evaluator.get(sink_kind) == "presence"
