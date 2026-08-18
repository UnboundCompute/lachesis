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
def substrate(sink_kind, tainted, value_bound, guard=None):
    """The dimensions every pattern predicates over, built once per sink occurrence:
      kind        -- the op / effect identity (atropos sink-arg kind)
      tainted     -- does an attacker-controlled value reach this arg (from the tainter)
      value_bound -- "unbounded" | "bounded" | None (None = arg carries no length obligation)
      guard       -- control-flow dominance of the sink relative to a validating branch,
                     the planner's already-computed four-state signal (never recomputed here):
                       "guarded-region" -- the sink runs only under a branch that tests the
                                           relevant variable (checked)
                       "fall-through"   -- such a branch EXISTS in the function but the sink is
                                           reached outside it (the missing-guard shape)
                       "none-observed"  -- no validating branch exists in the function
                       None             -- no guard evidence computed for this occurrence
    """
    return {"kind": sink_kind, "tainted": bool(tainted),
            "value_bound": value_bound, "guard": guard}


# ---- (b) EVALUATORS (closed set) -----------------------------------------------------------
def _reachability(fact):
    """Injection / traversal: an attacker-controlled value reaching the sink arg IS the lead.
    No bound obligation exists on the arg, so taint alone fires (command/sql/xss/ssrf/...)."""
    return fact["tainted"]


def _relational(fact):
    """Size / memory: the delivered length must be BOTH attacker-influenced AND unbounded vs
    the buffer capacity. Either alone is normal (a bounded tainted length, an unbounded
    constant). No taint -> no lead. A copy that runs only inside a size-testing branch
    (``guard == "guarded-region"``) is a checked copy, so it is suppressed."""
    return (fact["tainted"] and fact["value_bound"] == "unbounded"
            and fact.get("guard") != "guarded-region")


def _presence(fact):
    """Configuration weakness (weak crypto, insecure TLS, predictable temp file): the CALL
    ITSELF is the defect regardless of taint. Fires on presence -- taint is not consulted."""
    return True


def _missing_guard(fact):
    """Control-flow anomaly: a validating branch that tests this obligation's variable EXISTS
    in the enclosing function, but the sink is reached on the fall-through path outside that
    branch's region. The absent check IS the lead, so this is taint-INDEPENDENT (like presence)
    -- an attacker-reachable path is a separate, stronger corroboration the caller can add.
    Distinct from ``none-observed`` (no guard concept in the function at all), which never
    fires here: the signal is specifically a guard that this site escapes."""
    return fact.get("guard") == "fall-through"


EVALUATORS = {
    "reachability": _reachability,
    "relational":   _relational,
    "presence":     _presence,
    "missing-guard": _missing_guard,
}


# ---- (a) PATTERN DATA: injected, not held here ---------------------------------------------
# The `kind -> evaluator` recipe is DATA in the atropos catalog (detection/evaluators.json).
# `catalog.py` loads it and callers pass it in as `kind_evaluator` -- a plain
# {kind: evaluator-name} dict. This module intentionally holds no copy: the "add knowledge
# without code" seam is a row in atropos, never an edit here.


def _evaluators_for(sink_kind, kind_evaluator):
    """The evaluator names a kind selects. A recipe value is either one evaluator name or a
    LIST of them -- a kind can trigger several patterns over the one flow (e.g. a memory copy
    is both a `relational` size check and a `missing-guard` control-flow check). A bare string
    is normalized to a one-element list, so the single- and multi-pattern forms are one path."""
    spec = kind_evaluator.get(sink_kind)
    if spec is None:
        return []
    return [spec] if isinstance(spec, str) else list(spec)


def evaluate(sink_kind, fact, kind_evaluator):
    """Route a substrate fact through EVERY evaluator its kind selects, per the recipe table.
    Returns the list of evaluator names that fired (empty if the kind is absent from the recipe
    or no predicate is satisfied). A kind mapped to several evaluators can yield several leads
    for one occurrence -- each fired pattern is its own lead."""
    return [ev for ev in _evaluators_for(sink_kind, kind_evaluator) if EVALUATORS[ev](fact)]


def is_call_level(sink_kind, kind_evaluator):
    """Occurrence granularity of a kind, read off the recipe. A kind is CALL-level when any of
    its evaluators is taint-INDEPENDENT (`presence`: the sink being CALLED is the defect --
    weak crypto, insecure TLS; `missing-guard`: the absent check is the defect), so it must be
    collected per-call and fires even with constant arguments. Otherwise it is ARG-level: the
    occurrence is a (call, argument) pair carrying a value the taint/bound predicates read."""
    names = _evaluators_for(sink_kind, kind_evaluator)
    return "presence" in names or "missing-guard" in names
