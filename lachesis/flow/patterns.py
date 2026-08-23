"""Data-driven detector substrate.

The detector is CLASS-first, not language-first: a sink argument's *kind* (from the atropos
catalog -- `command-injection`, `alloc-size`, `weak-crypto`, ...) selects the detection recipe.
Adding a new sink kind to the catalog with an existing evaluator adds a whole detection category
with ZERO engine code. A genuinely new evaluation primitive is the only thing that needs code --
that is the closed-evaluator-set promise.

Three layers, kept separable so each graduates to its destination:

  (a) PATTERN DATA  -- the `kind -> evaluator` table. Pure data. Graduates to atropos, where
                       every language's sink rows already live, so one library holds all
                       knowledge and new rows auto-add categories.
  (b) EVALUATORS    -- a CLOSED set of generic predicates over the substrate. Graduates to the
                       OSS engine. reachability / relational / presence today; typestate and
                       differential are the next primitives (need an effect catalog + object id).
  (c) SUBSTRATE     -- the neutral fact a sink occurrence presents to a pattern:
                       {kind, tainted, value_bound, guarded}. Every bug is a predicate over
                       these dimensions (op/effect, object reachability, value, control).
"""


# ---- (c) SUBSTRATE -------------------------------------------------------------------------
def substrate(sink_kind, tainted, value_bound, guarded):
    """The dimensions every pattern predicates over, built once per sink occurrence:
      kind        -- the op / effect identity (atropos sink-arg kind)
      tainted     -- does an attacker-controlled value reach this arg (reach substrate)
      value_bound -- "unbounded" | "bounded" | None (None = arg carries no length obligation)
      guarded     -- is there a control guard on the value at the sink
    """
    return {"kind": sink_kind, "tainted": bool(tainted),
            "value_bound": value_bound, "guarded": guarded}


# ---- (b) EVALUATORS (closed set) -----------------------------------------------------------
def _reachability(fact):
    """Injection / traversal: an attacker-controlled value reaching the sink arg IS the lead.
    No bound obligation exists on the arg, so taint alone fires (command/sql/xss/ssrf/...)."""
    return fact["tainted"]


def _relational(fact):
    """Size / memory: the delivered length must be BOTH attacker-influenced AND unbounded vs
    the buffer capacity. Either alone is normal (a bounded tainted length, an unbounded
    constant). The overreach that plagued the raw bound axis is gone: no taint -> no lead."""
    return fact["tainted"] and fact["value_bound"] == "unbounded"


def _presence(fact):
    """Configuration weakness (weak crypto, insecure TLS, predictable temp file): the CALL
    ITSELF is the defect regardless of taint. Fires on presence -- the reach substrate is not consulted."""
    return True


def _missing_guard(fact):
    """Fire only when a validation exists but the sink is on its fall-through arm."""
    return fact["guarded"] == "fall-through"


EVALUATORS = {
    "reachability": _reachability,
    "relational":   _relational,
    "presence":     _presence,
    "missing-guard": _missing_guard,
}


# ---- (a) PATTERN DATA: kind -> evaluator recipe --------------------------------------------
# Pure data. This is the whole "add knowledge without code" seam: a row here (or, once
# graduated, a field on the atropos sink entry) routes a category to a generic evaluator.
KIND_EVALUATOR = {
    # injection & traversal -> reachability (taint reaches the sink arg, unsanitized)
    "command-injection":  "reachability",
    "code-injection":     "reachability",
    "sql-injection":      "reachability",
    "nosql-injection":    "reachability",
    "xss":                "reachability",
    "path-traversal":     "reachability",
    "ssrf":               "reachability",
    "template-injection": "reachability",
    "deserialization":    "reachability",
    "format-string":      "reachability",
    "xxe":                "reachability",
    "open-redirect":      "reachability",
    "prototype-pollution":"reachability",
    "ldap-injection":     "reachability",
    "xpath-injection":    "reachability",
    "redos":              "reachability",
    # size / memory -> relational (taint AND unbounded length vs capacity)
    "alloc-size":         "relational",
    "buffer-size":        "relational",
    "buffer-write":       ["relational", "missing-guard"],
    # configuration -> presence (taint-independent; the call is the bug)
    "weak-crypto":        "presence",
    "insecure-tls":       "presence",
    "insecure-temp-file": "presence",
}


def pattern_catalog():
    """Expose Atropos's declarative structural library to matcher clients."""
    try:
        from .atropos import pattern_catalog as _catalog
        return _catalog()
    except (ImportError, OSError, ValueError):
        return []


def evaluator_catalog():
    """Use Atropos routing when installed, retaining the compatibility table otherwise."""
    try:
        from .atropos import evaluator_catalog as _catalog
        return _catalog()
    except (ImportError, OSError, ValueError):
        return {"evaluators": EVALUATORS, "kind_evaluator": KIND_EVALUATOR}


def evaluator_for(sink_kind):
    """Return the catalogued evaluator recipe for a sink kind.

    Recipes may be a single evaluator or a list; keeping this lookup in the
    Atropos adapter prevents renderers from silently falling back to the old
    compatibility table when the catalog adds a second evaluator to a kind.
    """
    catalog = evaluator_catalog()
    return catalog.get("kind_evaluator", {}).get(sink_kind,
                                                   KIND_EVALUATOR.get(sink_kind))


def evaluate(sink_kind, fact):
    """Route a substrate fact through the evaluator its kind selects. Returns the evaluator
    name if the pattern fires, else None (unknown kind, or predicate not satisfied)."""
    catalog = evaluator_catalog()
    ev = catalog.get("kind_evaluator", {}).get(sink_kind, KIND_EVALUATOR.get(sink_kind))
    if ev is None:
        return None
    names = [ev] if isinstance(ev, str) else ev
    matches = [name for name in names
               if name in EVALUATORS and EVALUATORS[name](fact)]
    return matches[0] if matches else None


def evaluate_all(sink_kind, fact):
    """Return every catalogued evaluator that fires for one substrate fact."""
    catalog = evaluator_catalog()
    ev = catalog.get("kind_evaluator", {}).get(sink_kind, KIND_EVALUATOR.get(sink_kind))
    if ev is None:
        return []
    names = [ev] if isinstance(ev, str) else ev
    return [name for name in names
            if name in EVALUATORS and EVALUATORS[name](fact)]


def is_call_level(sink_kind):
    """Occurrence granularity of a kind. Presence-class kinds are CALL-level: the defect is
    that the sink is CALLED (weak crypto, insecure TLS), so it must be collected per-call and
    fires even with constant arguments. Every other class is ARG-level: the occurrence is a
    (call, argument) pair carrying a value the taint/bound predicates read. Adding a new
    presence KIND needs no code; only a new occurrence granularity would."""
    catalog = evaluator_catalog()
    ev = catalog.get("kind_evaluator", {}).get(sink_kind, KIND_EVALUATOR.get(sink_kind))
    return ev == "presence" or (isinstance(ev, list) and "presence" in ev)
