"""Data-driven vulnerability detection over a Lachesis code property graph.

Two pieces, kept separate on purpose:

  substrate  -- the CLASS-first detection core. A sink argument's *kind* (from the
                atropos catalog) selects a generic evaluator; adding a catalogued kind
                that maps to an existing evaluator adds a whole detection category with
                no engine code. Language- and graph-neutral.
  adapter    -- translates a Lachesis enriched kuzu graph into the neutral schema the
                core reasons over (functions, params, calls, arguments, bindings,
                returns, sinks). The only graph-specific code; swap it to detect over a
                different graph backend without touching the core.

The core reads a neutral fact per sink occurrence -- {kind, tainted, value_bound,
guarded} -- so the same evaluators run over any front-end that can produce it.
"""
