"""The planner: graph facts in, ranked investigation capsules out.

`nav/` is the verdict-free retrieval surface — it answers questions and never
decides anything. The planner is the layer that *does* decide, under one rule:

    the graph owns "don't miss", the judge owns "don't false-positive"

So the planner may enumerate candidates, suppress one it can prove is guarded, and
rank what is left. It may never declare a vulnerability. The only outcomes static
analysis produces here are ``PROVEN_PRESERVED`` (suppressed, with the guard named)
and ``UNPROVEN`` (queued, with its evidence attached). ``PROVEN_VIOLATED`` is
reserved for a downstream reasoner with runtime evidence, and nothing in this
package emits it.
"""
