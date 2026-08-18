"""Interprocedural flow pass over the Lachesis graph (the analysis pass).

This is the third pass in the pipeline -- after (1) build the graph and (2) enrich it, this
pass reads the already-built, enriched graph and, without reparsing anything:

  translate  project the graph into a compact per-function IR (F)
  traverse   cover the whole graph component-by-component (callers up, callees down)
  order      schedule each component bottom-up (callees before callers)
  summarize  compose a deterministic, interprocedural per-function summary
  skeleton   render the summaries into linear, nesting-aware {control|sink|lifecycle}
             token streams -- the stitched cross-function flow skeleton
  match      run shape patterns over the skeletons (guard differential + temporal patterns)

Everything downstream of `translate` touches only the IR, never the graph again.
"""
from .translate import load_graph, build_F
from .skeleton import build_skeletons, render_text
from .match import match_all

__all__ = ["load_graph", "build_F", "build_skeletons", "render_text", "match_all"]
