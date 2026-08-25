"""The warm analysis session: one loaded graph, every answer a query over it.

Both surfaces that drive Lachesis -- the CLI and the MCP server -- and every embedding
host used to answer each question by hand-writing ``GraphStore.load(...)`` + ``run_pass(...)``
and re-deriving leads from cold, because the only warm session that existed was trapped
inside ``mcp_server._Ctx``. This module lifts that session into a public ``Analysis`` class
so a question is a method call, not a script: load once, build each heavy analysis on first
use, and query the cached result. ``_Ctx`` now *subclasses* ``Analysis`` -- the MCP server
and the library share one implementation, so a fix on one is a fix on both.

Three types, one job each:
  ``Analysis`` -- the warm session. ``open`` a graph (or ``build`` one), then ``analyze`` for
                  leads, ``candidates``/``census`` for the obligation registry. Heavy work is
                  memoized and invalidated when the dataflow tier moves under it.
  ``LeadSet``  -- an immutable view over one pass's leads, with the filters both sessions kept
                  re-writing by hand (``by_function``/``near``/``at``/``by_pattern``) and a
                  ``to_json`` that persists them, so leads stop dying with the process.
  ``Deadline`` -- re-exported from ``lachesis.flow.deadline``; a cooperative wall-clock budget
                  so ``analyze`` is bounded by default instead of running for an hour.

Kept deliberately light at import time: the heavy ``nav.graph_store`` / ``flow.pipeline``
imports live inside the methods, and ``lachesis/__init__.py`` exports these three lazily
(PEP 562) so ``import lachesis`` stays cheap. This module must never import ``mcp_server``
(that is the subclass, and the cycle would be real).
"""
from __future__ import annotations

import json
import os
import tempfile
from collections import Counter
from dataclasses import dataclass, field, replace
from typing import Any, Callable, Iterator

from lachesis.flow.deadline import Deadline

__all__ = ["Analysis", "LeadSet", "Deadline"]

# A progress sink: called with a phase label and the seconds elapsed since the pass began,
# at each phase boundary a long analysis already measures. The library defines the shape but
# never imports the CLI's ``Progress`` -- a caller adapts its own sink to this signature.
ProgressFn = Callable[[str, float], None]

# The library defaults ``analyze`` to a wall-clock bound so a single call can never run
# unbounded (the friction that cost an hour). ``run_pass(deadline=None)`` stays unbounded for
# the four existing callers; the bound is a *library* default, resolved here, overridable per
# call (``hard_stop``) or by env (``LACHESIS_HARD_STOP``), and disabled by ``hard_stop=0``.
DEFAULT_HARD_STOP = 180.0


class Analysis:
    """A loaded graph plus its analyses, each built on first use and cached.

    Lazy on purpose. A store opened without an enriched tier grows its dataflow tier on
    demand, which rebinds ``store.index``; every cached analysis captured the index it was
    built against, so a build that predates the enrich would keep answering off the stale
    core tier. And orientation questions never touch dataflow, so they must never pay for it.
    ``_sync_tier`` drops every cache the moment the tier moves, so a cached answer is never
    served across the graft that existed to improve it.

    This is the BASE class. ``mcp_server._Ctx`` subclasses it and adds the navigation
    properties (``reach``/``guards``/``roles``/...); the store-load, the memo, and the two
    heavy builds (``_flow_bundle``/``_bind_bundle``) live here so there is one implementation.
    """

    def __init__(self, store: Any, *, progress: ProgressFn | None = None) -> None:
        self.store = store
        self._built: dict[Any, Any] = {}
        self._tier = (store.dataflow_ready, getattr(store, "cone_generation", 0))
        self._progress = progress

    # -- construction ---------------------------------------------------------------

    @classmethod
    def open(cls, path: str, *, overlay: str | None = None,
             progress: ProgressFn | None = None) -> "Analysis":
        """Load a graph once and return a warm session over it. ``~`` is expanded."""
        from lachesis.nav.graph_store import GraphStore

        path = os.path.expanduser(path)
        overlay = os.path.expanduser(overlay) if overlay else overlay
        store = GraphStore.load(path, overlay_path=overlay)
        return cls(store, progress=progress)

    @classmethod
    def build(cls, source: str, out: str, *, enrich: bool = False,
              timeout_seconds: int = 300, progress: ProgressFn | None = None) -> "Analysis":
        """Build a graph from source (default profile), write it, and open it warm.

        This is the plain single-process build -- one composed graph, no parallel-package or
        incremental machinery. The full flag surface lives on the ``lachesis build`` CLI verb;
        the library exposes the common case as one call so a fresh source tree is one step
        from a warm session.
        """
        from lachesis.pipeline import run_project
        from lachesis.kuzu_store import write_kuzu_graph

        source = os.path.expanduser(source)
        out = os.path.expanduser(out)
        graph, snapshots = run_project(source, None, enrich=enrich,
                                       timeout_seconds=timeout_seconds)
        write_kuzu_graph(graph, snapshots, out, enriched=enrich)
        return cls.open(out, progress=progress)

    # -- the memo (shared with every _Ctx navigation property) ----------------------

    def _sync_tier(self) -> None:
        """Drop every cache if the dataflow tier moved under it.

        Two ways the index can move: the whole tier arrives (``dataflow_ready`` flips) or a
        cone graft adds edges in place (``cone_generation`` ticks). The graft leaves
        ``dataflow_ready`` false forever, so watching only the flag would keep serving a
        pre-graft answer -- exactly what the graft existed to improve.
        """
        tier = (self.store.dataflow_ready, getattr(self.store, "cone_generation", 0))
        if self._tier != tier:
            self._built.clear()
            self._tier = tier

    def _analysis(self, key: Any, build: Callable[[], Any]) -> Any:
        self._sync_tier()
        if key not in self._built:
            self._built[key] = build()
        return self._built[key]

    # -- the two heavy builds, one implementation each ------------------------------

    def _flow_bundle(self, engine: str | None = None, lang: str = "c",
                     **run_kwargs: Any) -> dict:
        """The interprocedural flow pass over the whole graph, computed once and cached.

        Memoized under ``("flow", engine, lang)`` -- a tuple key that never collides with a
        subclass's string keys. A *partial* (timed-out) result is never cached: a later, more
        patient call must be free to recompute rather than inherit a truncated answer.
        """
        key = ("flow", engine, lang)
        self._sync_tier()
        cached = self._built.get(key)
        if cached is not None and not (cached.get("lifetime") or {}).get("timed_out"):
            return cached
        from lachesis.flow.pipeline import run_pass

        bundle = run_pass(self.store, lang=lang, lifetime_engine=engine, **run_kwargs)
        self._built[key] = bundle
        return bundle

    def _bind_bundle(self, *, temporal: bool = True,
                     deadline: Deadline | None = None) -> dict:
        """The catalog-stamped graph and its cached obligation registry.

        Candidate enumeration binds catalog facts against the core symbol index. The
        *structural* families (sizes, guards, injection sinks) come from that bind alone --
        fast, and no dataflow tier. The *temporal* families (double-free, use-after-free, ...)
        read the Pass 3 semantic skeleton, whose flow pass materializes the whole dataflow
        tier: the one part of this that can hang on a large graph.

        So there are two modes. ``temporal=True`` (default) folds the semantic skeleton in and
        answers every family; its ``(stamped, summary)`` is what the ``.bind.pb`` sidecar
        persists, so the cost is paid once per graph version, not once per process.
        ``temporal=False`` is the guaranteed-bounded fast path: the structural bind only, no
        flow pass, no tier -- it cannot hang, and its result carries ``temporal_evaluated`` so
        an absent double-free reads as "not evaluated", never as "clean".

        Memoized under ``("bind", temporal)``. A *partial* temporal result (the flow pass hit
        the ``deadline``) is never cached in-process or to disk: a later, more patient call
        must be free to recompute the complete answer rather than inherit a truncated one.
        """
        key = ("bind", temporal)
        self._sync_tier()
        cached = self._built.get(key)
        if cached is not None and not cached.get("partial"):
            return cached
        # A complete temporal bind subsumes a structural request; reuse it rather than
        # recomputing the cheap structural bind when the full answer is already in hand.
        if not temporal:
            full = self._built.get(("bind", True))
            if full is not None and not full.get("partial"):
                return full
        bundle = self._build_bind(temporal=temporal, deadline=deadline)
        if not bundle.get("partial"):
            self._built[key] = bundle
        return bundle

    def _build_bind(self, *, temporal: bool, deadline: Deadline | None) -> dict:
        from lachesis.planner.registry import default_candidate_registry
        from lachesis import bind_cache

        # The sidecar always holds the FULL temporal bind, so a hit answers both modes.
        cached = bind_cache.load(self.store)
        if cached is not None:
            stamped, summary = cached
            complete = True
        elif not temporal:
            stamped, summary = self._structural_bind()
            complete = False  # temporal families were not evaluated in the fast path
        else:
            stamped, summary, complete = self._enrich_and_merge(deadline=deadline)
            if complete:
                bind_cache.store(self.store, stamped, summary)
            else:
                # A truncated semantic skeleton would emit partial temporal observations that
                # read as fewer bugs, not as an incomplete run. Drop it and report structural
                # families only -- honest under-coverage beats a misleadingly thin temporal set.
                stamped.pop("semantic_graph", None)
        return {
            "registry": default_candidate_registry(stamped, summary),
            "stamped": stamped,
            "atropos": summary,
            "temporal_evaluated": complete,
            "partial": temporal and not complete,
        }

    def _structural_bind(self) -> tuple[dict, dict]:
        """The catalog bind alone: fast, and forces no dataflow tier. This is the fast path's
        whole cost, and the base the temporal merge builds on."""
        from lachesis.integrations.atropos.enrich import atropos_enrich
        from lachesis.nav.kuzu_index import materialize_graph

        graph = materialize_graph(self.store.index)
        return atropos_enrich(graph, complete_dataflow=False)

    def _enrich_and_merge(self, *, deadline: Deadline | None = None) -> tuple[dict, dict, bool]:
        """The structural bind plus the Pass 3 semantic skeleton the temporal families read.

        Returns ``(stamped, summary, complete)`` where ``complete`` is ``False`` if any flow
        pass hit the ``deadline`` -- the caller then declines to cache or emit the partial
        skeleton. This is the expensive, graph-version-invariant work the ``.bind.pb`` sidecar
        persists; a sidecar hit skips this method entirely (enrich *and* flow pass).
        """
        from lachesis.flow.pipeline import run_pass
        from lachesis.planner.temporal_obligation import merge_semantic_nodes

        stamped, summary = self._structural_bind()
        # Temporal families observe semantic operations (release, origin, dereference) that are
        # not catalog role nodes in the base CPG. Reuse the same cached Pass 3 graph the flow
        # bundle exposes rather than a second traversal or a language-specific lifecycle
        # extractor taught to the registry.
        semantic_nodes: dict = {}
        semantic_coverages: list = []
        complete = True
        for language in summary.get("languages") or ("c",):
            flow = (self._flow_bundle(engine=None, lang="c", deadline=deadline)
                    if language == "c" else
                    run_pass(self.store, lang=language, lifetime_engine="object",
                             deadline=deadline))
            if (flow.get("lifetime") or {}).get("timed_out"):
                complete = False
            semantic = flow.get("semantic_graph")
            if semantic is not None:
                merge_semantic_nodes(semantic_nodes, semantic, language)
                semantic_coverages.append(dict(semantic.coverage or {}))
        if semantic_nodes:
            stamped["semantic_graph"] = {"nodes": semantic_nodes}
            if semantic_coverages:
                stamped["semantic_graph"]["coverage"] = {
                    "converged": all(item.get("converged", True)
                                     for item in semantic_coverages),
                    "uncovered_states": [state for item in semantic_coverages
                                         for state in item.get("uncovered_states", ())],
                    "uncovered_contexts": [context for item in semantic_coverages
                                           for context in item.get("uncovered_contexts", ())],
                }
        return stamped, summary, complete

    # -- library surface: pass 3 (analyze -> leads) ---------------------------------

    def analyze(self, *, engine: str = "object", lang: str = "c",
                workers: int | None = None, hard_stop: float | None = None,
                snapshot: bool = False, deadline: Deadline | None = None,
                progress: ProgressFn | None = None) -> "LeadSet":
        """Run the flow pass and return its leads as a queryable, persistable ``LeadSet``.

        Bounded by default: with no explicit ``deadline``, ``hard_stop`` (or
        ``LACHESIS_HARD_STOP``, else :data:`DEFAULT_HARD_STOP`) becomes a cooperative budget,
        and ``hard_stop=0`` runs unbounded. ``snapshot=False`` keeps the semantic-graph disk
        cache off (a footgun on large graphs). The knobs are keyword parameters, not env vars
        -- discoverable and thread-safe, unlike the process-wide ``LACHESIS_*`` they replace.

        Re-calling ``analyze`` on the same session returns the cached ``LeadSet`` (the answer
        did not change); a partial, timed-out result is the one exception and recomputes.
        """
        deadline = self._resolve_deadline(hard_stop, deadline)
        bundle = self._flow_bundle(
            engine, lang,
            workers=workers, snapshot=snapshot, deadline=deadline,
            progress=progress if progress is not None else self._progress,
        )
        return LeadSet._from_bundle(bundle, self.store, engine=engine)

    @staticmethod
    def _resolve_deadline(hard_stop: float | None,
                          deadline: Deadline | None) -> Deadline | None:
        """The library's default-bounded budget: an explicit ``deadline`` wins; otherwise
        ``hard_stop`` (or ``LACHESIS_HARD_STOP``, else :data:`DEFAULT_HARD_STOP`) becomes one,
        and ``hard_stop=0`` runs unbounded. One resolver so ``analyze`` and the bounded
        candidate path agree on what "bounded by default" means."""
        if deadline is not None:
            return deadline
        resolved = hard_stop
        if resolved is None:
            env = os.environ.get("LACHESIS_HARD_STOP")
            resolved = float(env) if env else DEFAULT_HARD_STOP
        return Deadline.of(resolved)

    def leads(self, **kwargs: Any) -> "LeadSet":
        """Alias for :meth:`analyze` -- reads naturally as ``a.leads().near(...)``."""
        return self.analyze(**kwargs)

    # -- library surface: pass 2 (enrich -> warm sidecars) --------------------------

    def enrich(self, *, hard_stop: float | None = None,
               deadline: Deadline | None = None) -> dict:
        """Materialize the dataflow tier and the catalog bind to disk, so later reads are warm.

        Pass 2 as one call. ``ensure_dataflow_tier`` folds the overlay dataflow tier over the
        whole graph and persists it beside the store as ``.dataflow.pb``; a full temporal bind
        then writes the ``.bind.pb`` sidecar. After this a fresh process answering ``analyze`` /
        ``candidates`` / ``explain`` skips both costs. Idempotent: a store already enriched, and a
        bind already cached, are no-ops that simply report what is present.

        The *bind* is bounded by default, exactly like :meth:`analyze`: the temporal bind (the
        flow pass) is held to ``hard_stop`` (or ``LACHESIS_HARD_STOP``, else
        :data:`DEFAULT_HARD_STOP`); ``hard_stop=0`` runs it unbounded. A bind that hits the budget
        degrades to the structural families and is not persisted (a partial temporal sidecar is
        never written), so a later, more patient ``enrich`` still completes it.

        The *tier* materialization (``ensure_dataflow_tier`` above the bind) is NOT bounded by
        ``hard_stop`` -- it is a whole-graph, in-RAM step that runs to completion before the bind's
        clock ever starts. On a large graph it is the dominant cost and, on a machine short on RAM,
        it swaps; ``ensure_dataflow_tier`` warns up front when that is about to happen. It is cached
        to ``.dataflow.pb`` afterwards, so it is paid once per graph version, not per call.

        Returns a small report -- the sidecar paths, whether each is on disk, and whether the
        temporal families were evaluated -- so a CLI or a caller can say what it warmed.
        """
        from lachesis import bind_cache
        from lachesis.nav.graph_store import dataflow_overlay_path

        self.store.ensure_dataflow_tier()
        self._sync_tier()  # the tier moved under any cache built against the pre-enrich index
        bundle = self._bind_bundle(temporal=True,
                                   deadline=self._resolve_deadline(hard_stop, deadline))
        graph_path = getattr(self.store, "graph_path", None)
        dataflow = dataflow_overlay_path(self.store._core_path) if graph_path else None
        sidecar = bind_cache.sidecar_path(graph_path) if graph_path else None
        return {
            "dataflow_tier": self.store.dataflow_ready,
            "dataflow_sidecar": dataflow,
            "dataflow_written": bool(dataflow and os.path.isfile(dataflow)),
            "bind_sidecar": sidecar,
            "bind_written": bool(sidecar and os.path.isfile(sidecar)),
            "temporal_evaluated": bool(bundle.get("temporal_evaluated")),
        }

    # -- library surface: the obligation registry (candidates / census) -------------

    def _bound_bind(self, *, temporal: bool, hard_stop: float | None,
                    deadline: Deadline | None) -> dict:
        """The bind bundle for a candidate query, temporal families bounded by the budget.

        ``temporal=False`` takes the guaranteed-bounded structural fast path (no dataflow
        tier). ``temporal=True`` folds the semantic skeleton in under the resolved
        ``hard_stop``/``deadline`` and, if that times out, degrades to structural with
        ``temporal_evaluated=False`` rather than hang.
        """
        return self._bind_bundle(temporal=temporal,
                                 deadline=self._resolve_deadline(hard_stop, deadline))

    @staticmethod
    def _stamp_temporal(result: dict, bundle: dict) -> dict:
        """Carry the bind's ``temporal_evaluated`` onto a query result, so a caller can tell an
        absent temporal family (double-free, ...) from "not evaluated on this bounded run"."""
        result["temporal_evaluated"] = bool(bundle.get("temporal_evaluated"))
        return result

    def _registry(self, *, temporal: bool = True, hard_stop: float | None = None,
                  deadline: Deadline | None = None) -> Any:
        return self._bound_bind(temporal=temporal, hard_stop=hard_stop,
                                deadline=deadline)["registry"]

    def candidates(self, *, temporal: bool = True, hard_stop: float | None = None,
                   deadline: Deadline | None = None, **kwargs: Any) -> dict:
        """Candidate leads across the whole taxonomy (never scoped to one family).

        ``temporal=False`` is the fast path -- structural families only, no dataflow tier, so a
        large graph answers immediately instead of hanging; the result's ``temporal_evaluated``
        flag says the temporal families were skipped.
        """
        bundle = self._bound_bind(temporal=temporal, hard_stop=hard_stop, deadline=deadline)
        return self._stamp_temporal(bundle["registry"].candidates(**kwargs), bundle)

    def census(self, constructor: str | None = None, *, temporal: bool = True,
               hard_stop: float | None = None, deadline: Deadline | None = None) -> dict:
        bundle = self._bound_bind(temporal=temporal, hard_stop=hard_stop, deadline=deadline)
        return self._stamp_temporal(bundle["registry"].census(constructor=constructor), bundle)

    def constructors(self) -> tuple:
        return self._registry().constructors  # a @property on the registry, not a call

    def domains(self) -> list:
        return self._registry().domains()

    def candidate_detail(self, candidate_id: str, *, temporal: bool = True,
                         hard_stop: float | None = None,
                         deadline: Deadline | None = None) -> dict:
        """The full registry record for one candidate. For the composed one-shot -- provenance
        cone plus the sink's source read inline -- use :meth:`explain`."""
        bundle = self._bound_bind(temporal=temporal, hard_stop=hard_stop, deadline=deadline)
        return self._stamp_temporal(bundle["registry"].detail(candidate_id), bundle)

    # -- library surface: the one-shot explanation ----------------------------------

    def explain(self, candidate_id: str, *, temporal: bool = True,
                hard_stop: float | None = None, deadline: Deadline | None = None,
                provenance_limit: int = 200, max_source_chars: int = 4000) -> dict:
        """One call from a candidate id to a judgeable picture of the lead.

        Adjudicating a candidate used to be a five-tool ritual, threaded by hand and copying
        node ids between calls: census -> candidates -> candidate_detail -> sources_of ->
        read_body, identical for every case and the single biggest per-case cost. This composes
        that chain into one structured result -- the obligation and where it lands, the guard the
        enclosing function does or does not place over it, the bounded reverse cone of values that
        can feed the sink, and the source of the enclosing function read inline -- so a judgement
        is a read, not a scavenger hunt.

        The ``provenance`` and ``guard`` sections are evidence, never verdicts: an empty reverse
        cone means "nothing observed under the tier materialized here", not "not reachable", and a
        ``none-observed`` guard stays exactly that. Bounded like every other candidate call
        (``temporal``/``hard_stop``), and the provenance walk folds only a cone around the sink,
        never the whole graph.
        """
        bundle = self._bound_bind(temporal=temporal, hard_stop=hard_stop, deadline=deadline)
        detail = bundle["registry"].detail(candidate_id)
        candidate = detail.get("candidate")
        if not candidate:
            return self._stamp_temporal(
                {"move": "explain", "candidate_id": candidate_id,
                 "error": f"no candidate {candidate_id!r} in the registry"}, bundle)
        return self._stamp_temporal(
            self._compose_explanation(candidate, provenance_limit, max_source_chars), bundle)

    def explain_sink(self, file: str, line: int, *, temporal: bool = True,
                     hard_stop: float | None = None, deadline: Deadline | None = None,
                     provenance_limit: int = 200, max_source_chars: int = 4000) -> dict:
        """Explain the candidate at a source position, resolving ``file:line`` to it.

        The same one-shot as :meth:`explain`, entered by where the sink sits -- the position a
        reader has in hand from a diff or a stack trace -- rather than by an opaque id. ``file``
        matches by full path, path suffix, or basename. When several candidates share the line the
        best-ranked is explained and the rest are named under ``other_matches``, so the collapse is
        visible, never silent. An absent match says so honestly: a sink shape the catalog does not
        model is structurally unnameable, and no candidate there is not a proof of safety.
        """
        bundle = self._bound_bind(temporal=temporal, hard_stop=hard_stop, deadline=deadline)
        registry = bundle["registry"]
        matches = self._candidates_at(registry, file, line)
        if not matches:
            return self._stamp_temporal(
                {"move": "explain", "file": file, "line": line,
                 "error": f"no candidate sink at {file}:{line}",
                 "note": "a sink shape not modeled by the catalog is structurally unnameable "
                         "here -- an absent candidate is not a proof of safety"}, bundle)
        # Compose from the FULL detail row (with inferences), not the compact match row, so a
        # position-resolved explanation is exactly as rich as an id-resolved one.
        best_id = matches[0].get("candidate_id")
        full = registry.detail(best_id).get("candidate") or matches[0]
        result = self._compose_explanation(full, provenance_limit, max_source_chars)
        if len(matches) > 1:
            result["other_matches"] = [m.get("candidate_id") for m in matches[1:]]
        return self._stamp_temporal(result, bundle)

    def _compose_explanation(self, candidate: dict, provenance_limit: int,
                             max_source_chars: int) -> dict:
        """Assemble the one-shot record: obligation + where + guard + provenance + source.

        The candidate already carries the obligation, the observations, and the condition
        inference; this adds the two things a judgement otherwise costs a second tool each -- the
        reverse value-flow cone into the sink, and the enclosing function's source read inline.
        """
        handles = candidate.get("handles") or {}
        observations = candidate.get("observations") or {}
        inferences = candidate.get("inferences") or {}
        value_ids = handles.get("obligation_value_ids") or ()
        sink_value = value_ids[0] if value_ids else handles.get("site_node_id")
        return {
            "move": "explain",
            "candidate_id": candidate.get("candidate_id"),
            "constructor": candidate.get("constructor"),
            "domain": candidate.get("domain"),
            "language": candidate.get("language"),
            "obligation": candidate.get("obligation"),
            "sink": {"callee": observations.get("callee"), "site": observations.get("site"),
                     "file": observations.get("file"), "line": observations.get("line"),
                     "sink_kind": observations.get("sink_kind"), "cwe": observations.get("cwe")},
            "rank": candidate.get("rank"),
            "rank_reasons": candidate.get("rank_reasons"),
            "guard": self._guard_view(inferences),
            "input_reachability": inferences.get("input_reachability"),
            "provenance": self._provenance(sink_value, provenance_limit),
            "source": self._read_body(handles.get("enclosing_function_id"), max_source_chars),
            "next_op": candidate.get("next_op"),
        }

    @staticmethod
    def _guard_view(inferences: dict) -> dict:
        """The guard the enclosing function places over the sink -- read straight from the
        registry's condition inference, so ``none-observed`` stays ``none-observed`` and never
        quietly reads as safe."""
        conditions = inferences.get("conditions") or {}
        return {"status": conditions.get("status"),
                "dominance": conditions.get("dominance"),
                "referencing_conditions": conditions.get("referencing_conditions")}

    def _provenance(self, sink_value: str | None, limit: int) -> dict:
        """The bounded reverse value-flow cone into the sink.

        Folds the dataflow tier only around this sink (a cone, never the whole graph -- the same
        bound Phase 3 established) and walks the reverse cone. An empty result means nothing was
        observed under the tier materialized here, not that the sink is unreachable -- the
        ``cone``/``truncated`` fields say how much of the neighbourhood was actually in scope.
        """
        if not sink_value:
            return {"status": "no-sink-value", "sources": []}
        cone = self.store.ensure_dataflow_cone(sink_value)
        result = self._reach().sources_of(sink_value, limit=limit)
        manifest = result.get("manifest") or {}
        return {
            "sink_value": sink_value,
            "reached": manifest.get("reached"),
            "shown": manifest.get("shown"),
            "truncated": manifest.get("truncated"),
            "cone": cone,
            "sources": [{"id": node.get("id"), "name": node.get("name"),
                         "kind": node.get("kind"), "file": node.get("file"),
                         "line": node.get("line")}
                        for node in (result.get("nodes") or ())],
        }

    def _read_body(self, node_id: str | None, max_chars: int) -> dict | None:
        """The exact source of a declaration -- offsets first, L3 body nodes as a fallback --
        the same read the MCP ``read_body`` tool performs, lifted here so ``explain`` returns the
        function it is judging inline instead of demanding a second call."""
        if not node_id:
            return None
        gl = self.store.gl
        node = self.store.node(node_id)
        if node is None:
            return {"node_id": node_id, "error": "no such node"}
        file, start, end = gl.loc(node)
        body = gl.source_text(node)
        via = "offsets"
        if not body:  # offsets unavailable -- reconstruct from L3 body nodes in line order
            parts = sorted(gl.body_nodes(node_id), key=lambda n: (gl.loc(n)[1] or 0))
            body = "\n".join(gl.label(part) for part in parts if gl.label(part))
            via = "body_nodes"
        return {"node_id": node_id, "name": gl.label(node), "file": file,
                "start_line": start, "end_line": end, "via": via,
                "truncated": len(body) > max_chars, "body": body[:max_chars]}

    def _reach(self):
        """A reverse/forward value-flow engine over the current tier, built once per tier.

        Lives on the base session so ``explain`` works without the MCP subclass; ``_Ctx`` exposes
        the same object under the same memo key as its ``reach`` property, so the two never build
        two engines over one tier.
        """
        from lachesis.nav.reachability import Reachability

        return self._analysis("reach", lambda: Reachability(self.store))

    def _candidates_at(self, registry, file: str, line: int) -> list[dict]:
        """Every candidate whose sink observation sits at ``file:line``, best-ranked first.

        Scans the whole taxonomy (never one family), so a sink is found whatever catalog family
        names it; rank orders the matches but never filters them.
        """
        matches = [row for row in self._iter_candidates(registry)
                   if self._observed_at(row, file, line)]
        matches.sort(key=lambda row: row.get("rank") or 0.0, reverse=True)
        return matches

    @staticmethod
    def _iter_candidates(registry) -> Iterator[dict]:
        """Every candidate row across the whole taxonomy, paged out of the registry's public
        surface so this never reaches into registry internals."""
        page = registry.candidates(limit=200)
        for group in (page.get("groups") or (page,)):
            yield from group.get("candidates", ())
            constructor, cursor = group.get("constructor"), group.get("next_cursor")
            while cursor:
                more = registry.candidates(constructor=constructor, limit=200, cursor=cursor)
                yield from more.get("candidates", ())
                cursor = more.get("next_cursor")

    @staticmethod
    def _observed_at(row: dict, file: str, line: int) -> bool:
        observations = row.get("observations") or {}
        if observations.get("line") != line:
            return False
        stored = observations.get("file")
        return bool(stored) and _file_matches((stored,), file)


@dataclass(frozen=True)
class LeadSet:
    """An immutable view over one flow pass's leads, with the filters and the persistence
    both sessions kept re-writing by hand.

    A lead carries only its enclosing function (``entry``) and a source ``line`` -- never a
    file path -- so ``near``/``at`` resolve function -> file(s) lazily via the symbol index,
    treating homonyms as a set (a name can live in several files; never collapse them). The
    filters return a new ``LeadSet`` sharing the same store, so they chain.
    """

    leads: tuple[dict, ...] = ()
    timings: dict = field(default_factory=dict)
    lifetime: dict = field(default_factory=dict)
    coverage: Any = None
    engine: str | None = None
    timed_out: bool = False
    truncated_functions: tuple = ()
    _store: Any = field(default=None, compare=False, repr=False)
    _index_cache: Any = field(default=None, compare=False, repr=False, init=False)

    # -- construction ---------------------------------------------------------------

    @classmethod
    def _from_bundle(cls, bundle: dict, store: Any, *, engine: str | None) -> "LeadSet":
        lifetime = bundle.get("lifetime") or {}
        diagnostics = lifetime.get("diagnostics") or {}
        return cls(
            leads=tuple(bundle.get("leads") or ()),
            timings=dict(bundle.get("timings") or {}),
            lifetime=lifetime,
            coverage=bundle.get("coverage"),
            engine=engine,
            timed_out=bool(lifetime.get("timed_out")),
            truncated_functions=tuple(diagnostics.get("capped") or ()),
            _store=store,
        )

    def _with(self, leads) -> "LeadSet":
        clone = replace(self, leads=tuple(leads))
        # Carry the resolved index to a filtered clone so a chain resolves it once.
        if self._index_cache is not None:
            object.__setattr__(clone, "_index_cache", self._index_cache)
        return clone

    # -- container protocol ---------------------------------------------------------

    def __iter__(self) -> Iterator[dict]:
        return iter(self.leads)

    def __len__(self) -> int:
        return len(self.leads)

    def __bool__(self) -> bool:
        return bool(self.leads)

    # -- summary --------------------------------------------------------------------

    def summary(self) -> dict:
        """A one-glance description: totals by pattern, plus the honesty fields.

        ``timed_out``/``truncated_functions`` are surfaced here on purpose -- an empty or thin
        result over a partial run must never read as "clean code".
        """
        counts = Counter(lead.get("pattern") for lead in self.leads)
        return {
            "total": len(self.leads),
            "by_pattern": dict(counts),
            "engine": self.engine,
            "timed_out": self.timed_out,
            "truncated_functions": list(self.truncated_functions),
            # Which phase the budget stopped before, when it fired before object analysis even
            # began (tier/projection/summaries). None on a normal run or a mid-analysis timeout.
            # Lets a caller distinguish "setup alone blew the budget" (warm the graph first)
            # from "analysis was truncated" (raise the budget).
            "stopped_before": (self.lifetime.get("diagnostics") or {}).get("stopped_before"),
            "coverage": self._coverage_summary(),
        }

    def _coverage_summary(self) -> Any:
        """A compact, JSON-safe view of the pass's coverage.

        ``self.coverage`` is the rich ``CoveragePlan`` (kept as-is on the attribute for a
        caller who wants it), but ``summary`` is meant to serialize -- the MCP surface renders
        it with a bare ``json.dumps`` -- so collapse the plan to counts here rather than emit a
        non-serializable object.
        """
        coverage = self.coverage
        if coverage is None:
            return None
        covered = getattr(coverage, "covered_functions", None)
        uncovered = getattr(coverage, "uncovered_functions", None)
        if covered is not None or uncovered is not None:
            return {"covered": len(covered or ()), "uncovered": len(uncovered or ())}
        if isinstance(coverage, (dict, list, str, int, float, bool)):
            return coverage
        return str(coverage)

    def patterns(self) -> list[str]:
        return sorted({lead.get("pattern") for lead in self.leads if lead.get("pattern")})

    # -- filters (each returns a new LeadSet) ---------------------------------------

    def by_pattern(self, pattern: str) -> "LeadSet":
        return self._with(lead for lead in self.leads if lead.get("pattern") == pattern)

    def by_function(self, name: str, lines: tuple[int, int] | None = None) -> "LeadSet":
        return self._with(lead for lead in self.leads
                          if lead.get("entry") == name and self._in_lines(lead, lines))

    def near(self, file: str, lines: tuple[int, int] | None = None) -> "LeadSet":
        """Leads whose enclosing function resolves to ``file`` (path, suffix, or basename),
        optionally within an inclusive ``(lo, hi)`` line window over the sink line."""
        index = self._index()
        return self._with(lead for lead in self.leads
                          if _file_matches(index.get(lead.get("entry"), ()), file)
                          and self._in_lines(lead, lines))

    def at(self, file: str, line: int) -> "LeadSet":
        return self.near(file, (line, line))

    @staticmethod
    def _in_lines(lead: dict, lines: tuple[int, int] | None) -> bool:
        if lines is None:
            return True
        value = lead.get("line")
        return value is not None and lines[0] <= value <= lines[1]

    def _index(self) -> dict[str, set[str]]:
        if self._index_cache is not None:
            return self._index_cache
        from lachesis.nav.symbol_index import build_index

        mapping: dict[str, set[str]] = {}
        if self._store is not None:
            for entry in build_index(self._store.gl):
                name, file = entry.get("name"), entry.get("file")
                if name and file:
                    mapping.setdefault(name, set()).add(file)
        object.__setattr__(self, "_index_cache", mapping)
        return mapping

    # -- persistence ----------------------------------------------------------------

    def to_json(self, path: str | None = None, *, indent: int = 2) -> Any:
        """Return the JSON-able payload, and (if ``path`` is given) write it atomically.

        Leads used to die with the process -- printed as a ``len()`` then gone. Persisting is
        a tmp-write + ``os.replace`` so a reader never sees a half-written file.
        """
        payload = {
            "summary": self.summary(),
            "leads": list(self.leads),
        }
        if path is None:
            return payload
        path = os.path.expanduser(path)
        directory = os.path.dirname(os.path.abspath(path))
        os.makedirs(directory, exist_ok=True)
        handle, tmp = tempfile.mkstemp(dir=directory, suffix=".tmp")
        try:
            with os.fdopen(handle, "w", encoding="utf-8") as stream:
                json.dump(payload, stream, indent=indent, default=str)
            os.replace(tmp, path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        return path


def _file_matches(files, target: str) -> bool:
    """Does any of ``files`` name ``target`` -- as a full path, a path suffix, or a basename?

    A lead names a function, which the symbol index maps to the file(s) that define it. The
    caller may ask by full path, by a trailing slice (``src/tree.c``), or by basename
    (``tree.c``); accept all three so locating a sink never demands the exact stored path.
    """
    target = os.path.expanduser(target)
    base = os.path.basename(target)
    for file in files:
        if file == target or file.endswith("/" + target) or os.path.basename(file) == base:
            return True
    return False
