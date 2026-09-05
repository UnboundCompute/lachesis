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
import logging
import os
import tempfile
from time import perf_counter
from collections import Counter
from dataclasses import dataclass, field, replace
from functools import wraps
from typing import Any, Callable, Iterator, Mapping

from lachesis.flow.deadline import Deadline

__all__ = ["scan", "Analysis", "Lead", "LeadSet", "Deadline", "AnalysisError"]

# A progress sink: called with a phase label and the seconds elapsed since the pass began,
# at each phase boundary a long analysis already measures. The library defines the shape but
# never imports the CLI's ``Progress`` -- a caller adapts its own sink to this signature.
ProgressFn = Callable[[str, float], None]


class _ProgressAdapter:
    """Adapt the indexer's phase API to the library's callback-only progress contract."""

    def __init__(self, callback: ProgressFn | None) -> None:
        self.callback = callback

    def phase(self, label: str) -> None:
        if self.callback is not None:
            self.callback(label, 0.0)

    def note(self, message: str) -> None:
        if self.callback is not None:
            self.callback(message, 0.0)

    def done(self, *args: Any, **kwargs: Any) -> None:
        return None

    def fail(self) -> None:
        return None

# The library defaults ``analyze`` to a wall-clock bound so a single call can never run
# unbounded (the friction that cost an hour). ``run_pass(deadline=None)`` stays unbounded for
# the four existing callers; the bound is a *library* default, resolved here, overridable per
# call (``hard_stop``) or by env (``LACHESIS_HARD_STOP``), and disabled by ``hard_stop=0``.
DEFAULT_HARD_STOP = 180.0
_LOGGER = logging.getLogger("lachesis")


class AnalysisError(RuntimeError):
    """Base error for an analysis request that cannot produce a trustworthy answer."""


class NoSourceError(AnalysisError):
    """Raised when a requested source path has no supported source files."""


class NativeKernelError(AnalysisError):
    """Raised when the native analysis kernel cannot be loaded or run."""


def _analysis_boundary(function):
    """Keep expected public-session failures inside the documented error hierarchy."""
    @wraps(function)
    def wrapped(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except AnalysisError:
            raise
        except (KeyError, OSError, RuntimeError, ValueError) as error:
            raise AnalysisError(f"{function.__name__} failed: {error}") from error
    return wrapped


def scan(path: str = ".", *, lens: str = "all", hard_stop: float | None = None,
         refresh: bool = False, timeout: int = 300, limit: int | None = None,
         progress: ProgressFn | None = None) -> "LeadSet":
    """Build or open ``path`` and return ranked leads from one selected lens."""
    if lens not in {"all", "guard-diff", "flow"}:
        raise ValueError("lens must be one of: all, guard-diff, flow")
    source = os.path.expanduser(path)
    # A Kùzu store is itself a directory. Recognize the named graph artifact
    # before the generic directory/source-tree branch.
    is_graph = os.path.isdir(source) and (
        source.endswith(".kuzu") or os.path.isfile(os.path.join(source, "manifest.pb"))
    )
    if os.path.isdir(source) and not is_graph:
        try:
            from lachesis.cli.indexer import ensure_graph
            # The library must never install a terminal renderer. A caller that
            # wants progress supplies the callback; CLI rendering belongs to CLI code.
            cli_progress = _ProgressAdapter(progress)
            graph_path, _ = ensure_graph(
                source, refresh=refresh, progress=cli_progress,
                timeout_seconds=timeout,
            )
        except AnalysisError:
            raise
        except Exception as error:
            raise AnalysisError(f"could not index {source}: {error}") from error
    elif os.path.exists(source):
        graph_path = source
    else:
        raise NoSourceError(f"source or graph does not exist: {source}")

    analysis = Analysis.open(graph_path, progress=progress)
    return analysis.scan(lens=lens, hard_stop=hard_stop, limit=limit)


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
             progress: ProgressFn | None = None, defer_maps: bool = False) -> "Analysis":
        """Load a graph once and return a warm session over it. ``~`` is expanded."""
        from lachesis.nav.graph_store import GraphStore

        path = os.path.expanduser(path)
        overlay = os.path.expanduser(overlay) if overlay else overlay
        try:
            store = GraphStore.load(path, overlay_path=overlay, defer_maps=defer_maps)
        except AnalysisError:
            raise
        except (OSError, KeyError, ValueError, RuntimeError) as error:
            raise AnalysisError(f"could not open graph {path}: {error}") from error
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
        try:
            graph, snapshots = run_project(source, None, enrich=False,
                                           timeout_seconds=timeout_seconds)
            write_kuzu_graph(graph, snapshots, out, enriched=False)
        except AnalysisError:
            raise
        except (OSError, KeyError, ValueError, RuntimeError) as error:
            raise AnalysisError(f"could not build graph from {source}: {error}") from error
        analysis = cls.open(out, progress=progress)
        if enrich:
            analysis.enrich(hard_stop=0)
        return analysis

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

    @staticmethod
    def _pass2_timing(label: str, started: float) -> None:
        """Emit opt-in timings for the catalog/temporal half of Pass 2."""
        if os.environ.get("LACHESIS_PASS2_TIMINGS") == "1":
            import resource, sys as _sys
            _sc = 1.0 if _sys.platform == "darwin" else 1024.0  # ru_maxrss bytes(mac)/KiB(linux)
            _s = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * _sc / 1048576
            _k = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss * _sc / 1048576
            _LOGGER.info("pass2 %s: %.3fs  peakRSS self=%.0fMB kids=%.0fMB",
                         label, perf_counter() - started, _s, _k)

    @staticmethod
    def _pass2_progress(label: str, elapsed: float) -> None:
        if os.environ.get("LACHESIS_PASS2_TIMINGS") == "1":
            _LOGGER.info("pass2 temporal %s: %.3fs", label, elapsed)

    def _flow_bundle(self, lang: str = "mixed", **run_kwargs: Any) -> dict:
        """The interprocedural flow pass over the whole graph, computed once and cached.

        Memoized under ``("flow", lang)`` -- a tuple key that never collides with a
        subclass's string keys. A *partial* (timed-out) result is never cached: a later, more
        patient call must be free to recompute rather than inherit a truncated answer.
        """
        key = ("flow", lang)
        self._sync_tier()
        cached = self._built.get(key)
        if cached is not None and not (cached.get("lifetime") or {}).get("timed_out"):
            return cached
        from lachesis.flow.pipeline import run_pass

        try:
            bundle = run_pass(self.store, lang=lang, **run_kwargs)
        except RuntimeError as error:
            message = str(error)
            if "Native analysis kernel" in message or "native lifetime" in message.lower():
                raise NativeKernelError(message) from error
            raise AnalysisError(f"analysis could not complete: {message}") from error
        self._built[key] = bundle
        return bundle

    def _bind_bundle(self, *, temporal: bool = True,
                     deadline: Deadline | None = None,
                     workers: int | None = None) -> dict:
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
        bundle = self._build_bind(temporal=temporal, deadline=deadline,
                                  workers=workers)
        if not bundle.get("partial"):
            self._built[key] = bundle
        return bundle

    def _build_bind(self, *, temporal: bool, deadline: Deadline | None,
                    workers: int | None = None) -> dict:
        from lachesis.planner.registry import default_candidate_registry
        from lachesis import bind_cache

        # The sidecar always holds the FULL temporal bind, so a hit answers both modes.
        started = perf_counter()
        cached = bind_cache.load(self.store)
        self._pass2_timing("bind sidecar load", started)
        if cached is not None:
            stamped, summary = cached
            complete = True
        elif not temporal:
            stamped, summary = self._structural_bind()
            complete = False  # temporal families were not evaluated in the fast path
        else:
            stamped, summary, complete = self._enrich_and_merge(
                deadline=deadline, workers=workers)
            # ``_enrich_and_merge`` now handles cap truncation per function --
            # it drops only the capped functions' findings and reports them in
            # ``coverage.truncated_functions``, so the returned bind is the
            # complete, deterministic answer for this graph and is always safe
            # to cache. (The old path treated any single capped function as a
            # graph-wide veto and popped the whole temporal bind here, zeroing
            # the confirmed census of an otherwise-clean graph.)
            if complete:
                bind_cache.store(self.store, stamped, summary)
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
        from lachesis.nav.kuzu_index import materialize_graph, _sort_materialized_edges

        started = perf_counter()
        # Make the control-flow branch substrate (cfg-condition nodes + branch-region
        # edges) visible to the index before the bind reads it. On the retain=False
        # path (`enrich`) the full dataflow overlay is deliberately never decoded into
        # RAM, so without this the census has no conditions to classify guard dominance
        # against. This attaches only the tiny branch slice (bounded by control
        # structure), and is a no-op when a full overlay is already attached.
        self.store.ensure_branch_substrate()
        index = getattr(self.store, "index", None)
        projection_fn = getattr(index, "atropos_projection", None)
        if projection_fn is not None:
            # Bind against the compact callsite projection before materializing the
            # million-node graph.  Keeping the large graph out of the Python heap
            # during canonical projection avoids allocator/GC pressure that turned a
            # 0.1s standalone adapter call into ~30s on the cold full-graph path.
            projection = projection_fn()
            compact, summary = atropos_enrich(
                projection, complete_dataflow=False,
                symbol_index_source=index, compact_structural=True,
            )
            delta_nodes = [
                node for node in compact.get("nodes", ())
                if (node.get("properties") or {}).get("fact_origin") == "atropos-model"
            ]
            delta_edges = [
                edge for edge in compact.get("edges", ())
                if (edge.get("properties") or {}).get("fact_origin") == "atropos-model"
                or edge.get("kind") in {"TAINT_SOURCE", "TAINT_SINK"}
            ]
            self._pass2_timing("catalog structural bind", started)
            materialize_started = perf_counter()
            # The catalog projection already contains every callsite/value record
            # structural candidates can bind to.  Materializing the complete CPG
            # here used to add ~980k nodes/~2M edges and cost ~45s on libxml2.  Add
            # only the branch substrate and the bounded reverse value cones needed
            # for candidate evidence; the temporal path has its own native sidecars.
            graph = self._compact_structural_graph(index, projection, delta_nodes,
                                                    delta_edges)
            self._pass2_timing("bind graph materialize", materialize_started)
            self._pass2_timing("catalog structural bind total", started)
            return graph, summary

        graph = self.store.take_retained_enriched_graph()
        if graph is None:
            graph = materialize_graph(self.store.index)
            self._pass2_timing("bind graph materialize", started)
        else:
            # enrich_graph sorts by the public three-field edge key.  The Kùzu
            # materializer also orders equal triples by properties, which is
            # observable to downstream bind/flow iteration.  Match that canonical
            # order on the one-shot retained view before handing it to the binder.
            _sort_materialized_edges(graph["edges"])
            self._pass2_timing("bind retained graph sort", started)
        bind_started = perf_counter()
        result = atropos_enrich(
            graph, complete_dataflow=False,
            symbol_index_source=getattr(self.store, "index", None),
            compact_structural=True,
        )
        self._pass2_timing("catalog structural bind", bind_started)
        self._pass2_timing("catalog structural bind total", started)
        return result

    @staticmethod
    def _compact_structural_graph(index, projection, delta_nodes, delta_edges) -> dict:
        """Build the structural candidate view without materializing the whole CPG.

        Structural enumerators need call/value records, branch-region containment,
        and reaching-definition evidence.  They do not need declarations, AST
        wrappers, or unrelated edges.  Keep the projection as the base, fetch all
        branch-region records (small and shared), then walk backwards only from the
        Atropos sink values through ``VALUE_FLOWS_TO``.  This is exact for the
        evidence the structural constructors consume and avoids a graph-sized
        Python object population on every cold Pass 2 bind.
        """
        nodes = {node["id"]: node for node in projection.get("nodes", ())}
        edges = list(projection.get("edges", ()))
        for node in delta_nodes:
            nodes[node["id"]] = node
        edges.extend(delta_edges)

        from lachesis.planner.unbounded_copy import _REGION_EDGE_KINDS

        materialize_started = perf_counter()
        region_edges = list(index.edges_of_kind(*_REGION_EDGE_KINDS))
        edges.extend(region_edges)
        # Region-edge ENDPOINTS carry the two facts the guard adjudicator reads: the
        # cfg-condition SOURCE (which size variable a branch tests) and the branch-body
        # TARGET span (which a copy call site is placed inside for `guarded-region`).
        # The header warm below cannot supply either. The sources are overlay-derived
        # -- absent from Kùzu -- so ``node_headers`` returns them as empty stubs. And on
        # the deferred-maps bind path (``enrich`` opens with ``defer_maps=True``) the
        # promoted-header columns are never built, so ``node_headers`` returns the Kùzu
        # body targets span-less too. Either stubbing collapses a genuinely guarded copy
        # to a spurious ``none-observed``/``fall-through``. Warm both endpoints straight
        # from Kùzu (batched; ``_warm_nodes`` skips ids already resident, so the
        # overlay-cached cfg-condition sources are left intact) and seat the full,
        # span-bearing records through the overlay-aware accessor before the
        # ``difference`` so no stubbing path runs on them. Bounded by the program's
        # control structure, never by its size.
        node_getter = getattr(index, "nodes", None)
        region_endpoints = {edge.get("source") for edge in region_edges}
        region_endpoints.update(edge.get("target") for edge in region_edges)
        region_endpoints.discard(None)
        region_endpoints.difference_update(nodes)
        if region_endpoints and node_getter is not None:
            warmer = getattr(index, "_warm_nodes", None)
            if warmer is not None:
                warmer(region_endpoints)
            for endpoint_id in region_endpoints:
                record = node_getter.get(endpoint_id)
                if record is not None:
                    nodes[record["id"]] = record
        region_done = perf_counter()
        needed = {edge.get("source") for edge in region_edges}
        needed.update(edge.get("target") for edge in region_edges)

        # Atropos sink nodes identify the roots of the only value-flow walks the
        # structural constructors perform.  Traverse all incoming flow edges so
        # pass-through and definition/origin facts remain identical to the full
        # graph view, while never retaining unrelated function-local flow.
        work = [
            (node.get("properties") or {}).get("value_id")
            for node in delta_nodes
            if node.get("kind") == "sink"
        ]
        # A sink's location lives on its callsite node.  Call-expression sinks bind a
        # `call` node the Atropos projection already carries with its full span, but
        # an assignment/subscript sink (object-integrity.prototype `obj[key]=value`)
        # binds a `dynamic-behavior` write-site node that reaches the projection only
        # as a position-less edge-endpoint stub (id/kind/label, empty properties),
        # while its bound `value_id` is a synthetic access-path node with no span at
        # all.  A stub already sits in ``nodes`` so it is not "missing" and the header
        # warm below skips it, leaving the candidate with file/line=None even though
        # the span is known to the index.  Collect every sink callsite so its header
        # span can be merged in after the warm regardless of the stub.
        sink_callsite_ids = {
            (node.get("properties") or {}).get("callsite_id")
            for node in delta_nodes
            if node.get("kind") == "sink"
            and (node.get("properties") or {}).get("callsite_id")
        }
        seen = set()
        while work:
            batch = []
            while work and len(batch) < 5000:
                target = work.pop()
                if target and target not in seen:
                    seen.add(target)
                    needed.add(target)
                    batch.append(target)
            if not batch:
                continue
            batch_edges = (index.incoming_edges_for_targets(batch, "VALUE_FLOWS_TO")
                           if hasattr(index, "incoming_edges_for_targets") else
                           [edge for target in batch
                            for edge in index.incoming_of_kind(
                                target, "VALUE_FLOWS_TO")])
            for edge in batch_edges:
                edges.append(edge)
                source = edge.get("source")
                if source and source not in seen:
                    work.append(source)
                if source:
                    needed.add(source)
        cone_done = perf_counter()

        # Lifecycle release/use constructors census ``release`` nodes and the
        # member reads rooted in them.  Neither is a callsite nor reachable from
        # an Atropos sink, so the projection and the sink cone above drop them --
        # which silently zeroes the lifecycle.release/use census versus the full
        # graph.  Re-add exactly that small lineage: the release nodes plus the
        # ``HAS_PROPERTY_PATH -> DEFINES -> READS_FROM`` chain anchored on each
        # release target (and on any acquisition/source value a use may root in).
        # These need their full property tails -- the constructor reads
        # ``target_id``/``base_value_id``/``definition_id``, which the header-only
        # warm below does not carry -- so they are fetched as complete records
        # here.  Bounded by the lifecycle values in the program, never by its size.
        life_nodes, life_edges = Analysis._lifecycle_lineage(index, projection)
        for node in life_nodes:
            nodes[node["id"]] = node
            needed.discard(node["id"])
        edges.extend(life_edges)

        # Fetch only endpoints absent from the narrow Atropos projection.  Kùzu's
        # batch warmer turns this into a small number of primary-key probes rather
        # than one query per record.
        missing = needed.difference(nodes)
        # Cone endpoints are used by the structural evidence walkers for their
        # identity, kind, label, and source span.  The Atropos projection already
        # carries the full property tails for every candidate call/value node;
        # inflating another 90k Kùzu property blobs here only to read those header
        # fields cost ~18s on libxml2.  Promoted headers are exact for this use and
        # avoid that allocation/decompression entirely.
        headers = getattr(index, "node_headers", None)
        if missing and headers is not None:
            for node in headers(missing):
                nodes[node["id"]] = node
        else:
            warmer = getattr(index, "_warm_nodes", None)
            if missing and warmer is not None:
                warmer(missing)
            for node_id in missing:
                node = index.nodes.get(node_id)
                if node is not None:
                    nodes[node_id] = node

        # Merge the source span onto every sink callsite that entered as a
        # position-less stub (see the sink_callsite_ids comment above).  Fetch the
        # full record rather than a header: the promoted-header map is deferred for
        # this node kind, so only the warmed record carries the write site's real
        # file/line.  Merge it without clobbering any property a full record already
        # provided.  The set is one callsite per sink, so this is a small warm.
        warmer = getattr(index, "_warm_nodes", None)
        if sink_callsite_ids and warmer is not None:
            warmer(sink_callsite_ids)
            for callsite_id in sink_callsite_ids:
                record = index.nodes.get(callsite_id)
                if not record:
                    continue
                existing = nodes.get(callsite_id)
                if existing is None:
                    nodes[callsite_id] = record
                    continue
                merged = dict(existing.get("properties") or {})
                for key, value in (record.get("properties") or {}).items():
                    if value is not None and merged.get(key) is None:
                        merged[key] = value
                updated = dict(existing)
                updated["properties"] = merged
                nodes[callsite_id] = updated

        if os.environ.get("LACHESIS_PASS2_TIMINGS") == "1":
            _LOGGER.info(
                "pass2 structural phases: regions=%.3fs cone=%.3fs warm=%.3fs "
                "region_edges=%d cone_nodes=%d missing=%d",
                region_done - materialize_started, cone_done - region_done,
                perf_counter() - cone_done, len(region_edges), len(seen), len(missing),
            )
        return {"nodes": list(nodes.values()), "edges": edges}

    @staticmethod
    def _lifecycle_lineage(index, projection) -> tuple[list, list]:
        """Release nodes plus the bounded member-read lineage rooted in them.

        Returns ``(nodes, edges)`` as full records -- the lifecycle constructors
        read ``target_id``/``base_value_id``/``definition_id`` property tails that
        the compact graph's header warm does not carry.  Seeds are every release
        target and every acquisition/source call value (a use may root in either);
        the walk follows only ``HAS_PROPERTY_PATH -> DEFINES -> READS_FROM`` for a
        few hops, so the set is bounded by the lifecycle values in the program.
        """
        from lachesis.flow import atropos
        from lachesis.flow.normalize import normalizer

        release_nodes = list(index.nodes_of_kind("release"))
        seeds: set[str] = set()
        for node in release_nodes:
            target_id = (node.get("properties") or {}).get("target_id")
            if target_id:
                seeds.add(target_id)
        for node in projection.get("nodes", ()):
            if node.get("kind") not in ("call", "construct"):
                continue
            props = node.get("properties") or {}
            callee = props.get("callee") or props.get("method_name")
            if not callee:
                continue
            lang = atropos.lang_of(props.get("absolute_file") or props.get("file") or "")
            norm = normalizer(lang)
            if norm.is_acquire(callee) or norm.is_release(callee) or \
                    callee in atropos.source_catalog(lang):
                for key in ("return_value_id", "value_id", "assigned_value_id",
                            "receiver_value_id"):
                    if props.get(key):
                        seeds.add(props[key])
                seeds.update(props.get("argument_value_ids") or ())

        chain = ("HAS_PROPERTY_PATH", "DEFINES", "READS_FROM")
        lineage_edges: list = []
        discovered: set[str] = set()
        frontier = list(seeds)
        for _hop in range(4):
            if not frontier:
                break
            nxt: list[str] = []
            for value_id in frontier:
                for edge in index.outgoing_of_kind(value_id, *chain):
                    lineage_edges.append(edge)
                    target = edge.get("target")
                    if target and target not in discovered:
                        discovered.add(target)
                        nxt.append(target)
            frontier = nxt

        if discovered:
            index._warm_nodes(list(discovered))
        lineage_nodes = list(release_nodes)
        for node_id in discovered:
            node = index.nodes.get(node_id)
            if node is not None:
                lineage_nodes.append(node)
        return lineage_nodes, lineage_edges

    def _enrich_and_merge(self, *, deadline: Deadline | None = None,
                          workers: int | None = None) -> tuple[dict, dict, bool]:
        """The structural bind plus the Pass 3 semantic skeleton the temporal families read.

        Returns ``(stamped, summary, complete)`` where ``complete`` is ``False`` if any flow
        pass hit the ``deadline`` -- the caller then declines to cache or emit the partial
        skeleton. This is the expensive, graph-version-invariant work the ``.bind.pb`` sidecar
        persists; a sidecar hit skips this method entirely (enrich *and* flow pass).
        """
        stamped, summary = self._structural_bind()
        # Fresh Pass-1 stores have the complete binary substrate required by
        # Rust's path-only semantic stage. There is no Python compatibility
        # path: stores without these artifacts must be rebuilt.
        from lachesis.flow.native_translate import native_semantic_capable
        native_semantic = native_semantic_capable(
            self.store, languages=summary.get("languages"))
        if not native_semantic:
            raise RuntimeError(
                "Pass 2 requires a fresh Pass-1 binary substrate; rebuild the graph")
        from lachesis.flow.native_translate import (
            drop_capped_functions, ensure_native_match_sidecar,
            ensure_native_semantic_sidecar, load_native_temporal,
        )
        native_sidecar = ensure_native_semantic_sidecar(
            self.store, summary.get("catalog_path"),
        )
        # Completion is the Rust matcher's call, not ours to assert. A function is
        # ``capped`` when its state budget was exhausted or its skeleton was partial;
        # any capped function means the temporal skeleton is truncated. We report that
        # honestly so the caller drops the partial skeleton (structural families only)
        # rather than caching a misleadingly thin temporal set as a complete run. The
        # match sidecar is content-addressed, so the later flow pass reuses it.
        #
        # Convergence needs only the "any function capped" bit, so publish the match
        # sidecar and scan it for that flag rather than parsing the whole findings
        # protobuf -- the full parse would materialize ~350 MB of witnesses this path
        # never reads. The flow pass still builds the complete result from the same
        # content-addressed sidecar.
        match_sidecar = ensure_native_match_sidecar(
            native_sidecar, summary.get("catalog_path"))
        # The Rust matcher has already related the temporal events (a free reached
        # twice, a use of a freed object on a reachable path) into correlated
        # findings; the analyze pass surfaces them as leads. Publish the same
        # findings on the bind so the candidate census renders the matcher's
        # confirmed temporal relation instead of one not-queried candidate per
        # dereference. This reads only the compact fields (pattern/node/line/path)
        # from the content-addressed match sidecar -- the witness bytes that
        # dominate it are never materialized here.
        temporal = load_native_temporal(match_sidecar)
        # Cap-truncation is per function, so treat it per function -- not as one
        # graph-wide veto. A function is ``capped`` when its skeleton was
        # truncated (state budget exhausted or partial), which makes only *that*
        # function's findings unsound: a balancing free may lie past the cut, so
        # a reported leak/UAF there could be spurious. Drop exactly those
        # functions' findings (honest under-coverage, surfaced as
        # ``truncated_functions``) and keep every converged function's confirmed
        # findings. The previous behavior -- one capped function forcing the
        # caller to discard the entire ``native_temporal`` bind -- silently
        # zeroed the confirmed census of an otherwise-clean graph the moment it
        # contained a single large function.
        capped_functions = drop_capped_functions(temporal)
        converged = not capped_functions
        stamped["semantic_graph"] = {
            "native_sidecar": str(native_sidecar),
            "coverage": {
                "converged": converged,
                "truncated_functions": capped_functions,
            },
        }
        # The match sidecar carries each finding's enclosing declaration id but no
        # file: that lives only in the Pass-1 structural store, which the census
        # graph dict does not include. Resolve declaration id -> file:line here,
        # where the store is in hand, so a confirmed double-free/UAF lead is
        # locatable rather than carrying ``file: None``. Purely additive to the
        # bind: navigation facts for a lead already emitted, never a verdict.
        locations: dict[str, dict] = {}
        for function in temporal.get("functions", ()):
            for finding in function.get("findings", ()):
                decl = finding.get("function")
                if not decl or decl in locations:
                    continue
                node = self.store.node(decl)
                props = (node or {}).get("properties") or {}
                file = props.get("absolute_file") or props.get("file")
                if file or props.get("start_line") is not None:
                    locations[decl] = {"file": file, "line": props.get("start_line")}
        if locations:
            temporal["locations"] = locations
        stamped["native_temporal"] = temporal
        # Temporal was evaluated across the whole graph. Per-function cap
        # truncation is reported in ``coverage.truncated_functions`` and the
        # affected functions' findings were already dropped above; it is no
        # longer a completeness veto, so the (filtered, deterministic) bind is
        # always safe to cache and return.
        return stamped, summary, True

    # -- library surface: pass 3 (analyze -> leads) ---------------------------------

    @_analysis_boundary
    def analyze(self, *, lang: str | None = None,
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
            lang or "mixed",
            workers=workers, snapshot=snapshot, deadline=deadline,
            progress=progress if progress is not None else self._progress,
        )
        return LeadSet._from_bundle(bundle, self.store)

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

    @_analysis_boundary
    def scan(self, *, lens: str = "all", limit: int | None = 20,
              hard_stop: float | None = None, workers: int | None = None) -> "LeadSet":
        """Return one ranked lead set for the selected view.

        ``all`` is the honest front-door view: it combines the obligation registry and the
        native flow leads, removes duplicate identities, and ranks the surviving questions
        together. ``flow`` is the lifetime-flow view; ``guard-diff`` is the entrypoint guard
        view. All three return the same typed result object used by :func:`scan`.
        """
        if lens == "flow":
            result = self.analyze(hard_stop=hard_stop, workers=workers)
            return result if limit is None else result._with(result.top(limit))
        if lens == "guard-diff":
            from lachesis.planner.constructors import GuardDifferential
            result = GuardDifferential(self.store).run(limit_entrypoints=0)
            rows = [Lead.from_dict(row) for row in (result.get("queue") or ())]
            rows.sort(key=lambda lead: lead.rank or 0.0, reverse=True)
            return LeadSet(leads=tuple(rows[:limit] if limit is not None else rows),
                           coverage=result.get("census"), _store=self.store)
        if lens != "all":
            raise ValueError("lens must be one of: all, guard-diff, flow")

        bundle = self._bound_bind(temporal=True, hard_stop=hard_stop, deadline=None,
                                  workers=workers)
        registry_leads = [Lead.from_dict(row)
                          for row in self._iter_candidates(bundle["registry"])]
        flow_leads = list(self.analyze(hard_stop=hard_stop, workers=workers))
        merged: dict[tuple[Any, ...], Lead] = {}
        for lead in (*registry_leads, *flow_leads):
            raw = lead.to_dict()
            key = (raw.get("candidate_id") or raw.get("pattern_id") or
                   (lead.pattern, lead.file, lead.line, lead.entry))
            current = merged.get(key)
            if current is None or (lead.rank or 0.0) > (current.rank or 0.0):
                merged[key] = lead
        rows = sorted(merged.values(), key=lambda lead: (
            -(lead.rank or 0.0), lead.file or "", lead.line or 0, lead.pattern or ""))
        if limit is not None:
            rows = rows[:limit]
        coverage = {"registry": bundle.get("atropos"),
                    "flow": LeadSet._from_bundle(self._built.get(("flow", "mixed"), {}),
                                                   self.store).summary()}
        return LeadSet(leads=tuple(rows), coverage=coverage, _store=self.store)

    # -- library surface: pass 2 (enrich -> warm sidecars) --------------------------

    @_analysis_boundary
    def enrich(self, *, hard_stop: float | None = None,
               deadline: Deadline | None = None,
               workers: int | None = None) -> dict:
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

        # Do not retain the whole enriched Python graph for the catalog bind.  The retained
        # path requires sorting roughly two million edge dictionaries before binding, which
        # can dominate Pass 2 and keep the graph-sized object peak alive.  The indexed
        # materializer below is bounded and was already the measured ~46s path on libxml2.
        # enrich only writes the sidecars to disk; it issues no queries against the tier
        # afterwards. Skip decoding the dataflow overlay back into Python so its ~1 GB does
        # not sit resident on top of the semantic Pass-3 native transient the bind runs next.
        self.store.ensure_dataflow_tier(retain_materialized=False)
        self._sync_tier()  # the tier moved under any cache built against the pre-enrich index
        bundle = self._bind_bundle(temporal=True,
                                   deadline=self._resolve_deadline(hard_stop, deadline),
                                   workers=workers)
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
                    deadline: Deadline | None, workers: int | None = None) -> dict:
        """The bind bundle for a candidate query, temporal families bounded by the budget.

        ``temporal=False`` takes the guaranteed-bounded structural fast path (no dataflow
        tier). ``temporal=True`` folds the semantic skeleton in under the resolved
        ``hard_stop``/``deadline`` and, if that times out, degrades to structural with
        ``temporal_evaluated=False`` rather than hang.
        """
        return self._bind_bundle(temporal=temporal,
                                 deadline=self._resolve_deadline(hard_stop, deadline),
                                 workers=workers)

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

    @_analysis_boundary
    def candidates(self, *, temporal: bool = True, hard_stop: float | None = None,
                   deadline: Deadline | None = None, **kwargs: Any) -> dict:
        """Candidate leads across the whole taxonomy (never scoped to one family).

        ``temporal=False`` is the fast path -- structural families only, no dataflow tier, so a
        large graph answers immediately instead of hanging; the result's ``temporal_evaluated``
        flag says the temporal families were skipped.
        """
        bundle = self._bound_bind(temporal=temporal, hard_stop=hard_stop, deadline=deadline)
        return self._stamp_temporal(bundle["registry"].candidates(**kwargs), bundle)

    @_analysis_boundary
    def census(self, constructor: str | None = None, *, temporal: bool = True,
               hard_stop: float | None = None, deadline: Deadline | None = None) -> dict:
        bundle = self._bound_bind(temporal=temporal, hard_stop=hard_stop, deadline=deadline)
        return self._stamp_temporal(bundle["registry"].census(constructor=constructor), bundle)

    def constructors(self) -> tuple:
        return self._registry().constructors  # a @property on the registry, not a call

    def domains(self) -> list:
        return self._registry().domains()

    @_analysis_boundary
    def candidate_detail(self, candidate_id: str, *, temporal: bool = True,
                         hard_stop: float | None = None,
                         deadline: Deadline | None = None) -> dict:
        """The full registry record for one candidate. For the composed one-shot -- provenance
        cone plus the sink's source read inline -- use :meth:`explain`."""
        bundle = self._bound_bind(temporal=temporal, hard_stop=hard_stop, deadline=deadline)
        return self._stamp_temporal(bundle["registry"].detail(candidate_id), bundle)

    # -- library surface: the one-shot explanation ----------------------------------

    @_analysis_boundary
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

    @_analysis_boundary
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
        registry's inferences. A guard may be a branch *condition* that names the argument
        (``conditions``) or a validation-shaped *call* the argument passes through
        (``guard_calls``, e.g. ``validate_redirect_uri``); either one counts as observed.
        Absent both it stays ``none-observed`` and never quietly reads as safe. Presence is
        neutral throughout -- a place worth reading, never a verdict that the sink is safe."""
        conditions = inferences.get("conditions") or {}
        guard_calls = inferences.get("guard_calls") or {}
        statuses = (conditions.get("status"), guard_calls.get("status"))
        status = "observed" if "observed" in statuses else (
            conditions.get("status") or guard_calls.get("status"))
        return {"status": status,
                "dominance": conditions.get("dominance"),
                "referencing_conditions": conditions.get("referencing_conditions"),
                "validation_calls": guard_calls.get("validation_calls")}

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
class Lead:
    """One typed, question-not-verdict finding from a Lachesis analysis."""

    rank: float | None = None
    pattern: str | None = None
    file: str | None = None
    line: int | None = None
    entry: str | None = None
    evaluator: str | None = None
    guard: str | None = None
    tier: str | int | None = None
    witness: Any = None
    source_function: str | None = None
    source_line: int | None = None
    pattern_id: str | None = None
    _raw: Mapping[str, Any] = field(default_factory=dict, repr=False, compare=False)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "Lead":
        """Create a typed lead while preserving producer-specific fields."""
        observations = value.get("observations") or {}
        known = {
            "rank", "pattern", "file", "line", "entry", "evaluator", "guard",
            "tier", "witness", "source_function", "source_line", "pattern_id",
        }
        return cls(
            rank=value.get("rank") if value.get("rank") is not None else 0.0,
            pattern=value.get("pattern") or value.get("constructor"),
            file=value.get("file") or observations.get("file"),
            line=value.get("line") if value.get("line") is not None
            else observations.get("line"),
            entry=value.get("entry") or observations.get("function"),
            evaluator=value.get("evaluator"), guard=value.get("guard"),
            tier=value.get("tier"), witness=value.get("witness"),
            source_function=value.get("source_function"), source_line=value.get("source_line"),
            pattern_id=value.get("pattern_id"),
            _raw={key: item for key, item in value.items() if key not in known},
        )

    def to_dict(self) -> dict[str, Any]:
        """Return the explicit plain-data representation for serialization."""
        result = dict(self._raw)
        for name in (
            "rank", "pattern", "file", "line", "entry", "evaluator", "guard", "tier",
            "witness", "source_function", "source_line", "pattern_id",
        ):
            value = getattr(self, name)
            if value is not None:
                result[name] = value
        return result

    def get(self, key: str, default: Any = None) -> Any:
        """Compatibility accessor for renderers while callers migrate to attributes."""
        return self.to_dict().get(key, default)

    def __getitem__(self, key: str) -> Any:
        return self.to_dict()[key]

    def __repr__(self) -> str:
        """Show the lead's question and source location in a REPL-friendly form."""
        pattern = self.pattern or "lead"
        location = self.file or self.entry or "unknown location"
        if self.line is not None:
            location = f"{location}:{self.line}"
        return f"<Lead {pattern!r} at {location}>"

    def _repr_html_(self) -> str:
        """Render one compact lead row in notebook environments."""
        import html
        pattern = html.escape(self.pattern or "lead")
        location = html.escape(self.file or self.entry or "unknown location")
        if self.line is not None:
            location += f":{self.line}"
        rank = "" if self.rank is None else f"{self.rank:.3f}"
        return ("<div><strong>%s</strong> <code>%s</code>"
                " <span>rank=%s</span></div>" % (pattern, location, rank))


@dataclass(frozen=True)
class LeadSet:
    """An immutable view over one flow pass's leads, with the filters and the persistence
    both sessions kept re-writing by hand.

    A lead carries only its enclosing function (``entry``) and a source ``line`` -- never a
    file path -- so ``near``/``at`` resolve function -> file(s) lazily via the symbol index,
    treating homonyms as a set (a name can live in several files; never collapse them). The
    filters return a new ``LeadSet`` sharing the same store, so they chain.
    """

    leads: tuple[Lead, ...] = ()
    timings: dict = field(default_factory=dict)
    lifetime: dict = field(default_factory=dict)
    coverage: Any = None
    timed_out: bool = False
    truncated_functions: tuple = ()
    _store: Any = field(default=None, compare=False, repr=False)
    _index_cache: Any = field(default=None, compare=False, repr=False, init=False)

    # -- construction ---------------------------------------------------------------

    @classmethod
    def _from_bundle(cls, bundle: dict, store: Any) -> "LeadSet":
        lifetime = bundle.get("lifetime") or {}
        diagnostics = lifetime.get("diagnostics") or {}
        return cls(
            leads=tuple(
                lead if isinstance(lead, Lead) else Lead.from_dict(lead)
                for lead in (bundle.get("leads") or ())
            ),
            timings=dict(bundle.get("timings") or {}),
            lifetime=lifetime,
            coverage=bundle.get("coverage"),
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

    def __iter__(self) -> Iterator[Lead]:
        return iter(self.leads)

    def __len__(self) -> int:
        return len(self.leads)

    def __bool__(self) -> bool:
        return bool(self.leads)

    def __getitem__(self, item: int | slice) -> "Lead | LeadSet":
        """Read one lead or return a new immutable result view for a slice."""
        if isinstance(item, slice):
            return self._with(self.leads[item])
        return self.leads[item]

    def top(self, n: int) -> list[Lead]:
        """Return the highest-ranked ``n`` leads without changing this result set."""
        if n < 0:
            raise ValueError("n must be zero or greater")
        return sorted(self.leads, key=lambda lead: lead.rank or 0.0, reverse=True)[:n]

    def __repr__(self) -> str:
        patterns = len(self.patterns())
        files = len({lead.file for lead in self.leads if lead.file})
        return f"<LeadSet: {len(self.leads)} leads across {patterns} patterns, {files} files>"

    __str__ = __repr__

    def _repr_html_(self) -> str:
        """Render a bounded ranked table in notebook environments."""
        import html
        rows = []
        for lead in self.top(20):
            pattern = html.escape(lead.pattern or "lead")
            location = html.escape(lead.file or lead.entry or "unknown location")
            if lead.line is not None:
                location += f":{lead.line}"
            rank = "" if lead.rank is None else f"{lead.rank:.3f}"
            rows.append(f"<tr><td>{rank}</td><td>{pattern}</td><td>{location}</td></tr>")
        if not rows:
            return "<p><em>No leads.</em></p>"
        extra = len(self.leads) - min(20, len(self.leads))
        suffix = f"<p>+{extra} more</p>" if extra else ""
        return ("<table><thead><tr><th>Rank</th><th>Lead</th><th>Location</th></tr>"
                "</thead><tbody>" + "".join(rows) + "</tbody></table>" + suffix)

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

    def by_pattern(self, pattern: str | None = None):
        """Filter to one pattern, or -- called with no argument -- return the
        pattern -> count breakdown.

        The name reads two ways: as a filter (``by_pattern("mem.copy...")`` -> a new
        LeadSet with only that pattern) and as the grouping ``summary()["by_pattern"]``
        exposes. A bare ``by_pattern()`` used to raise TypeError, colliding with that
        summary key; it now returns the same ``{pattern: count}`` mapping, so the natural
        call is no longer a dead end.
        """
        if pattern is None:
            return dict(Counter(lead.get("pattern") for lead in self.leads))
        return self._with(lead for lead in self.leads if lead.get("pattern") == pattern)

    def by_function(self, name: str, lines: tuple[int, int] | None = None) -> "LeadSet":
        """Return a new result containing leads in one enclosing function."""
        return self._with(lead for lead in self.leads
                          if lead.get("entry") == name and self._in_lines(lead, lines))

    def filter(self, predicate: Callable[[Lead], bool]) -> "LeadSet":
        """Return a new result containing leads for which ``predicate`` returns true."""
        if not callable(predicate):
            raise TypeError("predicate must be callable")
        return self._with(lead for lead in self.leads if predicate(lead))

    def near(self, file: str, lines: tuple[int, int] | None = None) -> "LeadSet":
        """Leads located in ``file`` (path, suffix, or basename), optionally within an
        inclusive ``(lo, hi)`` line window over the sink line.

        A lead's file comes from two places: the lead may carry its own file directly
        (scan and candidate leads do), and a flow lead that carries only its enclosing
        function resolves that function -> file(s) via the symbol index. Match either, so
        ``near``/``at`` work for ``scan()`` output too -- previously they consulted only
        the function index, and a lead with no ``entry`` (every scan lead) silently
        matched nothing.
        """
        index = self._index()

        def _here(lead) -> bool:
            files = set(index.get(lead.get("entry"), ()))
            own = lead.get("file")
            if own:
                files.add(own)
            return _file_matches(files, file) and self._in_lines(lead, lines)

        return self._with(lead for lead in self.leads if _here(lead))

    def at(self, file: str, line: int) -> "LeadSet":
        """Return leads whose source location matches one file and line."""
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
            "schema": "lead/v1",
            "leads": [lead.to_dict() for lead in self.leads],
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
