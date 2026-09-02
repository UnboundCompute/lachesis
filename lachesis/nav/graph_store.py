#!/usr/bin/env python3
"""Load-once store + the shared labeled-path shape every reasoning move returns.

This is the seam the whole reasoning layer (and, last, the MCP server) sits on:

  * **load once** — the canonical graph is parsed a single time into `GraphLib`
    (`GraphIndex` adjacency + `by_kind`/`by_label`/`by_file`/`by_owner`), the name
    index is built once, and the **sidecar overlay** (`overlay.py`) is merged in
    memory so derived `guard_signal` / `GUARDED` / `role` signals are queryable
    right alongside the base facts. The store on disk is never rewritten.

  * **one output shape** — `path_shape(nodes, edges)` renders any traversal result
    into the same labeled-path envelope so every move (`flow`, `reaches`,
    `siblings`, `guards`, …) speaks one language to the agent:
      - nodes: `{id, name, kind, file, line}`  (named + `file:line` anchored)
      - edges: `{src, tgt, kind, via, reason, role, confidence, fact_origin}`
    `via`/`reason`/`role` explain *why* the hop exists; `confidence`/`fact_origin`
    carry the graph's built-in provenance straight through to the answer.

Query scoping by `owner_function_id` (`scope_owner`) gives cheap function-local
slices without a re-parse.

  python3 nav/graph_store.py graph.kuzu --stat
  python3 nav/graph_store.py graph.kuzu --resolve verifySignature
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lachesis.nav.graphlib import GraphLib
from lachesis.nav import symbol_index as si
from lachesis.nav.overlay import Overlay, sidecar_path
from lachesis.core.graph_wire import (
    decode_overlay, is_dataflow_stream, read_dataflow_stream,
    read_dataflow_stream_header,
)


def node_view(node: dict) -> dict:
    """The `{id, name, kind, file, line}` projection every shape node uses."""
    props = node.get("properties") or {}
    return {
        "id": node.get("id"),
        "name": node.get("label"),
        "kind": node.get("kind"),
        "file": props.get("file"),
        "line": props.get("start_line"),
    }


def edge_view(edge: dict) -> dict:
    """The `{src, tgt, kind, via, reason, role, confidence, fact_origin}` projection.

    `kind` is the *semantic* kind (an `EXPANDS_TO` wrapper is unwrapped to its
    `via` relationship), while the raw `via`/`reason`/`role` and provenance ride
    along untouched so the caller sees exactly why a hop is in the path."""
    props = edge.get("properties") or {}
    kind = edge.get("kind")
    if kind == "EXPANDS_TO":
        kind = props.get("via") or kind
    return {
        "src": edge.get("source"),
        "tgt": edge.get("target"),
        "kind": kind,
        "via": props.get("via"),
        "reason": props.get("reason") or props.get("transition"),
        "role": props.get("role"),
        "confidence": props.get("confidence"),
        "fact_origin": props.get("fact_origin"),
    }


def enriched_store_path(graph_path: str) -> str:
    """The derived overlay-tier cache that sits beside a core-only store."""
    return str(graph_path).rstrip("/") + ".enriched"


def dataflow_overlay_path(graph_path: str) -> str:
    """Protobuf additive dataflow cache beside a core Kùzu store."""
    return str(graph_path).rstrip("/") + ".dataflow.pb"


def _dataflow_cache_matches(path: str, core_hash: str | None) -> bool:
    if not core_hash or not os.path.isfile(path):
        return False
    try:
        sidecar = Path(path)
        payload = (read_dataflow_stream_header(sidecar) if is_dataflow_stream(sidecar)
                   else decode_overlay(sidecar.read_bytes()))
    except (OSError, ValueError, TypeError):
        return False
    return payload.get("version") == 1 and payload.get("core_content_hash") == core_hash


def _merge_overlays(primary: Overlay, secondary: Overlay) -> Overlay:
    """Combine the nav sidecar and additive dataflow sidecar for one index."""
    merged = Overlay(source=primary.source or secondary.source)
    merged.node_props = {**primary.node_props, **secondary.node_props}
    merged.edge_props = {**primary.edge_props, **secondary.edge_props}
    merged.derived_nodes = [*primary.derived_nodes, *secondary.derived_nodes]
    merged.derived_edges = [*primary.derived_edges, *secondary.derived_edges]
    return merged


def _load_dataflow_overlay(path: str) -> Overlay:
    """Load the internal protobuf dataflow sidecar."""
    sidecar = Path(path)
    payload = (read_dataflow_stream(sidecar) if is_dataflow_stream(sidecar)
               else decode_overlay(sidecar.read_bytes()))
    return Overlay.from_dict(payload)


def joined_store_path(graph_path: str) -> str:
    """The rejoined store that sits beside a reduced one, once its bodies are back."""
    return str(graph_path).rstrip("/") + ".joined"


def _close_node_property_references(index, graph: dict) -> int:
    """Add resident nodes named by ``*_id`` properties to a materialized cone.

    Frontend value/path nodes are not always owned by the function whose call node
    refers to them.  A cone selected only through ownership can therefore contain a
    call with ``value_id=path`` but omit the path node. Runtime overlays legitimately
    turn that property into an edge, and composition then (correctly) rejects the
    dangling endpoint. Close those explicit graph references before enrichment.

    Only canonical ids that actually exist in the backing index are admitted. The
    closure is recursive because a value can name its owner or another path, but it
    does not follow ordinary graph edges and therefore does not widen into another
    function body.
    """
    resident = {node["id"]: node for node in graph["nodes"]}
    frontier = list(graph["nodes"])
    added = 0
    while frontier:
        node = frontier.pop()
        for key, value in (node.get("properties") or {}).items():
            if key == "evidence_ids":
                continue
            if key.endswith("_id"):
                values = (value,)
            elif key.endswith("_ids") and isinstance(value, (list, tuple, set)):
                values = value
            else:
                continue
            for candidate in values:
                if (not isinstance(candidate, str) or not candidate.startswith("v2:")
                        or candidate in resident):
                    continue
                referenced = index.nodes.get(candidate)
                if referenced is None:
                    continue
                resident[candidate] = referenced
                frontier.append(referenced)
                added += 1
    if added:
        graph["nodes"] = sorted(resident.values(), key=lambda item: item["id"])
    return added


def _joined_cache_matches(cache_path: str, source_hash: str | None) -> bool:
    """True when ``cache_path`` is a rejoin of exactly this source tree.

    Same rule as ``_cache_matches`` one function down, keyed on the source instead of on
    the core graph: a reduced store's missing half comes from a compile, so what has to
    be unchanged is the thing that was compiled. A missing hash on either side is a miss.
    """
    from lachesis.kuzu_store import (STORE_FORMAT_VERSION, is_kuzu_dir,
                                     read_store_manifest)
    if not source_hash or not is_kuzu_dir(cache_path):
        return False
    cached = read_store_manifest(cache_path)
    return (cached.get("version") == STORE_FORMAT_VERSION
            and bool(cached.get("enriched"))
            and cached.get("source_content_hash") == source_hash)


def _rejoin(graph_path: str, manifest: dict) -> str:
    """Give a reduced store its bodies back, and return the path to open instead.

    A reduced store holds the spine and the semantic layer and nothing from inside a
    function. Those bodies are a pure function of the source, so they are recompiled here
    and the stored semantics are joined onto them by content-addressed id. The result is
    written to a ``<store>.joined`` cache keyed by the source hash, so only the first
    load of a given tree pays the compile.

    Refuses rather than degrades. A body-less graph does not answer approximately, it
    answers *confidently wrong*: measured on this repo, ``guards`` reported a real guard
    function as class ``passthrough`` with score 0.0 and zero conditions, where the truth
    was ``guard``, 0.5, and three. So a missing or changed source tree is an error with
    the recorded path in it, not a warning over a thinner answer.

    Worth being plain about the trade: the reduction is a win on the artifact you build,
    ship and transfer. After a first load the machine also holds the full-size join, so
    disk at rest is not smaller.
    """
    from lachesis.kuzu_store import write_kuzu_graph
    from lachesis.partition import join_graphs
    from lachesis.pipeline import run_project_incremental, source_content_hash
    from lachesis.nav.kuzu_index import KuzuGraphIndex, materialize_graph

    source_dir = manifest.get("source_dir")
    if not source_dir or not os.path.isdir(source_dir):
        raise ValueError(
            f"{graph_path} is a reduced store: it holds no function bodies and gets "
            f"them back by recompiling the source it was built from, which it records "
            f"as {source_dir!r}. That directory is not there. Point it at the source "
            f"again, or rebuild the store without --reduced."
        )
    recorded = manifest.get("source_content_hash")
    current = source_content_hash(source_dir)
    if recorded and recorded != current:
        raise ValueError(
            f"{graph_path} is a reduced store built from {source_dir}, which has "
            f"changed since (recorded {recorded[:12]}, now {current[:12]}). Its stored "
            f"semantics describe source that is no longer there; rebuild it with "
            f"`lachesis build {source_dir} {graph_path} --reduced`."
        )
    cache = joined_store_path(graph_path)
    if _joined_cache_matches(cache, current):
        return cache

    stored = materialize_graph(KuzuGraphIndex(graph_path))
    # Incremental so that a rebuild after a source change recompiles only what moved;
    # the bundles live beside the cache they feed, not in a temporary directory.
    fresh, snapshots = run_project_incremental(
        source_dir, cache + ".frontends", enrich=False)
    joined = join_graphs(fresh, stored)
    # prune=False: whatever the reduced store held is already the decision the build made,
    # and the recompiled half must not be pruned to a different shape than the stored one.
    write_kuzu_graph(joined, snapshots, cache, prune=False, enriched=True,
                     source_content_hash=current)
    return cache


def _cache_matches(cache_path: str, core_hash: str | None) -> bool:
    """True when ``cache_path`` is a store derived from exactly this core graph.

    A missing hash on either side is a miss, never a match: an unkeyed cache cannot be
    proven to describe the current core, and serving a stale dataflow tier is worse
    than rebuilding one.

    A cache written by an older store format is a miss too, and it has to be caught
    here rather than at open: ``core_content_hash`` covers node ids and edge triples
    and deliberately excludes properties, so an outdated cache still hashes as a hit
    and would be opened by a reader whose columns it does not have."""
    from lachesis.kuzu_store import (STORE_FORMAT_VERSION, is_kuzu_dir,
                                     read_store_manifest)
    if not core_hash or not is_kuzu_dir(cache_path):
        return False
    cached = read_store_manifest(cache_path)
    return (cached.get("version") == STORE_FORMAT_VERSION
            and bool(cached.get("enriched"))
            and cached.get("core_content_hash") == core_hash)


def _copy_frontend_inventory(core_path: str, cache_path: str) -> None:
    """Carry the core's frontend inventory into the derived store's manifest, so the
    cache stays self-describing (capabilities, languages) rather than depending on the
    core store still being readable."""
    from lachesis.kuzu_store import read_store_manifest, store_manifest_file
    payload = read_store_manifest(cache_path)
    payload["frontends"] = read_store_manifest(core_path).get("frontends", [])
    with open(store_manifest_file(cache_path), "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
        handle.write("\n")


# The dataflow tier still inflates the whole store back into Python objects and folds four
# overlays over it, all in RAM. The streaming delta sidecar removes the old core/enriched
class GraphStore:
    """Everything a reasoning move needs, loaded once and shared."""

    def __init__(self, graph: dict, overlay: Overlay | None = None,
                 graph_path: str | None = None) -> None:
        self.overlay = overlay or Overlay()
        # merge derived signals in memory; the canonical dict is left untouched
        merged = self.overlay.apply_to(graph) if overlay else graph
        self.graph = merged
        self.gl = GraphLib(merged)
        self.index = self.gl.index
        self.graph_path = graph_path
        self._entries: list[dict] | None = None
        # Declarations whose neighbourhood has already been folded, so a second question
        # about the same region is free and an overlapping one folds only its remainder.
        self._folded_cones: frozenset = frozenset()
        # Bumped by every graft that actually added an edge. Anything holding a
        # analysis built over this index watches it to know the ground moved.
        self.cone_generation = 0
        # an in-memory graph is whatever the caller handed us; there is no core store to
        # re-enrich from, so the lazy path is a no-op
        self._enriched = True
        self._core_path = graph_path
        self._overlay_path = None
        self._retained_enriched_graph = None

    @classmethod
    def from_graphlib(cls, gl: GraphLib, graph_path: str | None = None,
                      overlay: Overlay | None = None) -> "GraphStore":
        """Build a store around an already-constructed ``GraphLib`` (the disk-backed
        store path), bypassing the dict merge an in-memory graph needs. The overlay is
        folded into the index itself rather than into a dict, so nothing materializes."""
        self = cls.__new__(cls)
        self.overlay = overlay or Overlay()
        self.graph = None
        self.gl = gl
        self.index = gl.index
        self.graph_path = graph_path
        self._entries = None
        self._folded_cones = frozenset()
        self.cone_generation = 0
        self._enriched = True
        self._core_path = graph_path
        self._overlay_path = None
        self._retained_enriched_graph = None
        return self

    @classmethod
    def load(cls, graph_path: str, overlay_path: str | None = None,
             *, defer_maps: bool = False) -> "GraphStore":
        """Open a Kùzu store directory. The disk-backed index satisfies the same
        accessor surface as the in-RAM one, so ``GraphLib`` and every nav tool are
        unchanged, and nothing loads the whole graph into memory.

        A core-only store (the default `lachesis build` output) opens as-is; the
        overlay dataflow tier is materialized lazily by ``ensure_dataflow_tier`` on the
        first tool that needs it, and a previously built cache beside the store is
        opened directly here so the steady state costs nothing extra."""
        from lachesis.kuzu_store import (STORE_FORMAT_VERSION, is_kuzu_dir,
                                         read_store_manifest)
        # Expand a leading ``~`` once, at the single load chokepoint, so a home-relative
        # path resolves the same from the library, the CLI, and the MCP server instead of
        # failing "not a graph store" for a directory that plainly exists.
        import os as _os
        graph_path = _os.path.expanduser(graph_path) if graph_path else graph_path
        if overlay_path:
            overlay_path = _os.path.expanduser(overlay_path)
        if not is_kuzu_dir(graph_path):
            raise ValueError(
                f"{graph_path} is not a Lachesis graph store; build one with "
                f"`lachesis build <source_dir> {graph_path}`"
            )
        core_manifest = read_store_manifest(graph_path)
        # Checked here rather than deeper down because the failure it replaces is a
        # Cypher error naming a column, which says nothing about what to do. A store is
        # a rebuildable artifact, so the fix is always the same sentence.
        found = core_manifest.get("version")
        if found != STORE_FORMAT_VERSION:
            raise ValueError(
                f"{graph_path} is a v{found} graph store and this build reads "
                f"v{STORE_FORMAT_VERSION}; rebuild it with "
                f"`lachesis build <source_dir> {graph_path}`"
            )
        open_path = graph_path
        dataflow_path = None
        # A reduced store is opened through its rejoin, never directly: without the
        # bodies the graph is half of itself, and no caller should have to know that.
        # Same shape as the `.enriched` redirect below, and for the same reason — the
        # missing tier is derivable, so deriving it is the loader's job.
        if core_manifest.get("reduced"):
            open_path = _rejoin(graph_path, core_manifest)
        elif not core_manifest.get("enriched", True):
            cached = enriched_store_path(graph_path)
            if _cache_matches(cached, core_manifest.get("core_content_hash")):
                open_path = cached
            else:
                candidate = dataflow_overlay_path(graph_path)
                if _dataflow_cache_matches(candidate, core_manifest.get("core_content_hash")):
                    dataflow_path = candidate
        self = cls._open(open_path, overlay_path=overlay_path,
                         dataflow_path=dataflow_path, defer_maps=defer_maps)
        # Structural Pass-3 artifacts are published beside the caller-facing
        # core store even when this load transparently opened an enriched/rejoined
        # implementation store.
        self.index._pass3_cache_base = graph_path
        # The overlay sidecar and the caller-facing identity stay the *core* path even
        # when the derived cache is what is actually open: the cache is an
        # implementation detail, and its sidecar would be a second, divergent copy.
        self.graph_path = graph_path
        self._core_path = graph_path
        self._overlay_path = overlay_path
        self._enriched = (
            open_path != graph_path or dataflow_path is not None
            or bool(core_manifest.get("enriched", True))
        )
        return self

    @classmethod
    def _open(cls, path: str, overlay_path: str | None = None,
              dataflow_path: str | None = None,
              *, defer_maps: bool = False) -> "GraphStore":
        from lachesis.nav.kuzu_index import KuzuGraphIndex
        index = KuzuGraphIndex(path, defer_maps=defer_maps)
        ov_path = Path(overlay_path) if overlay_path else sidecar_path(path)
        overlay = Overlay.load(ov_path)
        if dataflow_path:
            overlay = _merge_overlays(overlay, _load_dataflow_overlay(dataflow_path))
        index.attach_overlay(overlay)
        return cls.from_graphlib(GraphLib.from_index(index), graph_path=path,
                                 overlay=overlay)

    @property
    def dataflow_ready(self) -> bool:
        """Whether the overlay dataflow tier is already in the open index. Callers that
        cache ``store.index`` can watch this to tell when they have gone stale."""
        return bool(getattr(self, "_enriched", True))

    def ensure_dataflow_tier(self, *, retain_materialized: bool = True) -> "GraphStore":
        """Guarantee the overlay dataflow tier is present, building it if needed.

        Idempotent, and a no-op for a store that was built with ``--enrich`` or for an
        in-memory graph. Otherwise: materialize the core, fold the four overlay
        registries over it (``enriched = f(core_graph, languages, capabilities)`` —
        pure, so this is exactly what a build-time enrich would have produced), write
        additive records to a compact sibling ``<store>.dataflow.pb`` sidecar keyed
        by the core's content hash. Rust owns the complete cold-path enrichment;
        Python only rebinds the resulting binary overlay for query consumers.

        The manifest is written last, so a cache torn by a crash (or by a second
        process rebuilding concurrently) carries no matching hash and is rejected on the
        next load rather than served half-built.

        Callers must invoke this **before** constructing anything that caches
        ``store.index`` (``Reachability`` does, at construction), because this rebinds
        the index rather than mutating it in place."""
        if getattr(self, "_enriched", True):
            return self
        from lachesis.kuzu_store import read_store_manifest

        timing_enabled = os.environ.get("LACHESIS_PASS2_TIMINGS") == "1"
        timing_started = time.perf_counter()

        def timing(label: str) -> None:
            if timing_enabled:
                print(
                    f"[lachesis pass2] {label}: "
                    f"{time.perf_counter() - timing_started:.3f}s",
                    file=sys.stderr, flush=True,
                )

        core_path = self._core_path
        manifest = read_store_manifest(core_path)
        # The Pass-1 complete binary input is the native Pass-2 contract. When it is
        # present, keep Python out of the whole-graph enrichment step: Rust opens the
        # framed protobuf by path, runs the overlays, and publishes the sidecar. The
        # Python index is only rebound afterwards for query/bind consumers.
        from lachesis.nav.dataflow.substrate import pass2_input_cache_path
        native_input = pass2_input_cache_path(core_path)
        native_cache = dataflow_overlay_path(core_path)
        if native_input.is_file():
            from lachesis.flow.native_lifetime import run_pass2_path
            catalog_path = None
            from lachesis.integrations.atropos.enrich import locate_atropos
            atropos_root = locate_atropos()
            if atropos_root is not None:
                from lachesis.integrations.atropos.native_bind import compiled_catalog
                catalog_path = compiled_catalog(atropos_root, core_path)
            if not _dataflow_cache_matches(native_cache, manifest.get("core_content_hash")):
                timing("native Pass-2 starting")
                run_pass2_path(native_input, native_cache, catalog_path)
                timing("native Pass-2 published")
            if retain_materialized:
                # Rebind the open index onto the decoded dataflow overlay so in-process
                # query/bind consumers see the tier. This pins the whole overlay
                # (node/edge props + derived nodes/edges, ~1 GB on a large graph) in
                # Python for the life of the store -- the price of answering queries
                # from RAM. Every no-arg caller (nav queries, planners) wants this.
                dataflow_overlay = _load_dataflow_overlay(native_cache)
                merged_overlay = _merge_overlays(self.overlay, dataflow_overlay)
                self.index.attach_overlay(merged_overlay)
                self.overlay = merged_overlay
                self.gl = GraphLib.from_index(self.index)
                timing("dataflow overlay attached")
            else:
                # The tier is fully persisted to `.dataflow.pb`; a caller that only
                # needs the sidecars on disk (enrich) skips decoding it back into
                # Python, keeping the dataflow overlay out of the cold-materialization
                # peak. It never coexists with the semantic Pass-3 native transient
                # that the bind runs next. The tier is reconstructable on demand from
                # `native_cache` via `_load_dataflow_overlay`, so a later query path
                # must call `ensure_dataflow_tier()` (retaining) before touching it.
                timing("dataflow overlay materialized (not retained)")
            self.graph = None
            self._retained_enriched_graph = None
            self._entries = None
            self._enriched = True
            return self
        raise RuntimeError(
            "Pass 2 requires the binary sidecar emitted by a fresh Pass 1; "
            "rebuild this graph with `lachesis build`")

    def take_retained_enriched_graph(self):
        """Return the one-shot graph retained for the immediately following bind."""
        graph = getattr(self, "_retained_enriched_graph", None)
        self._retained_enriched_graph = None
        return graph

    def ensure_dataflow_cone(self, seed_id: str, budget: int = None) -> dict:
        """Ensure the complete native tier before a scoped query consumes it.

        The old scoped Python fold was removed. ``budget`` is retained in the signature
        for callers that still pass it, but native Pass 2 always operates on the complete
        binary substrate so a scoped query cannot silently under-approximate results.
        """
        empty = {"members": 0, "nodes": 0, "edges": 0, "truncated": False,
                 "deferred_edges_omitted": 0}
        # The native Pass-2 engine is whole-graph and binary. A scoped Python
        # overlay fold is no longer an alternate implementation; ensure the
        # canonical native tier and let callers query its indexed result.
        self.ensure_dataflow_tier()
        return empty


    # -- name entry / teleport ----------------------------------------------

    @property
    def entries(self) -> list[dict]:
        if self._entries is None:
            self._entries = si.build_index(self.gl)
        return self._entries

    @property
    def resolver(self):
        """The lazy resolution tier over this store's index.

        Lazy like ``entries``, and for the same reason: a store that is only ever asked
        for a file listing should not pay for one. Bound to the index rather than to the
        store because that is what the resolver actually reads — and because
        ``ensure_dataflow_tier`` swaps ``self.index`` for a larger one, at which point a
        resolver cached on the store would be memoizing answers about a graph that is no
        longer the one being queried.
        """
        from lachesis.resolution import resolver_for
        return resolver_for(self.index, self.graph_hash())

    def graph_hash(self) -> str:
        """The identity a memo is keyed on: which graph these answers are about.

        The base store and its ``.enriched`` sidecar are two databases whose call sites
        resolve differently, so a memo that crossed between them would be a confident
        wrong answer. The open store's own manifest hash is what distinguishes them.
        """
        from lachesis.kuzu_store import read_store_manifest
        try:
            path = getattr(self, "graph_path", None)
            manifest = read_store_manifest(path) if path else {}
        except Exception:
            return ""
        return str(manifest.get("graph_content_hash")
                   or manifest.get("core_content_hash") or "")

    def resolve(self, name: str) -> list[dict]:
        """Name -> candidate index entries (exact first, else fuzzy)."""
        return si._resolve(self.gl, self.entries, name)

    def node(self, node_id: str) -> dict | None:
        return self.gl.nodes.get(node_id)

    # -- scoping -------------------------------------------------------------

    def scope_owner(self, owner_id: str) -> tuple[dict, ...]:
        """Cheap function-local slice: nodes owned by a function (no re-parse)."""
        return self.index.nodes_owned_by(owner_id)

    # -- the one output shape ------------------------------------------------

    def path_shape(self, nodes, edges, *, manifest: dict | None = None) -> dict:
        """Render nodes/edges into the shared labeled-path envelope.

        `nodes` may be node dicts or ids; `edges` are edge dicts. Node order is
        preserved (a witness path stays in path order); duplicates collapse."""
        seen: set[str] = set()
        out_nodes: list[dict] = []
        for n in nodes:
            node = self.node(n) if isinstance(n, str) else n
            if not node:
                continue
            nid = node.get("id")
            if nid in seen:
                continue
            seen.add(nid)
            out_nodes.append(node_view(node))
        out_edges = [edge_view(e) for e in edges]
        env = {"nodes": out_nodes, "edges": out_edges,
               "counts": {"nodes": len(out_nodes), "edges": len(out_edges)}}
        if manifest:
            env["manifest"] = manifest
        return env

    def stat(self) -> dict:
        return {
            "graph": self.graph_path,
            "nodes": len(self.gl.nodes),
            "edges": sum(len(v) for v in self.index.outgoing.values()),
            "names_indexed": len(self.entries),
            "overlay": self.overlay.summary(),
        }


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="load-once reasoning store + path-shape")
    p.add_argument("graph")
    p.add_argument("--overlay", help="override the sidecar overlay path")
    p.add_argument("--stat", action="store_true", help="graph + overlay stats")
    p.add_argument("--resolve", metavar="NAME", help="resolve a name to node(s)")
    return p


def main(argv: list[str]) -> int:
    args = _parser().parse_args(argv)
    store = GraphStore.load(args.graph, overlay_path=args.overlay)
    if args.stat:
        # --stat reports node/edge counts, which are tier-dependent; --resolve is a name
        # lookup and stays on whatever tier the store already has.
        store.ensure_dataflow_tier()
    if args.resolve:
        hits = store.resolve(args.resolve)
        print(json.dumps(hits, indent=2, ensure_ascii=False))
        return 0
    print(json.dumps(store.stat(), indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
