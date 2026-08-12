"""Build one canonical project graph through registered compiler frontends."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from .core.contract import ContractError as FrontendError, FrontendSnapshot
from .core.runner import run_frontend
from .core.snapshot import load_snapshot
from .frontends.registry import FrontendRegistry, default_registry
from .types import CodeGraph, GraphEdge, GraphNode


def snapshot_graph(snapshot: FrontendSnapshot) -> CodeGraph:
    """Convert one validated frontend snapshot without changing its facts."""
    nodes: List[GraphNode] = []
    for source in snapshot.nodes:
        properties = dict(source.get("properties", {}))
        properties.update({
            "frontend_id": snapshot.frontend_id,
            "frontend_tier": source.get("tier"),
        })
        nodes.append({
            "id": source["id"], "kind": source["kind"],
            "label": source.get("label", source["id"]), "properties": properties,
        })
    edges: List[GraphEdge] = []
    for source in snapshot.edges:
        properties = dict(source.get("properties", {}))
        properties.update({
            "frontend_id": snapshot.frontend_id,
            "source_tier": source.get("source_tier"),
            "relationship_class": source.get("relationship_class"),
        })
        edges.append({
            "kind": source["kind"], "source": source["source"],
            "target": source["target"], "properties": properties,
        })
    return {"nodes": nodes, "edges": edges}


def combine_graphs(graphs: Iterable[CodeGraph]) -> CodeGraph:
    """Union canonical graphs while rejecting conflicting stable identities."""
    graph, _ = _combine_graphs(graphs, drop_dangling=False)
    return graph


def _combine_graphs(
    graphs: Iterable[CodeGraph], *, drop_dangling: bool,
) -> Tuple[CodeGraph, int]:
    """``combine_graphs``, plus a count of the edges dropped for a missing endpoint.

    ``drop_dangling`` exists for the per-package parallel build, where a cross-package
    edge's far endpoint legitimately lives in a graph this union does not contain. It
    is never silent: the count comes back so the caller can report it. The serial path
    passes ``False`` and keeps raising, because there a dangling edge is a real bug.
    """
    nodes: Dict[str, GraphNode] = {}
    edges: List[GraphEdge] = []
    edge_keys = set()
    for graph in graphs:
        for node in graph["nodes"]:
            existing = nodes.get(node["id"])
            if existing and existing != node:
                raise FrontendError(f"frontends emitted conflicting node id {node['id']}")
            nodes[node["id"]] = node
        for edge in graph["edges"]:
            key = (
                edge["kind"], edge["source"], edge["target"],
                json.dumps(edge.get("properties", {}), sort_keys=True),
            )
            if key not in edge_keys:
                edge_keys.add(key)
                edges.append(edge)
    known = set(nodes)
    dangling = [
        edge for edge in edges
        if edge["source"] not in known or edge["target"] not in known
    ]
    if dangling and not drop_dangling:
        first = dangling[0]
        raise FrontendError(
            f"combined graph has {len(dangling)} dangling edges; first is "
            f"{first['source']} -> {first['target']}"
        )
    if dangling:
        dropped = {id(edge) for edge in dangling}
        edges = [edge for edge in edges if id(edge) not in dropped]
    return {
        "nodes": sorted(nodes.values(), key=lambda item: item["id"]),
        "edges": sorted(edges, key=lambda item: (
            item["kind"], item["source"], item["target"],
        )),
    }, len(dangling)


def source_inventory(source_dir: str, include_tests: bool = False) -> List[str]:
    """Discover source files. Test/spec files are excluded by default — they are not
    attack surface and production code does not import them, so dropping them at
    discovery (before compile) is safe for type resolution and shrinks the graph. The
    test predicate is the single source of truth in ``nav.symbol_index`` (imported
    lazily to avoid an import cycle), so build-time exclusion can never drift from any
    query-time notion of "is a test"."""
    # node_modules has a Python counterpart in every direction: an installed
    # virtualenv, a build cache, and a tool cache. Walking any of them analyses
    # somebody else's source as if it were the project's, which is both slow and
    # wrong; site-packages alone can outweigh the repository several times over.
    # A framework's build directory is the same problem wearing a different name, and
    # it is worse than a dependency tree: the files in it are *generated bundles* of
    # code already in the repository, so walking them analyses the project twice, once
    # as source and once as minified output. A single bundled file also concentrates a
    # whole application into one enormous line, which is what actually exhausts a
    # compiler's heap. Measured on `vercel-chat/apps`: 809 of 909 discovered files were
    # Next.js output under `.next`, and the TypeScript frontend ran out of memory at a
    # 12 GB heap. Only unambiguously generated directory names belong here; `out` and
    # `vendor` are deliberately absent because a project may legitimately keep source
    # under either.
    ignored = {
        ".git", "node_modules", "graph_out", "dist", "build",
        ".venv", "venv", "__pycache__", ".tox", ".nox",
        ".mypy_cache", ".pytest_cache", ".ruff_cache", "site-packages", ".eggs",
        ".next", ".nuxt", ".svelte-kit", ".output", ".turbo", ".angular",
        ".parcel-cache", ".docusaurus", ".vercel", ".cache", "coverage",
        "bower_components",
    }
    is_test = None
    if not include_tests:
        from nav.symbol_index import is_test_path as is_test
    result = []
    for root, directories, files in os.walk(os.path.abspath(source_dir)):
        directories[:] = sorted(name for name in directories if name not in ignored)
        for name in sorted(files):
            path = os.path.join(root, name)
            if is_test is not None and is_test(path):
                continue
            result.append(path)
    return result


def _combined_capabilities(snapshots: Sequence[FrontendSnapshot]) -> dict[str, str]:
    rank = {"none": 0, "partial": 1, "complete": 2}
    names = {name for snapshot in snapshots for name in snapshot.capabilities}
    return {
        name: max(
            (snapshot.capability(name) for snapshot in snapshots),
            key=lambda level: rank[level],
        )
        for name in names
    }


def enrich_graph(
    graph: CodeGraph, languages: Iterable[str], capabilities: Dict[str, str],
) -> CodeGraph:
    """Fold the four overlay registries over a core graph to produce the dataflow tier.

    Pure and deterministic: ``enriched = f(core_graph, languages, capabilities)``. The
    package inventory the ecosystem registry needs is derived from the graph, so those
    two values are the *only* inputs beyond the graph itself — which is exactly why
    this can run at load time from a core-only store, given a manifest.
    """
    from .core.overlays import (
        default_model_overlay_registry,
        default_overlay_registry,
        default_security_overlay_registry,
    )
    from .core.query import GraphIndex
    from .ecosystems import default_ecosystem_registry

    graph = default_overlay_registry().enrich(graph)
    index = GraphIndex(graph)
    graph = default_ecosystem_registry().enrich(
        graph, index.package_inventory(), set(languages), capabilities,
    )
    graph = default_model_overlay_registry().enrich(graph)
    return default_security_overlay_registry().enrich(graph)


def _enrich_graph(graph: CodeGraph, snapshots: Sequence[FrontendSnapshot]) -> CodeGraph:
    return enrich_graph(
        graph,
        {language for snapshot in snapshots for language in snapshot.languages},
        _combined_capabilities(snapshots),
    )


def run_project(
    source_dir: str,
    output_root: Optional[str] = None,
    registry: Optional[FrontendRegistry] = None,
    timeout_seconds: int = 300,
    include_tests: bool = False,
    *,
    enrich: bool = True,
) -> Tuple[CodeGraph, List[FrontendSnapshot]]:
    """Run selected frontends and enrich their canonical facts directly.

    Discovery (``source_inventory``) drops test files by default; the filtered
    per-frontend file list is handed to each frontend as its explicit root set, so a
    frontend that re-walks the tree cannot re-introduce the tests we excluded.

    ``enrich=False`` returns the compact core graph (T0-T3) without the overlay
    dataflow tier, which the nav layer can rebuild on demand from a store manifest.
    The default stays ``True`` so every library caller is unaffected."""
    source_dir = os.path.abspath(source_dir)
    registry = registry or default_registry()
    groups = registry.partition(source_inventory(source_dir, include_tests=include_tests))
    snapshots = []
    for frontend_id in sorted(groups):
        frontend = registry.get(frontend_id)
        frontend_output = (
            os.path.join(os.path.abspath(output_root), frontend_id)
            if output_root else None
        )
        snapshots.append(run_frontend(
            frontend, source_dir, frontend_output, timeout_seconds,
            roots=groups[frontend_id],
        ))
    if not snapshots:
        supported = sorted({
            extension for item in registry.frontends for extension in item.extensions
        })
        raise FrontendError(
            f"no registered frontend supports files below {source_dir}; "
            f"supported extensions: {', '.join(supported)}"
        )
    graph = combine_graphs(snapshot_graph(snapshot) for snapshot in snapshots)
    return (_enrich_graph(graph, snapshots) if enrich else graph), snapshots


def _file_digest(path: str) -> str:
    """SHA-256 of a source file's bytes — the incremental change key. Self-contained
    (not tied to how any frontend stamps its own content_hash) so the manifest is
    internally consistent regardless of frontend behavior."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _group_digests(files: Iterable[str], source_dir: str) -> Dict[str, str]:
    """Digest each file in a frontend's group, keyed by path relative to
    ``source_dir`` so the manifest is portable across checkout locations."""
    return {os.path.relpath(path, source_dir): _file_digest(path)
            for path in sorted(files)}


def _load_manifest(manifest_path: Optional[str]) -> Dict[str, dict]:
    if not manifest_path or not os.path.isfile(manifest_path):
        return {}
    try:
        payload = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}  # a corrupt/partial manifest just forces a full recompile
    frontends = payload.get("frontends") if isinstance(payload, dict) else None
    return frontends if isinstance(frontends, dict) else {}


def _write_manifest(manifest_path: str, frontends: Dict[str, dict]) -> None:
    output = Path(manifest_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps({"version": 1, "frontends": frontends}, indent=2) + "\n",
        encoding="utf-8",
    )


def default_manifest_path(output_root: str) -> str:
    """The incremental manifest lives beside the per-frontend bundles."""
    return os.path.join(os.path.abspath(output_root), "incremental_manifest.json")


def run_project_incremental(
    source_dir: str,
    output_root: str,
    registry: Optional[FrontendRegistry] = None,
    timeout_seconds: int = 300,
    include_tests: bool = False,
    manifest_path: Optional[str] = None,
    *,
    enrich: bool = True,
) -> Tuple[CodeGraph, List[FrontendSnapshot]]:
    """Like ``run_project`` but reuse a frontend's prior on-disk bundle when none of
    its source files changed, recompiling only the frontends that did.

    The compose + enrich tail is shared verbatim with ``run_project``, so the result
    is identical to a full run: a reused snapshot is exactly the bytes a recompile of
    unchanged files would produce, and ``combine_graphs``/``_enrich_graph`` are
    deterministic over the same snapshot set. ``output_root`` is required — the reused
    bundles and the change manifest both live under it."""
    source_dir = os.path.abspath(source_dir)
    output_root = os.path.abspath(output_root)
    registry = registry or default_registry()
    manifest_path = manifest_path or default_manifest_path(output_root)
    groups = registry.partition(source_inventory(source_dir, include_tests=include_tests))
    prior = _load_manifest(manifest_path)

    snapshots: List[FrontendSnapshot] = []
    manifest: Dict[str, dict] = {}
    for frontend_id in sorted(groups):
        frontend_output = os.path.join(output_root, frontend_id)
        digests = _group_digests(groups[frontend_id], source_dir)
        prior_entry = prior.get(frontend_id) or {}
        can_reuse = (
            prior_entry.get("files") == digests
            and Path(frontend_output, "manifest.json").is_file()
        )
        if can_reuse:
            snapshots.append(load_snapshot(frontend_output))
        else:
            frontend = registry.get(frontend_id)
            snapshots.append(run_frontend(
                frontend, source_dir, frontend_output, timeout_seconds,
                roots=groups[frontend_id],
            ))
        manifest[frontend_id] = {"bundle_dir": frontend_output, "files": digests}

    if not snapshots:
        supported = sorted({
            extension for item in registry.frontends for extension in item.extensions
        })
        raise FrontendError(
            f"no registered frontend supports files below {source_dir}; "
            f"supported extensions: {', '.join(supported)}"
        )
    graph = combine_graphs(snapshot_graph(snapshot) for snapshot in snapshots)
    result = _enrich_graph(graph, snapshots) if enrich else graph
    _write_manifest(manifest_path, manifest)
    return result, snapshots


def _job_output_dir(output_root: str, frontend_id: str, package: str) -> str:
    """A private output directory per (frontend, package).

    Mandatory, not an optimization: ``run_frontend`` writes ``lachesis-roots.txt`` into
    its output directory under a fixed name, so two jobs sharing one directory would
    overwrite each other's root set and compile the wrong files.
    """
    slug = package.replace(os.sep, "__").replace("<", "").replace(">", "") or "root"
    return os.path.join(output_root, frontend_id, slug)


def package_jobs(
    source_dir: str,
    output_root: str,
    registry: FrontendRegistry,
    include_tests: bool = False,
) -> List[Tuple[str, str, str, str, List[str]]]:
    """The (frontend_id, package, compile_root, output_dir, roots) units of a build.

    ``compile_root`` is the package directory, not the repo root, so each job discovers
    its own ``tsconfig.json`` and compiles as one program — which is the semantic change
    that makes this opt-in.
    """
    from .packages import detect_packages, package_root_for

    source_dir = os.path.abspath(source_dir)
    output_root = os.path.abspath(output_root)
    packages = detect_packages(source_dir,
                               source_inventory(source_dir, include_tests=include_tests))
    jobs = []
    for (frontend_id, package), roots in registry.partition_by_package(packages).items():
        jobs.append((frontend_id, package, package_root_for(source_dir, package),
                     _job_output_dir(output_root, frontend_id, package), roots))
    return jobs


def _run_package_job(job: Tuple[str, str, str, List[str], int, Optional[str]]) -> str:
    """Pool worker: compile one (frontend, package) unit, return its bundle directory.

    The worker returns a *path*, not the snapshot: a ``FrontendSnapshot`` is a large
    dict-of-lists and pickling it back through the pool is pure overhead when the
    parent can ``load_snapshot`` the bundle it just wrote — which is exactly what the
    incremental path already does. Module-level and taking only picklable arguments so
    it works under the spawn start method.
    """
    frontend_id, compile_root, output_dir, roots, timeout_seconds, workspace_root = job
    registry = default_registry(workspace_root)
    run_frontend(registry.get(frontend_id), compile_root, output_dir, timeout_seconds,
                 roots=roots)
    return output_dir


def _reanchor_file(node: GraphNode, source_dir: str) -> GraphNode:
    """Rewrite a node's ``file`` to be relative to the *project*, not its package.

    The frontend reports ``file`` relative to the directory it was pointed at, so a
    per-package build gives every package its own ``src/index.ts`` — the same
    user-facing path for different files, which breaks `open_file`, the by-file index,
    and every ``file:line`` anchor an answer prints. ``absolute_file`` is unambiguous
    and always present for in-tree nodes, so the project-relative path is recoverable
    exactly. Out-of-tree nodes (the TypeScript lib declarations) are left alone: the
    whole-repo build reports those as absolute paths too.
    """
    properties = node.get("properties") or {}
    absolute = properties.get("absolute_file")
    prefix = source_dir.rstrip(os.sep) + os.sep
    if not isinstance(absolute, str) or not absolute.startswith(prefix):
        return node
    relative = os.path.relpath(absolute, source_dir)
    previous = properties.get("file")
    if previous == relative:
        return node
    node = {**node, "properties": {**properties, "file": relative}}
    # `file` and `source-span` nodes carry the path in their *label* as well, which is
    # what every answer prints; leaving it package-relative would keep exactly the
    # ambiguity this rewrite removes. Anchored to the old value rather than guessed, so
    # a label that is not path-derived is untouched.
    label = node.get("label")
    if isinstance(previous, str) and isinstance(label, str):
        if label == previous:
            node["label"] = relative
        elif label.startswith(previous + ":"):
            node["label"] = relative + label[len(previous):]
    return node


def _merge_package_graphs(
    units: Sequence[Tuple[str, CodeGraph]], owner_of_file: Dict[str, str],
    source_dir: str,
) -> Tuple[CodeGraph, int]:
    """Union per-package graphs, letting the package that owns a file speak for it.

    Per-package programs overlap: compiling ``packages/api`` pulls ``packages/core``'s
    sources in as imported dependencies and emits nodes for them too. Those nodes carry
    the *same* ids but strictly poorer facts — the neighbour sees the file as a
    ``workspace-library`` and resolves no ``scope_id``/``symbol_id`` for it, while the
    owning package sees it as ``application`` code and resolves both. Feeding both
    copies to ``combine_graphs`` is what makes it raise on conflicting ids, and picking
    arbitrarily would silently degrade whichever file lost.

    So the rule is ownership: a node about a file belongs to the package that contains
    that file, and every other package's view of it is discarded. Nodes with no
    first-party owner (the TypeScript lib declarations, synthetic package nodes) go to
    the first unit that emits them, in the units' fixed sorted order, so the result does
    not depend on scheduling. Edges follow their source node's winner, which keeps
    cross-package call edges — their target id is the same id the owning package
    emitted, so the union resolves them.
    """
    winner: Dict[str, int] = {}
    for index, (package, graph) in enumerate(units):
        for node in graph["nodes"]:
            path = (node.get("properties") or {}).get("absolute_file")
            if path is not None and owner_of_file.get(path) == package:
                winner[node["id"]] = index  # an owning package always outranks a viewer
            elif node["id"] not in winner:
                winner[node["id"]] = index
    selected = [
        {"nodes": [_reanchor_file(n, source_dir)
                   for n in graph["nodes"] if winner.get(n["id"]) == index],
         "edges": [e for e in graph["edges"] if winner.get(e["source"]) == index]}
        for index, (_package, graph) in enumerate(units)
    ]
    return _combine_graphs(selected, drop_dangling=True)


def run_project_parallel(
    source_dir: str,
    output_root: str,
    registry: Optional[FrontendRegistry] = None,
    timeout_seconds: int = 300,
    include_tests: bool = False,
    *,
    enrich: bool = True,
    max_workers: Optional[int] = None,
    workspace_root: Optional[str] = None,
) -> Tuple[CodeGraph, List[FrontendSnapshot], int]:
    """Compile each (frontend, package) unit in its own process, then compose.

    Returns the graph, the snapshots, and the number of cross-package edges dropped.

    Two honest caveats, both structural:

    * **This is not the serial build made faster.** Each package compiles as its own
      program, so type resolution spans one package rather than the whole tree. The
      result is compared against a *serial per-package* build, not against a whole-repo
      one. That is why the caller has to opt in.
    * **Wall time is floored by the largest single package.** A repo whose work sits in
      one big package gains nothing here, and a repo with N packages does not go N times
      faster. Do not read this as linear scaling.

    A single-unit repo takes the serial path and constructs no pool.
    """
    from concurrent.futures import ProcessPoolExecutor

    from .packages import detect_packages

    source_dir = os.path.abspath(source_dir)
    output_root = os.path.abspath(output_root)
    registry = registry or default_registry(workspace_root)
    jobs = package_jobs(source_dir, output_root, registry, include_tests=include_tests)
    if not jobs:
        supported = sorted({
            extension for item in registry.frontends for extension in item.extensions
        })
        raise FrontendError(
            f"no registered frontend supports files below {source_dir}; "
            f"supported extensions: {', '.join(supported)}"
        )

    payloads = [(frontend_id, compile_root, output_dir, roots, timeout_seconds,
                 workspace_root)
                for frontend_id, _package, compile_root, output_dir, roots in jobs]
    # capped at the core count: the frontends are themselves CPU-bound compilers, so
    # oversubscribing turns parallelism into contention.
    workers = max_workers or min(len(payloads), os.cpu_count() or 1)
    if len(payloads) == 1 or workers <= 1:
        # ``max_workers=1`` is the serial-over-the-same-partition reference the parallel
        # build is tested against; a single unit never justifies a pool either way.
        bundles = [_run_package_job(payload) for payload in payloads]
    else:
        with ProcessPoolExecutor(max_workers=workers) as pool:
            # map preserves input order, so the snapshot order (and with it the composed
            # graph) does not depend on which worker finished first
            bundles = list(pool.map(_run_package_job, payloads))

    snapshots = [load_snapshot(bundle) for bundle in bundles]
    owner_of_file = {
        path: package
        for package, paths in detect_packages(
            source_dir, source_inventory(source_dir, include_tests=include_tests),
        ).items()
        for path in paths
    }
    graph, dropped = _merge_package_graphs(
        [(job[1], snapshot_graph(snapshot))
         for job, snapshot in zip(jobs, snapshots)],
        owner_of_file, source_dir,
    )
    return (_enrich_graph(graph, snapshots) if enrich else graph), snapshots, dropped


def semantic_snapshot_graph(snapshot: FrontendSnapshot) -> CodeGraph:
    """Enrich one already-loaded snapshot without a FileInfo round trip."""
    return _enrich_graph(snapshot_graph(snapshot), [snapshot])
