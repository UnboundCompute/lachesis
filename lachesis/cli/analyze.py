#!/usr/bin/env python3
"""Run all registered compiler frontends and write one composed graph."""
from __future__ import annotations

import argparse
import hashlib
import os
import sys
import tempfile
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from lachesis.cache import _version
from lachesis.kuzu_store import read_store_manifest, write_kuzu_graph, write_kuzu_shards
from lachesis.core.shards import CompositeShardReader
from lachesis.partition import (BODY, SEMANTIC, SPINE, partition_counts,
                                reduce_graph)
from lachesis.pipeline import (run_project,
                               run_project_incremental, run_project_parallel,
                               run_project_streaming, run_project_streaming_parallel,
                               source_content_hash,
                               default_manifest_path)
from lachesis.projections import build_layered_graph, write_layered_graph


def _positive_int(value: str) -> int:
    """Argparse type that prevents silently useless zero/negative limits."""
    try:
        parsed = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be an integer") from error
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def _run(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="version", version=_version())
    parser.add_argument("source_dir")
    parser.add_argument(
        "output_path", nargs="?", default="graph_out/compiler_project.kuzu",
        help="Kùzu store directory to write (holds graph.kuzu plus the store "
             "manifest). This is the graph: nav and `lachesis query` both read it.",
    )
    parser.add_argument(
        "-o", "--output", dest="output_flag", metavar="PATH", default=None,
        help="the same output path as the positional argument, spelled as a flag "
             "so it matches `lachesis analyze -o`; a user who learned -o on one pass "
             "should not be rejected on the other. If both are given, the flag wins.",
    )
    parser.add_argument(
        "--frontend-out", metavar="DIR", default=None,
        help="also retain each compiler's native layered snapshot here. Off by "
             "default: nothing in a normal build reads these bundles back, and a "
             "frontend that can run in this process skips serialising them at all, "
             "which is most of what the Python frontend spends its time on. Name a "
             "directory to keep them for inspection or for an incremental rebuild.",
    )
    parser.add_argument(
        "--layered-out", metavar="DIR", default=None,
        help="also write the layered-v2 projection here: one file per tier (T0-T4) "
             "plus node_index.json and manifest.json. This is the progressive, "
             "LLM-drillable view of the same canonical graph.",
    )
    parser.add_argument(
        "--prune", action=argparse.BooleanOptionalAction, default=True,
        help="drop the pure-lexical `token` and `source-span` nodes (and the edges "
             "that touch them) from the store. Every navigation tool answers "
             "identically without them (source excerpts are read from the file by "
             "offset), so this is lossless for nav and roughly halves the store — and "
             "it also spares the frontend the token/proof passes that produced them "
             "(for C, a whole extra clang parse of every file). ON by default so a "
             "normal build is lean and fast without any flag; pass --no-prune to keep "
             "the full T0 lexical content, which only matters when literal value nodes "
             "must be observable (e.g. maximum guard-rank fidelity).",
    )
    parser.add_argument(
        "--enrich", action="store_true",
        default=os.environ.get("LACHESIS_ENRICH_AT_BUILD") == "1",
        help="fold the overlay dataflow tier (taint, CFG, points-to, routes) into the "
             "store at build time. Off by default: the tier is a pure function of the "
             "core graph plus the store manifest, so nav rebuilds it on first use and "
             "caches it beside the store, keeping it off the critical path of every "
             "build. Set LACHESIS_ENRICH_AT_BUILD=1 for the same effect.",
    )
    parser.add_argument(
        "--reduced", action="store_true",
        help="store only the spine (files, declarations, scopes, call sites) and the "
             "semantic layer that enrichment derived, leaving out the intra-function "
             "bodies. A frontend hands the bodies back from the same source in seconds "
             "and node ids are content-addressed, so nav recompiles them at load and "
             "rejoins the stored semantics onto them. Implies --enrich, since there is "
             "no semantic layer to keep without it.",
    )
    parser.add_argument(
        "--timeout", type=_positive_int, default=300, metavar="SECONDS",
        help="how long one frontend subprocess may run before the build gives up on "
             "it (default 300). This bounds a single compile, not the whole build, so "
             "a project with three frontends can legitimately take three times this. "
             "Raise it for a large tree: a frontend killed mid-analysis reports as a "
             "contract error, which reads like a bug in the source it was pointed at.",
    )
    parser.add_argument(
        "--incremental", action="store_true",
        help="reuse each frontend's prior on-disk bundle (under --frontend-out) when "
             "none of its source files changed, recompiling only the ones that did; "
             "the composed graph is identical to a full run.",
    )
    parser.add_argument(
        "--parallel-packages", action="store_true",
        help="compile each first-party package (a directory with a package.json, "
             "outside node_modules) in its own process. OFF by default because it is "
             "a semantic change, not just a scheduling one: each package becomes its "
             "own compiler program, so types resolve within a package rather than "
             "across the whole tree, and cross-package edges whose far endpoint lands "
             "in another unit are dropped (the count is printed). Wall time is floored "
             "by the largest single package, so this is not linear scaling.",
    )
    parser.add_argument(
        "--max-workers", type=_positive_int, default=None, metavar="N",
        help="cap the --parallel-packages pool (default: one worker per package, "
        "never more than the core count). N=1 runs the same partition serially.",
    )
    parser.add_argument(
        "--shard-large-packages", type=_positive_int, default=None, metavar="FILES",
        help="with --parallel-packages, split any package larger than FILES roots "
        "into bounded compiler jobs; this is an opt-in semantic tradeoff and "
        "reports cross-shard edges that cannot be merged",
    )
    parser.add_argument(
        "--stream-shards", metavar="DIR", default=None,
        help="stream core-only frontend shards directly into Kùzu",
    )
    parser.add_argument(
        "--memory-budget-mb", type=_positive_int, default=None, metavar="MiB",
        help="total memory budget for the whole build process tree, in MiB. The C "
             "frontend is compiled in bounded per-chunk processes and the store is "
             "written with bounded RSS, so a Linux-scale tree builds without OOM; this "
             "is the single knob that sizes the chunking. The default (5120) suits a "
             "laptop; raise it on a big box to compile more translation units per chunk "
             "(fewer, larger frontend processes) and lower it on a constrained runner. "
             "Equivalent to setting LACHESIS_MEMORY_BUDGET_MB; the flag wins if both "
             "are given. The emitted graph is identical at any budget -- only where the "
             "chunk boundaries fall, and thus peak memory, changes.",
    )
    parser.add_argument(
        "--include", metavar="PATH", action="append", default=None, dest="include_paths",
        help="also analyse this file or directory, even when it lies outside "
             "source_dir. Repeatable. This is the guided-scope guarantee: when a build "
             "is narrowed to a sub-tree to fit the time budget, point --include at the "
             "advisory's vulnerable file (or its directory) so the one file the run "
             "exists to reach is never scoped out. An explicitly named file is always "
             "kept; a directory is walked with the same ignore rules as source_dir.",
    )
    args = parser.parse_args(argv)
    if args.output_flag is not None:
        args.output_path = args.output_flag
    # The memory budget drives frontend chunk sizing (resources.c_chunk_files) and the
    # TypeScript heap ceiling, both of which read the environment at build time. Setting
    # it here -- before any pipeline call -- lets the flag stand in for the env var; the
    # flag wins so an explicit `--memory-budget-mb` is never silently shadowed by an
    # inherited LACHESIS_MEMORY_BUDGET_MB. An explicit LACHESIS_C_CHUNK_FILES still
    # overrides the derived chunk size, exactly as it does without the flag.
    if args.memory_budget_mb is not None:
        os.environ["LACHESIS_MEMORY_BUDGET_MB"] = str(args.memory_budget_mb)
    if args.parallel_packages and args.incremental:
        parser.error("--parallel-packages and --incremental cannot be combined: the "
            "incremental manifest keys bundles by frontend, not by package")
    if args.shard_large_packages is not None and not args.parallel_packages:
        parser.error("--shard-large-packages requires --parallel-packages")
    if args.stream_shards and (args.enrich or args.reduced or args.layered_out):
        parser.error("--stream-shards currently supports core-only stores")
    if args.stream_shards and args.incremental:
        parser.error("--stream-shards cannot combine with incremental builds")
    if args.enrich:
        parser.error("build-time enrichment was removed; run `lachesis enrich` after build")
    if args.reduced or args.layered_out:
        parser.error("--reduced/--layered-out are not available in the native-only build path")
    if args.stream_shards and args.parallel_packages and args.max_workers not in (None, 1):
        parser.error("streamed package shards are serialized; use --max-workers 1")
    include_paths = args.include_paths or []
    if include_paths and args.parallel_packages:
        parser.error("--include is not supported with --parallel-packages: the package "
            "partition keys jobs by their path under source_dir, so a path outside it "
            "has no package to join. Scope with a sub-directory (the serial path) and "
            "point --include at the advisory file instead")
    for included in include_paths:
        if not os.path.exists(included):
            parser.error(f"--include path does not exist: {included}")
    # --prune deletes pure-lexical/proof records at the store boundary, so apply the
    # same output defaults before the streaming branch as the ordinary path below.
    # Previously the early return skipped this block and made --stream-shards run
    # token/proof Clang passes whose output was immediately discarded.
    if args.prune:
        os.environ.setdefault("LACHESIS_EMIT_TOKENS", "0")
        os.environ.setdefault("LACHESIS_EMIT_PROOFS", "0")
    if args.stream_shards:
        frontend_out = args.frontend_out or os.path.join(args.stream_shards, "frontends")
        if args.parallel_packages:
            readers, snapshots = run_project_streaming_parallel(
                args.source_dir, args.stream_shards, frontend_out,
                timeout_seconds=args.timeout,
                max_files_per_package=args.shard_large_packages,
            )
        else:
            readers, snapshots = run_project_streaming(
                args.source_dir, args.stream_shards, frontend_out,
                timeout_seconds=args.timeout, include_paths=include_paths,
            )
        stored = write_kuzu_shards(
            CompositeShardReader(readers), args.output_path, snapshots,
            prune=args.prune,
        )
        print(f"Streamed {len(snapshots)} frontends into {stored}")
        if args.parallel_packages:
            dropped = 0
            for snapshot, reader in zip(snapshots, readers):
                original = int(snapshot.manifest.get("edge_count", snapshot.payload_edge_count))
                retained = sum(int(item.get("edge_count", 0))
                               for item in reader.manifest.get("shards", []))
                dropped += max(0, original - retained)
            print(f"Dropped {dropped} imported-view edges (package-sharded streaming)")
        return
    # The layered projection is by definition a view of the enriched tier (T4 is the
    # dataflow layer), so asking for it forces enrichment rather than silently emitting
    # an empty top tier.
    enrich = False
    # --prune deletes the pure-lexical nodes on the way into the store, so asking a
    # frontend for them is work whose entire output is discarded a step later. Telling
    # the frontends up front turns that into work not done: for C the token stream costs
    # a whole extra clang parse of every file. setdefault, not assignment, so an explicit
    # LACHESIS_EMIT_TOKENS from the caller still wins in either direction.
    # A reduced store is defined by the difference between the two tiers — an edge is
    # carried because the core graph does *not* contain it — so the two have to exist as
    # separate values. The compile runs unenriched and this folds the overlay itself.
    compile_enrich = False

    # Core-only builds do not need a materialized Python graph. Keep frontend
    # records in binary shards and stream them directly into Kùzu to bound RSS.
    if (
        not compile_enrich
        and not args.reduced
        and not args.incremental
        and not args.parallel_packages
        and not args.layered_out
    ):
        with tempfile.TemporaryDirectory(prefix="lachesis-stream-") as stream_root:
            frontend_out = args.frontend_out or os.path.join(stream_root, "frontends")
            readers, snapshots = run_project_streaming(
                args.source_dir, stream_root, frontend_out,
                timeout_seconds=args.timeout, include_paths=include_paths,
            )
            stored = write_kuzu_shards(
                CompositeShardReader(readers), args.output_path, snapshots,
                prune=args.prune,
            )
        print(f"Streamed {len(snapshots)} frontends into {stored}")
        print("Tier: core-only (nav rebuilds the dataflow tier on first use)")
        return

    frontend_out = args.frontend_out
    if frontend_out is None and (args.parallel_packages or args.incremental):
        # These two keep state on disk by construction: the parallel path gives every
        # (frontend, package) job its own directory to write into, and the incremental
        # path reuses the bundles and the change manifest it wrote last time. Neither
        # means anything without a directory, so they keep the default a plain build
        # no longer needs.
        frontend_out = "graph_out/frontends"
    dropped = 0
    if args.parallel_packages:
        graph, snapshots, dropped = run_project_parallel(
            args.source_dir, frontend_out, enrich=compile_enrich,
            max_workers=args.max_workers, timeout_seconds=args.timeout,
            max_files_per_package=args.shard_large_packages,
        )
    elif args.incremental:
        graph, snapshots = run_project_incremental(args.source_dir, frontend_out,
                                                   enrich=compile_enrich,
                                                   timeout_seconds=args.timeout,
                                                   include_paths=include_paths)
    else:
        graph, snapshots = run_project(args.source_dir, frontend_out,
                                       enrich=compile_enrich,
                                       timeout_seconds=args.timeout,
                                       include_paths=include_paths)
    build_fingerprint = None
    if args.incremental and frontend_out:
        manifest_path = default_manifest_path(frontend_out)
        try:
            build_fingerprint = hashlib.sha256(
                Path(manifest_path).read_bytes()).hexdigest()
        except OSError:
            build_fingerprint = None
        if build_fingerprint and os.path.isdir(args.output_path):
            existing = read_store_manifest(args.output_path)
            if (
                existing.get("build_fingerprint") == build_fingerprint
                and existing.get("pruned") is args.prune
                and existing.get("enriched") is bool(enrich)
            ):
                print(f"Reused unchanged graph store: {args.output_path}")
                return
    stored = graph
    if args.reduced:
        enriched = enrich_project_graph(graph, snapshots)
        stored = reduce_graph(graph, enriched)
        counts = partition_counts(enriched)
        print(f"Reduced store: kept {counts[SPINE]} spine + {counts[SEMANTIC]} semantic "
              f"nodes, left {counts[BODY]} body nodes to the recompile")
        graph = enriched
    written = write_kuzu_graph(
        stored, snapshots, args.output_path, prune=args.prune, enriched=enrich,
        carry_unresolved_edges=args.reduced,
        source_dir=args.source_dir if args.reduced else None,
        # Hashed rather than assumed: the store records what the tree was at build time,
        # so a load can tell whether an already-joined cache still describes it.
        source_content_hash=(source_content_hash(args.source_dir, include_paths=include_paths)
                             if args.reduced else None),
        build_fingerprint=build_fingerprint,
    )
    if args.layered_out:
        layered_files = write_layered_graph(build_layered_graph(graph), args.layered_out)
        print(f"Layered projection: {len(layered_files)} files in {args.layered_out}")
    # The census describes the artifact, not the analysis: with --reduced the two differ,
    # and the number a reader wants beside the store path is what the store holds.
    kinds = Counter(node["kind"] for node in stored["nodes"])
    # a parallel build runs one frontend per package, so snapshots counts units, not frontends
    unit = "package units" if args.parallel_packages else "frontends"
    print(
        f"Composed {len(snapshots)} {unit} into {len(stored['nodes'])} nodes "
        f"and {len(stored['edges'])} edges: {written}"
    )
    if args.parallel_packages:
        print(f"Dropped {dropped} cross-package edges (parallel build)")
    print("Tier: " + ("enriched (core + overlay dataflow)" if enrich else
                      "core-only (nav rebuilds the dataflow tier on first use)"))
    print("Frontends: " + ", ".join(sorted({item.frontend_id for item in snapshots})))
    print("Node kinds: " + ", ".join(f"{kind}={count}" for kind, count in sorted(kinds.items())))


def main(argv: list[str] | None = None) -> int:
    # stdout is block-buffered when piped to a file, so a long build that is killed (or a
    # `| tee log` capture) loses every line it "printed". Line-buffer so progress reaches
    # the file as it happens and a kill never swallows the tail. Guarded: some wrapped
    # streams predate `.reconfigure`.
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except (AttributeError, ValueError):
        pass
    try:
        _run(argv)
    except KeyboardInterrupt:
        print("lachesis build: interrupted", file=sys.stderr)
        return 130
    except Exception as error:  # noqa: BLE001 - CLI converts build errors to guidance
        if os.environ.get("LACHESIS_TRACEBACK"):
            raise
        print(f"lachesis build: {error}", file=sys.stderr)
        print("set LACHESIS_TRACEBACK=1 for the full traceback", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
