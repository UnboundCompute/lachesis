"""Execute an out-of-process compiler frontend without knowing its language."""
from __future__ import annotations

import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
from typing import Callable, Optional, Sequence

from .contract import ContractError, FrontendSnapshot, FrontendSpec
from . import graph_pb2
from .graph_wire import WIRE_FORMAT_VERSION, decode_node, iter_tier_records
from .shards import ShardSetWriter
from .snapshot import load_manifest, load_snapshot


def _run_frontend_command(
    command: Sequence[str], *, cwd: str, env: dict[str, str], timeout: int,
) -> subprocess.CompletedProcess:
    """Run a frontend and terminate its whole process group on timeout."""
    process = subprocess.Popen(
        command,
        cwd=cwd,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=(os.name == "posix"),
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        if os.name == "posix":
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        else:  # pragma: no cover - supported deployments are POSIX runners
            process.kill()
        process.communicate()
        raise
    return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)


def _persist_shard(
    snapshot: FrontendSnapshot, root: Optional[str],
    *, keep_node: Optional[Callable[[dict], bool]] = None,
) -> None:
    """Persist a language-neutral cache shard when the caller opts in."""
    if not root:
        return
    directory = os.path.join(root, snapshot.frontend_id)
    shard_set = ShardSetWriter(directory, frontend_id=snapshot.frontend_id)
    shard_id = snapshot.manifest.get("source_content_hash", "0")
    writer = shard_set.start(str(shard_id))
    try:
        retained = set()
        for node in snapshot.nodes:
            if keep_node is not None and not keep_node(node):
                continue
            writer.add_node(node)
            retained.add(node["id"])
        for edge in snapshot.edges:
            if keep_node is not None and edge.get("source") not in retained:
                continue
            writer.add_edge(edge)
        shard_set.complete(str(shard_id), writer)
    except Exception:
        writer.close()
        raise


def _stream_bundle_to_shard(
    output_dir: str, root: str, stdout: str, stderr: str,
    *, keep_node: Optional[Callable[[dict], bool]] = None,
) -> FrontendSnapshot:
    """Persist a protobuf bundle record-by-record, without loading its tier arrays."""
    manifest = load_manifest(output_dir)
    frontend_id = manifest.get("frontend_id") or manifest.get("generator")
    # The native Clang frontend emits the same framed protobuf shard that this
    # bridge is meant to produce. When no ownership filter is needed, publish the
    # files directly; decoding and re-encoding every record here is pure Python
    # overhead and can dominate a large binary frontend's handoff.
    raw_shard = Path(output_dir) / "shard-0"
    raw_manifest_path = raw_shard / "manifest.pb"
    if keep_node is None and frontend_id == "clang-c" and raw_manifest_path.is_file():
        raw_manifest = graph_pb2.ShardManifest()
        raw_manifest.ParseFromString(raw_manifest_path.read_bytes())
        if (
            raw_manifest.format_version == WIRE_FORMAT_VERSION
            and raw_manifest.nodes_file == "nodes.pb"
            and raw_manifest.edges_file == "edges.pb"
        ):
            shard_set = ShardSetWriter(os.path.join(root, frontend_id), frontend_id=frontend_id)
            shard_set.complete_payloads(
                str(raw_manifest.shard_id),
                raw_shard / raw_manifest.nodes_file,
                raw_shard / raw_manifest.edges_file,
                raw_manifest.node_count, raw_manifest.edge_count,
            )
            return FrontendSnapshot(
                frontend_id=frontend_id,
                contract_version=manifest.get("frontend_contract_version", manifest.get("version")),
                languages=tuple(manifest.get("languages", ())),
                capabilities=dict(manifest.get("capabilities", {})),
                manifest=manifest, nodes=[], edges=[], stdout=stdout, stderr=stderr,
                released=True, _released_node_count=raw_manifest.node_count,
                _released_edge_count=raw_manifest.edge_count,
            )
    directory = os.path.join(root, frontend_id)
    shard_set = ShardSetWriter(directory, frontend_id=frontend_id)
    shard_id = manifest.get("source_content_hash", "0")
    writer = shard_set.start(str(shard_id))
    node_count = edge_count = 0
    retained_node_ids: set[str] = set()
    try:
        for tier_name, tier_path in ((item.get("tier"), os.path.join(output_dir, item.get("file", "")))
                                     for item in manifest.get("tiers", [])):
            for collection, payload in iter_tier_records(tier_path, raw=True):
                if collection == "nodes":
                    node = None
                    if keep_node is not None:
                        # The predicate is intentionally applied while the protobuf
                        # record is live.  It lets package-sharded builds discard
                        # imported dependency views without materialising a bundle.
                        node = decode_node(payload)
                        if not keep_node(node):
                            continue
                    message = graph_pb2.NodeRecord()
                    message.ParseFromString(payload)
                    node_id = node["id"] if node is not None else message.id
                    message.tier = tier_name
                    writer.add_node_payload(message.SerializeToString())
                    retained_node_ids.add(node_id)
                    node_count += 1
                    continue
                message = graph_pb2.EdgeRecord()
                message.ParseFromString(payload)
                message.source_tier = tier_name
                message.relationship_class = collection
                if keep_node is not None and message.source not in retained_node_ids:
                    continue
                writer.add_edge_payload(message.SerializeToString())
                edge_count += 1
        shard_set.complete(str(shard_id), writer)
    except Exception:
        writer.close()
        raise
    snapshot = FrontendSnapshot(
        frontend_id=frontend_id,
        contract_version=manifest.get("frontend_contract_version", manifest.get("version")),
        languages=tuple(manifest.get("languages", ())),
        capabilities=dict(manifest.get("capabilities", {})),
        manifest=manifest, nodes=[], edges=[], stdout=stdout, stderr=stderr,
        released=True, _released_node_count=node_count, _released_edge_count=edge_count,
    )
    return snapshot


def _in_process_applies(
    frontend: FrontendSpec, output_dir: Optional[str],
) -> bool:
    """Whether this frontend may be run here instead of as a child process.

    The subprocess is the contract and the in-process route is an optimisation, so
    each condition below is a reason the two could differ, and any one of them sends
    the work to the child, where the behaviour is the one that has always shipped.

    ``output_dir is None`` is the caller saying it wants the graph and not the
    bundle. When it names a directory it expects files in it, and not writing them
    is the whole saving.

    An empty ``environment`` matters because a spec that sets variables for its child
    is saying something about how that child must run, and this process is not it.
    Roots need no such condition: they go down as an argument rather than through
    binary ``LACHESIS_ROOTS_FILE``, so both routes compile the same set without this process
    having to mutate its own environment to say so.

    ``LACHESIS_INPROCESS=0`` forces the child unconditionally, so a difference
    between the two routes can be bisected without reverting anything.
    """
    return (
        output_dir is None
        and frontend.in_process is not None
        and not frontend.environment
        and os.environ.get("LACHESIS_INPROCESS") != "0"
    )


def run_frontend(
    frontend: FrontendSpec,
    source_dir: str,
    output_dir: Optional[str] = None,
    timeout_seconds: int = 300,
    roots: Optional[Sequence[str]] = None,
    keep_node: Optional[Callable[[dict], bool]] = None,
) -> FrontendSnapshot:
    started = time.perf_counter()

    def report(snapshot: FrontendSnapshot) -> FrontendSnapshot:
        if os.environ.get("LACHESIS_TIMINGS") == "1":
            print(
                "[lachesis timing] frontend %s: %.3fs (%d nodes, %d edges)"
                % (frontend.frontend_id, time.perf_counter() - started,
                   len(snapshot.nodes), len(snapshot.edges)),
                file=sys.stderr, flush=True,
            )
        return snapshot

    if _in_process_applies(frontend, output_dir):
        snapshot = frontend.in_process(source_dir, roots)
        _persist_shard(snapshot, os.environ.get("LACHESIS_SHARD_ROOT"),
                       keep_node=keep_node)
        return report(snapshot)
    temporary = None
    if output_dir is None:
        temporary = tempfile.TemporaryDirectory(prefix="lachesis-frontend-")
        output_dir = temporary.name
    os.makedirs(output_dir, exist_ok=True)
    environment = os.environ.copy()
    environment.update(frontend.environment)
    # When discovery hands us an explicit root set (test files already excluded),
    # write it beside the output and point the frontend at it so a frontend that
    # re-walks the tree compiles exactly this list — one discovery, no drift.
    if roots is not None:
        roots_file = os.path.join(output_dir, "lachesis-roots.pb")
        roots_message = graph_pb2.FrontendRoots(
            format_version=WIRE_FORMAT_VERSION,
            paths=[str(path) for path in roots],
        )
        with open(roots_file, "wb") as handle:
            handle.write(roots_message.SerializeToString())
        environment["LACHESIS_ROOTS_FILE"] = roots_file
    command = frontend.render_command(source_dir, output_dir)
    try:
        completed = _run_frontend_command(
            command,
            cwd=frontend.working_directory,
            env=environment,
            timeout=timeout_seconds,
        )
        if completed.returncode != 0:
            raise ContractError(
                f"frontend {frontend.frontend_id} exited {completed.returncode}\n"
                f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
            )
        shard_root = environment.get("LACHESIS_SHARD_ROOT")
        if shard_root:
            snapshot = _stream_bundle_to_shard(
                output_dir, shard_root, completed.stdout, completed.stderr,
                keep_node=keep_node,
            )
        else:
            snapshot = load_snapshot(output_dir, completed.stdout, completed.stderr)
        return report(snapshot)
    except subprocess.TimeoutExpired as error:
        raise ContractError(
            f"frontend {frontend.frontend_id} exceeded {timeout_seconds}s"
        ) from error
    finally:
        if temporary is not None:
            temporary.cleanup()
