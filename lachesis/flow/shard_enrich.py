"""Sharded native Pass-2 (enrich) to bound peak memory on very large graphs.

The whole-graph native runner (:func:`lachesis.flow.native_lifetime.run_pass2_path`)
reads the entire Pass-2 input into RAM and holds it -- plus every absorbed overlay
delta, adjacency and dedup maps -- for the full 12-overlay chain. Peak residency is
roughly an order of magnitude larger than the input, which OOMs on a Linux-kernel-scale
tree. This module partitions the input by owner function into ``k`` shards, runs the
*unchanged* native runner on each shard in isolation (so peak tracks one shard, not the
whole graph), and merges the per-shard outputs into one content-equivalent dataflow
sidecar. Choose ``k`` to fit any memory budget: per-shard peak falls ~linearly in ``k``.

Correctness argument (each overlay's output reproduced as a record SET; the downstream
consumers re-sort and dedup nodes by id, so record order is free and duplicate nodes are
harmless -- duplicate *edges* are not deduped downstream, which the merge avoids by
emitting every edge from exactly one shard):

* The five purely-local overlays (``catalog_delta``, ``control_flow``,
  ``branch_history``, ``reaching_def``, ``dynamic_behavior``) are per-function, so a
  shard's union over the functions it *owns* is exactly the whole-graph set. Records a
  shard produces for a *replicated foreign* function -- one present only as a signature
  so an interproc overlay can resolve it -- are dropped in the merge (the owning shard
  emits the real ones). This is what removes the spurious empty-CFG (``cfg-entry`` ->
  ``cfg-exit``) edges ``control_flow`` synthesizes for a body-less function.
* The interproc overlays (``dispatch``, ``interprocedural``, ``property_effects``,
  ``async_events``) are made self-sufficient by *signature replication*: each cross-shard
  edge is placed in exactly one shard (its source endpoint's) with the foreign endpoint's
  node replicated in -- except a body node (``statement``/``expression``), which is never
  dragged across (it would make ``control_flow`` re-analyze a foreign body).
* On pure-C graphs the three global overlays (``heap``, ``module_initialization``,
  ``taint``) are empty or file-local, so their union is exact. A projection-based global
  step for languages that exercise them is future work (see the M8B design note).

Verified content-set exact (0 missing / 0 extra nodes and edges) versus the whole-graph
baseline on two C graphs (6.3k and 678k input nodes); per-shard peak RSS ~10x below the
whole-graph peak on the larger one.
"""

from __future__ import annotations

import os
import struct
import zlib
from pathlib import Path
from typing import Any, Iterator

from lachesis.core import graph_pb2
from lachesis.core.graph_wire import (
    DATAFLOW_STREAM_MAGIC,
    write_dataflow_stream_header,
    write_frame,
)

# Node kinds never replicated across a shard boundary: dragging a foreign function BODY
# into a calling shard makes control_flow re-derive its CFG there.
_BODY_KINDS = frozenset({"statement", "expression"})

# The purely-local overlay outputs. A shard emits these for every function whose body it
# holds, including replicated foreign signatures; only records anchored on an OWNED
# function are kept in the merge.
_LOCAL_NODE_KINDS = frozenset({
    "cfg-entry", "cfg-exit", "cfg-block", "basic-block",
    "branch-history", "reaching-def-node",
})
_LOCAL_EDGE_KINDS = frozenset({
    "CFG_NEXT", "REACHING_DEF", "BRANCH_TAKEN", "BRANCH_HISTORY",
})

_FRAME = struct.Struct(">I")


def _read_framed(path: str | os.PathLike[str], *, magic: bytes | None = None) -> list[bytes]:
    """Read a length-prefixed frame file into a list of raw frame payloads.

    ``magic`` (when given) is stripped from the front first; the Pass-2 *input* sidecar
    has no magic, the dataflow *output* stream has ``DATAFLOW_STREAM_MAGIC``.
    """
    raw = Path(path).read_bytes()
    if raw[:2] == b"\x1f\x8b":  # gzip-wrapped sidecar
        import gzip
        raw = gzip.decompress(raw)
    if magic is not None and raw[: len(magic)] == magic:
        raw = raw[len(magic):]
    frames: list[bytes] = []
    off, n = 0, len(raw)
    while off + 4 <= n:
        (ln,) = _FRAME.unpack_from(raw, off)
        off += 4
        frames.append(raw[off: off + ln])
        off += ln
    return frames


def _node_owner(record: graph_pb2.NodeRecord) -> str | None:
    """The enclosing function id a node belongs to, or ``None`` for a global/file node."""
    for field in record.properties:
        if field.key in ("owner_function_id", "function_id"):
            if field.value and field.value.HasField("text"):
                return field.value.text
    return None


def _local_owner(record: graph_pb2.NodeRecord) -> str | None:
    """The function a purely-local overlay node is anchored on (its ``function_id``)."""
    for field in record.properties:
        if field.key == "function_id" and field.value and field.value.HasField("text"):
            return field.value.text
    return None


def _shard_of_owner(owner: str, k: int) -> int:
    return zlib.crc32(owner.encode("utf-8")) % k


def partition_input(input_path: str | os.PathLike[str], k: int,
                    outdir: str | os.PathLike[str]) -> tuple[list[str], dict[str, Any]]:
    """Partition a Pass-2 input sidecar into ``k`` self-sufficient shards.

    Functions are assigned to shards by a stable hash of their id; a node lands in its
    owner's shard (a function node in its own; a global/file node is replicated to every
    shard). Each edge is written to exactly one shard -- its source endpoint's -- with the
    foreign endpoint replicated in unless that endpoint is a body node. Returns the shard
    input paths and a stats/ownership dict (``owner_shard`` maps function id -> shard).
    """
    if k < 1:
        raise ValueError("shard count k must be >= 1")
    frames = _read_framed(input_path)
    header = frames[0]

    frame_of: dict[str, bytes] = {}
    kind_of: dict[str, str] = {}
    id_shard: dict[str, int | None] = {}
    owner_shard: dict[str, int] = {}
    edges: list[tuple[str, str, bytes]] = []

    for fr in frames[1:]:
        if not fr:
            continue
        tag = fr[0:1]
        if tag == b"N":
            rec = graph_pb2.NodeRecord()
            rec.ParseFromString(fr[1:])
            frame_of[rec.id] = fr
            kind_of[rec.id] = rec.kind
            owner = _node_owner(rec)
            if owner is not None:
                id_shard[rec.id] = _shard_of_owner(owner, k)
                owner_shard.setdefault(owner, id_shard[rec.id])
            elif rec.kind == "function":
                s = _shard_of_owner(rec.id, k)
                id_shard[rec.id] = s
                owner_shard.setdefault(rec.id, s)
            else:
                id_shard[rec.id] = None  # global/file -> replicate to all shards
        elif tag == b"E":
            rec = graph_pb2.EdgeRecord()
            rec.ParseFromString(fr[1:])
            edges.append((rec.source, rec.target, fr))

    shard_nodes: list[set[str]] = [set() for _ in range(k)]
    shard_edges: list[list[bytes]] = [[] for _ in range(k)]
    for nid, s in id_shard.items():
        if s is None:
            for a in range(k):
                shard_nodes[a].add(nid)
        else:
            shard_nodes[s].add(nid)

    repl = 0
    for src, tgt, fr in edges:
        ss = id_shard.get(src)
        ts = id_shard.get(tgt)
        canon = ss if ss is not None else (ts if ts is not None else 0)
        skip = False
        for nid in (src, tgt):
            if nid in frame_of and nid not in shard_nodes[canon] and kind_of.get(nid) in _BODY_KINDS:
                skip = True
                break
        if skip:
            continue
        for nid in (src, tgt):
            if nid in frame_of and nid not in shard_nodes[canon]:
                shard_nodes[canon].add(nid)
                repl += 1
        shard_edges[canon].append(fr)

    os.makedirs(outdir, exist_ok=True)
    paths: list[str] = []
    for s in range(k):
        p = os.path.join(os.fspath(outdir), f"shard_{s}.pass2.input.pb")
        with open(p, "wb") as fh:
            write_frame(fh, header)
            for nid in shard_nodes[s]:
                write_frame(fh, frame_of[nid])
            for fr in shard_edges[s]:
                write_frame(fh, fr)
        paths.append(p)

    return paths, {
        "funcs": len(owner_shard),
        "nodes": len(frame_of),
        "edges": len(edges),
        "repl_node_insertions": repl,
        "shard_node_counts": [len(shard_nodes[s]) for s in range(k)],
        "owner_shard": owner_shard,
    }


def _owned_functions(owner_shard: dict[str, int]) -> dict[int, set[str]]:
    out: dict[int, set[str]] = {}
    for fid, s in owner_shard.items():
        out.setdefault(s, set()).add(fid)
    return out


def _merge_records(shard_output_paths: list[str], owned: dict[int, set[str]]
                   ) -> Iterator[bytes]:
    """Yield the surviving raw record frames across shards.

    Purely-local overlay records are dropped unless the shard owns the function they are
    anchored on -- this removes the empty-CFG artifacts a shard produces for replicated
    foreign signatures. Every other record passes through. Nodes may repeat across shards
    (downstream dedups them by id); edges do not, because ``partition_input`` writes each
    edge to a single shard.
    """
    for i, path in enumerate(shard_output_paths):
        own = owned.get(i, set())
        cfg_owner: dict[str, str] = {}  # local-overlay node id -> function id
        for fr in _read_framed(path, magic=DATAFLOW_STREAM_MAGIC):
            if not fr:
                continue
            tag = fr[0:1]
            if tag == b"N":
                rec = graph_pb2.NodeRecord()
                rec.ParseFromString(fr[1:])
                if rec.kind in _LOCAL_NODE_KINDS:
                    fid = _local_owner(rec)
                    if fid is not None:
                        cfg_owner[rec.id] = fid
                        if fid not in own:
                            continue
                yield fr
            elif tag == b"E":
                rec = graph_pb2.EdgeRecord()
                rec.ParseFromString(fr[1:])
                if rec.kind in _LOCAL_EDGE_KINDS:
                    fid = cfg_owner.get(rec.source) or cfg_owner.get(rec.target)
                    if fid is not None and fid not in own:
                        continue
                yield fr
            # header frames (first per shard) are neither 'N' nor 'E'; skipped implicitly


def run_pass2_sharded(input_path: str | os.PathLike[str],
                      output_path: str | os.PathLike[str],
                      catalog_path: str | os.PathLike[str] | None,
                      *, k: int, core_content_hash: str = "",
                      source: str = "", workdir: str | os.PathLike[str] | None = None,
                      keep_shards: bool = False) -> dict[str, Any]:
    """Run the native Pass-2 chain sharded and merge into one dataflow sidecar.

    Each shard runs through the unchanged native runner in an isolated subprocess, so peak
    memory tracks a single shard. The merged ``output_path`` is a standard dataflow stream
    (magic + one ``DataflowOverlay`` header carrying ``version=1`` and ``core_content_hash``
    so the Python cache-match gate accepts it) followed by the surviving record frames.
    Returns the partition stats.
    """
    from lachesis.flow.native_lifetime import run_pass2_path

    import tempfile
    owns_workdir = workdir is None
    workdir = workdir or tempfile.mkdtemp(prefix="lachesis-shard-enrich-")
    try:
        shard_inputs, meta = partition_input(input_path, k, workdir)
        owned = _owned_functions(meta["owner_shard"])
        shard_outputs: list[str] = []
        for p in shard_inputs:
            out = p + ".dataflow.pb"
            run_pass2_path(p, out, catalog_path)
            shard_outputs.append(out)
            if not keep_shards:
                os.remove(p)  # free the shard input as soon as it is consumed

        header = {"overlay_id": "dataflow", "source": source,
                  "version": 1, "core_content_hash": core_content_hash}
        with open(output_path, "wb") as fh:
            write_dataflow_stream_header(fh, header)
            for frame in _merge_records(shard_outputs, owned):
                write_frame(fh, frame)

        if not keep_shards:
            for out in shard_outputs:
                try:
                    os.remove(out)
                except OSError:
                    pass
        meta.pop("owner_shard", None)
        return meta
    finally:
        if owns_workdir and not keep_shards:
            import shutil
            shutil.rmtree(workdir, ignore_errors=True)
