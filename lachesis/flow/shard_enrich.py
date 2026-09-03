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

The split itself is *streaming*: :func:`partition_input` decompresses the gzip input to a
temp file once, then makes two seeking passes holding only a compact ``id -> (offset, len,
shard, is_body)`` index -- never the graph's frame bytes -- writing each node straight to
its shard and re-reading a foreign edge endpoint by ``seek`` when it must be replicated.
The merge streams each shard output frame-by-frame too. So neither the whole input nor a
whole shard ever lands in RAM; Python residency scales with node *count* (a small index),
not input size.

Verified content-set exact (0 missing / 0 extra nodes and edges) versus the whole-graph
baseline on two C graphs (6.3k and 678k input nodes); per-shard peak RSS ~10x below the
whole-graph peak on the larger one, and the partition step's own residency cut from
~1.9 GB (whole-input buffering) to the index alone.
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


def _iter_frames(fh, *, magic: bytes | None = None) -> Iterator[tuple[int, bytes]]:
    """Stream ``(payload_offset, payload)`` frames from a seekable binary handle.

    ``magic`` (when given) is consumed from the front if present. This holds only one
    frame at a time -- the whole point of the streaming split -- so a Linux-scale input
    never lands in RAM. The offset lets a later pass re-read one node frame by ``seek``
    (used to replicate a foreign edge endpoint without buffering the graph).
    """
    if magic is not None:
        head = fh.read(len(magic))
        if head[: len(magic)] != magic:
            fh.seek(0)
    while True:
        lb = fh.read(4)
        if len(lb) < 4:
            break
        (ln,) = _FRAME.unpack(lb)
        off = fh.tell()
        payload = fh.read(ln)
        if len(payload) < ln:
            break
        yield off, payload


def _decompress_to(input_path: str | os.PathLike[str], workdir: str | os.PathLike[str]
                   ) -> tuple[str, bool]:
    """Return a seekable *uncompressed* copy of ``input_path`` and whether it is temporary.

    The Pass-2 input sidecar is gzip-wrapped; random ``seek`` for endpoint replication
    needs an uncompressed, seekable file. Decompression streams in fixed-size chunks, so
    peak stays bounded regardless of input size. A non-gzip input is used in place.
    """
    with open(input_path, "rb") as fh:
        head = fh.read(2)
    if head != b"\x1f\x8b":
        return os.fspath(input_path), False
    import gzip
    tmp = os.path.join(os.fspath(workdir), "_input.uncompressed.pb")
    with gzip.open(input_path, "rb") as src, open(tmp, "wb") as dst:
        while True:
            chunk = src.read(1 << 20)
            if not chunk:
                break
            dst.write(chunk)
    return tmp, True


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


def _ensure_fd_limit(needed: int) -> None:
    """Raise the soft open-file limit if a large ``k`` needs more handles than allowed.

    All ``k`` shard writers stay open across both partition passes; on macOS the default
    soft limit is 256, so a big shard count would otherwise hit EMFILE. Best-effort.
    """
    try:
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        if soft != resource.RLIM_INFINITY and soft < needed:
            resource.setrlimit(resource.RLIMIT_NOFILE, (min(max(needed, soft), hard), hard))
    except (ImportError, ValueError, OSError):
        pass


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
    os.makedirs(outdir, exist_ok=True)
    _ensure_fd_limit(k + 8)
    src_path, is_temp = _decompress_to(input_path, outdir)

    _GLOBAL = -1  # present in every shard (global/file node), never replicated per-edge
    # id -> (payload_offset, payload_len, shard, is_body); NO frame bytes retained.
    info: dict[str, tuple[int, int, int, bool]] = {}
    owner_shard: dict[str, int] = {}
    shard_counts = [0] * k
    node_total = 0

    paths = [os.path.join(os.fspath(outdir), f"shard_{s}.pass2.input.pb") for s in range(k)]
    writers = [open(p, "wb") for p in paths]
    try:
        # Pass 1 -- stream nodes: index each node, write it straight to its shard(s).
        with open(src_path, "rb") as fh:
            first = True
            for off, payload in _iter_frames(fh):
                if first:  # the Document header frame
                    for w in writers:
                        write_frame(w, payload)
                    first = False
                    continue
                if payload[0:1] != b"N":
                    continue
                rec = graph_pb2.NodeRecord()
                rec.ParseFromString(payload[1:])
                node_total += 1
                is_body = rec.kind in _BODY_KINDS
                owner = _node_owner(rec)
                if owner is not None:
                    shard = _shard_of_owner(owner, k)
                    owner_shard.setdefault(owner, shard)
                elif rec.kind == "function":
                    shard = _shard_of_owner(rec.id, k)
                    owner_shard.setdefault(rec.id, shard)
                else:
                    shard = _GLOBAL
                info[rec.id] = (off, len(payload), shard, is_body)
                if shard == _GLOBAL:
                    for w in writers:
                        write_frame(w, payload)
                    for s in range(k):
                        shard_counts[s] += 1
                else:
                    write_frame(writers[shard], payload)
                    shard_counts[shard] += 1

        # Pass 2 -- stream edges: place each edge in one shard, replicating a foreign
        # (non-global, non-body) endpoint by seeking its node frame back out of src_path.
        repl = 0
        edge_total = 0
        repl_sets: list[set[str]] = [set() for _ in range(k)]
        with open(src_path, "rb") as fh, open(src_path, "rb") as rf:
            first = True
            for _off, payload in _iter_frames(fh):
                if first:
                    first = False
                    continue
                if payload[0:1] != b"E":
                    continue
                rec = graph_pb2.EdgeRecord()
                rec.ParseFromString(payload[1:])
                edge_total += 1
                sm = info.get(rec.source)
                tm = info.get(rec.target)
                ss = None if (sm is None or sm[2] == _GLOBAL) else sm[2]
                ts = None if (tm is None or tm[2] == _GLOBAL) else tm[2]
                canon = ss if ss is not None else (ts if ts is not None else 0)
                # Never drag a foreign function BODY across a shard seam.
                skip = False
                for m in (sm, tm):
                    if m is None or m[2] == _GLOBAL or m[2] == canon:
                        continue
                    if m[3]:  # is_body
                        skip = True
                        break
                if skip:
                    continue
                for nid, m in ((rec.source, sm), (rec.target, tm)):
                    if m is None or m[2] == _GLOBAL or m[2] == canon:
                        continue
                    if nid in repl_sets[canon]:
                        continue
                    rf.seek(m[0])
                    write_frame(writers[canon], rf.read(m[1]))
                    repl_sets[canon].add(nid)
                    repl += 1
                    shard_counts[canon] += 1
                write_frame(writers[canon], payload)
    finally:
        for w in writers:
            w.close()
        if is_temp:
            try:
                os.remove(src_path)
            except OSError:
                pass

    return paths, {
        "funcs": len(owner_shard),
        "nodes": node_total,
        "edges": edge_total,
        "repl_node_insertions": repl,
        "shard_node_counts": shard_counts,
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
        with open(path, "rb") as fh:
            for _off, fr in _iter_frames(fh, magic=DATAFLOW_STREAM_MAGIC):
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
                # header frame (first per shard) is neither 'N' nor 'E'; skipped implicitly


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
