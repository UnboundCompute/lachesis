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


# ---------------------------------------------------------------------------
# M8g part 2 -- WCC-cohesive sharding for the interprocedural semantic (Pass-3)
# ---------------------------------------------------------------------------
#
# The semantic pass (``lachesis_lifetime_semantic_path``) holds every prepared
# function AND the final ``NativeSemanticFunction`` vector resident at once (see
# ``prepare.rs::semantic_request``); on a Linux-scale tree that O(graph) floor is
# the last enrich OOM frontier after M8f bounded the split and the encode.
#
# Unlike Pass-2's hash sharding, the semantic pass is interprocedural -- a region
# cone and its call seams span multiple functions -- so a hash split would sever
# cones and lose coverage. Instead we shard by *weakly-connected component* of the
# input graph: union every function whose nodes are joined by ANY cross-function
# edge (a safe superset of the call/seam edges the semantic pass walks). Because a
# WCC is closed under every cross-function edge, every call seam and every region
# cone lies wholly inside one component, so:
#
#   * batching whole components together loses NO coverage -- each batch is a
#     self-contained subgraph the unchanged native pass analyzes exactly as it
#     would inside the whole graph (``pick_regions``/``call_graph``/``skeleton``
#     see the identical induced call graph; the seeded shuffle only permutes the
#     order regions are emitted, never the set);
#   * components are disjoint, so the merge is a plain concatenation of the four
#     repeated result fields (functions/seams/regions/skeletons) -- no function
#     dedup, no signature replication, no body-drop that Pass-2's merge needed
#     (both endpoints of every cross-function edge already co-locate in a batch);
#   * peak residency tracks one batch (~total/k), and each subprocess ``prepare``s
#     only its batch, so the O(graph) prepare floor falls ~1/k as well.
#
# Measured on a 678k-node C graph: 6000 components, max component 113 nodes
# (0.02% of the graph) -- granular enough to bin-pack into k balanced batches with
# per-batch peak ~1/k and zero coverage loss.


def _uf_find(parent: dict[str, str], node: str) -> str:
    root = node
    while parent[root] != root:
        root = parent[root]
    while parent[node] != root:
        parent[node], node = root, parent[node]
    return root


def _uf_union(parent: dict[str, str], a: str, b: str) -> None:
    ra, rb = _uf_find(parent, a), _uf_find(parent, b)
    if ra != rb:
        parent[ra] = rb


def partition_input_cohesive(input_path: str | os.PathLike[str], k: int,
                             outdir: str | os.PathLike[str]
                             ) -> tuple[list[str], dict[str, Any]]:
    """Partition a Pass-2 input sidecar into ``k`` WCC-cohesive semantic batches.

    Each batch is a union of whole weakly-connected components of the graph's
    cross-function edge relation, so every call seam and region cone stays intra
    batch and the unchanged semantic pass reproduces each function's result
    byte-for-byte. Global/file nodes (and global-only edges) are replicated to
    every batch so each batch sees the complete global substructure. Returns the
    batch input paths and a stats dict.

    The split is streaming: four seeking scans of the uncompressed input holding
    only compact ``id -> owner`` / ``owner -> batch`` maps (sized by node/function
    count), never the graph's frame bytes.
    """
    if k < 1:
        raise ValueError("batch count k must be >= 1")
    os.makedirs(outdir, exist_ok=True)
    _ensure_fd_limit(k + 8)
    src_path, is_temp = _decompress_to(input_path, outdir)

    # id -> owning function id (a function node maps to itself); absent => global.
    node_owner: dict[str, str] = {}
    owner_count: dict[str, int] = {}   # function id -> owned node count (bin-pack weight)
    node_total = 0
    global_total = 0
    writers: list[Any] = []
    paths = [os.path.join(os.fspath(outdir), f"batch_{b}.pass2.input.pb") for b in range(k)]
    try:
        # Pass A -- nodes: owner map + per-function node weight.
        with open(src_path, "rb") as fh:
            first = True
            for _off, payload in _iter_frames(fh):
                if first:
                    first = False
                    continue
                if payload[0:1] != b"N":
                    continue
                rec = graph_pb2.NodeRecord()
                rec.ParseFromString(payload[1:])
                node_total += 1
                owner = _node_owner(rec)
                if owner is not None:
                    node_owner[rec.id] = owner
                    owner_count[owner] = owner_count.get(owner, 0) + 1
                elif rec.kind == "function":
                    node_owner[rec.id] = rec.id
                    owner_count[rec.id] = owner_count.get(rec.id, 0) + 1
                else:
                    global_total += 1

        # Pass B -- edges: union owners joined by any cross-function edge.
        parent: dict[str, str] = {fid: fid for fid in owner_count}
        edge_total = 0
        with open(src_path, "rb") as fh:
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
                o1 = node_owner.get(rec.source)
                o2 = node_owner.get(rec.target)
                if o1 is not None and o2 is not None and o1 != o2 \
                        and o1 in parent and o2 in parent:
                    _uf_union(parent, o1, o2)

        # Components -> greedy bin-pack into k batches balanced by node weight.
        components: dict[str, list[str]] = {}
        for fid in owner_count:
            components.setdefault(_uf_find(parent, fid), []).append(fid)
        weighted = sorted(
            ((sum(owner_count[m] for m in members), members)
             for members in components.values()),
            key=lambda item: -item[0])
        import heapq
        heap = [(0, b) for b in range(k)]
        heapq.heapify(heap)
        owner_batch: dict[str, int] = {}
        batch_weight = [0] * k
        for weight, members in weighted:
            cur, b = heapq.heappop(heap)
            for m in members:
                owner_batch[m] = b
            heapq.heappush(heap, (cur + weight, b))
            batch_weight[b] += weight
        max_wcc = weighted[0][0] if weighted else 0

        # Pass C -- nodes: write each node to its batch; globals to every batch.
        writers = [open(p, "wb") for p in paths]
        batch_node_counts = [0] * k
        with open(src_path, "rb") as fh:
            first = True
            for _off, payload in _iter_frames(fh):
                if first:  # Document header frame -> every batch
                    for w in writers:
                        write_frame(w, payload)
                    first = False
                    continue
                if payload[0:1] != b"N":
                    continue
                rec = graph_pb2.NodeRecord()
                rec.ParseFromString(payload[1:])
                owner = node_owner.get(rec.id)
                if owner is None:  # global/file node -> every batch
                    for w in writers:
                        write_frame(w, payload)
                    for b in range(k):
                        batch_node_counts[b] += 1
                else:
                    b = owner_batch[owner]
                    write_frame(writers[b], payload)
                    batch_node_counts[b] += 1

        # Pass D -- edges: route to the (single) batch owning a non-global
        # endpoint; both function endpoints agree by WCC closure. A global-only
        # edge goes to every batch so no batch loses global structure.
        with open(src_path, "rb") as fh:
            first = True
            for _off, payload in _iter_frames(fh):
                if first:
                    first = False
                    continue
                if payload[0:1] != b"E":
                    continue
                rec = graph_pb2.EdgeRecord()
                rec.ParseFromString(payload[1:])
                o1 = node_owner.get(rec.source)
                owner = o1 if o1 is not None else node_owner.get(rec.target)
                if owner is None:
                    for w in writers:
                        write_frame(w, payload)
                else:
                    write_frame(writers[owner_batch[owner]], payload)
    finally:
        for w in writers:
            w.close()
        if is_temp:
            try:
                os.remove(src_path)
            except OSError:
                pass

    return paths, {
        "funcs": len(owner_count),
        "nodes": node_total,
        "global_nodes": global_total,
        "edges": edge_total,
        "batches": k,
        "components": len(components),
        "max_wcc_nodes": max_wcc,
        "batch_weight": batch_weight,
        "batch_node_counts": batch_node_counts,
        "owner_batch": owner_batch,
    }


def _read_varint_fh(fh) -> tuple[int | None, bytes]:
    """Decode one base-128 varint from a binary handle; return (value, raw_bytes).

    ``(None, b"")`` signals a clean EOF at a field boundary.
    """
    raw = bytearray()
    value = shift = 0
    while True:
        byte = fh.read(1)
        if not byte:
            if raw:
                raise ValueError("truncated varint in semantic sidecar")
            return None, b""
        raw += byte
        value |= (byte[0] & 0x7F) << shift
        if not byte[0] & 0x80:
            return value, bytes(raw)
        shift += 7


def _merge_semantic_sidecars(batch_paths: list[str], output_path: str) -> None:
    """Wire-level streaming merge of per-batch ``NativeSemanticResult`` sidecars.

    Concatenating serialized protobuf messages merges their fields, so the union
    of disjoint batches is a byte concatenation of every length-delimited field
    (functions=1, seams=3, regions=4, skeletons=5) with the scalar ``complete``
    (field 2) recombined as a logical AND. Copies one field element at a time, so
    residency stays bounded by the largest single element -- never a whole batch.
    """
    complete_all = True
    tmp = f"{output_path}.merge.{os.getpid()}.tmp"
    with open(tmp, "wb") as out:
        for path in batch_paths:
            batch_complete = False
            with open(path, "rb") as fh:
                while True:
                    tag, tag_raw = _read_varint_fh(fh)
                    if tag is None:
                        break
                    field, wire = tag >> 3, tag & 7
                    if wire == 0:  # varint
                        val, val_raw = _read_varint_fh(fh)
                        if field == 2:  # complete: recombine as AND, don't copy
                            batch_complete = bool(val)
                        else:
                            out.write(tag_raw)
                            out.write(val_raw)
                    elif wire == 2:  # length-delimited: copy tag+len+payload verbatim
                        length, len_raw = _read_varint_fh(fh)
                        out.write(tag_raw)
                        out.write(len_raw)
                        remaining = length
                        while remaining > 0:
                            chunk = fh.read(min(1 << 20, remaining))
                            if not chunk:
                                raise ValueError("truncated field in semantic sidecar")
                            out.write(chunk)
                            remaining -= len(chunk)
                    elif wire == 1:  # 64-bit
                        out.write(tag_raw)
                        out.write(fh.read(8))
                    elif wire == 5:  # 32-bit
                        out.write(tag_raw)
                        out.write(fh.read(4))
                    else:
                        raise ValueError(f"unsupported wire type {wire}")
            complete_all = complete_all and batch_complete
        if complete_all:
            out.write(b"\x10\x01")  # field 2 (complete) = true
    os.replace(tmp, output_path)


def _split_translation_facts(facts_src: str, owner_batch: dict[str, int],
                             k: int, batch_bases: list[str]) -> None:
    """Split a flat ``TranslationResult`` facts sidecar into per-batch siblings.

    The facts must be the batch SUBSET -- ``reach`` emits a skeleton per
    translation function, so passing the whole facts to every batch would emit
    each non-batch function's reach skeletons k times. A function's facts entry
    goes to the batch owning it; a facts function absent from the owner map
    (should not happen -- facts functions are a subset of the graph's) falls to
    batch 0 so nothing is dropped. Reads gzip or raw.
    """
    from lachesis.core import lifetime_pb2
    whole = lifetime_pb2.TranslationResult()
    whole.ParseFromString(_read_maybe_gzip_bytes(facts_src))
    batches = [lifetime_pb2.TranslationResult() for _ in range(k)]
    for function in whole.functions:
        batches[owner_batch.get(function.id, 0)].functions.append(function)
    for base, result in zip(batch_bases, batches):
        with open(f"{base}.pass2.facts.pb", "wb") as fh:
            fh.write(result.SerializeToString())


def _read_maybe_gzip_bytes(path: str) -> bytes:
    with open(path, "rb") as fh:
        head = fh.read(2)
    if head == b"\x1f\x8b":
        import gzip
        with gzip.open(path, "rb") as fh:
            return fh.read()
    return Path(path).read_bytes()


def run_semantic_sharded(input_path: str | os.PathLike[str],
                         output_path: str | os.PathLike[str],
                         catalog_path: str | os.PathLike[str] | None,
                         *, k: int, workdir: str | os.PathLike[str] | None = None,
                         keep_shards: bool = False) -> dict[str, Any]:
    """Run the native semantic pass WCC-sharded and merge into one sidecar pair.

    Publishes both ``output_path`` (the full ``NativeSemanticResult``) and its
    compact ``output_path.events.pb`` sibling -- exactly what the whole-graph
    ``write_semantic_path`` publishes -- by running each batch through the
    unchanged native pass in an isolated subprocess (peak tracks one batch) and
    concatenating the disjoint per-batch results. Returns the partition stats.

    When a catalog is given the native pass reads two co-located siblings of the
    input: the flat translation facts (``<base>.pass2.facts.pb``) and the taint
    source-evidence overlay (``<base>.dataflow.pb``). Each batch is given the
    batch-subset facts (split by the same WCC map) and a symlink to the WHOLE
    dataflow overlay -- the overlay is keyed by node anchor, so a batch only ever
    consults evidence for its own nodes, making the shared whole overlay
    byte-equivalent to a per-batch split.
    """
    from lachesis.flow.native_lifetime import write_semantic_path

    import tempfile
    input_str = os.fspath(input_path)
    owns_workdir = workdir is None
    workdir = workdir or tempfile.mkdtemp(prefix="lachesis-shard-semantic-")
    try:
        batch_inputs, meta = partition_input_cohesive(input_path, k, workdir)
        batch_bases = [p[: -len(".pass2.input.pb")] for p in batch_inputs]
        owner_batch = meta.pop("owner_batch")

        # Provision the sibling inputs the native pass resolves by input basename.
        base_suffix = ".pass2.input.pb"
        if catalog_path is not None and input_str.endswith(base_suffix):
            src_base = input_str[: -len(base_suffix)]
            facts_src = f"{src_base}.pass2.facts.pb"
            substrate_src = f"{src_base}.pass3.substrate.pb"
            if os.path.isfile(facts_src):
                _split_translation_facts(facts_src, owner_batch, k, batch_bases)
            elif os.path.isfile(substrate_src):
                raise NotImplementedError(
                    "semantic sharding needs the flat .pass2.facts.pb; substrate-"
                    "only (deferred-facts) builds are not split yet")
            dataflow_src = f"{src_base}.dataflow.pb"
            if os.path.isfile(dataflow_src):
                dataflow_abs = os.path.abspath(dataflow_src)
                for base in batch_bases:
                    link = f"{base}.dataflow.pb"
                    try:
                        os.symlink(dataflow_abs, link)
                    except OSError:
                        import shutil
                        shutil.copy2(dataflow_abs, link)

        semantic_outputs: list[str] = []
        events_outputs: list[str] = []
        for batch_in in batch_inputs:
            batch_out = f"{batch_in}.pass3.semantic.pb"
            write_semantic_path(batch_in, batch_out, catalog_path)
            semantic_outputs.append(batch_out)
            events_outputs.append(f"{batch_out}.events.pb")
            if not keep_shards:
                os.remove(batch_in)  # free the batch input as soon as it is consumed

        _merge_semantic_sidecars(semantic_outputs, os.fspath(output_path))
        _merge_semantic_sidecars(events_outputs, f"{os.fspath(output_path)}.events.pb")

        if not keep_shards:
            for path in (*semantic_outputs, *events_outputs):
                try:
                    os.remove(path)
                except OSError:
                    pass
        return meta
    finally:
        if owns_workdir and not keep_shards:
            import shutil
            shutil.rmtree(workdir, ignore_errors=True)


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
