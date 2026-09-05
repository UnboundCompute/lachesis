"""Federated sharding: query many independently-built stores as one graph.

A Linux-scale source tree does not fit in a single store on a commodity disk -- the
merged store and its build transients exceed the volume long before RAM is the limit
(the ingest itself is already bounded; see ``core/shard_merge`` and ``pipeline``).
Federation keeps each source subtree in its own byte-identical ``lachesis build``
store and resolves cross-shard references *at query time*, so no store is ever larger
than one shard and nothing is ever merged into one giant store.

**Why node ids cannot be the cross-shard join key.** A node id embeds the absolute
file path of the entity it names (verified: the same function compiled under two
different shard roots gets two different ids). So an id minted in one shard is
meaningless in another, and ``storeA``'s ``target_fn`` id never appears in ``storeB``
even when ``storeB`` calls ``target_fn``. The join key must be path-independent.

**The join key is the compiler symbol identity.** Every ``function``/``value``/
``variable`` node carries the frontend's canonical symbol id -- clang's USR for C
(``c:@F@target_fn``) -- which is a pure function of the symbol, not of the file path,
so it is identical across independent builds. A reference in one shard (an ``extern``
prototype, ``declaration_only=True``) and the definition in another (``declaration_only
=False``, ``linkage="external"``) carry the *same* USR. Federation is therefore a
linker over per-shard USR symbol tables.

**Equivalence to a full merge.** The resolver picks the canonical instance of each
``(kind, usr)`` with the exact rule the on-disk merge uses
(``core.shard_merge.ShardMerger._canonical_remap``): prefer a definition over a
declaration, smallest id as the tiebreak. Because the rule is identical, a federated
cross-shard resolution returns the same endpoint a full merge would have produced --
equivalence by construction, so a federated query does not regress against a
single-store query of the same sources.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Iterator, Optional
import json
import os
import subprocess

# Kinds whose cross-shard instances share a canonical identity (the frontend's USR).
# MUST stay in sync with ``core.shard_merge.ShardMerger._CANONICAL_KINDS`` -- the
# federated resolver and the on-disk merge have to agree on what is canonicalizable
# or a federated query would answer differently from a merged store.
CANONICAL_KINDS = ("function", "value", "variable")

MANIFEST_VERSION = 1
MANIFEST_FILENAME = "federation.json"


# --------------------------------------------------------------------------- manifest


@dataclass
class ShardEntry:
    """One independently-built store and the source it covers."""

    shard_id: str
    store_path: str
    source_root: str
    coverage: list[str] = field(default_factory=list)
    node_count: int = 0
    edge_count: int = 0
    content_hash: str = ""

    def to_dict(self) -> dict:
        return {
            "shard_id": self.shard_id,
            "store_path": self.store_path,
            "source_root": self.source_root,
            "coverage": list(self.coverage),
            "node_count": self.node_count,
            "edge_count": self.edge_count,
            "content_hash": self.content_hash,
        }

    @classmethod
    def from_dict(cls, value: dict) -> "ShardEntry":
        return cls(
            shard_id=str(value["shard_id"]),
            store_path=str(value["store_path"]),
            source_root=str(value.get("source_root", "")),
            coverage=list(value.get("coverage", [])),
            node_count=int(value.get("node_count", 0)),
            edge_count=int(value.get("edge_count", 0)),
            content_hash=str(value.get("content_hash", "")),
        )


@dataclass
class FederationManifest:
    """The federation: which shards exist, where their stores are, what they cover."""

    source_root: str
    shards: list[ShardEntry] = field(default_factory=list)
    version: int = MANIFEST_VERSION

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "source_root": self.source_root,
            "shards": [s.to_dict() for s in self.shards],
        }

    @classmethod
    def from_dict(cls, value: dict) -> "FederationManifest":
        return cls(
            version=int(value.get("version", MANIFEST_VERSION)),
            source_root=str(value.get("source_root", "")),
            shards=[ShardEntry.from_dict(s) for s in value.get("shards", [])],
        )

    def write(self, path: str | Path) -> str:
        """Serialize to ``path`` (a directory gets ``federation.json``); return the file."""
        target = Path(path)
        if target.is_dir():
            target = target / MANIFEST_FILENAME
        target.write_text(json.dumps(self.to_dict(), indent=2, sort_keys=True))
        return str(target)

    @classmethod
    def read(cls, path: str | Path) -> "FederationManifest":
        target = Path(path)
        if target.is_dir():
            target = target / MANIFEST_FILENAME
        return cls.from_dict(json.loads(target.read_text()))


# --------------------------------------------------------------------------- planner


def _count_c_files(directory: Path) -> int:
    return sum(1 for _ in directory.rglob("*.c"))


def plan_shards(source_root: str | Path, *, max_files_per_shard: int = 3000
                ) -> list[tuple[str, list[str]]]:
    """Partition ``source_root``'s immediate subdirectories into shard groups.

    Each group's C-file count stays at or under ``max_files_per_shard`` -- the shard
    size that keeps a single ``lachesis build`` inside the disk and RAM budget (the
    density measured on the kernel is ~1.2-1.7k nodes per C file, so ~3000 files is a
    store comfortably under the per-shard ceiling). A subdirectory larger than the
    budget on its own becomes its own shard rather than being split mid-directory:
    finer splitting is a later refinement, and an over-budget single shard still
    builds -- it just uses more of the budget. Grouping is greedy over subdirectories
    sorted by name so the plan is deterministic (a stable plan means a stable set of
    shard ids and store paths across replans).
    """
    root = Path(os.path.expanduser(str(source_root)))
    subdirs = sorted(p for p in root.iterdir() if p.is_dir())
    sized = [(p, _count_c_files(p)) for p in subdirs]
    sized = [(p, n) for p, n in sized if n > 0]

    groups: list[list[str]] = []
    current: list[str] = []
    running = 0
    for directory, count in sized:
        if count >= max_files_per_shard:
            if current:
                groups.append(current)
                current, running = [], 0
            groups.append([directory.name])
            continue
        if running + count > max_files_per_shard and current:
            groups.append(current)
            current, running = [], 0
        current.append(directory.name)
        running += count
    if current:
        groups.append(current)

    return [(f"shard-{i:04d}", dirs) for i, dirs in enumerate(groups)]


# --------------------------------------------------------------------------- builder


def _shard_manifest_counts(store_path: str) -> tuple[int, int, str]:
    """(node_count, edge_count, content_hash) for a freshly built shard store."""
    from lachesis.kuzu_store import read_store_manifest, graph_content_hash
    from lachesis.nav.graph_store import GraphStore

    manifest = read_store_manifest(store_path)
    node_count = int(manifest.get("node_count", 0))
    edge_count = int(manifest.get("edge_count", 0))
    # The overlay cache key is the store's own content hash; compute it from the store
    # so the manifest records the same identity nav uses to bind derived tiers.
    store = GraphStore.load(store_path)
    try:
        content_hash = store.graph_hash()
    except Exception:  # noqa: BLE001 -- a missing hash must not abort a good build
        content_hash = ""
    return node_count, edge_count, content_hash


def build_shards(source_root: str | Path, out_dir: str | Path,
                 plan: Optional[list[tuple[str, list[str]]]] = None, *,
                 memory_budget_mb: int = 2048, max_files_per_shard: int = 3000,
                 lachesis_bin: Optional[str] = None, timeout_seconds: int = 21600,
                 progress=None) -> FederationManifest:
    """Build one byte-identical ``lachesis build`` store per planned shard.

    Each shard is built by invoking the ``lachesis build`` CLI on a directory holding
    only that shard's subtrees. That path is exactly the bounded-RAM streaming build a
    user runs by hand, unchanged -- so per-shard output is byte-identical to a
    single-directory build and there is no new build code to regress. Shards are built
    one at a time, so peak RAM is one shard's build, not the whole tree's.
    """
    root = Path(os.path.expanduser(str(source_root)))
    out = Path(os.path.expanduser(str(out_dir)))
    out.mkdir(parents=True, exist_ok=True)
    binary = lachesis_bin or os.environ.get("LACHESIS_BIN") or "lachesis"
    if plan is None:
        plan = plan_shards(root, max_files_per_shard=max_files_per_shard)

    shards: list[ShardEntry] = []
    for shard_id, dirs in plan:
        if progress is not None:
            progress(f"building {shard_id}: {', '.join(dirs)}")
        # Build the shard's subtrees at their real source paths: the first directory is
        # the build root and the rest are added with ``--include`` (the CLI's own
        # sub-tree scoping). No staging or copying -- a copy of a Linux-scale subtree
        # would itself blow the disk budget, and real paths keep every node id and USR
        # identical to a single-directory build of the same sources (zero regression).
        present = [root / name for name in dirs if (root / name).exists()]
        if not present:
            continue
        source_dir = str(present[0])
        include_paths = [str(p) for p in present[1:]]
        store_path = str(out / f"{shard_id}.kuzu")
        _run_build(binary, source_dir, store_path, memory_budget_mb,
                   timeout_seconds, include_paths=include_paths)
        node_count, edge_count, content_hash = _shard_manifest_counts(store_path)
        shards.append(ShardEntry(
            shard_id=shard_id, store_path=store_path, source_root=str(root),
            coverage=list(dirs), node_count=node_count, edge_count=edge_count,
            content_hash=content_hash,
        ))

    return FederationManifest(source_root=str(root), shards=shards)


def _run_build(binary: str, source: str, store_path: str, budget_mb: int,
               timeout_seconds: int, *, include_paths: Optional[list[str]] = None
               ) -> None:
    import shlex
    cmd = [*shlex.split(binary), "build", source, store_path,
           "--memory-budget-mb", str(budget_mb), "--timeout", str(timeout_seconds)]
    for included in include_paths or []:
        cmd += ["--include", included]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_seconds)
    if result.returncode != 0 or not os.path.isdir(store_path):
        raise RuntimeError(
            f"shard build failed ({binary} build {source} -> {store_path}): "
            f"rc={result.returncode}\n{result.stderr[-2000:]}")


# ---------------------------------------------------------------------- symbol index


@dataclass(frozen=True)
class SymbolSite:
    shard_id: str
    node_id: str
    declaration_only: bool


class SymbolIndex:
    """Linker table: ``(kind, usr) -> canonical owning (shard, node)`` across shards.

    Built by scanning every shard once for its canonical-kind nodes. For each
    ``(kind, usr)`` the canonical owner is chosen by the merge's rule -- a definition
    over a declaration, smallest node id as the tiebreak -- so ``resolve`` returns the
    endpoint a full merge would have produced.
    """

    def __init__(self) -> None:
        self._sites: dict[tuple[str, str], list[SymbolSite]] = {}
        self._canonical: dict[tuple[str, str], SymbolSite] = {}

    @classmethod
    def build(cls, manifest: FederationManifest,
              index_for=None) -> "SymbolIndex":
        """Scan each shard's canonical-kind nodes and resolve owners.

        ``index_for(shard_id, store_path)`` returns a ``KuzuGraphIndex``-like object
        exposing ``nodes_of_kind``; the default opens the store directly. Injecting it
        lets a caller reuse already-open shard indexes.
        """
        from lachesis.nav.kuzu_index import KuzuGraphIndex

        def _default_index(_shard_id: str, store_path: str):
            return KuzuGraphIndex(store_path)

        opener = index_for or _default_index
        self = cls()
        for shard in manifest.shards:
            index = opener(shard.shard_id, shard.store_path)
            for node in index.nodes_of_kind(*CANONICAL_KINDS):
                props = node.get("properties") or {}
                usr = props.get("usr")
                if not usr:
                    continue
                key = (node.get("kind", ""), usr)
                self._sites.setdefault(key, []).append(SymbolSite(
                    shard_id=shard.shard_id, node_id=node["id"],
                    declaration_only=bool(props.get("declaration_only")),
                ))
        self._resolve_canonical()
        return self

    def _resolve_canonical(self) -> None:
        for key, sites in self._sites.items():
            defs = [s for s in sites if not s.declaration_only]
            pool = defs or sites
            # Smallest (shard_id, node_id) is the deterministic tiebreak; preferring a
            # definition mirrors ShardMerger._canonical_remap exactly.
            self._canonical[key] = min(pool, key=lambda s: (s.shard_id, s.node_id))

    def resolve(self, kind: str, usr: str) -> Optional[SymbolSite]:
        return self._canonical.get((kind, usr))

    def owner_of(self, kind: str, usr: str) -> Optional[tuple[str, str]]:
        site = self.resolve(kind, usr)
        return (site.shard_id, site.node_id) if site else None

    def __len__(self) -> int:
        return len(self._canonical)

    def stats(self) -> dict:
        multi = sum(1 for sites in self._sites.values() if len(sites) > 1)
        return {"symbols": len(self._canonical), "cross_shard_symbols": multi}


# ------------------------------------------------------------------- federated store


@dataclass(frozen=True)
class FederatedNode:
    shard_id: str
    node: dict


class FederatedStore:
    """Query a set of shard stores as one graph, resolving cross-shard by USR.

    Shard stores are opened lazily and kept in a small bounded cache, so peak memory
    is a handful of open shards, not the whole federation. Cross-shard hops are
    resolved through :class:`SymbolIndex`: a call landing on a ``declaration_only``
    node (a shard-local ``extern`` prototype) is redirected to the shard that defines
    that USR, and the traversal continues there.
    """

    def __init__(self, manifest: FederationManifest, *, cache_size: int = 8,
                 symbol_index: Optional[SymbolIndex] = None) -> None:
        self.manifest = manifest
        self._by_id = {s.shard_id: s for s in manifest.shards}
        self._cache_size = max(1, cache_size)
        self._open: "dict[str, object]" = {}
        self._lru: list[str] = []
        self._symbol_index = symbol_index

    @classmethod
    def open(cls, manifest_path: str | Path, **kwargs) -> "FederatedStore":
        return cls(FederationManifest.read(manifest_path), **kwargs)

    # -- shard handles -----------------------------------------------------------

    def _graphstore(self, shard_id: str):
        from lachesis.nav.graph_store import GraphStore

        if shard_id in self._open:
            self._lru.remove(shard_id)
            self._lru.append(shard_id)
            return self._open[shard_id]
        entry = self._by_id.get(shard_id)
        if entry is None:
            raise KeyError(f"unknown shard: {shard_id}")
        store = GraphStore.load(entry.store_path)
        self._open[shard_id] = store
        self._lru.append(shard_id)
        while len(self._lru) > self._cache_size:
            evict = self._lru.pop(0)
            self._open.pop(evict, None)
        return store

    @property
    def symbol_index(self) -> SymbolIndex:
        if self._symbol_index is None:
            self._symbol_index = SymbolIndex.build(self.manifest)
        return self._symbol_index

    # -- queries -----------------------------------------------------------------

    def search(self, name: str) -> list[FederatedNode]:
        """Every node named ``name`` across all shards (declarations included)."""
        hits: list[FederatedNode] = []
        for shard in self.manifest.shards:
            index = self._graphstore(shard.shard_id).gl.index
            for node in index.nodes_named(name):
                hits.append(FederatedNode(shard.shard_id, node))
        return hits

    def _canonicalize(self, shard_id: str, node: dict) -> FederatedNode:
        """Redirect a declaration-only reference to its defining shard, if known."""
        props = node.get("properties") or {}
        usr = props.get("usr")
        if usr and props.get("declaration_only"):
            owner = self.symbol_index.resolve(node.get("kind", ""), usr)
            if owner is not None and (owner.shard_id != shard_id
                                      or owner.node_id != node.get("id")):
                target = self._graphstore(owner.shard_id).gl.nodes.get(owner.node_id)
                if target is not None:
                    return FederatedNode(owner.shard_id, target)
        return FederatedNode(shard_id, node)

    def callees(self, shard_id: str, node_id: str) -> list[FederatedNode]:
        """Callees of a function, following cross-shard references to their definitions."""
        gl = self._graphstore(shard_id).gl
        out: list[FederatedNode] = []
        seen: set[tuple[str, str]] = set()
        for target in gl.calls_from(node_id):
            resolved = self._canonicalize(shard_id, target)
            key = (resolved.shard_id, resolved.node["id"])
            if key not in seen:
                seen.add(key)
                out.append(resolved)
        return out

    def close(self) -> None:
        self._open.clear()
        self._lru.clear()
