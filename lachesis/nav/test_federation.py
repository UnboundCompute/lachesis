"""Federated sharding: manifest, planner, and the cross-shard USR linker join.

The load-bearing claim is that two shards built independently -- one defining a
function, another only referencing it via ``extern`` -- resolve to one canonical
endpoint at query time, the same endpoint a full merge would pick. That is what makes
a federated query equivalent to a single-store query without ever merging the stores.
"""
from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

import pytest

from lachesis.nav.federation import (
    FederatedStore, FederationManifest, ShardEntry, SymbolIndex,
    build_shards, plan_shards,
)


def _lachesis_bin() -> str:
    """Locate the ``lachesis`` console script; skip the build tests if it is absent."""
    candidate = Path(sys.executable).parent / "lachesis"
    if candidate.exists():
        return str(candidate)
    found = shutil.which("lachesis")
    if found:
        return found
    pytest.skip("lachesis CLI not available for shard build")


def test_manifest_round_trips(tmp_path):
    manifest = FederationManifest(
        source_root="/src",
        shards=[ShardEntry("shard-0000", "/s/0.kuzu", "/src", ["kernel"], 10, 20, "abc")],
    )
    path = manifest.write(tmp_path)
    again = FederationManifest.read(path)
    assert again.to_dict() == manifest.to_dict()
    assert again.shards[0].coverage == ["kernel"]


def test_plan_groups_subdirs_under_budget(tmp_path):
    for name, n in (("a", 2), ("b", 2), ("big", 5)):
        d = tmp_path / name
        d.mkdir()
        for i in range(n):
            (d / f"f{i}.c").write_text("int x;\n")
    plan = plan_shards(tmp_path, max_files_per_shard=3)
    # 'big' (5 >= 3) is its own shard; 'a'+'b' (2+2=4>3) split into two groups.
    covered = sorted(sum((dirs for _, dirs in plan), []))
    assert covered == ["a", "b", "big"]
    assert ["big"] in [dirs for _, dirs in plan]
    assert all(len(sid) > 0 for sid, _ in plan)


def _write_cross_shard_fixture(root: Path) -> None:
    (root / "shard1").mkdir(parents=True)
    (root / "shard2").mkdir(parents=True)
    # shard1 DEFINES target_fn; shard2 only references it via extern and calls it.
    (root / "shard1" / "def.c").write_text(
        "#include <stdlib.h>\n"
        "void *target_fn(unsigned n) { return malloc(n); }\n"
    )
    (root / "shard2" / "use.c").write_text(
        "extern void *target_fn(unsigned n);\n"
        "void *caller(unsigned k) { return target_fn(k); }\n"
    )


def test_cross_shard_usr_join_resolves_to_definition(tmp_path):
    binary = _lachesis_bin()
    src = tmp_path / "src"
    _write_cross_shard_fixture(src)
    out = tmp_path / "fed"

    plan = [("shard-0000", ["shard1"]), ("shard-0001", ["shard2"])]
    manifest = build_shards(src, out, plan, memory_budget_mb=2048, lachesis_bin=binary)
    assert len(manifest.shards) == 2
    assert all(s.node_count > 0 for s in manifest.shards)

    index = SymbolIndex.build(manifest)
    # target_fn is defined in one shard and declared in the other -> one cross-shard symbol.
    assert index.stats()["cross_shard_symbols"] >= 1

    fed = FederatedStore(manifest, symbol_index=index)
    try:
        # The definition shard owns target_fn; its owner node is NOT declaration_only.
        callers = [n for n in fed.search("caller")]
        assert callers, "caller function should be found"
        caller = callers[0]
        callees = fed.callees(caller.shard_id, caller.node["id"])
        names = {(c.shard_id, c.node.get("name") or c.node.get("label")) for c in callees}
        # target_fn resolves to the DEFINING shard (shard-0000), not the referencing one.
        assert any(name == "target_fn" for _, name in names), names
        resolved = [c for c in callees
                    if (c.node.get("name") or c.node.get("label")) == "target_fn"]
        assert resolved, "target_fn callee must resolve"
        owner = resolved[0]
        assert owner.shard_id == "shard-0000", f"expected definition shard, got {owner.shard_id}"
        assert not (owner.node.get("properties") or {}).get("declaration_only"), \
            "cross-shard callee must land on the definition, not the extern declaration"

        # Reverse direction: callers of the DEFINITION must include the cross-shard
        # caller that reaches it through its extern prototype in the other shard.
        callers_of_def = fed.callers(owner.shard_id, owner.node["id"])
        caller_names = {(c.shard_id, c.node.get("name") or c.node.get("label"))
                        for c in callers_of_def}
        assert ("shard-0001", "caller") in caller_names, caller_names
    finally:
        fed.close()


def test_symbol_index_prefers_definition_over_declaration():
    # Pure-logic check of the canonicalization rule (no build needed): a definition
    # wins over a declaration for the same (kind, usr), mirroring ShardMerger.
    manifest = FederationManifest(source_root="/src", shards=[
        ShardEntry("shard-0000", "/s/0.kuzu", "/src"),
        ShardEntry("shard-0001", "/s/1.kuzu", "/src"),
    ])

    def fake_index(shard_id, _store_path):
        if shard_id == "shard-0001":  # the DEFINITION lives in the higher-id shard
            return _FakeIndex([_node("v2:...:1", "function", "u1", declaration=False)])
        return _FakeIndex([_node("v2:...:0", "function", "u1", declaration=True)])

    index = SymbolIndex.build(manifest, index_for=fake_index)
    owner = index.owner_of("function", "u1")
    # Even though shard-0000's id sorts first, the definition in shard-0001 must win.
    assert owner == ("shard-0001", "v2:...:1")


def _node(node_id, kind, usr, *, declaration):
    return {"id": node_id, "kind": kind,
            "properties": {"usr": usr, "declaration_only": declaration}}


class _FakeIndex:
    def __init__(self, nodes):
        self._nodes = nodes

    def nodes_of_kind(self, *kinds):
        return [n for n in self._nodes if n.get("kind") in kinds]
