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
    FederatedReachability, FederatedStore, FederationManifest, ShardEntry,
    SymbolIndex, _args_in_order, _params_in_order, build_shards, plan_shards,
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


def _assert_cross_shard_resolves(manifest, *, callee_name="target_fn",
                                 caller_name="caller", def_shard="shard-0000",
                                 ref_shard="shard-0001"):
    """Shared cross-shard assertions: a call in the referencing shard resolves to the
    real definition in the defining shard, and the reverse (callers of the def) sees it.

    Frontends emit many nodes per name (e.g. TS identifier/definition/function/symbol),
    so we filter to ``kind == "function"`` before picking the caller.
    """
    index = SymbolIndex.build(manifest)
    assert index.stats()["cross_shard_symbols"] >= 1

    fed = FederatedStore(manifest, symbol_index=index)
    try:
        callers = [c for c in fed.search(caller_name)
                   if c.node.get("kind") == "function"]
        assert callers, f"{caller_name} function should be found"
        caller = callers[0]
        assert caller.shard_id == ref_shard

        callees = fed.callees(caller.shard_id, caller.node["id"])
        resolved = [c for c in callees
                    if (c.node.get("name") or c.node.get("label")) == callee_name]
        assert resolved, f"{callee_name} callee must resolve cross-shard"
        owner = resolved[0]
        assert owner.shard_id == def_shard, \
            f"expected definition shard {def_shard}, got {owner.shard_id}"
        assert not (owner.node.get("properties") or {}).get("declaration_only"), \
            "cross-shard callee must land on the definition, not the placeholder"

        callers_of_def = fed.callers(owner.shard_id, owner.node["id"])
        caller_names = {(c.shard_id, c.node.get("name") or c.node.get("label"))
                        for c in callers_of_def}
        assert (ref_shard, caller_name) in caller_names, caller_names
    finally:
        fed.close()


def _write_python_cross_shard_fixture(root: Path) -> None:
    # shard1 is a package DEFINING target_fn; shard2 imports it absolutely and calls it.
    (root / "shard1").mkdir(parents=True)
    (root / "shard2").mkdir(parents=True)
    (root / "shard1" / "__init__.py").write_text("")
    (root / "shard1" / "lib.py").write_text("def target_fn(n):\n    return n * 2\n")
    (root / "shard2" / "__init__.py").write_text("")
    (root / "shard2" / "use.py").write_text(
        "from shard1.lib import target_fn\n"
        "def caller(k):\n    return target_fn(k)\n"
    )


def test_cross_shard_usr_join_python(tmp_path):
    _lachesis_bin_or_skip = _lachesis_bin()
    src = tmp_path / "src"
    _write_python_cross_shard_fixture(src)
    plan = [("shard-0000", ["shard1"]), ("shard-0001", ["shard2"])]
    manifest = build_shards(src, tmp_path / "fed", plan,
                            memory_budget_mb=2048, lachesis_bin=_lachesis_bin_or_skip)
    assert len(manifest.shards) == 2
    _assert_cross_shard_resolves(manifest)


def _write_ts_cross_shard_fixture(root: Path, ext: str) -> None:
    # shard1 exports target_fn; shard2 imports it via a relative specifier and calls it.
    (root / "shard1").mkdir(parents=True)
    (root / "shard2").mkdir(parents=True)
    (root / "shard1" / f"lib.{ext}").write_text(
        "export function target_fn(n) { return n * 2; }\n"
    )
    (root / "shard2" / f"use.{ext}").write_text(
        "import { target_fn } from '../shard1/lib';\n"
        "export function caller(k) { return target_fn(k); }\n"
    )


def test_cross_shard_usr_join_typescript(tmp_path):
    binary = _lachesis_bin()
    src = tmp_path / "src"
    _write_ts_cross_shard_fixture(src, "ts")
    plan = [("shard-0000", ["shard1"]), ("shard-0001", ["shard2"])]
    manifest = build_shards(src, tmp_path / "fed", plan,
                            memory_budget_mb=2048, lachesis_bin=binary)
    assert len(manifest.shards) == 2
    _assert_cross_shard_resolves(manifest)


def test_cross_shard_usr_join_javascript(tmp_path):
    binary = _lachesis_bin()
    src = tmp_path / "src"
    _write_ts_cross_shard_fixture(src, "js")
    plan = [("shard-0000", ["shard1"]), ("shard-0001", ["shard2"])]
    manifest = build_shards(src, tmp_path / "fed", plan,
                            memory_budget_mb=2048, lachesis_bin=binary)
    assert len(manifest.shards) == 2
    _assert_cross_shard_resolves(manifest)


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


# --------------------------------------------------------------- cross-shard dataflow
#
# Pass-1 proves a call *resolves* across shards. These prove a *value* moves across the
# shard boundary: Pass-2 that an argument in the referencing shard reaches the callee's
# parameter (and back), and Pass-3 that the crossing is context-sensitive -- a value
# returned from a cross-shard callee flows back only to the call site it came from.
# Both must hold for all four languages, which is the standing federation goal.

# Each fixture: shard1 defines a passthrough function (param flows to the return);
# shard2's caller passes a value across the shard boundary into it.
_PASS2_FIXTURES = {
    "c": dict(ext="c", pkg=False,
              deff="char *target_fn(char *p){ char *q = p; return q; }\n",
              use=("extern char *target_fn(char *p);\n"
                   "char *caller(char *tainted){ return target_fn(tainted); }\n")),
    "python": dict(ext="py", pkg=True,
                   deff="def target_fn(p):\n    q = p\n    return q\n",
                   use=("from shard1.lib import target_fn\n"
                        "def caller(tainted):\n    return target_fn(tainted)\n")),
    "typescript": dict(ext="ts", pkg=False,
                       deff="export function target_fn(p){ let q = p; return q; }\n",
                       use=("import { target_fn } from '../shard1/lib';\n"
                            "export function caller(tainted){ return target_fn(tainted); }\n")),
    "javascript": dict(ext="js", pkg=False,
                       deff="export function target_fn(p){ let q = p; return q; }\n",
                       use=("import { target_fn } from '../shard1/lib';\n"
                            "export function caller(tainted){ return target_fn(tainted); }\n")),
}

# Two callers of one cross-shard passthrough, to exercise call/return context matching.
_PASS3_FIXTURES = {
    "c": dict(ext="c", pkg=False,
              deff="char *id_fn(char *p){ return p; }\n",
              use=("extern char *id_fn(char *p);\n"
                   "char *callerA(char *a){ return id_fn(a); }\n"
                   "char *callerB(char *b){ return id_fn(b); }\n")),
    "python": dict(ext="py", pkg=True,
                   deff="def id_fn(p):\n    return p\n",
                   use=("from shard1.lib import id_fn\n"
                        "def callerA(a):\n    return id_fn(a)\n"
                        "def callerB(b):\n    return id_fn(b)\n")),
    "typescript": dict(ext="ts", pkg=False,
                       deff="export function id_fn(p){ return p; }\n",
                       use=("import { id_fn } from '../shard1/lib';\n"
                            "export function callerA(a){ return id_fn(a); }\n"
                            "export function callerB(b){ return id_fn(b); }\n")),
    "javascript": dict(ext="js", pkg=False,
                       deff="export function id_fn(p){ return p; }\n",
                       use=("import { id_fn } from '../shard1/lib';\n"
                            "export function callerA(a){ return id_fn(a); }\n"
                            "export function callerB(b){ return id_fn(b); }\n")),
}


def _build_dataflow_shards(root, out, spec, binary):
    (root / "shard1").mkdir(parents=True)
    (root / "shard2").mkdir(parents=True)
    ext = spec["ext"]
    if spec["pkg"]:
        (root / "shard1" / "__init__.py").write_text("")
        (root / "shard2" / "__init__.py").write_text("")
        (root / "shard1" / "lib.py").write_text(spec["deff"])
        (root / "shard2" / "use.py").write_text(spec["use"])
    else:
        (root / "shard1" / f"lib.{ext}").write_text(spec["deff"])
        (root / "shard2" / f"use.{ext}").write_text(spec["use"])
    plan = [("shard-0000", ["shard1"]), ("shard-0001", ["shard2"])]
    return build_shards(root, out, plan, memory_budget_mb=2048, lachesis_bin=binary)


def _cross_shard_calls(fed):
    """Every cross-shard call in the referencing shard: (call_id, first_arg, owner)."""
    gl = fed._graphstore("shard-0001").gl
    si = fed.symbol_index
    out = []
    for node in gl.nodes.values():
        props = node.get("properties") or {}
        if not (props.get("usr") and props.get("declaration_only")):
            continue
        owner = si.resolve(node.get("kind", ""), props["usr"])
        if owner is None:
            continue
        for call in gl.index.sources(node["id"], "INVOKES"):
            args = _args_in_order(gl, call["id"])
            if args:
                out.append((call["id"], args[0], owner))
    return out


@pytest.mark.parametrize("lang", list(_PASS2_FIXTURES))
def test_cross_shard_pass2_dataflow(tmp_path, lang):
    """Pass-2: an argument passed across the shard boundary reaches the callee's
    parameter in the defining shard, and the reverse cone from that parameter finds
    its way back to the referencing shard."""
    binary = _lachesis_bin()
    src = tmp_path / "src"
    manifest = _build_dataflow_shards(src, tmp_path / "fed",
                                      _PASS2_FIXTURES[lang], binary)
    fed = FederatedStore(manifest, symbol_index=SymbolIndex.build(manifest))
    try:
        calls = _cross_shard_calls(fed)
        assert calls, f"{lang}: no cross-shard call with an argument found"
        call_id, arg_id, owner = calls[0]
        params = _params_in_order(fed._graphstore(owner.shard_id).gl, owner.node_id)
        assert params, f"{lang}: callee has no parameter node"
        param_id = params[0]

        fr = fed.reachability
        fwd = fr.reaches("shard-0001", arg_id, owner.shard_id, param_id)
        assert fwd["reachable"], f"{lang}: argument did not reach callee param cross-shard"

        cone = fr.flow("shard-0001", arg_id)
        assert any(n.shard_id == owner.shard_id for n in cone), \
            f"{lang}: forward cone never entered the defining shard"

        rev = fr.sources_of(owner.shard_id, param_id)
        assert any(n.shard_id == "shard-0001" for n in rev), \
            f"{lang}: reverse cone from callee param never reached the referencing shard"
    finally:
        fed.close()


@pytest.mark.parametrize("lang", list(_PASS3_FIXTURES))
def test_cross_shard_pass3_context_sensitive(tmp_path, lang):
    """Pass-3: with two callers of one cross-shard passthrough, a value from caller A
    reaches A's own call result under context-sensitive traversal but NOT B's, whereas
    the context-insensitive walk conflates them -- i.e. the seam matches calls to
    returns by call site across the shard boundary."""
    binary = _lachesis_bin()
    src = tmp_path / "src"
    manifest = _build_dataflow_shards(src, tmp_path / "fed",
                                      _PASS3_FIXTURES[lang], binary)
    fed = FederatedStore(manifest, symbol_index=SymbolIndex.build(manifest))
    try:
        calls = _cross_shard_calls(fed)
        assert len(calls) >= 2, f"{lang}: expected two cross-shard calls, got {len(calls)}"
        calls.sort(key=lambda c: c[0])
        (callA, argA, _), (callB, _argB, _) = calls[0], calls[1]

        fr = fed.reachability
        aa = fr.reaches("shard-0001", argA, "shard-0001", callA,
                        context_sensitive=True)["reachable"]
        ab_ci = fr.reaches("shard-0001", argA, "shard-0001", callB)["reachable"]
        ab_cs = fr.reaches("shard-0001", argA, "shard-0001", callB,
                           context_sensitive=True)["reachable"]

        assert aa, f"{lang}: A's argument did not reach A's own call result cross-shard"
        assert ab_ci, f"{lang}: context-insensitive walk should conflate A and B's returns"
        assert not ab_cs, f"{lang}: context-sensitive walk must not leak A's value to B's return"
    finally:
        fed.close()
