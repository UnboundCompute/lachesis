"""Cross-TU declaration->definition linking is rebuilt at shard merge.

The clang frontend links every function declaration to its definition at the end
of a single run, over that run's accumulated USR map. Under sharding each frontend
sees only its own translation units, so a prototype in one shard and the definition
in another are never linked and the REFERS_TO(reason=prototype-of) edge is lost.
``write_kuzu_shards`` rebuilds those links globally from the compiler USR carried on
each function node. These tests pin that behaviour and its dedup against the
prototype-of links a shard already carried when a declaration and its definition
happen to land in the same shard.
"""
import pytest

from .core.shards import ShardSetReader, ShardSetWriter
from .flow import native_lifetime

kuzu = pytest.importorskip("kuzu")

from .kuzu_store import db_file, write_kuzu_shards  # noqa: E402

# Every case here writes shards through ``write_kuzu_shards``, which loads the native
# lifetime kernel during the merge. Without a staged/built kernel the whole module is
# a toolchain gap, not a set of defects, so skip it exactly as the rest of the suite
# skips its native-dependent tests.
pytestmark = pytest.mark.skipif(
    not native_lifetime.available(),
    reason="native analysis kernel not built; shard merge unavailable",
)


def _fn(node_id, *, usr, declaration_only, file):
    return {
        "id": node_id, "kind": "function", "label": "add",
        "properties": {"usr": usr, "declaration_only": declaration_only,
                       "file": file, "language": "c"},
    }


def _refers_to(source, target):
    return {"kind": "REFERS_TO", "source": source, "target": target,
            "properties": {"reason": "prototype-of"},
            "source_tier": "T1", "relationship_class": "REFERS_TO"}


def _prototype_of_edges(db_dir):
    conn = kuzu.Connection(kuzu.Database(db_file(db_dir)))
    result = conn.execute(
        "MATCH (a:Node)-[e:REFERS_TO]->(b:Node) RETURN a.id, b.id")
    edges = []
    while result.has_next():
        edges.append(tuple(result.get_next()))
    return sorted(edges)


def _param_node(node_id, *, index, file="callee.h"):
    return {
        "id": node_id, "kind": "parameter", "label": node_id,
        "properties": {"param_index": index, "file": file, "language": "c"},
    }


def _edge(kind, source, target, **props):
    return {"kind": kind, "source": source, "target": target,
            "properties": props, "source_tier": "T3",
            "relationship_class": kind}


def _typed_edges(db_dir, kind):
    conn = kuzu.Connection(kuzu.Database(db_file(db_dir)))
    result = conn.execute(
        f"MATCH (a:Node)-[e:EDGE]->(b:Node) WHERE e.kind='{kind}' "
        "RETURN a.id, b.id")
    edges = []
    while result.has_next():
        edges.append(tuple(result.get_next()))
    return sorted(edges)


def _value_flows(db_dir):
    conn = kuzu.Connection(kuzu.Database(db_file(db_dir)))
    result = conn.execute(
        "MATCH (a:Node)-[e:VALUE_FLOWS_TO]->(b:Node) RETURN a.id, b.id")
    edges = []
    while result.has_next():
        edges.append(tuple(result.get_next()))
    return sorted(edges)


def test_cross_shard_prototype_link_is_rebuilt(tmp_path):
    # Declaration and definition share a USR but land in separate shards, exactly
    # as they would when two translation units are compiled by different frontends.
    root = tmp_path / "shards"
    shard_set = ShardSetWriter(root, frontend_id="clang-c")
    decl = shard_set.start("0")
    decl.add_node(_fn("decl", usr="c:@F@add", declaration_only=True, file="hdr.h"))
    shard_set.complete("0", decl)
    defn = shard_set.start("1")
    defn.add_node(_fn("defn", usr="c:@F@add", declaration_only=False, file="a.c"))
    shard_set.complete("1", defn)

    db_dir = write_kuzu_shards(
        ShardSetReader(root / "shards.pb"), str(tmp_path / "out.kuzu"))

    # A single frontend run would have linked decl -> defn; the merge rebuilds it.
    assert _prototype_of_edges(db_dir) == [("decl", "defn")]


def test_same_shard_prototype_link_is_not_duplicated(tmp_path):
    # When a declaration and its definition sit in one shard, that shard's frontend
    # already emitted the prototype-of edge. The merge must not emit a second copy.
    root = tmp_path / "shards"
    shard_set = ShardSetWriter(root, frontend_id="clang-c")
    shard = shard_set.start("0")
    shard.add_node(_fn("decl", usr="c:@F@add", declaration_only=True, file="hdr.h"))
    shard.add_node(_fn("defn", usr="c:@F@add", declaration_only=False, file="a.c"))
    shard.add_edge(_refers_to("decl", "defn"))
    shard_set.complete("0", shard)

    db_dir = write_kuzu_shards(
        ShardSetReader(root / "shards.pb"), str(tmp_path / "out.kuzu"))

    assert _prototype_of_edges(db_dir) == [("decl", "defn")]


def _call_shard(shard):
    # A call site whose callee lives elsewhere: the INVOKES edge names the callee
    # and HAS_ARGUMENT names each argument by position, but the callee's formals
    # are not visible here so no binding is emitted in this shard.
    shard.add_node({"id": "call", "kind": "call", "label": "add(y, x)",
                    "properties": {"file": "user.c", "language": "c"}})
    shard.add_node({"id": "arg0", "kind": "expression", "label": "y",
                    "properties": {"file": "user.c", "language": "c"}})
    shard.add_node({"id": "arg1", "kind": "expression", "label": "x",
                    "properties": {"file": "user.c", "language": "c"}})
    shard.add_edge(_edge("INVOKES", "call", "callee"))
    shard.add_edge(_edge("HAS_ARGUMENT", "call", "arg0", position=0))
    shard.add_edge(_edge("HAS_ARGUMENT", "call", "arg1", position=1))


def _callee_shard(shard):
    # The callee and its formals. Parameter ids are chosen so that sorting by id
    # ('a' < 'z') is the OPPOSITE of signature order (param_index) -- the merge must
    # pair arguments by param_index, not by id, to reproduce the single-run bindings.
    shard.add_node({"id": "callee", "kind": "function", "label": "add",
                    "properties": {"file": "callee.h", "language": "c"}})
    shard.add_node(_param_node("zzz_p0", index=0))
    shard.add_node(_param_node("aaa_p1", index=1))
    shard.add_edge(_edge("DECLARES_VALUE", "callee", "zzz_p0"))
    shard.add_edge(_edge("DECLARES_VALUE", "callee", "aaa_p1"))


def test_cross_shard_call_binding_is_rebuilt_by_param_index(tmp_path):
    # Call site and callee in separate shards -- the frontend never paired them.
    root = tmp_path / "shards"
    shard_set = ShardSetWriter(root, frontend_id="clang-c")
    caller = shard_set.start("0")
    _call_shard(caller)
    shard_set.complete("0", caller)
    callee = shard_set.start("1")
    _callee_shard(callee)
    shard_set.complete("1", callee)

    db_dir = write_kuzu_shards(
        ShardSetReader(root / "shards.pb"), str(tmp_path / "out.kuzu"))

    # position 0 -> param_index 0 (zzz_p0), position 1 -> param_index 1 (aaa_p1).
    expected = [("arg0", "zzz_p0"), ("arg1", "aaa_p1")]
    assert _typed_edges(db_dir, "ARGUMENT_BINDS_PARAMETER") == expected
    # The paired dataflow edge is emitted alongside each binding.
    flows = _value_flows(db_dir)
    assert ("arg0", "zzz_p0") in flows and ("arg1", "aaa_p1") in flows


def test_same_shard_call_binding_is_not_duplicated(tmp_path):
    # Call site and callee in one shard: the frontend already emitted the bindings,
    # so the merge must not add a second copy.
    root = tmp_path / "shards"
    shard_set = ShardSetWriter(root, frontend_id="clang-c")
    shard = shard_set.start("0")
    _call_shard(shard)
    _callee_shard(shard)
    shard.add_edge(_edge("ARGUMENT_BINDS_PARAMETER", "arg0", "zzz_p0",
                         position=0, callsite="call"))
    shard.add_edge(_edge("ARGUMENT_BINDS_PARAMETER", "arg1", "aaa_p1",
                         position=1, callsite="call"))
    shard.add_edge(_edge("VALUE_FLOWS_TO", "arg0", "zzz_p0",
                         reason="call-argument", callsite="call"))
    shard.add_edge(_edge("VALUE_FLOWS_TO", "arg1", "aaa_p1",
                         reason="call-argument", callsite="call"))
    shard_set.complete("0", shard)

    db_dir = write_kuzu_shards(
        ShardSetReader(root / "shards.pb"), str(tmp_path / "out.kuzu"))

    assert _typed_edges(db_dir, "ARGUMENT_BINDS_PARAMETER") == [
        ("arg0", "zzz_p0"), ("arg1", "aaa_p1")]
    assert _value_flows(db_dir) == [("arg0", "zzz_p0"), ("arg1", "aaa_p1")]
