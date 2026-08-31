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

kuzu = pytest.importorskip("kuzu")

from .kuzu_store import db_file, write_kuzu_shards  # noqa: E402


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
