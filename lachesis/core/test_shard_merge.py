from .shard_merge import ShardMerger
from .shards import ShardSetReader, ShardSetWriter


def test_shard_merger_deduplicates_and_streams(tmp_path):
    shard_root = tmp_path / "shards"
    shard_set = ShardSetWriter(shard_root, frontend_id="fixture")
    first = shard_set.start("0")
    first.add_node({"id": "n", "kind": "file", "label": "n"})
    first.add_edge({"kind": "CALLS", "source": "n", "target": "m"})
    shard_set.complete("0", first)
    second = shard_set.start("1")
    second.add_node({"id": "n", "kind": "file", "label": "n"})
    second.add_node({"id": "m", "kind": "function", "label": "m"})
    second.add_edge({"kind": "CALLS", "source": "n", "target": "m"})
    shard_set.complete("1", second)

    with ShardMerger(tmp_path / "merge.sqlite") as merger:
        merger.ingest(ShardSetReader(shard_root / "shards.json"))
        assert merger.counts() == (2, 1)
        assert [node["id"] for node in merger.iter_nodes()] == ["m", "n"]
        assert list(merger.iter_edges())[0]["kind"] == "CALLS"
