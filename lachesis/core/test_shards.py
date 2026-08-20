import json

from .shards import (SHARD_FORMAT_VERSION, ShardReader, ShardSetReader,
                     ShardSetWriter, write_snapshot_shard)


def test_shards_round_trip_records_incrementally(tmp_path):
    nodes = ({"id": f"n{i}", "kind": "function", "properties": {"i": i}}
             for i in range(3))
    edges = ({"kind": "CALLS", "source": "n0", "target": f"n{i}"}
             for i in range(1, 3))
    counts = write_snapshot_shard(
        tmp_path, frontend_id="test", shard_id="0", nodes=nodes, edges=edges,
    )
    assert counts == {"nodes": 3, "edges": 2}
    reader = ShardReader(tmp_path)
    assert list(reader.nodes())[2]["id"] == "n2"
    assert list(reader.edges())[1]["target"] == "n2"
    manifest = json.loads((tmp_path / "manifest.json").read_text())
    assert manifest["shard_format_version"] == 1


def test_shard_set_skips_incomplete_work_and_orders_shards(tmp_path):
    for shard_id, value in (("1", "one"), ("0", "zero")):
        write_snapshot_shard(
            tmp_path / f"shard-{shard_id}", frontend_id="test", shard_id=shard_id,
            nodes=({"id": value} for _ in range(1)), edges=(),
        )
    (tmp_path / "shards.json").write_text(
        '{"shard_format_version": 1, "shards": ['
        '{"shard_id": "1", "directory": "shard-1", "status": "complete"},'
        '{"shard_id": "0", "directory": "shard-0", "status": "complete"},'
        '{"shard_id": "2", "directory": "missing", "status": "running"}]}'
    )
    reader = ShardSetReader(tmp_path / "shards.json")
    assert [node["id"] for node in reader.nodes()] == ["zero", "one"]


def test_shard_set_writer_marks_only_completed_work_reusable(tmp_path):
    shards = ShardSetWriter(tmp_path, frontend_id="test")
    writer = shards.start("0")
    writer.add_node({"id": "n"})
    shards.complete("0", writer)
    reader = ShardSetReader(tmp_path / "shards.json")
    assert list(reader.nodes()) == [{"id": "n"}]
    running = shards.start("1")
    running.add_node({"id": "not-yet-complete"})
    assert list(reader.nodes()) == [{"id": "n"}]
