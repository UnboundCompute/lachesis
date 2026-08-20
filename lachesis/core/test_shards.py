import json

from .shards import ShardReader, write_snapshot_shard


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
