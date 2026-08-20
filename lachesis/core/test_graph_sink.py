from .graph_sink import MemoryGraphSink, ShardGraphSink
from .shards import ShardReader


def test_memory_sink_preserves_records():
    sink = MemoryGraphSink()
    sink.node({"id": "n"})
    sink.edge({"source": "n", "target": "n2"})
    sink.close()
    assert sink.nodes == [{"id": "n"}]
    assert sink.edges == [{"source": "n", "target": "n2"}]


def test_shard_sink_streams_records(tmp_path):
    sink = ShardGraphSink(str(tmp_path), frontend_id="fixture", shard_id="0")
    sink.node({"id": "n"})
    sink.edge({"source": "n", "target": "n2"})
    sink.close()
    reader = ShardReader(tmp_path)
    assert list(reader.nodes()) == [{"id": "n"}]
    assert list(reader.edges()) == [{"source": "n", "target": "n2"}]
