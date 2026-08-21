from . import graph_wire


def test_write_tier_property_cache_preserves_uncached_bytes(tmp_path):
    payload = {
        "tier": "T1", "name": "reachability",
        "nodes": [
            {"id": "n0", "kind": "function", "label": "f",
             "properties": {"confidence": "exact", "evidence_ids": [],
                            "fact_origin": "compiler", "via": "DECLARES"}},
            {"id": "n1", "kind": "variable", "label": "x",
             "properties": {"confidence": "exact", "file": "x.c",
                            "start_line": 4}},
        ],
        "edges": [{"kind": "CALLS", "source": "n0", "target": "n1",
                   "properties": {"confidence": "exact", "evidence_ids": [],
                                  "fact_origin": "compiler"}}],
        "expands_to": [], "links": [],
    }
    cached_path = tmp_path / "cached.pb"
    graph_wire.write_tier(cached_path, payload)

    uncached_path = tmp_path / "uncached.pb"
    with uncached_path.open("wb") as handle:
        handle.write(graph_wire._field_bytes(1, b"T1"))
        handle.write(graph_wire._field_bytes(2, b"reachability"))
        for node in payload["nodes"]:
            handle.write(graph_wire._field_bytes(3, graph_wire.encode_node(node)))
        for edge in payload["edges"]:
            handle.write(graph_wire._field_bytes(4, graph_wire.encode_edge(edge)))

    assert cached_path.read_bytes() == uncached_path.read_bytes()
