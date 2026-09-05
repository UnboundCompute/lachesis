from . import graph_wire


def test_value_scrubs_lone_surrogate_instead_of_crashing():
    # A source string literal can carry an unpaired UTF-16 surrogate (a common
    # malformed-unicode test fixture). Proto ``string`` fields require valid
    # UTF-8, so a raw assignment would raise UnicodeEncodeError and abort the
    # whole build. The wire encoder must scrub the bad code point and keep the
    # surrounding text, so one bad char never loses the file or the repo.
    value = graph_wire._value("ab\ud800cd")
    assert value.text == "ab?cd"
    assert value.SerializeToString()  # round-trips as valid UTF-8


def test_value_preserves_real_astral_chars():
    # Genuine astral characters (stored as a single code point) are valid UTF-8
    # and must pass through untouched -- only lone surrogates are scrubbed.
    text = "hi \U00010000 \U0001f389"
    value = graph_wire._value(text)
    assert value.text == text


def test_encode_node_with_surrogate_property_does_not_raise():
    # End-to-end: a node whose property value holds a surrogate must encode
    # rather than crash the tier writer (regression for the python-sdk build).
    node = {"id": "n0", "kind": "constant", "label": "lit",
            "properties": {"value": "x\ud800y"}}
    assert graph_wire.encode_node(node)  # no UnicodeEncodeError


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
