from lachesis.projections.layered import (
    build_layered_graph,
    build_security_query_projection,
)
from lachesis.reasoning.query import ReasoningQuery


def _security_graph():
    return {
        "nodes": [
            {"id": "file:f", "kind": "file", "label": "app.c",
             "properties": {"file": "app.c", "absolute_file": "/repo/app.c"}},
            {"id": "fn:f", "kind": "function", "label": "handler",
             "properties": {"file": "app.c", "absolute_file": "/repo/app.c",
                            "start_line": 1}},
            {"id": "call:c", "kind": "call", "label": "sink()",
             "properties": {"owner_function_id": "fn:f", "file": "app.c",
                            "absolute_file": "/repo/app.c", "start_line": 3}},
            {"id": "source:s", "kind": "source", "label": "input",
             "properties": {"function_id": "fn:f", "file": "app.c",
                            "absolute_file": "/repo/app.c", "start_line": 2}},
            {"id": "sink:s", "kind": "sink", "label": "sink",
             "properties": {"callsite_id": "call:c", "sink_kind": "io"}},
            {"id": "reach:r", "kind": "taint-reach", "label": "input -> sink",
             "properties": {"source_id": "source:s", "sink_id": "sink:s",
                            "witness_ids": ["source:s", "call:c"]}},
        ],
        "edges": [
            {"kind": "CALLS", "source": "fn:f", "target": "call:c",
             "properties": {}},
        ],
    }


def test_security_projection_matches_full_security_query():
    graph = _security_graph()
    full = ReasoningQuery(
        graph, layered=build_layered_graph(graph),
    ).security_paths()
    reduced = ReasoningQuery(
        graph, layered=build_security_query_projection(graph),
    ).security_paths()
    assert reduced == full
