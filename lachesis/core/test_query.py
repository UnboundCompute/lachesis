from .query import GraphIndex


def test_compact_index_matches_ecosystem_queries():
    graph = {
        "nodes": [
            {"id": "pkg", "kind": "package", "label": "demo",
             "properties": {"package_name": "demo"}},
            {"id": "fn", "kind": "function", "label": "run",
             "properties": {}},
            {"id": "arg", "kind": "argument", "label": "input",
             "properties": {}},
        ],
        "edges": [
            {"kind": "PASSES_CALLBACK", "source": "arg", "target": "fn",
             "properties": {}},
            {"kind": "EXPORTS", "source": "pkg", "target": "fn",
             "properties": {}},
        ],
    }
    full = GraphIndex(graph)
    compact = GraphIndex(graph, compact=True)

    assert compact.package_inventory() == full.package_inventory()
    assert list(compact.nodes_of_kind("package", "function")) == list(
        full.nodes_of_kind("package", "function")
    )
    assert list(compact.targets("arg", "PASSES_CALLBACK")) == list(
        full.targets("arg", "PASSES_CALLBACK")
    )
    assert list(compact.edges_of_kind("EXPORTS")) == list(
        full.edges_of_kind("EXPORTS")
    )
    assert compact.nodes.get("fn") == full.nodes.get("fn")
