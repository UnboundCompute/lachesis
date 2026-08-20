from ..core.composition import GraphDelta, compose
from ..core.query import GraphIndex
from .registry import EcosystemRegistry


class _Model:
    model_id = "test-model"
    supported_languages = ("c",)
    required_capabilities = ()

    def applies(self, graph, package_inventory):
        return "demo" in package_inventory

    def enrich(self, graph, index=None):
        assert index is not None
        assert list(index.nodes_of_kind("package"))
        return GraphDelta(
            self.model_id,
            nodes=[{"id": "derived", "kind": "fact", "label": "derived",
                    "properties": {}}],
            edges=[{"kind": "DERIVES", "source": "pkg", "target": "derived",
                    "properties": {}}],
        )


def test_ecosystem_accumulator_matches_composition_contract():
    graph = {
        "nodes": [{"id": "pkg", "kind": "package", "label": "demo",
                   "properties": {"package_name": "demo"}}],
        "edges": [],
    }
    registry = EcosystemRegistry()
    registry.register(_Model())
    actual = registry.enrich(graph, ["demo"], ["c"], {})
    expected = compose([
        GraphDelta("canonical-input", graph["nodes"], graph["edges"]),
        _Model().enrich(graph, GraphIndex(graph)),
    ])
    assert actual == expected
