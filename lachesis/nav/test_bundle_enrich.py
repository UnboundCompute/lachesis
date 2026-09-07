from __future__ import annotations

import sys
import tempfile
import types
import unittest
from unittest.mock import patch

from . import bundle_enrich
from .graph_store import GraphStore


class _FakeEmbedding:
    """Two separable clusters: 'config/parse/load' vs 'render/template/page'.

    Enough signal for the enrichment maths to produce meaningful neighbours,
    module coherence and facet tags without a real model.
    """

    def __init__(self, **kwargs):
        pass

    def embed(self, documents, **_kwargs):
        for document in documents:
            text = document.casefold()
            a = float(any(t in text for t in ("config", "parse", "load", "setting")))
            b = float(any(t in text for t in ("render", "template", "page", "markup")))
            yield [a, b, 0.1]


def _store() -> GraphStore:
    nodes = [
        {"id": "parse", "kind": "function", "label": "parseConfig",
         "properties": {"file": "src/config.py", "start_line": 2}},
        {"id": "load", "kind": "function", "label": "loadConfig",
         "properties": {"file": "src/config.py", "start_line": 8}},
        {"id": "render", "kind": "function", "label": "renderTemplate",
         "properties": {"file": "src/view.py", "start_line": 3}},
        {"id": "page", "kind": "function", "label": "renderPage",
         "properties": {"file": "src/view.py", "start_line": 9}},
    ]
    return GraphStore({"nodes": nodes, "edges": []})


def _bundle_objects():
    nodes = [
        {"id": "parse", "label": "parseConfig", "kind": "function",
         "file": "src/config.py", "module": "config"},
        {"id": "load", "label": "loadConfig", "kind": "function",
         "file": "src/config.py", "module": "config"},
        {"id": "render", "label": "renderTemplate", "kind": "function",
         "file": "src/view.py", "module": "view"},
        {"id": "page", "label": "renderPage", "kind": "function",
         "file": "src/view.py", "module": "view"},
    ]
    modules = [
        {"id": "module.config", "name": "config",
         "node_ids": ["parse", "load"], "definition_count": 2},
        {"id": "module.view", "name": "view",
         "node_ids": ["render", "page"], "definition_count": 2},
    ]
    concepts = [
        {"id": "concept.config", "label": "config",
         "node_ids": ["parse", "load"]},
    ]
    return nodes, modules, concepts


class BundleEnrichTests(unittest.TestCase):
    def test_missing_model_is_a_silent_no_op(self):
        # No runtime -> the pass adds nothing and returns None, so the bundle ships
        # exactly as the structural projection built it.
        nodes, modules, concepts = _bundle_objects()
        with patch("lachesis.nav.concept.importlib.util.find_spec", return_value=None):
            overlay = bundle_enrich.enrich(_store(), nodes, modules, concepts, [])
        self.assertIsNone(overlay)
        self.assertNotIn("related", nodes[0])
        self.assertNotIn("semantic_label", modules[0])

    def test_enrichment_decorates_structure_in_place(self):
        fake_module = types.SimpleNamespace(TextEmbedding=_FakeEmbedding)
        nodes, modules, concepts = _bundle_objects()
        with tempfile.TemporaryDirectory() as directory, \
                patch.dict(sys.modules, {"fastembed": fake_module}), \
                patch("lachesis.nav.concept.importlib.util.find_spec",
                      return_value=object()), \
                patch.dict("os.environ", {"LACHESIS_CONCEPT_CACHE": directory}):
            from .concept import download_model
            download_model()
            overlay = bundle_enrich.enrich(_store(), nodes, modules, concepts, [])

        # Top-level overlay shape.
        self.assertIsNotNone(overlay)
        self.assertEqual(3, overlay["dimensions"])
        self.assertEqual(4, overlay["coverage"]["vector_nodes"])
        self.assertIn("near_duplicates", overlay)
        self.assertIn("reading_order", overlay)
        self.assertEqual({"module.config", "module.view"},
                         set(overlay["reading_order"]))

        # Per-node: neighbours are attached, and the nearest neighbour of a config
        # function is the *other* config function, not a view function -- meaning,
        # not spelling, drives the ordering.
        by_id = {n["id"]: n for n in nodes}
        self.assertTrue(by_id["parse"].get("related"))
        self.assertEqual("load", by_id["parse"]["related"][0]["id"])
        self.assertTrue(all("xy" in n for n in nodes))

        # Per-module: a semantic label and a coherence score, and the two coherent
        # single-concern modules cohere strongly.
        config_module = next(m for m in modules if m["id"] == "module.config")
        self.assertIn(config_module.get("semantic_label"), {"parseConfig", "loadConfig"})
        self.assertGreater(config_module["coherence"], 0.9)

        # Per-concept: a coherence score is recorded.
        self.assertIn("coherence", concepts[0])

    def test_overlay_is_json_serialisable(self):
        import json
        fake_module = types.SimpleNamespace(TextEmbedding=_FakeEmbedding)
        nodes, modules, concepts = _bundle_objects()
        with tempfile.TemporaryDirectory() as directory, \
                patch.dict(sys.modules, {"fastembed": fake_module}), \
                patch("lachesis.nav.concept.importlib.util.find_spec",
                      return_value=object()), \
                patch.dict("os.environ", {"LACHESIS_CONCEPT_CACHE": directory}):
            from .concept import download_model
            download_model()
            overlay = bundle_enrich.enrich(_store(), nodes, modules, concepts, [])
        # No numpy scalars leak into the artifact (they would break json.dumps).
        json.dumps({"enrichment": overlay, "nodes": nodes, "modules": modules,
                    "concepts": concepts})


if __name__ == "__main__":
    unittest.main()
