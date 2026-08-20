from __future__ import annotations

import sys
import tempfile
import types
import unittest
from unittest.mock import patch

from .concept import ConceptSearch, download_model, model_status, semantic_cards
from .graph_store import GraphStore


class _FakeEmbedding:
    calls = []

    def __init__(self, **kwargs):
        self.calls.append(kwargs)

    def embed(self, documents):
        for document in documents:
            text = document.casefold()
            yield [float("valid" in text or "untrusted" in text),
                   float("database" in text), 0.1]


def _store():
    nodes = [
        {"id": "validate", "kind": "function", "label": "validateInput",
         "properties": {"file": "src/input.py", "start_line": 2}},
        {"id": "query", "kind": "function", "label": "runDatabaseQuery",
         "properties": {"file": "src/db.py", "start_line": 5}},
    ]
    return GraphStore({"nodes": nodes, "edges": []})


class ConceptSearchTests(unittest.TestCase):
    def test_cli_exposes_explicit_status_and_download_actions(self):
        from lachesis.cli.main import build_parser
        parser = build_parser()
        self.assertEqual("status", parser.parse_args(["concept-model", "status"]).model_action)
        self.assertEqual("download", parser.parse_args(
            ["concept-model", "download"]).model_action)

    def test_core_import_has_no_fastembed_requirement(self):
        status = model_status()
        self.assertIn(status["runtime"], {"installed", "missing"})
        self.assertIn("concept-search", status["install"])
        self.assertEqual(2, len(semantic_cards(_store())))

    def test_missing_runtime_is_an_instruction_not_a_download(self):
        with patch("lachesis.nav.concept.importlib.util.find_spec", return_value=None):
            answer = ConceptSearch(_store()).search("input validation")
        self.assertEqual("concept-runtime-missing", answer["error"])
        self.assertIn("concept-model download", answer["download"])

    def test_explicit_download_then_offline_search_and_index_cache(self):
        fake_module = types.SimpleNamespace(TextEmbedding=_FakeEmbedding)
        with tempfile.TemporaryDirectory() as directory, \
                patch.dict(sys.modules, {"fastembed": fake_module}), \
                patch("lachesis.nav.concept.importlib.util.find_spec", return_value=object()), \
                patch.dict("os.environ", {"LACHESIS_CONCEPT_CACHE": directory}):
            _FakeEmbedding.calls.clear()
            downloaded = download_model()
            self.assertTrue(downloaded["model_ready"])
            self.assertFalse(_FakeEmbedding.calls[0]["local_files_only"])

            answer = ConceptSearch(_store()).search("validate untrusted input")
            self.assertEqual("validateInput", answer["results"][0]["name"])
            self.assertTrue(_FakeEmbedding.calls[1]["local_files_only"])

            first_page = ConceptSearch(_store()).search(
                "validate untrusted input", limit=1)
            second_page = ConceptSearch(_store()).search(
                "validate untrusted input", limit=1,
                offset=first_page["page"]["next_offset"],
            )
            self.assertTrue(first_page["page"]["has_more"])
            self.assertNotEqual(first_page["results"], second_page["results"])

            # A fresh query object loads the graph-vector cache but still opens the
            # model in offline-only mode; no embedding download path is re-entered.
            again = ConceptSearch(_store()).search("database query")
            self.assertEqual("runDatabaseQuery", again["results"][0]["name"])
            self.assertTrue(_FakeEmbedding.calls[2]["local_files_only"])


if __name__ == "__main__":
    unittest.main()
