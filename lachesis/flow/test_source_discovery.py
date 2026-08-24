import unittest

from .source_discovery import discover_sources


class SourceDiscoveryTests(unittest.TestCase):
    def test_catalog_source_creates_launch_and_seam_binding(self):
        functions = {
            "handle": {"callers": [], "params": ("input",), "calls": [{
                "callee": "read_input", "node": "read", "line": 4,
                "assigned": "buf", "args": [{"pos": 0, "root": "fd"}],
            }, {"callee": "worker", "node": "call", "line": 5,
                "assigned": "out", "args": [{"pos": 0, "root": "buf"}]}]},
            "worker": {"callers": ["handle"], "params": ("value",), "calls": []},
        }
        result = discover_sources(functions, {"handle": ["worker"], "worker": []},
                                  {"read_input": {"kind": "user-input"}})
        self.assertEqual(result.launch_nodes["handle"], ("read",))
        self.assertEqual(result.launch_provenance["handle"], "catalog")
        self.assertEqual(result.sites[0].kind, "user-input")
        self.assertEqual(result.bindings[0].formal_to_actual, (("value", "buf"),))
        self.assertEqual(result.reachable_functions, {"handle", "worker"})
        self.assertIn("buf", result.influenced_roots["handle"])
        self.assertIn("value", result.influenced_roots["worker"])

    def test_empty_catalog_keeps_structural_entry_fallback(self):
        result = discover_sources({"main": {"callers": [], "params": (), "calls": []}},
                                  {"main": []})
        self.assertEqual(result.launch_nodes, {"main": ("__entry__",)})
        self.assertEqual(result.launch_provenance, {"main": "structural"})
        self.assertEqual(result.sites, ())


if __name__ == "__main__":
    unittest.main()
