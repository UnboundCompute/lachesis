"""Source-path remap for graphs built in one environment and read in another.

A graph built in a container records absolute build paths (``/src/...``) that do not
exist on the machine querying it. ``resolve_source_path`` bridges that gap so
``read_body``/``source_text`` return real offset text instead of falling back to the
degraded body-node reconstruction. When the source is already local, resolution is a
no-op and behaviour is unchanged.
"""
import os
import unittest
from pathlib import Path

from lachesis.nav.graphlib import _parse_source_map, resolve_source_path


class ResolveSourcePathTests(unittest.TestCase):
    def setUp(self):
        # A stand-in "local" tree; the recorded (build) path points elsewhere.
        self.root = Path(os.environ["PYTEST_TMP"]) if os.environ.get("PYTEST_TMP") else None
        self._saved = {k: os.environ.get(k) for k in ("LACHESIS_SOURCE_MAP", "LACHESIS_SOURCE_ROOT")}
        for k in self._saved:
            os.environ.pop(k, None)
        _parse_source_map.cache_clear()

    def tearDown(self):
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        _parse_source_map.cache_clear()

    def _tree(self, tmp):
        f = Path(tmp) / "lib" / "parse.c"
        f.parent.mkdir(parents=True)
        f.write_text("int main(void){return 0;}\n")
        return f

    def test_local_path_is_returned_unchanged(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            f = self._tree(tmp)
            self.assertEqual(resolve_source_path(str(f)), str(f))

    def test_missing_path_with_no_config_is_returned_unchanged(self):
        self.assertEqual(resolve_source_path("/src/lib/parse.c"),
                         "/src/lib/parse.c")

    def test_prefix_map_rewrites_container_path(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            self._tree(tmp)
            os.environ["LACHESIS_SOURCE_MAP"] = f"/src={tmp}"
            _parse_source_map.cache_clear()
            self.assertEqual(resolve_source_path("/src/lib/parse.c"),
                             str(Path(tmp) / "lib" / "parse.c"))

    def test_source_root_matches_longest_trailing_tail(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            self._tree(tmp)
            os.environ["LACHESIS_SOURCE_ROOT"] = tmp
            # container path carries an extra "/src" segment the root doesn't have;
            # the longest tail that exists (<root>/lib/parse.c) wins.
            self.assertEqual(resolve_source_path("/src/lib/parse.c"),
                             str(Path(tmp) / "lib" / "parse.c"))

    def test_map_takes_precedence_over_root(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            self._tree(tmp)
            os.environ["LACHESIS_SOURCE_MAP"] = f"/src={tmp}"
            os.environ["LACHESIS_SOURCE_ROOT"] = "/nonexistent"
            _parse_source_map.cache_clear()
            self.assertTrue(resolve_source_path("/src/lib/parse.c").startswith(tmp))

    def test_parse_source_map_ignores_malformed_chunks(self):
        self.assertEqual(_parse_source_map("garbage,,=,x="), ())
        self.assertEqual(_parse_source_map("/a=/b, /c/ = /d/ "), (("/a", "/b"), ("/c", "/d")))


if __name__ == "__main__":
    unittest.main()
