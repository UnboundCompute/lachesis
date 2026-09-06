import os
import tempfile
import unittest
from pathlib import Path

from lachesis.pipeline import source_inventory


class SourceInventoryTests(unittest.TestCase):
    def test_external_file_symlinks_are_not_analyzed(self):
        with tempfile.TemporaryDirectory() as project, tempfile.TemporaryDirectory() as outside:
            root = Path(project)
            external = Path(outside) / "outside.py"
            external.write_text("def external():\n    return 1\n", encoding="utf-8")
            (root / "inside.py").write_text("def inside():\n    return 1\n", encoding="utf-8")
            link = root / "linked.py"
            try:
                link.symlink_to(external)
            except (OSError, NotImplementedError):
                self.skipTest("file symlinks are unavailable")

            files = {os.path.relpath(path, root) for path in source_inventory(str(root))}
            self.assertIn("inside.py", files)
            self.assertNotIn("linked.py", files)

    def test_empty_include_paths_is_the_historical_inventory(self):
        with tempfile.TemporaryDirectory() as project:
            root = Path(project)
            (root / "a.py").write_text("def a():\n    return 1\n", encoding="utf-8")
            (root / "b.py").write_text("def b():\n    return 2\n", encoding="utf-8")
            self.assertEqual(source_inventory(str(root)),
                             source_inventory(str(root), include_paths=[]))

    def test_include_folds_in_a_file_outside_the_scope(self):
        with tempfile.TemporaryDirectory() as project, tempfile.TemporaryDirectory() as outside:
            scope = Path(project) / "pkg_a"
            scope.mkdir()
            (scope / "mod.py").write_text("def a():\n    return 1\n", encoding="utf-8")
            advisory = Path(outside) / "vuln.py"
            advisory.write_text("import os\ndef v(x):\n    os.system(x)\n", encoding="utf-8")

            base = source_inventory(str(scope))
            widened = source_inventory(str(scope), include_paths=[str(advisory)])
            # the scope is preserved and the out-of-scope advisory file is guaranteed in
            self.assertTrue(set(base).issubset(set(widened)))
            self.assertIn(str(advisory.resolve()),
                          {os.path.realpath(p) for p in widened})

    def test_include_walks_a_directory_and_dedupes_the_scope(self):
        with tempfile.TemporaryDirectory() as project, tempfile.TemporaryDirectory() as outside:
            scope = Path(project) / "pkg_a"
            scope.mkdir()
            (scope / "mod.py").write_text("def a():\n    return 1\n", encoding="utf-8")
            other = Path(outside) / "sub"
            other.mkdir()
            (other / "helper.py").write_text("def h():\n    return 2\n", encoding="utf-8")

            widened = source_inventory(str(scope), include_paths=[str(other)])
            self.assertIn(str((other / "helper.py").resolve()),
                          {os.path.realpath(p) for p in widened})
            # including the scope itself again must not duplicate any file
            deduped = source_inventory(str(scope), include_paths=[str(scope)])
            self.assertEqual(len(deduped), len(source_inventory(str(scope))))

    def test_explicit_file_survives_the_test_path_heuristic(self):
        with tempfile.TemporaryDirectory() as project, tempfile.TemporaryDirectory() as outside:
            scope = Path(project) / "pkg_a"
            scope.mkdir()
            (scope / "mod.py").write_text("def a():\n    return 1\n", encoding="utf-8")
            test_file = Path(outside) / "test_vuln.py"
            test_file.write_text("def v():\n    return 1\n", encoding="utf-8")
            # include_tests=False drops discovered test-looking files, but an explicitly
            # named file is the caller's deliberate choice and must not be vetoed.
            kept = source_inventory(str(scope), include_tests=False,
                                    include_paths=[str(test_file)])
            self.assertIn(str(test_file.resolve()),
                          {os.path.realpath(p) for p in kept})

    def _tree(self, root: Path) -> None:
        (root / "src" / "pkg").mkdir(parents=True)
        (root / "tests").mkdir()
        (root / "examples").mkdir()
        (root / "docs").mkdir()
        (root / "src" / "pkg" / "app.py").write_text("def a():\n    return 1\n", "utf-8")
        # A product module whose name merely contains a keyword must survive.
        (root / "src" / "pkg" / "testing.py").write_text("def t():\n    return 1\n", "utf-8")
        (root / "tests" / "test_app.py").write_text("def test():\n    pass\n", "utf-8")
        (root / "examples" / "demo.py").write_text("def d():\n    return 1\n", "utf-8")
        (root / "docs" / "conf.py").write_text("x = 1\n", "utf-8")
        (root / "conftest.py").write_text("import pytest\n", "utf-8")

    def test_path_filter_drops_nonproduct_by_default(self):
        from lachesis.config import Config
        with tempfile.TemporaryDirectory() as project:
            root = Path(project)
            self._tree(root)
            kept = {os.path.relpath(p, root)
                    for p in source_inventory(str(root), path_filter=Config().build.paths)}
            self.assertEqual(kept, {os.path.join("src", "pkg", "app.py"),
                                    os.path.join("src", "pkg", "testing.py")})

    def test_no_path_filter_keeps_everything(self):
        with tempfile.TemporaryDirectory() as project:
            root = Path(project)
            self._tree(root)
            kept = {os.path.relpath(p, root) for p in source_inventory(str(root))}
            self.assertIn("conftest.py", kept)
            self.assertIn(os.path.join("tests", "test_app.py"), kept)

    def test_content_hash_tracks_the_filtered_set(self):
        # The cache-validity key must describe exactly the file set the build sees, or a
        # filtered build could hit a stale cache written by an unfiltered one.
        from lachesis.config import Config
        from lachesis.pipeline import source_content_hash
        with tempfile.TemporaryDirectory() as project:
            root = Path(project)
            self._tree(root)
            unfiltered = source_content_hash(str(root))
            filtered = source_content_hash(str(root), path_filter=Config().build.paths)
            self.assertNotEqual(unfiltered, filtered)


if __name__ == "__main__":
    unittest.main()
