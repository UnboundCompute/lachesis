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


if __name__ == "__main__":
    unittest.main()
