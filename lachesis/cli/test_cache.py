from __future__ import annotations

import argparse
import contextlib
import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lachesis.cache import entry_for
from lachesis.cli.main import command_cache, build_parser


class CachePruneTests(unittest.TestCase):
    def test_clear_all_requires_explicit_confirmation(self) -> None:
        with tempfile.TemporaryDirectory() as cache_dir:
            old_value = os.environ.get("LACHESIS_CACHE_DIR")
            os.environ["LACHESIS_CACHE_DIR"] = cache_dir
            try:
                args = argparse.Namespace(cache_action="clear", path=None, all=False)
                with contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(command_cache(args), 2)
                self.assertTrue(Path(cache_dir).exists())
            finally:
                if old_value is None:
                    os.environ.pop("LACHESIS_CACHE_DIR", None)
                else:
                    os.environ["LACHESIS_CACHE_DIR"] = old_value

    def test_clear_all_removes_the_cache(self) -> None:
        with tempfile.TemporaryDirectory() as cache_dir:
            old_value = os.environ.get("LACHESIS_CACHE_DIR")
            os.environ["LACHESIS_CACHE_DIR"] = cache_dir
            try:
                Path(cache_dir, "entry").mkdir(parents=True)
                Path(cache_dir, "entry", "data").write_bytes(b"cache")
                args = argparse.Namespace(cache_action="clear", path=None, all=True)
                with contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(command_cache(args), 0)
                self.assertFalse(Path(cache_dir).exists())
            finally:
                if old_value is None:
                    os.environ.pop("LACHESIS_CACHE_DIR", None)
                else:
                    os.environ["LACHESIS_CACHE_DIR"] = old_value

    def test_prune_is_dry_run_until_apply(self) -> None:
        with tempfile.TemporaryDirectory() as cache_dir:
            source = Path(cache_dir).parent / "source-that-is-gone"
            old_value = os.environ.get("LACHESIS_CACHE_DIR")
            os.environ["LACHESIS_CACHE_DIR"] = cache_dir
            try:
                entry = entry_for(source)
                entry.directory.mkdir(parents=True)
                entry.graph_path.write_bytes(b"graph")
                entry.write_meta("hash")

                dry_run = argparse.Namespace(
                    cache_action="prune", older_than=30.0, apply=False
                )
                with contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(command_cache(dry_run), 0)
                self.assertTrue(entry.directory.exists())

                apply = argparse.Namespace(
                    cache_action="prune", older_than=30.0, apply=True
                )
                with contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(command_cache(apply), 0)
                self.assertFalse(entry.directory.exists())
            finally:
                if old_value is None:
                    os.environ.pop("LACHESIS_CACHE_DIR", None)
                else:
                    os.environ["LACHESIS_CACHE_DIR"] = old_value

    def test_prune_defaults_to_dry_run(self) -> None:
        args = build_parser().parse_args(["cache", "prune"])
        self.assertFalse(args.apply)
        self.assertEqual(args.older_than, 30.0)

    def test_clear_all_reports_filesystem_failure(self) -> None:
        with tempfile.TemporaryDirectory() as cache_dir:
            old_value = os.environ.get("LACHESIS_CACHE_DIR")
            os.environ["LACHESIS_CACHE_DIR"] = cache_dir
            try:
                Path(cache_dir, "entry").mkdir()
                args = argparse.Namespace(cache_action="clear", path=None, all=True)
                with patch("lachesis.cli.main.shutil.rmtree", side_effect=OSError("read-only")), \
                     contextlib.redirect_stderr(io.StringIO()) as output:
                    self.assertEqual(command_cache(args), 4)
                self.assertIn("could not remove cached indexes", output.getvalue())
            finally:
                if old_value is None:
                    os.environ.pop("LACHESIS_CACHE_DIR", None)
                else:
                    os.environ["LACHESIS_CACHE_DIR"] = old_value


if __name__ == "__main__":
    unittest.main()
