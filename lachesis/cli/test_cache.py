from __future__ import annotations

import argparse
import contextlib
import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lachesis.cache import build_options_fingerprint, entry_for
from lachesis.cli.main import command_cache, build_parser
from lachesis.core.contract import FrontendSpec
from lachesis.pipeline import _frontend_fingerprint


class CachePruneTests(unittest.TestCase):
    def test_frontend_binary_change_invalidates_fingerprint(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory, "frontend")
            executable.write_bytes(b"compiler-v1")
            frontend = FrontendSpec(
                frontend_id="compiler",
                languages=("c",), extensions=(".c",),
                command=(str(executable), "{source_dir}", "{output_dir}"),
                working_directory=directory,
            )
            original = _frontend_fingerprint(frontend)
            executable.write_bytes(b"compiler-v2")
            self.assertNotEqual(_frontend_fingerprint(frontend), original)

    def test_output_build_options_invalidate_cached_graph(self) -> None:
        with tempfile.TemporaryDirectory() as cache_dir, patch.dict(
            os.environ, {"LACHESIS_EMIT_TOKENS": "1"}, clear=False
        ):
            old_value = os.environ.get("LACHESIS_CACHE_DIR")
            os.environ["LACHESIS_CACHE_DIR"] = cache_dir
            try:
                entry = entry_for(Path(cache_dir, "source"))
                entry.graph_path.parent.mkdir(parents=True)
                entry.graph_path.write_bytes(b"graph")
                entry.write_meta("hash")
                self.assertEqual(entry.status("hash"), "fresh")
                original = build_options_fingerprint()

                os.environ["LACHESIS_EMIT_TOKENS"] = "0"
                self.assertNotEqual(build_options_fingerprint(), original)
                self.assertEqual(entry.status("hash"), "stale")
            finally:
                if old_value is None:
                    os.environ.pop("LACHESIS_CACHE_DIR", None)
                else:
                    os.environ["LACHESIS_CACHE_DIR"] = old_value

    def test_build_lock_is_stable_and_outside_cache(self) -> None:
        entry = entry_for("/tmp/example-project")
        self.assertNotEqual(entry.lock_path.parent, entry.directory.parent)
        with entry.build_lock():
            self.assertTrue(entry.lock_path.exists())

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
                entry = entry_for(Path(cache_dir, "source"))
                entry.write_meta("hash")
                entry.graph_path.write_bytes(b"cache")
                args = argparse.Namespace(cache_action="clear", path=None, all=True)
                with contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(command_cache(args), 0)
                self.assertFalse(Path(cache_dir).exists())
            finally:
                if old_value is None:
                    os.environ.pop("LACHESIS_CACHE_DIR", None)
                else:
                    os.environ["LACHESIS_CACHE_DIR"] = old_value

    def test_clear_all_preserves_unrecognized_files(self) -> None:
        with tempfile.TemporaryDirectory() as cache_dir:
            old_value = os.environ.get("LACHESIS_CACHE_DIR")
            os.environ["LACHESIS_CACHE_DIR"] = cache_dir
            try:
                entry = entry_for(Path(cache_dir, "source"))
                entry.write_meta("hash")
                entry.graph_path.write_bytes(b"cache")
                Path(cache_dir, "do-not-delete.txt").write_text("keep")
                args = argparse.Namespace(cache_action="clear", path=None, all=True)
                with contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(command_cache(args), 0)
                self.assertTrue(Path(cache_dir, "do-not-delete.txt").exists())
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
                entry = entry_for(Path(cache_dir, "source"))
                entry.write_meta("hash")
                entry.graph_path.write_bytes(b"cache")
                args = argparse.Namespace(cache_action="clear", path=None, all=True)
                with patch("lachesis.cache.shutil.rmtree", side_effect=OSError("read-only")), \
                     contextlib.redirect_stderr(io.StringIO()) as output:
                    self.assertEqual(command_cache(args), 1)
                self.assertIn("could not remove", output.getvalue())
            finally:
                if old_value is None:
                    os.environ.pop("LACHESIS_CACHE_DIR", None)
                else:
                    os.environ["LACHESIS_CACHE_DIR"] = old_value


if __name__ == "__main__":
    unittest.main()
