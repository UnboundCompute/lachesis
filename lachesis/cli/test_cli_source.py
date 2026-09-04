"""Tests for ``lachesis.cli.source`` -- the local-path/remote-URL scan resolver.

These cover the pure logic (spec detection, ``#subdir`` fragment handling, local
passthrough, and failure cleanup) without hitting the network. The one live-clone
path is exercised end-to-end by the CLI scan tests; here we only guarantee that a
failed fetch raises and leaves no temp directory behind, using a bogus URL that
git rejects offline.
"""
from __future__ import annotations

import glob
import tempfile
import unittest
from pathlib import Path

from lachesis.cli.source import (ResolvedSource, is_remote_spec, resolve_source,
                                 _split_fragment)


class DetectionTests(unittest.TestCase):
    def test_remote_specs(self):
        for spec in [
            "https://github.com/org/repo",
            "http://x/y",
            "https://github.com/org/repo.git",
            "git@github.com:org/repo.git",
            "git@github.com:org/repo",
            "git://host/repo.git",
            "ssh://git@host/repo.git",
            "https://github.com/microsoft/playwright#packages/x/src",
        ]:
            self.assertTrue(is_remote_spec(spec), spec)

    def test_local_specs(self):
        for spec in [
            None, "", ".", "/abs/path", "~/rel", "./sub", "relative/dir",
            "C:\\Users\\me\\proj",   # Windows drive, not scp-like
            "my#weird/localdir",     # '#' but no transport
            "repo.git",              # bare name, no host/slash -> local dir
        ]:
            self.assertFalse(is_remote_spec(spec), repr(spec))


class FragmentTests(unittest.TestCase):
    def test_no_fragment(self):
        self.assertEqual(_split_fragment("https://h/r"), ("https://h/r", None))

    def test_plain_fragment(self):
        self.assertEqual(_split_fragment("https://h/r#a/b"), ("https://h/r", "a/b"))

    def test_fragment_normalised(self):
        # leading/trailing slashes and '.' segments are stripped
        self.assertEqual(_split_fragment("https://h/r#/a//b/./"), ("https://h/r", "a/b"))

    def test_parent_escape_rejected(self):
        with self.assertRaises(ValueError):
            _split_fragment("https://h/r#../etc")


class LocalPassthroughTests(unittest.TestCase):
    def test_resolves_in_place_with_noop_cleanup(self):
        rs = resolve_source(".")
        self.assertIsInstance(rs, ResolvedSource)
        self.assertFalse(rs.remote)
        self.assertEqual(rs.path, Path(".").resolve())
        rs.cleanup()  # must not raise

    def test_none_becomes_cwd(self):
        self.assertEqual(resolve_source(None).path, Path(".").resolve())

    def test_context_manager(self):
        with resolve_source("~") as rs:
            self.assertEqual(rs.path, Path("~").expanduser().resolve())


class FailureCleanupTests(unittest.TestCase):
    def test_failed_fetch_raises_and_leaves_no_temp(self):
        pattern = tempfile.gettempdir() + "/lachesis-src-*"
        before = set(glob.glob(pattern))
        with self.assertRaises(RuntimeError):
            # A syntactically valid URL that resolves to nothing; git fails fast
            # offline. GIT_TERMINAL_PROMPT=0 (set inside the resolver) keeps it
            # from blocking on a credential prompt.
            resolve_source("https://github.com/this-org-does-not/exist-xyz-404.git")
        leaked = set(glob.glob(pattern)) - before
        self.assertEqual(leaked, set(), f"leaked temp dirs: {leaked}")


if __name__ == "__main__":
    unittest.main()
