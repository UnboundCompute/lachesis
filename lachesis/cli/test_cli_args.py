import json
import tempfile
import unittest
from pathlib import Path


from lachesis.cli.main import _load_curated_tour, _resolved, build_parser


class CliArgumentTests(unittest.TestCase):
    def test_source_commands_accept_positive_timeout(self):
        parser = build_parser()
        for command in ("scan", "mcp"):
            with self.subTest(command=command):
                args = parser.parse_args([command, "--timeout", "7"])
                self.assertEqual(args.timeout, 7)

    def test_source_commands_reject_non_positive_timeout(self):
        parser = build_parser()
        for command in ("scan", "mcp"):
            for value in ("0", "-1"):
                with self.subTest(command=command, value=value):
                    with self.assertRaises(SystemExit) as raised:
                        parser.parse_args([command, "--timeout", value])
                    self.assertEqual(raised.exception.code, 2)

    def test_scan_rejects_invalid_limits_and_ranks(self):
        parser = build_parser()
        for option, value in (("--limit", "-1"), ("--entrypoints", "-1"),
                              ("--min-rank", "-0.1"), ("--min-rank", "1.1")):
            with self.subTest(option=option, value=value):
                with self.assertRaises(SystemExit) as raised:
                    parser.parse_args(["scan", option, value])
                    self.assertEqual(raised.exception.code, 2)

    def test_trace_repo_flag_is_not_clobbered_by_positional_default(self):
        # Regression: ``--repo`` once shared ``dest`` with the ``nargs="?"``
        # positional, so an absent positional overwrote the flag with its default
        # and the requested tree was silently replaced by the current directory.
        parser = build_parser()
        flagged = parser.parse_args(["trace", "--repo", "/abs/requested/tree"])
        self.assertEqual(_resolved(flagged.repo_opt or flagged.repo),
                         Path("/abs/requested/tree"))
        positional = parser.parse_args(["trace", "/positional/tree"])
        self.assertEqual(_resolved(positional.repo_opt or positional.repo),
                         Path("/positional/tree"))
        bare = parser.parse_args(["trace"])
        self.assertEqual(_resolved(bare.repo_opt or bare.repo), Path.cwd())

    def test_trace_repo_flag_reads_only_the_requested_tree(self):
        # End-to-end isolation: pointed at a small temp Python repo via --repo from
        # an unrelated cwd, the resolved source is the temp tree, and a source
        # inventory over it references only files under that tree -- never cwd's.
        from lachesis.pipeline import source_inventory
        parser = build_parser()
        with tempfile.TemporaryDirectory() as requested, \
                tempfile.TemporaryDirectory() as elsewhere:
            (Path(requested) / "app.py").write_text(
                "def handler(request):\n    return request\n", encoding="utf-8")
            (Path(elsewhere) / "other.py").write_text(
                "def unrelated():\n    return 1\n", encoding="utf-8")
            cwd = Path.cwd()
            try:
                import os
                os.chdir(elsewhere)
                args = parser.parse_args(["trace", "--repo", requested])
                source = _resolved(args.repo_opt or args.repo)
                self.assertEqual(source, Path(requested).resolve())
                files = [str(p) for p in source_inventory(str(source))]
            finally:
                os.chdir(cwd)
        resolved_requested = str(Path(requested).resolve())
        resolved_elsewhere = str(Path(elsewhere).resolve())
        self.assertTrue(files, "inventory found no source under the requested tree")
        self.assertTrue(all(f.startswith(resolved_requested) for f in files), files)
        self.assertFalse(any(f.startswith(resolved_elsewhere) for f in files), files)

    def test_curated_tour_argument_and_loader_strip_unverified_identity(self):
        args = build_parser().parse_args(["trace", "--curated-tour", "lachesis-tour.json"])
        self.assertEqual(args.curated_tour, "lachesis-tour.json")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "tour.json"
            path.write_text(json.dumps({"meta": {"curated_tour": {
                "id": "tour.start", "title": "Start here",
                "maintainer": {"name": "Untrusted", "verified": True},
                "steps": [{"flow_id": "request.main"}],
            }}}), encoding="utf-8")
            loaded = _load_curated_tour(str(path))
        self.assertNotIn("maintainer", loaded)
        self.assertEqual("tour.start", loaded["id"])


if __name__ == "__main__":
    unittest.main()
