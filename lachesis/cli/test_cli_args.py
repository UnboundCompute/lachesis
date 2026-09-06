import json
import tempfile
import unittest
from pathlib import Path


from lachesis.cli.main import _load_curated_tour, build_parser


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
