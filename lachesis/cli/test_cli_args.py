import unittest


from lachesis.cli.main import build_parser


class CliArgumentTests(unittest.TestCase):
    def test_source_commands_accept_positive_timeout(self):
        parser = build_parser()
        for command in ("scan", "index", "mcp"):
            with self.subTest(command=command):
                args = parser.parse_args([command, "--timeout", "7"])
                self.assertEqual(args.timeout, 7)

    def test_source_commands_reject_non_positive_timeout(self):
        parser = build_parser()
        for command in ("scan", "index", "mcp"):
            for value in ("0", "-1"):
                with self.subTest(command=command, value=value):
                    with self.assertRaises(SystemExit) as raised:
                        parser.parse_args([command, "--timeout", value])
                    self.assertEqual(raised.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
