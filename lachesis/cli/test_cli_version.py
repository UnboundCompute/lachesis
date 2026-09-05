import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class CliVersionTests(unittest.TestCase):
    def test_all_console_modules_report_version(self):
        modules = (
            "lachesis.cli.main",
            "lachesis.cli.analyze",
            "lachesis.cli.query",
            "lachesis.planner.cli",
            "lachesis.nav.mcp_server",
        )
        for module in modules:
            with self.subTest(module=module):
                result = subprocess.run(
                    [sys.executable, "-m", module, "--version"],
                    cwd=ROOT,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=20,
                )
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertTrue(result.stdout.strip(), result)


if __name__ == "__main__":
    unittest.main()
