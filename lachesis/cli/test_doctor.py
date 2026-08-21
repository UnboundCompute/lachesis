from __future__ import annotations

import sys
import unittest
from argparse import Namespace
from unittest.mock import patch

from lachesis.cli import doctor
import lachesis.cli.main as cli_main


class DoctorCompatibilityTests(unittest.TestCase):
    def test_inventory_failure_is_not_reported_as_success(self) -> None:
        report = [doctor.Check("python", True, "ok")]
        with patch.object(doctor, "full_report", return_value=report), \
             patch.object(doctor, "languages_present", side_effect=OSError("permission denied")):
            self.assertEqual(
                cli_main.command_doctor(Namespace(path=".")),
                cli_main.EXIT_FAILURE,
            )

    def test_python_floor_matches_package_support(self) -> None:
        with patch.object(sys, "version_info", (3, 10, 0, "final", 0)):
            report = doctor.full_report()

        python_check = next(check for check in report if check.name == "python")
        self.assertTrue(python_check.ok)

    def test_python_below_floor_is_actionable(self) -> None:
        with patch.object(sys, "version_info", (3, 9, 18, "final", 0)):
            report = doctor.full_report()

        python_check = next(check for check in report if check.name == "python")
        self.assertFalse(python_check.ok)
        self.assertEqual(python_check.fix, "lachesis needs Python 3.10 or newer")

    def test_node_floor_matches_documented_runtime(self) -> None:
        with patch.object(doctor.shutil, "which", return_value="/usr/bin/node"), \
             patch.object(doctor, "_version_of", return_value="v19.9.0"):
            old = doctor.check_node()
        self.assertFalse(old.ok)
        self.assertIn("need 20 or newer", old.detail)
        self.assertEqual(old.fix, "install Node.js 20 or newer: https://nodejs.org/")

        with patch.object(doctor.shutil, "which", return_value="/usr/bin/node"), \
             patch.object(doctor, "_version_of", return_value="v20.0.0"):
            supported = doctor.check_node()
        self.assertTrue(supported.ok)

    def test_kuzu_recovery_uses_selected_interpreter(self) -> None:
        with patch.dict(sys.modules, {"kuzu": None}):
            check = doctor.check_kuzu()
        self.assertIn("python -m pip install", check.fix)


if __name__ == "__main__":
    unittest.main()
