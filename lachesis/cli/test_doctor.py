from __future__ import annotations

import sys
import unittest
from unittest.mock import patch

from lachesis.cli import doctor


class DoctorCompatibilityTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
