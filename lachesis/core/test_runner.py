import sys
import tempfile
import unittest

from lachesis.core.contract import ContractError, FrontendSpec
from lachesis.core.runner import run_frontend


class RunnerTimeoutTests(unittest.TestCase):
    def test_timeout_reports_contract_error_and_stops_frontend(self):
        frontend = FrontendSpec(
            frontend_id="sleeping-test-frontend",
            languages=("python",),
            extensions=(".py",),
            command=(sys.executable, "-c", "import time; time.sleep(30)"),
            working_directory=tempfile.gettempdir(),
        )
        with self.assertRaisesRegex(ContractError, r"sleeping-test-frontend exceeded 1s"):
            run_frontend(frontend, tempfile.gettempdir(), timeout_seconds=1)


if __name__ == "__main__":
    unittest.main()
