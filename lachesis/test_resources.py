import unittest
from unittest.mock import patch

from lachesis.frontends.registry import typescript_compiler_frontend
from lachesis.resources import frontend_jobs, memory_budget_mb, typescript_heap_mb


class ResourcePolicyTests(unittest.TestCase):
    def test_defaults_fit_the_total_process_tree_budget(self):
        with patch.dict("os.environ", {}, clear=True):
            self.assertEqual(memory_budget_mb(), 5120)
            self.assertEqual(typescript_heap_mb(), 3584)
            self.assertEqual(frontend_jobs(), 1)
            command = typescript_compiler_frontend().command
            self.assertIn("--max-old-space-size=3584", command)

    def test_explicit_typescript_heap_cannot_exceed_shared_budget_share(self):
        environment = {
            "LACHESIS_MEMORY_BUDGET_MB": "4096",
            "LACHESIS_TS_MAX_OLD_SPACE_MB": "12000",
        }
        with patch.dict("os.environ", environment, clear=True):
            self.assertEqual(typescript_heap_mb(), 2867)

    def test_invalid_budget_and_concurrency_are_rejected(self):
        with patch.dict("os.environ", {"LACHESIS_MEMORY_BUDGET_MB": "512"}, clear=True):
            with self.assertRaisesRegex(ValueError, "at least 1024"):
                memory_budget_mb()
        with patch.dict("os.environ", {"LACHESIS_FRONTEND_JOBS": "0"}, clear=True):
            with self.assertRaisesRegex(ValueError, "positive integer"):
                frontend_jobs()


if __name__ == "__main__":
    unittest.main()
