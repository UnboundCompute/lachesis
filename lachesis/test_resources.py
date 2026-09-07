import unittest
from unittest.mock import patch

from lachesis.frontends.registry import typescript_compiler_frontend
from lachesis.resources import (
    MIN_MEMORY_BUDGET_MB,
    c_chunk_files,
    frontend_jobs,
    kuzu_buffer_pool_bytes,
    memory_budget_mb,
    typescript_heap_mb,
)


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

    def test_documented_768_floor_is_accepted(self):
        # 768 MiB is the smallest supported *budget setting* -- the knee at which
        # the dominant derived sub-limit (V8 old-space at 70% of the budget) still
        # sits above its own 512 MiB floor (768*0.7 = 537 > 512) rather than
        # collapsing to the floor. It is the documented preflight budget; the
        # engine must accept it, and it is also the constant the guard advertises.
        self.assertEqual(MIN_MEMORY_BUDGET_MB, 768)
        with patch.dict(
            "os.environ", {"LACHESIS_MEMORY_BUDGET_MB": "768"}, clear=True
        ):
            self.assertEqual(memory_budget_mb(), 768)

    def test_floor_budget_propagates_to_child_process_sub_limits(self):
        # The budget is a sizing input threaded into every child process. At the
        # 768 floor the derived limits carried into those children must stay
        # internally consistent: the TS frontend child is launched with the
        # derived V8 old-space (537 MiB) on its actual command line, the C
        # frontend chunk size holds its 250-TU floor, and the embedded Kuzu
        # buffer pool takes 40% of the budget (307 MiB).
        with patch.dict(
            "os.environ", {"LACHESIS_MEMORY_BUDGET_MB": "768"}, clear=True
        ):
            self.assertEqual(typescript_heap_mb(), 537)
            command = typescript_compiler_frontend().command
            self.assertIn("--max-old-space-size=537", command)
            self.assertEqual(c_chunk_files(), 250)
            self.assertEqual(kuzu_buffer_pool_bytes(), 307 << 20)

    def test_unsafe_and_malformed_budgets_are_rejected(self):
        # Below the floor: rejected before any graph work, naming the 768 floor.
        with patch.dict(
            "os.environ", {"LACHESIS_MEMORY_BUDGET_MB": "767"}, clear=True
        ):
            with self.assertRaisesRegex(ValueError, "at least 768"):
                memory_budget_mb()
        with patch.dict(
            "os.environ", {"LACHESIS_MEMORY_BUDGET_MB": "512"}, clear=True
        ):
            with self.assertRaisesRegex(ValueError, "at least 768"):
                memory_budget_mb()
        # Malformed (non-integer): rejected as an integer-count error, not silently
        # coerced or defaulted.
        with patch.dict(
            "os.environ", {"LACHESIS_MEMORY_BUDGET_MB": "abc"}, clear=True
        ):
            with self.assertRaisesRegex(ValueError, "integer MiB count"):
                memory_budget_mb()
        with patch.dict("os.environ", {"LACHESIS_FRONTEND_JOBS": "0"}, clear=True):
            with self.assertRaisesRegex(ValueError, "positive integer"):
                frontend_jobs()


if __name__ == "__main__":
    unittest.main()
