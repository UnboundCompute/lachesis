"""End-to-end FP/FN gate for the native lifetime matcher.

This is the integration counterpart to :mod:`test_temporal_native` (which drives
the census with synthetic binds).  Here the real reader runs: the C fixtures in
``native/lifetime_kernel/corpus`` are compiled into a graph, the temporal census
runs, and every COMPLETE lifetime finding is checked against the manifest in
``native/lifetime_kernel/run_corpus.py`` -- positive controls must raise their
one target family and negative controls must raise nothing.

It is skipped unless the ``lachesis`` build CLI and a C frontend are actually
available, so a unit-only environment does not fail on a missing toolchain.  The
graph is built into a temporary directory and deleted with it, so no artifact
outlives the test.
"""
import importlib.util
import shutil
import tempfile
import unittest
from pathlib import Path

from lachesis.flow import native_lifetime

REPO_ROOT = Path(__file__).resolve().parents[2]
RUNNER = REPO_ROOT / "native" / "lifetime_kernel" / "run_corpus.py"


def _load_runner():
    spec = importlib.util.spec_from_file_location("lifetime_corpus_runner", RUNNER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@unittest.skipUnless(RUNNER.exists(), "corpus runner not present")
@unittest.skipUnless(shutil.which("lachesis"), "lachesis build CLI not on PATH")
@unittest.skipUnless(native_lifetime.available(), "native analysis kernel not built")
class LifetimeCorpusTest(unittest.TestCase):
    """Compile the corpus once, adjudicate every family's controls."""

    def test_no_false_positives_and_expected_true_positives(self):
        runner = _load_runner()
        scratch = Path(tempfile.mkdtemp(prefix="lifetime-corpus-"))
        graph = scratch / "corpus.kuzu"
        try:
            failures = runner.run(graph, verbose=False)
        except FileNotFoundError as exc:  # clang/frontend missing under the CLI
            self.skipTest(f"native C frontend unavailable: {exc}")
            return
        finally:
            shutil.rmtree(scratch, ignore_errors=True)
        self.assertEqual(failures, [], "\n".join(["lifetime corpus regressions:", *failures]))


if __name__ == "__main__":
    unittest.main()
