"""P3 proof: a project manifest's ``memory.free`` vocabulary changes what the object
engine finds.

A project that frees through its own wrapper (``my_release``, not the libc ``free``)
is invisible to the default lifecycle catalog -- so the engine sees no free event and
reports no double-free, a false negative every off-the-shelf analyzer shares. Declaring
that wrapper in ``lachesis.toml`` is the highest-recall lever the manifest adds: the same
graph, run with the manifest, now fires the double-free.

Also covers the ``analysis`` config plumbing (:func:`_manifest_config`): which knobs are
applied, and the honest record of one declared-but-not-yet-enforced (``timeout_per_fn``)
so config can never become a silent verdict override.
"""
import subprocess
import sys
import tempfile
import unittest
from collections import defaultdict
from pathlib import Path

from lachesis.core.snapshot import load_snapshot
from lachesis.manifest.schema import (
    AnalysisConfig,
    Manifest,
    Memory,
    ProjectFacts,
)
from lachesis.nav.graph_store import GraphStore
from lachesis.pipeline import semantic_snapshot_graph

from .pipeline import _manifest_config, run_pass

# A double-free routed entirely through a project-specific free wrapper. The libc
# ``free`` never appears, so nothing in the default catalog marks a lifecycle event.
SOURCE = r"""
void *malloc(unsigned long);
void my_release(void *);

void custom_double_free(void) {
    char *first = malloc(8);
    char *second = first;
    my_release(first);
    my_release(second);
}
"""


def _patterns_by_function(result):
    by_function = defaultdict(set)
    for lead in result["leads"]:
        if lead["pattern"] in {"double-free", "use-after-free"}:
            by_function[lead["entry"]].add(lead["pattern"])
    return by_function


class ManifestDrivenLifetimeTests(unittest.TestCase):
    def test_manifest_free_wrapper_makes_double_free_fire(self):
        with tempfile.TemporaryDirectory() as source_dir, tempfile.TemporaryDirectory() as output:
            Path(source_dir, "custom.c").write_text(SOURCE)
            completed = subprocess.run(
                [sys.executable, "-m", "lachesis.frontends.c.build_graph", source_dir, output],
                text=True, capture_output=True, check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            snapshot = load_snapshot(output)

            # Baseline: no manifest. my_release is not a known free -> no double-free.
            store = GraphStore(semantic_snapshot_graph(snapshot))
            baseline = run_pass(store, lang="c", lifetime_engine="object")
            self.assertEqual(
                _patterns_by_function(baseline)["custom_double_free"], set(),
                "custom free wrapper must be invisible without a manifest",
            )

            # With a manifest declaring the wrapper, the same graph fires the double-free.
            manifest = Manifest(project=ProjectFacts(memory=Memory(free=("my_release",))))
            store2 = GraphStore(semantic_snapshot_graph(snapshot))
            declared = run_pass(store2, lang="c", lifetime_engine="object", manifest=manifest)
            self.assertEqual(
                _patterns_by_function(declared)["custom_double_free"], {"double-free"},
                "declaring the free wrapper must recover the double-free",
            )

            # The applied-config audit records the recall lever the manifest pulled.
            applied = declared["lifetime"]["applied_config"]
            self.assertIn("memory.free", applied)
            self.assertIn("my_release", applied["memory.free"])

    def test_manifest_config_extraction_and_audit(self):
        # No manifest -> empty knobs, empty audit.
        engine, alloc, dealloc, cap, applied = _manifest_config(None)
        self.assertEqual((engine, alloc, dealloc, cap, applied), (None, (), (), None, {}))

        # A full analysis block: applied knobs are recorded; timeout is surfaced as
        # declared-but-unenforced rather than silently dropped.
        manifest = Manifest(
            project=ProjectFacts(memory=Memory(alloc=("xmalloc",), free=("xfree",))),
            analysis=AnalysisConfig(engine="object", disjunct_cap=16, timeout_per_fn=30.0),
        )
        engine, alloc, dealloc, cap, applied = _manifest_config(manifest)
        self.assertEqual(engine, "object")
        self.assertEqual(alloc, ("xmalloc",))
        self.assertEqual(dealloc, ("xfree",))
        self.assertEqual(cap, 16)
        self.assertIn("memory.alloc", applied)
        self.assertIn("analysis.disjunct_cap", applied)
        self.assertIn("NOT enforced", applied["analysis.timeout_per_fn"])


if __name__ == "__main__":
    unittest.main()
