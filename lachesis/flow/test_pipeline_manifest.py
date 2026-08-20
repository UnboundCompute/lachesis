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
from lachesis.cli.manifest_run import execute_manifest_run
from lachesis.manifest.schema import (
    AnalysisConfig,
    FunctionContract,
    Manifest,
    Memory,
    Ownership,
    ProjectFacts,
)
from lachesis.nav.graph_store import GraphStore
from lachesis.pipeline import semantic_snapshot_graph

from .object_lifetime import _contracts_to_summaries, _parse_arg_path
from .object_state import OpKind, ParamEffect
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
        engine, alloc, dealloc, cap, contracts, applied = _manifest_config(None)
        self.assertEqual((engine, alloc, dealloc, cap, contracts, applied),
                         (None, (), (), None, (), {}))

        # A full analysis block: applied knobs are recorded; timeout is surfaced as
        # declared-but-unenforced rather than silently dropped.
        manifest = Manifest(
            project=ProjectFacts(memory=Memory(alloc=("xmalloc",), free=("xfree",))),
            analysis=AnalysisConfig(engine="object", disjunct_cap=16, timeout_per_fn=30.0),
        )
        engine, alloc, dealloc, cap, contracts, applied = _manifest_config(manifest)
        self.assertEqual(engine, "object")
        self.assertEqual(alloc, ("xmalloc",))
        self.assertEqual(dealloc, ("xfree",))
        self.assertEqual(cap, 16)
        self.assertIn("memory.alloc", applied)
        self.assertIn("analysis.disjunct_cap", applied)
        self.assertIn("NOT enforced", applied["analysis.timeout_per_fn"])


# An opaque (declaration-only, cross-TU) free that releases its whole argument. Only a
# manifest contract can tell the engine what it does; without one the call is a blind USE.
CONTRACT_SOURCE = r"""
void *malloc(unsigned long);
void ext_release(void *p);

void frees_via_opaque(void) {
    char *p = malloc(8);
    ext_release(p);
    *p = 1;
}
"""


class ContractConversionTests(unittest.TestCase):
    def test_parse_arg_path(self):
        self.assertEqual(_parse_arg_path("arg0"), (0, ()))
        self.assertEqual(_parse_arg_path("arg1.data"), (1, ("data",)))
        self.assertEqual(_parse_arg_path("arg2.next.data"), (2, ("next", "data")))
        # non-positional forms are unresolvable and skipped, not mis-bound
        self.assertIsNone(_parse_arg_path("value"))
        self.assertIsNone(_parse_arg_path("argX"))

    def test_contract_to_summary_skips_analyzable_and_maps_effects(self):
        contracts = (
            FunctionContract(name="ext_free_data", frees=("arg0.data",)),
            FunctionContract(name="ext_use", uses=("arg0",)),
            FunctionContract(name="local_fn", frees=("arg0",)),   # excluded: has a body
        )
        summaries = _contracts_to_summaries(contracts, exclude={"local_fn"})
        self.assertNotIn("local_fn", summaries)  # body-authoritative, never overridden
        self.assertEqual(summaries["ext_free_data"],
                         ((ParamEffect(OpKind.FREE, 0, ("data",)),),))
        self.assertEqual(summaries["ext_use"], ((ParamEffect(OpKind.USE, 0, ()),),))


class ContractDrivenLifetimeTests(unittest.TestCase):
    def test_opaque_free_contract_composes_use_after_free(self):
        with tempfile.TemporaryDirectory() as source_dir, tempfile.TemporaryDirectory() as output:
            Path(source_dir, "contract.c").write_text(CONTRACT_SOURCE)
            completed = subprocess.run(
                [sys.executable, "-m", "lachesis.frontends.c.build_graph", source_dir, output],
                text=True, capture_output=True, check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            snapshot = load_snapshot(output)

            # Baseline: ext_release is opaque, so the engine cannot know it frees p.
            store = GraphStore(semantic_snapshot_graph(snapshot))
            baseline = run_pass(store, lang="c", lifetime_engine="object")
            self.assertEqual(
                _patterns_by_function(baseline)["frees_via_opaque"], set(),
                "an opaque free must be invisible without a contract",
            )

            # A contract declaring ext_release frees arg0 composes across the boundary:
            # the later *p = 1 becomes a use-after-free.
            manifest = Manifest(project=ProjectFacts(functions=(
                FunctionContract(name="ext_release", frees=("arg0",),
                                 returns=Ownership.UNKNOWN),
            )))
            store2 = GraphStore(semantic_snapshot_graph(snapshot))
            declared = run_pass(store2, lang="c", lifetime_engine="object", manifest=manifest)
            self.assertEqual(
                _patterns_by_function(declared)["frees_via_opaque"], {"use-after-free"},
                "the free contract must compose a cross-TU use-after-free",
            )
            self.assertIn("functions", declared["lifetime"]["applied_config"])


RUN_SOURCE = r"""
void *malloc(unsigned long);
void free(void *);

void kept_double_free(void) {
    char *p = malloc(8);
    free(p);
    free(p);
}

void claims_to_free(char *p) {
    (void)p;
}
"""

EXCLUDED_SOURCE = r"""
void *malloc(unsigned long);
void free(void *);

void excluded_double_free(void) {
    char *p = malloc(8);
    free(p);
    free(p);
}
"""

RUN_MANIFEST = r"""
[project]
name = "manifest-run-proof"
language = "c"

[project.source]
exclude = ["tests", "**/vendor/**"]

[project.functions.claims_to_free]
frees = ["arg0"]

[analysis]
engine = "object"
"""


class ManifestRunTests(unittest.TestCase):
    def test_end_to_end_summary_scopes_excludes_and_warns_on_body_contradiction(self):
        with tempfile.TemporaryDirectory() as source_dir, tempfile.TemporaryDirectory() as output:
            Path(source_dir, "src").mkdir()
            Path(source_dir, "tests").mkdir()
            Path(source_dir, "src", "kept.c").write_text(RUN_SOURCE)
            Path(source_dir, "tests", "excluded.c").write_text(EXCLUDED_SOURCE)
            manifest_path = Path(source_dir, "lachesis.toml")
            manifest_path.write_text(RUN_MANIFEST)
            completed = subprocess.run(
                [sys.executable, "-m", "lachesis.frontends.c.build_graph", source_dir, output],
                text=True, capture_output=True, check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            snapshot = load_snapshot(output)
            store = GraphStore(semantic_snapshot_graph(snapshot))

            payload = execute_manifest_run(
                Path(source_dir), manifest_path, Path(output), store)
            summary = payload["run_summary"]

            entries = {lead["entry"] for lead in payload["leads"]}
            self.assertIn("kept_double_free", entries)
            self.assertNotIn("excluded_double_free", entries)
            self.assertGreaterEqual(summary["excluded_leads"], 1)
            self.assertIn("project.source.exclude", summary["applied_config"])
            self.assertEqual(summary["manifest_validation"]["warnings"], 0)
            self.assertEqual(
                [warning["symbol"] for warning in summary["semantic_warnings"]],
                ["claims_to_free"],
            )


if __name__ == "__main__":
    unittest.main()
