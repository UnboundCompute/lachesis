"""Project configuration (``lachesis.yml``): classifier, globs, precedence, env.

The classifier is the default build- and export-time filter, so its two failure
modes both matter: dropping a product module whose *name* merely contains a keyword
(``testing.py``), and keeping scaffolding it should drop. The glob translator, the
exclude/include precedence, and the runtime-env passthrough are pinned here too. The
YAML-loading tests are skipped when PyYAML is absent — that is a genuine environment
gap, not a defect, and the lazy-import contract is exactly that the core runs without
it.
"""
import os
import tempfile
import unittest
from pathlib import Path

import pytest

from lachesis import config


class ClassifierTests(unittest.TestCase):
    def test_keeps_product_modules_that_contain_a_keyword(self):
        for path in ("src/flask/testing.py", "src/flask/templating.py",
                     "pkg/documentation.py", "a/b/specs_helper.py"):
            self.assertFalse(config.is_nonproduct(path), path)

    def test_drops_scaffolding_by_segment_and_basename(self):
        for path in ("tests/test_cli.py", "examples/tutorial/app.py", "docs/conf.py",
                     "benchmarks/bench_x.py", "fixtures/data.py", "vendor/lib.py",
                     "third_party/x.py", "node_modules/y.js", "conftest.py",
                     "src/foo_test.py", "a/thing.spec.ts", "a/thing.test.js"):
            self.assertTrue(config.is_nonproduct(path), path)

    def test_drops_vendored_generated_and_build_config(self):
        # Dependencies, generated output, and build configs are not product source;
        # a graph over an application has no business modelling them. Language-agnostic,
        # so one rule covers Python/TS/JS/C at once.
        for path in ("dist/bundle.js", "scripts/check-dist-rules.py",
                     "lib/parser.min.js", "assets/app.min.css",
                     "lib/stringify.d.ts", "types/index.d.ts",
                     "rollup.config.js", "webpack.config.ts", "vite.config.mjs",
                     "jest.config.cjs"):
            self.assertTrue(config.is_nonproduct(path), path)

    def test_generated_patterns_do_not_over_match_product(self):
        # A normal ``.ts`` module, a bare ``config.js`` (no ``<name>.config.js``
        # shape), and a product module under ``distributed/`` must all survive.
        for path in ("src/reader.ts", "lib/config.js", "src/distributed/queue.py",
                     "src/scripting/engine.py"):
            self.assertFalse(config.is_nonproduct(path), path)


class GlobTests(unittest.TestCase):
    def test_bare_segment_matches_anywhere(self):
        pat = config._glob_to_regex("tests")
        self.assertTrue(pat.search("a/tests/b.py"))
        self.assertTrue(pat.search("tests/b.py"))
        self.assertFalse(pat.search("a/testsuite/b.py"))

    def test_doublestar_and_single_star(self):
        self.assertTrue(config._glob_to_regex("src/**/gen_*.py").search("src/a/b/gen_x.py"))
        self.assertFalse(config._glob_to_regex("src/*.py").search("src/a/b.py"))


class PathFilterTests(unittest.TestCase):
    def test_default_excludes_nonproduct(self):
        pf = config.PathFilter()
        self.assertTrue(pf.excluded("tests/test_a.py"))
        self.assertFalse(pf.excluded("src/app.py"))

    def test_explicit_empty_exclude_keeps_everything(self):
        # `exclude: []` clears the default; nothing is excluded.
        pf = config.parse({"build": {"exclude": []}}).build.paths
        self.assertFalse(pf.excluded("tests/test_a.py"))

    def test_explicit_exclude_replaces_default(self):
        pf = config.parse({"build": {"exclude": ["examples"]}}).build.paths
        self.assertTrue(pf.excluded("examples/x.py"))
        # Tests are no longer dropped: the explicit list is the whole policy now.
        self.assertFalse(pf.excluded("tests/test_a.py"))

    def test_include_allowlist_wins(self):
        pf = config.parse({"build": {"include": ["tests/keep_me.py"]}}).build.paths
        self.assertFalse(pf.excluded("tests/keep_me.py"))
        self.assertTrue(pf.excluded("tests/other.py"))


class ParseTests(unittest.TestCase):
    def test_unknown_section_warns_not_fatal(self):
        cfg = config.parse({"nonsense": 1, "build": {"max_files": 10}})
        self.assertEqual(cfg.build.max_files, 10)
        self.assertTrue(any("nonsense" in w for w in cfg.warnings))

    def test_bad_int_is_dropped_with_a_warning(self):
        cfg = config.parse({"build": {"max_nodes": "lots"}})
        self.assertIsNone(cfg.build.max_nodes)
        self.assertTrue(any("max_nodes" in w for w in cfg.warnings))

    def test_export_paths_default_to_build_paths(self):
        cfg = config.parse({"build": {"exclude": ["examples"]}})
        self.assertTrue(cfg.export.paths.excluded("examples/x.py"))

    def test_unknown_runtime_var_warns_but_applies(self):
        cfg = config.parse({"runtime": {"LACHESIS_NOT_REAL": "1"}})
        self.assertIn("LACHESIS_NOT_REAL", cfg.runtime)
        self.assertTrue(any("LACHESIS_NOT_REAL" in w for w in cfg.warnings))


class RuntimeEnvTests(unittest.TestCase):
    def test_apply_sets_env_but_env_wins(self):
        cfg = config.parse({
            "runtime": {"LACHESIS_MEMORY_BUDGET_MB": 2048},
            "atropos": {"root": "/opt/atropos", "timings": True},
        })
        saved = {k: os.environ.get(k) for k in
                 ("LACHESIS_MEMORY_BUDGET_MB", "ATROPOS_ROOT", "LACHESIS_ATROPOS_TIMINGS")}
        try:
            for k in saved:
                os.environ.pop(k, None)
            config.apply_runtime_env(cfg)
            self.assertEqual(os.environ["LACHESIS_MEMORY_BUDGET_MB"], "2048")
            self.assertEqual(os.environ["ATROPOS_ROOT"], "/opt/atropos")
            self.assertEqual(os.environ["LACHESIS_ATROPOS_TIMINGS"], "1")
            # An inherited env var wins over the file (setdefault).
            os.environ["LACHESIS_MEMORY_BUDGET_MB"] = "9999"
            config.apply_runtime_env(cfg)
            self.assertEqual(os.environ["LACHESIS_MEMORY_BUDGET_MB"], "9999")
        finally:
            for k, v in saved.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v


class LoadTests(unittest.TestCase):
    def test_no_file_is_all_defaults_still_excluding_nonproduct(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = config.load(start=d)
            self.assertIsNone(cfg.source)
            self.assertTrue(cfg.build.paths.excluded("tests/test_a.py"))

    def test_finds_file_walking_up(self):
        pytest.importorskip("yaml")
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "lachesis.yml").write_text("build:\n  max_files: 7\n", "utf-8")
            sub = root / "a" / "b"
            sub.mkdir(parents=True)
            cfg = config.load(start=str(sub))
            self.assertEqual(cfg.build.max_files, 7)
            # find_config resolves symlinks (e.g. macOS /var -> /private/var), so
            # compare resolved paths rather than the raw tempdir string.
            self.assertEqual(Path(cfg.source).resolve(),
                             (root / "lachesis.yml").resolve())

    def test_explicit_missing_config_is_an_error(self):
        with self.assertRaises(config.ConfigError):
            config.load(explicit="/no/such/lachesis.yml")


if __name__ == "__main__":
    unittest.main()
