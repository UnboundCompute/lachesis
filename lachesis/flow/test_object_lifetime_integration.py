import subprocess
import sys
import tempfile
import unittest
from collections import defaultdict
from pathlib import Path

from lachesis.core.snapshot import load_snapshot
from lachesis.nav.graph_store import GraphStore
from lachesis.pipeline import semantic_snapshot_graph

from .object_lifetime import analyze_object_lifetimes
from .translate import build_F


SOURCE = r"""
void *malloc(unsigned long);
void free(void *);
void consume(void *);

void alias_release(void) {
    char *first = malloc(8);
    char *second = first;
    free(first);
    free(second);
}

void reset_release(void) {
    char *item = malloc(8);
    free(item);
    item = 0;
    free(item);
}

void exclusive_release(int choose) {
    char *item = malloc(8);
    if (choose)
        free(item);
    else
        free(item);
}

void write_after_release(void) {
    char *item = malloc(8);
    free(item);
    *item = 1;
}

void release_argument(char *value) {
    free(value);
}

void caller_alias_effect(void) {
    char *first = malloc(8);
    char *second = first;
    release_argument(second);
    consume(first);
}
"""


class ObjectLifetimeIntegrationTests(unittest.TestCase):
    def test_frontend_graph_drives_object_identity_analysis(self):
        with tempfile.TemporaryDirectory() as source_dir, tempfile.TemporaryDirectory() as output:
            Path(source_dir, "lifetime.c").write_text(SOURCE)
            completed = subprocess.run(
                [sys.executable, "-m", "lachesis.frontends.c.build_graph", source_dir, output],
                text=True, capture_output=True, check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            snapshot = load_snapshot(output)
            store = GraphStore(semantic_snapshot_graph(snapshot))
            functions, successors = build_F(store, lang="c")

            result = analyze_object_lifetimes(store, functions, successors, lang="c")
            by_function = defaultdict(set)
            for lead in result.leads:
                by_function[lead["entry"]].add(lead["pattern"])

            self.assertEqual(by_function["alias_release"], {"double-free"})
            self.assertEqual(by_function["reset_release"], set())
            self.assertEqual(by_function["exclusive_release"], set())
            self.assertEqual(by_function["write_after_release"], {"use-after-free"})
            self.assertEqual(by_function["caller_alias_effect"], {"use-after-free"})
            self.assertEqual(result.diagnostics["unplaced"], 0)
            self.assertEqual(result.diagnostics["capped"], [])


if __name__ == "__main__":
    unittest.main()
