import subprocess
import sys
import tempfile
import unittest
from collections import defaultdict
from pathlib import Path

from lachesis.core.snapshot import load_snapshot
from lachesis.nav.graph_store import GraphStore
from lachesis.pipeline import semantic_snapshot_graph

from .pipeline import run_pass


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
            result = run_pass(store, lang="c", lifetime_engine="object")
            by_function = defaultdict(set)
            for lead in result["leads"]:
                if lead["pattern"] in {"double-free", "uaf.deref"}:
                    by_function[lead["entry"]].add(lead["pattern"])

            self.assertEqual(by_function["alias_release"], {"double-free"})
            self.assertEqual(by_function["reset_release"], set())
            self.assertEqual(by_function["exclusive_release"], set())
            self.assertEqual(by_function["write_after_release"], {"uaf.deref"})
            self.assertEqual(by_function["caller_alias_effect"], set())
            self.assertTrue(any(lead["entry"] == "caller_alias_effect" and
                                lead["pattern"] == "use.dangling"
                                for lead in result["leads"]))
            # Leak remains on the legacy property domain during this migration.
            self.assertTrue(any(lead["pattern"] == "leak" for lead in result["leads"]))
            self.assertEqual(result["lifetime"]["active"], "object")
            self.assertEqual(result["lifetime"]["diagnostics"]["unplaced"], 0)
            self.assertEqual(result["lifetime"]["diagnostics"]["capped"], [])


if __name__ == "__main__":
    unittest.main()
