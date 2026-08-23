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
void memcpy(void *, const void *, unsigned long);
char *identity(char *value) { return value; }
struct Buffer { char *data; };
char *borrowed_field(struct Buffer *buffer) { return buffer->data; }

struct Aggregate { char *owned; };

void aggregate_copy(void) {
    struct Aggregate *src = malloc(sizeof(struct Aggregate));
    struct Aggregate *clone = malloc(sizeof(struct Aggregate));
    if (!src || !clone) return;
    src->owned = malloc(8);
    memcpy(clone, src, sizeof(struct Aggregate));
    free(src->owned);
    free(clone->owned);
}

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

void loop_reuse(void) {
    char *item = malloc(8);
    for (int i = 0; i < 2; ++i) {
        free(item);
        item = malloc(8);
    }
    *item = 1;
}

void caller_return_alias(void) {
    char *first = malloc(8);
    char *second = identity(first);
    free(second);
    *first = 1;
}

void caller_return_field_alias(void) {
    struct Buffer *buffer = malloc(sizeof(struct Buffer));
    if (!buffer) return;
    buffer->data = malloc(8);
    char *borrowed = borrowed_field(buffer);
    free(buffer->data);
    *borrowed = 1;
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
            self.assertFalse(any(lead["entry"] == "loop_reuse" and
                                 lead["pattern"] == "uaf.deref"
                                 for lead in result["leads"]))
            self.assertTrue(any(lead["entry"] == "caller_return_alias" and
                                lead["pattern"] == "uaf.deref"
                                for lead in result["leads"]))
            self.assertTrue(any(lead["entry"] == "caller_return_field_alias" and
                                lead["pattern"] == "uaf.deref"
                                for lead in result["leads"]))
            self.assertTrue(any(lead["entry"] == "aggregate_copy" and
                                lead["pattern"] == "double-free"
                                for lead in result["leads"]))
            structural_kinds = {
                node.event.kind.value if hasattr(node.event.kind, "value") else node.event.kind
                for node in result["semantic_graph"].nodes.values() if node.event is not None
            }
            self.assertTrue({"branch", "merge", "loop", "return"} <= structural_kinds)
            self.assertTrue(all(lead.get("tier") in {1, 2} for lead in result["leads"]
                                if lead.get("pattern") in {"leak", "uaf.deref", "use.dangling",
                                                             "double-free", "null-deref"}))
            # Leak remains on the legacy property domain during this migration.
            self.assertTrue(any(lead["pattern"] == "leak" for lead in result["leads"]))
            self.assertEqual(result["lifetime"]["active"], "object")
            self.assertEqual(result["lifetime"]["diagnostics"]["unplaced"], 0)
            self.assertEqual(result["lifetime"]["diagnostics"]["capped"], [])


if __name__ == "__main__":
    unittest.main()
