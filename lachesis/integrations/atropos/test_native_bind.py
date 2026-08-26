from __future__ import annotations

import unittest

from lachesis.integrations.atropos.enrich import locate_atropos
from lachesis.integrations.atropos.native_bind import bind_all, available


class NativeAtroposBinderParity(unittest.TestCase):
    """The Rust binder must remain report-compatible with Atropos's oracle."""

    @classmethod
    def setUpClass(cls):
        if not available():
            raise unittest.SkipTest("release Atropos Rust library is not built")
        root = locate_atropos()
        if root is None:
            raise unittest.SkipTest("Atropos checkout is not available")

    def test_endpoint_and_status_matrix(self):
        models = [
            {"id": "source", "language": "c", "method": "read",
             "role": "source", "access_path": "Argument[0]"},
            {"id": "summary", "language": "c", "method": "copy",
             "role": "summary", "access_path": "Argument[1] -> Argument[0]"},
            {"id": "return", "language": "c", "method": "read",
             "role": "sink", "access_path": "ReturnValue"},
            {"id": "receiver", "language": "c", "method": "read",
             "role": "sink", "access_path": "Receiver"},
            {"id": "unsupported", "language": "c", "method": "read",
             "role": "sink", "access_path": "Argument[*]"},
            {"id": "arity", "language": "c", "method": "read",
             "role": "sink", "access_path": "Argument[2]"},
        ]
        index = {
            "format": "atropos-symbol-index", "version": 1,
            "language": "c", "source": "test",
            "callsites": [
                {"id": "read-call", "callee": {"name": "read", "module": "libc",
                 "receiver_type": None, "arity": 1}, "call_value_id": "ret",
                 "receiver_value_id": None, "arg_value_ids": ["buf"]},
                {"id": "copy-call", "callee": {"name": "copy", "module": "libc",
                 "receiver_type": None, "arity": 2}, "call_value_id": "copy-ret",
                 "receiver_value_id": None, "arg_value_ids": ["dst", "src"]},
            ],
        }
        report = bind_all(models, index)
        by_id = {row["model_id"]: row for row in report["results"]}
        self.assertEqual(by_id["source"]["status"], "bound")
        self.assertEqual(by_id["summary"]["status"], "bound")
        self.assertEqual(by_id["return"]["status"], "bound")
        self.assertEqual(by_id["receiver"]["status"], "unsupported-path")
        self.assertEqual(by_id["unsupported"]["status"], "unsupported-path")
        self.assertEqual(by_id["arity"]["status"], "arity-mismatch")


if __name__ == "__main__":
    unittest.main()
