from __future__ import annotations

import unittest

from lachesis.integrations.atropos.enrich import _load_binder, locate_atropos
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
        cls.binder = _load_binder(root)

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
        expected = self.binder.bind_all(models, index)
        self.assertEqual(bind_all(models, index), expected)


if __name__ == "__main__":
    unittest.main()
