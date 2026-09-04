"""The convergence scanner reads the same ``capped`` bit the full protobuf parse
would, without decoding the findings.

``_enrich_and_merge`` only needs "did any function cap?" to decide whether the
temporal skeleton converged. Parsing the whole match sidecar to answer that
materializes every finding and witness (~350 MB on a large graph), so the bind
scans the protobuf wire form for field-1 ``functions`` / field-5 ``capped``
instead. These tests pin that scan to the full-parse answer across the cases
that matter: no functions, none capped, some capped, and -- critically -- with
findings and witnesses present, since the scan's correctness rests on skipping
those length-delimited fields without decoding them.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from lachesis.core import lifetime_pb2
from lachesis.flow.native_translate import (
    drop_capped_functions, load_native_temporal, native_match_any_capped)


def _result(*capped_flags: bool, with_findings: bool = False):
    """A ``NativeTemporalResult`` with one function per flag. When
    ``with_findings`` is set, every function also carries a finding with a
    multi-node witness and guards, so the scanner must skip real
    length-delimited payloads to reach ``capped``."""
    result = lifetime_pb2.NativeTemporalResult()
    for index, capped in enumerate(capped_flags):
        function = result.functions.add()
        function.id = f"fn:{index}"
        function.transfers = 1234 + index
        function.widenings = index
        function.capped = capped
        if with_findings:
            finding = function.findings.add()
            finding.function = f"fn:{index}"
            finding.pattern = "use-after-free"
            finding.node = f"n:{index}"
            finding.line = 40 + index
            finding.has_line = True
            finding.witness_nodes.extend(
                [f"w:{index}:{step}" for step in range(6)])
            finding.witness_complete = True
            guard = finding.guards.add()
            guard.kind = "null-check"
            guard.value = "ptr != NULL"
            finding.guarded = True
    return result


class NativeMatchConvergenceScanTest(unittest.TestCase):
    def _roundtrip(self, result) -> bool:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "m.match.pb"
            path.write_bytes(result.SerializeToString())
            return native_match_any_capped(path)

    def _assert_matches_full_parse(self, result) -> None:
        expected = any(f.capped for f in result.functions)
        self.assertEqual(expected, self._roundtrip(result))

    def test_empty_result_is_converged(self):
        self.assertFalse(self._roundtrip(_result()))

    def test_none_capped(self):
        self._assert_matches_full_parse(_result(False, False, False))

    def test_some_capped(self):
        self._assert_matches_full_parse(_result(False, True, False))

    def test_last_function_capped(self):
        self._assert_matches_full_parse(_result(False, False, True))

    def test_all_capped(self):
        self._assert_matches_full_parse(_result(True, True))

    def test_findings_and_witnesses_are_skipped(self):
        # The scan must reach ``capped`` past real findings/witness/guard bytes.
        self._assert_matches_full_parse(
            _result(False, True, False, with_findings=True))
        self._assert_matches_full_parse(
            _result(False, False, False, with_findings=True))


class LoadNativeTemporalTest(unittest.TestCase):
    """``load_native_temporal`` must surface each finding's enclosing
    declaration id (field 1), the key the census resolves to a file:line, past
    the witness/guard bytes it deliberately skips."""

    def test_finding_carries_its_enclosing_declaration(self):
        result = _result(False, True, with_findings=True)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "m.match.pb"
            path.write_bytes(result.SerializeToString())
            loaded = load_native_temporal(path)
        findings = [f for fn in loaded["functions"] for f in fn["findings"]]
        self.assertEqual(len(findings), 2)
        for index, finding in enumerate(findings):
            self.assertEqual(finding["function"], f"fn:{index}")
            self.assertEqual(finding["pattern"], "use-after-free")
            self.assertEqual(finding["node"], f"n:{index}")
            self.assertEqual(finding["line"], 40 + index)

    def test_each_function_carries_its_capped_flag(self):
        # ``load_native_temporal`` surfaces the per-function ``capped`` bit so
        # cap truncation is handled per function, not as one graph-wide veto.
        result = _result(False, True, False, with_findings=True)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "m.match.pb"
            path.write_bytes(result.SerializeToString())
            loaded = load_native_temporal(path)
        self.assertEqual([fn["capped"] for fn in loaded["functions"]],
                         [False, True, False])


class DropCappedFunctionsTest(unittest.TestCase):
    """A capped function taints only itself: its findings are dropped, every
    converged function's confirmed findings survive. This is the regression
    guard for the graph-wide-zeroing bug where one capped function discarded
    the entire confirmed census."""

    @staticmethod
    def _temporal(*flags):
        return {"functions": [
            {"id": f"fn:{i}",
             "findings": [{"pattern": "double-free", "function": f"fn:{i}"}],
             "capped": capped}
            for i, capped in enumerate(flags)]}

    def test_no_capped_function_keeps_everything(self):
        temporal = self._temporal(False, False, False)
        capped = drop_capped_functions(temporal)
        self.assertEqual(capped, [])
        self.assertEqual(len(temporal["functions"]), 3)

    def test_capped_function_dropped_converged_findings_survive(self):
        # The whole point: a converged function's finding must NOT vanish just
        # because a sibling function capped.
        temporal = self._temporal(False, True, False)
        capped = drop_capped_functions(temporal)
        self.assertEqual(capped, ["fn:1"])
        surviving = {fn["id"] for fn in temporal["functions"]}
        self.assertEqual(surviving, {"fn:0", "fn:2"})
        findings = [f for fn in temporal["functions"] for f in fn["findings"]]
        self.assertEqual(len(findings), 2)

    def test_all_capped_returns_all_ids_and_no_findings(self):
        temporal = self._temporal(True, True)
        capped = drop_capped_functions(temporal)
        self.assertEqual(capped, ["fn:0", "fn:1"])
        self.assertEqual(temporal["functions"], [])

    def test_empty_bind_is_a_noop(self):
        temporal = {"functions": []}
        self.assertEqual(drop_capped_functions(temporal), [])
        self.assertEqual(temporal, {"functions": []})


if __name__ == "__main__":
    unittest.main()
