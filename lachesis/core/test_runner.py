import sys
import tempfile
import unittest

from lachesis.core import graph_pb2
from lachesis.core.contract import ContractError, FrontendSpec
from lachesis.core.runner import _is_reference_read, run_frontend


class RunnerTimeoutTests(unittest.TestCase):
    def test_timeout_reports_contract_error_and_stops_frontend(self):
        frontend = FrontendSpec(
            frontend_id="sleeping-test-frontend",
            languages=("python",),
            extensions=(".py",),
            command=(sys.executable, "-c", "import time; time.sleep(30)"),
            working_directory=tempfile.gettempdir(),
        )
        with self.assertRaisesRegex(ContractError, r"sleeping-test-frontend exceeded 1s"):
            run_frontend(frontend, tempfile.gettempdir(), timeout_seconds=1)


def _edge(kind, reason=None):
    edge = graph_pb2.EdgeRecord(kind=kind, source="decl", target="use")
    if reason is not None:
        prop = edge.properties.add()
        prop.key = "reason"
        prop.value.text = reason
    return edge


class ReferenceReadOwnershipTests(unittest.TestCase):
    """The shard ownership filter keeps an edge by its source, which drops the
    reverse-direction reference read (its source declaration lives in another
    shard). ``_is_reference_read`` is what lets the use shard retain it by
    target instead, so it must recognise exactly that one edge shape."""

    def test_reference_read_is_recognised(self):
        self.assertTrue(_is_reference_read(_edge("VALUE_FLOWS_TO", "read")))

    def test_other_value_flows_reasons_are_not_reads(self):
        # A call-argument flow is owned by its source (the argument) and must not
        # be swept in by the target-retention path.
        self.assertFalse(_is_reference_read(_edge("VALUE_FLOWS_TO", "call-argument")))
        self.assertFalse(_is_reference_read(_edge("VALUE_FLOWS_TO", "arithmetic-operand")))
        self.assertFalse(_is_reference_read(_edge("VALUE_FLOWS_TO")))

    def test_non_value_flows_edges_are_not_reads(self):
        # The paired REFERS_TO is already source-owned by the use site; it must
        # not also be treated as a read.
        self.assertFalse(_is_reference_read(_edge("REFERS_TO")))
        self.assertFalse(_is_reference_read(_edge("DEPENDS_ON", "read")))


if __name__ == "__main__":
    unittest.main()
