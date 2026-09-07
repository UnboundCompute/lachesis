"""External-reference provenance exemption (the Flask `trace` v2 regression).

A partial or federated build cannot resolve a ``from lib import target`` whose
module is absent, so the frontend emits a declaration-only placeholder -- the
Python analogue of a C ``extern`` prototype -- keyed by the import's ``usr`` so a
query-time linker can rejoin it to the defining shard. Such a stub has a callable
kind but, by construction, no source span in this snapshot. It must not be held to
the source-provenance contract, or every partial export aborts. These tests pin
that exemption and its boundaries: a real source-backed declaration is never
waved through, and a partial provenance set is still a defect.
"""
import os
import unittest

from lachesis.core.contract import ContractError, FrontendSnapshot
from lachesis.core.identities import stable_id
from lachesis.core.provenance import SOURCE_PROVENANCE_FIELDS
from lachesis.core.schema import CURRENT_CONTRACT_VERSION
from lachesis.core.validation import _is_external_reference, validate_snapshot


class ExternalReferencePredicateTests(unittest.TestCase):
    def _full_provenance(self):
        # Any non-None value per field is enough to prove "this node has a span".
        return {name: 1 for name in SOURCE_PROVENANCE_FIELDS}

    def test_declaration_only_without_any_span_is_external(self):
        self.assertTrue(_is_external_reference(
            {"declaration_only": True, "usr": "py:werkzeug.exceptions.abort"}))

    def test_declaration_only_with_a_span_is_not_external(self):
        # A C ``extern`` prototype declared in a header keeps its real source span,
        # so it is a source-backed declaration and stays under the full contract.
        props = {"declaration_only": True, "usr": "c:@F@add"}
        props.update(self._full_provenance())
        self.assertFalse(_is_external_reference(props))

    def test_partial_provenance_is_not_external(self):
        self.assertFalse(_is_external_reference(
            {"declaration_only": True, "absolute_file": "hdr.h"}))

    def test_definition_is_never_external(self):
        self.assertFalse(_is_external_reference(
            {"declaration_only": False, "usr": "py:mod.fn"}))
        self.assertFalse(_is_external_reference({"usr": "py:mod.fn"}))


class ExternalReferenceSnapshotTests(unittest.TestCase):
    """The exemption at the ``validate_snapshot`` boundary the exporter runs."""

    def setUp(self):
        # Tiers are deprecated and orthogonal to this fix; switch their strict
        # check off so the test pins provenance behavior alone.
        self._prev = os.environ.get("LACHESIS_TIER_VALIDATION")
        os.environ["LACHESIS_TIER_VALIDATION"] = "off"

    def tearDown(self):
        if self._prev is None:
            os.environ.pop("LACHESIS_TIER_VALIDATION", None)
        else:
            os.environ["LACHESIS_TIER_VALIDATION"] = self._prev

    def _snapshot(self, node):
        return FrontendSnapshot(
            frontend_id="testfe", contract_version=CURRENT_CONTRACT_VERSION,
            languages=("python",), capabilities={}, manifest={},
            nodes=[node], edges=[])

    def _stub_node(self, **props_over):
        usr = "py:werkzeug.exceptions.abort"
        props = {"usr": usr, "declaration_only": True, "fact_origin": "compiler",
                 "confidence": "conservative", "resolution": "cross-shard-import"}
        props.update(props_over)
        return {"id": stable_id("frontend", "testfe", "external", usr),
                "kind": "function", "tier": "T1", "properties": props}

    def test_cross_shard_stub_passes_validation(self):
        # The exact regression: a from-import to an absent module emits a
        # declaration-only placeholder with no source span; validation must accept
        # it rather than abort the whole export.
        validate_snapshot(self._snapshot(self._stub_node()))  # no raise

    def test_declaration_with_partial_provenance_still_fails(self):
        # A declaration_only node that carries *some* provenance is not an external
        # stub -- it is a real (buggy) partial node and must still be rejected.
        with self.assertRaises(ContractError):
            validate_snapshot(self._snapshot(self._stub_node(absolute_file="/x.py")))


if __name__ == "__main__":
    unittest.main()
