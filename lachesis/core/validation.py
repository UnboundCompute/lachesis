"""Strict validation for canonical v2 frontend snapshots."""
from __future__ import annotations

import os
import sys
from collections import Counter
from typing import Iterable

from .capabilities import ALL_CAPABILITIES, VALID_CAPABILITY_LEVELS
from .contract import ContractError, FrontendSnapshot
from .identities import identity_namespace, validate_identity
from .provenance import inference_provenance_errors, source_provenance_errors
from .schema import (
    CANONICAL_EDGE_KINDS,
    CANONICAL_NODE_KINDS,
    CURRENT_CONTRACT_VERSION,
    FRONTEND_FORBIDDEN_EDGE_KINDS,
    FRONTEND_FORBIDDEN_NODE_KINDS,
    NODE_KIND_TIERS,
    SOURCE_DERIVED_NODE_KINDS,
    TIERS,
)


def validate_snapshot(snapshot: FrontendSnapshot) -> None:
    """Validate one compiler snapshot against the current canonical contract."""
    if snapshot.contract_version != CURRENT_CONTRACT_VERSION:
        raise ContractError(
            f"unsupported frontend contract {snapshot.contract_version}; "
            f"required version is {CURRENT_CONTRACT_VERSION}"
        )
    _validate_v2(snapshot)


def _validate_common(snapshot: FrontendSnapshot) -> None:
    if not snapshot.frontend_id:
        raise ContractError("snapshot has no frontend_id")
    if not snapshot.languages:
        raise ContractError("snapshot has no languages")
    unknown_capabilities = set(snapshot.capabilities) - ALL_CAPABILITIES
    if unknown_capabilities:
        raise ContractError(f"unknown capabilities: {sorted(unknown_capabilities)}")
    invalid_levels = {
        name: level for name, level in snapshot.capabilities.items()
        if level not in VALID_CAPABILITY_LEVELS
    }
    if invalid_levels:
        raise ContractError(f"invalid capability levels: {invalid_levels}")

    node_ids = [node.get("id") for node in snapshot.nodes]
    if any(node_id is None for node_id in node_ids):
        raise ContractError("frontend nodes must all have ids")
    duplicates = [
        node_id for node_id, count in Counter(node_ids).items() if count > 1
    ]
    if duplicates:
        raise ContractError(f"duplicate frontend node ids: {duplicates[:3]}")
    known = set(node_ids)
    dangling = [
        edge for edge in snapshot.edges
        if edge.get("source") not in known or edge.get("target") not in known
    ]
    if dangling:
        first = dangling[0]
        raise ContractError(
            f"frontend emitted {len(dangling)} dangling relationships; first is "
            f"{first.get('kind')} {first.get('source')} -> {first.get('target')}"
        )

    expected_nodes = snapshot.manifest.get("node_count")
    expected_edges = snapshot.manifest.get("edge_count")
    if expected_nodes is not None and expected_nodes != len(snapshot.nodes):
        raise ContractError(
            f"manifest says {expected_nodes} nodes but snapshot has {len(snapshot.nodes)}"
        )
    if expected_edges is not None and expected_edges != len(snapshot.edges):
        raise ContractError(
            f"manifest says {expected_edges} edges but snapshot has {len(snapshot.edges)}"
        )


TIER_VALIDATION_MODES = ("strict", "warn", "off")

_tier_warned = False


def tier_validation_mode() -> str:
    """How hard to enforce the deprecated T0-T4 placement rules.

    ``strict`` is the default and is what has always shipped: a misplaced tier is a
    ContractError. ``warn`` reports the first violation and keeps the graph.
    ``off`` skips the two checks entirely.

    The knob exists because tiers are on their way out (docs/DEPRECATED.md) and the
    honest way to retire a rule is to be able to run without it and see what breaks,
    rather than to argue about it. Read per snapshot rather than cached, so a test
    can set it around one call.
    """
    mode = os.environ.get("LACHESIS_TIER_VALIDATION", "strict").strip().lower()
    if mode not in TIER_VALIDATION_MODES:
        raise ContractError(
            f"LACHESIS_TIER_VALIDATION must be one of "
            f"{', '.join(TIER_VALIDATION_MODES)}; got {mode!r}"
        )
    return mode


def _tier_violation(mode: str, message: str) -> None:
    global _tier_warned
    if mode == "strict":
        raise ContractError(message)
    if not _tier_warned:
        _tier_warned = True
        print(
            f"lachesis: {message} (LACHESIS_TIER_VALIDATION={mode}; further tier "
            f"violations in this process are not reported)",
            file=sys.stderr,
        )


def _validate_v2(snapshot: FrontendSnapshot) -> None:
    _validate_common(snapshot)
    tier_mode = tier_validation_mode()
    node_ids = {node["id"] for node in snapshot.nodes}
    for node in snapshot.nodes:
        node_id = node["id"]
        kind = node.get("kind")
        tier = node.get("tier")
        properties = node.get("properties", {})
        if kind not in CANONICAL_NODE_KINDS:
            raise ContractError(f"v2 node {node_id} has unknown canonical kind {kind!r}")
        if kind in FRONTEND_FORBIDDEN_NODE_KINDS:
            raise ContractError(
                f"v2 frontend node {node_id} uses core/model-owned kind {kind!r}"
            )
        # Deprecated, and the only thing keeping tiers alive. See docs/DEPRECATED.md:
        # nothing downstream reads a node's tier, so these two checks are the entire
        # reason a frontend has to decide one. LACHESIS_TIER_VALIDATION exists to
        # measure what removing them would cost, not to be turned off in a build
        # whose output anyone keeps.
        if tier_mode != "off":
            if tier not in TIERS:
                _tier_violation(
                    tier_mode, f"v2 node {node_id} has invalid tier {tier!r}")
            elif tier not in NODE_KIND_TIERS.get(kind, frozenset()):
                _tier_violation(
                    tier_mode,
                    f"v2 node {node_id} kind {kind!r} cannot be placed in {tier}",
                )
        if not validate_identity(node_id, "frontend"):
            raise ContractError(f"v2 frontend node has non-frontend identity: {node_id}")
        if identity_namespace(node_id) != snapshot.frontend_id:
            raise ContractError(
                f"v2 frontend node {node_id} is outside namespace {snapshot.frontend_id}"
            )
        if kind in SOURCE_DERIVED_NODE_KINDS:
            missing = source_provenance_errors(properties)
            if missing:
                raise ContractError(
                    f"v2 source node {node_id} has invalid provenance fields: {missing}"
                )
            if properties.get("frontend_id") != snapshot.frontend_id:
                raise ContractError(
                    f"v2 source node {node_id} has mismatched frontend_id"
                )
            if properties.get("language") not in snapshot.languages:
                raise ContractError(
                    f"v2 source node {node_id} has unregistered language"
                )
        provenance_errors = inference_provenance_errors(properties)
        if provenance_errors:
            raise ContractError(
                f"v2 node {node_id} has invalid fact provenance: {provenance_errors}"
            )
        extensions = properties.get("frontend_extensions", {})
        if extensions and (
            not isinstance(extensions, dict)
            or any(language not in snapshot.languages for language in extensions)
        ):
            raise ContractError(
                f"v2 node {node_id} has unregistered frontend extension namespace"
            )

    for edge in snapshot.edges:
        kind = edge.get("kind")
        if kind not in CANONICAL_EDGE_KINDS:
            raise ContractError(f"v2 edge has unknown canonical kind {kind!r}")
        if kind in FRONTEND_FORBIDDEN_EDGE_KINDS:
            raise ContractError(f"v2 frontend edge uses core/model-owned kind {kind!r}")
        properties = edge.get("properties", {})
        provenance_errors = inference_provenance_errors(properties)
        if provenance_errors:
            raise ContractError(
                f"v2 edge {kind} has invalid fact provenance: {provenance_errors}"
            )
        for evidence_id in properties.get("evidence_ids", []):
            if evidence_id not in node_ids:
                raise ContractError(
                    f"v2 edge {kind} references missing evidence node {evidence_id}"
                )
