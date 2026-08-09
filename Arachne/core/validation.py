"""Strict validation for canonical v2 snapshots and explicit v1 migration."""
from __future__ import annotations

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
    LEGACY_CONTRACT_VERSIONS,
    NODE_KIND_TIERS,
    SOURCE_DERIVED_NODE_KINDS,
    TIERS,
)


LEGACY_SOURCE_KINDS = frozenset({
    "function", "method", "constructor", "class", "interface", "type", "enum",
    "record", "parameter", "variable", "binding", "property", "statement",
    "expression", "identifier", "call", "construct", "source-span", "token",
})


def validate_snapshot(snapshot: FrontendSnapshot) -> None:
    """Validate a snapshot at its declared contract version.

    Version 1 remains readable only as a migration input. New frontend output
    must use v2 to receive strict kind, ownership, provenance and evidence checks.
    """
    if snapshot.contract_version == CURRENT_CONTRACT_VERSION:
        _validate_v2(snapshot)
    elif snapshot.contract_version in LEGACY_CONTRACT_VERSIONS:
        _validate_v1_migration_input(snapshot)
    else:
        raise ContractError(
            f"unsupported frontend contract {snapshot.contract_version}; "
            f"supported versions are {sorted({CURRENT_CONTRACT_VERSION, *LEGACY_CONTRACT_VERSIONS})}"
        )


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


def _validate_v1_migration_input(snapshot: FrontendSnapshot) -> None:
    _validate_common(snapshot)
    missing = []
    for node in snapshot.nodes:
        if node.get("kind") not in LEGACY_SOURCE_KINDS:
            continue
        properties = node.get("properties", {})
        required = ("file", "start_offset", "end_offset", "start_line", "end_line")
        if any(properties.get(key) is None for key in required):
            missing.append(node["id"])
    if missing:
        raise ContractError(
            f"{len(missing)} v1 source nodes lack migration provenance; first is {missing[0]}"
        )


def _validate_v2(snapshot: FrontendSnapshot) -> None:
    _validate_common(snapshot)
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
        if tier not in TIERS:
            raise ContractError(f"v2 node {node_id} has invalid tier {tier!r}")
        if tier not in NODE_KIND_TIERS.get(kind, frozenset()):
            raise ContractError(
                f"v2 node {node_id} kind {kind!r} cannot be placed in {tier}"
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
