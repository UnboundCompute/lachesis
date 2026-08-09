"""Load the layered on-disk interchange format into a canonical snapshot."""
from __future__ import annotations

import json
from pathlib import Path
from typing import List, Tuple

from .contract import ContractError, FrontendSnapshot
from .validation import validate_snapshot


def _tier_files(manifest: dict, output_dir: str) -> List[Tuple[str, Path]]:
    result = []
    for tier in manifest.get("tiers", []):
        tier_name = tier.get("tier")
        file_name = tier.get("file")
        if not tier_name or not file_name:
            raise ContractError("manifest tier is missing `tier` or `file`")
        result.append((tier_name, Path(output_dir) / file_name))
    return result


def load_snapshot(
    output_dir: str, stdout: str = "", stderr: str = "",
) -> FrontendSnapshot:
    manifest_path = Path(output_dir) / "manifest.json"
    if not manifest_path.is_file():
        raise ContractError(f"frontend did not emit {manifest_path}")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    contract_version = manifest.get(
        "frontend_contract_version", manifest.get("version")
    )
    frontend_id = manifest.get("frontend_id") or manifest.get("generator")
    if not frontend_id:
        raise ContractError("manifest is missing `frontend_id`")

    nodes = []
    edges = []
    for tier_name, tier_path in _tier_files(manifest, output_dir):
        if not tier_path.is_file():
            raise ContractError(f"missing tier file: {tier_path}")
        payload = json.loads(tier_path.read_text(encoding="utf-8"))
        nodes.extend({**node, "tier": tier_name} for node in payload.get("nodes", []))
        for collection in ("edges", "expands_to", "links"):
            edges.extend({
                **edge,
                "source_tier": tier_name,
                "relationship_class": collection,
            } for edge in payload.get(collection, []))

    snapshot = FrontendSnapshot(
        frontend_id=frontend_id,
        contract_version=contract_version,
        languages=tuple(manifest.get("languages", ())),
        capabilities=dict(manifest.get("capabilities", {})),
        manifest=manifest,
        nodes=nodes,
        edges=edges,
        stdout=stdout,
        stderr=stderr,
    )
    validate_snapshot(snapshot)
    return snapshot

