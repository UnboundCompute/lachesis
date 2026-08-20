"""Turn one frontend's tier payloads into a canonical snapshot.

The payloads arrive by one of two routes. A frontend that ran as a subprocess left
them on disk and ``load_snapshot`` reads them back; a frontend that ran in this
process hands them over directly and ``snapshot_from_payloads`` takes them as they
are. Everything after that point — the tier stamping, the manifest header, the
contract validation — is shared, so which route a payload travelled cannot change
what the snapshot says about it.
"""
from __future__ import annotations

import marshal
import json
from pathlib import Path
from typing import Iterable, Iterator, List, Mapping, Tuple

from .contract import ContractError, FrontendSnapshot
from .graph_wire import decode_document, decode_tier
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


def _read_tiers(manifest: dict, output_dir: str) -> Iterator[Tuple[str, dict]]:
    """One tier payload at a time, so the whole bundle is never resident at once."""
    for tier_name, tier_path in _tier_files(manifest, output_dir):
        if not tier_path.is_file():
            raise ContractError(f"missing tier file: {tier_path}")
        # Format is carried by the manifest-declared filename: a frontend that spills
        # marshal (C's large tier payloads) names its files `.bin`; the json route
        # (Python/TS) is unchanged. marshal only round-trips JSON-shaped values, which
        # every frontend already emits (see snapshot_from_payloads' invariant).
        if tier_path.suffix == ".pb":
            yield tier_name, decode_tier(tier_path.read_bytes())
        elif tier_path.suffix == ".bin":
            # Compatibility for pre-protobuf frontend bundles.
            yield tier_name, marshal.loads(tier_path.read_bytes())
        elif tier_path.suffix == ".json":
            # Transitional compatibility for the TypeScript/Python subprocess
            # frontends while their writers move to the shared protobuf schema.
            yield tier_name, json.loads(tier_path.read_text(encoding="utf-8"))
        else:
            raise ContractError(f"unsupported tier encoding: {tier_path}")


def _merge_tiers(
    tiers: Iterable[Tuple[str, dict]],
) -> Tuple[List[dict], List[dict]]:
    """Flatten the tier payloads, stamping each element with where it came from.

    A node carries the tier it was emitted in; an edge carries that plus which of
    the three edge collections held it, because the collection is the relationship
    class and nothing downstream can recover it once the payloads are flat.
    """
    nodes: List[dict] = []
    edges: List[dict] = []
    for tier_name, payload in tiers:
        # Tier payloads are owned by this snapshot construction path. Stamp records
        # in place instead of copying every property dictionary with ``{**record}``:
        # on large C bundles the copy and the still-live marshal payload briefly
        # doubled the graph footprint before shard persistence could release it.
        tier_nodes = payload.get("nodes", [])
        for node in tier_nodes:
            node["tier"] = tier_name
        nodes.extend(tier_nodes)
        for collection in ("edges", "expands_to", "links"):
            tier_edges = payload.get(collection, [])
            for edge in tier_edges:
                edge["source_tier"] = tier_name
                edge["relationship_class"] = collection
            edges.extend(tier_edges)
    return nodes, edges


def _header(manifest: dict) -> Tuple[str, int]:
    frontend_id = manifest.get("frontend_id") or manifest.get("generator")
    if not frontend_id:
        raise ContractError("manifest is missing `frontend_id`")
    return frontend_id, manifest.get(
        "frontend_contract_version", manifest.get("version")
    )


def _snapshot(
    manifest: dict, nodes: List[dict], edges: List[dict], stdout: str, stderr: str,
) -> FrontendSnapshot:
    frontend_id, contract_version = _header(manifest)
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


def load_snapshot(
    output_dir: str, stdout: str = "", stderr: str = "",
) -> FrontendSnapshot:
    manifest_path = Path(output_dir) / "manifest.pb"
    if not manifest_path.is_file():
        # Transitional compatibility for Python/TypeScript frontends that have not
        # switched their subprocess bundle writer yet.
        manifest_path = Path(output_dir) / "manifest.json"
    if not manifest_path.is_file():
        raise ContractError(f"frontend did not emit {manifest_path}")
    if manifest_path.suffix == ".pb":
        manifest = decode_document(manifest_path.read_bytes())
    else:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    # Read the header before any tier file is opened. A bundle with no frontend_id
    # is unusable whatever its tiers hold, and complaining about that first is the
    # error this has always raised.
    _header(manifest)
    nodes, edges = _merge_tiers(_read_tiers(manifest, output_dir))
    return _snapshot(manifest, nodes, edges, stdout, stderr)


def snapshot_from_payloads(
    manifest: dict, payloads: Mapping[str, dict],
    stdout: str = "", stderr: str = "",
) -> FrontendSnapshot:
    """The snapshot ``load_snapshot`` would build, without the trip through disk.

    A frontend running in this process already holds the payloads the file route
    would serialise, write and immediately parse back. On a tree of any size that
    round trip is most of the frontend's wall time, and nobody between the two ends
    of it wants the file.

    One thing the file route does incidentally is normalise: ``json.dumps`` followed
    by ``json.loads`` turns tuples into lists and non-string mapping keys into
    strings. This route does no such thing, so a frontend wired in here has to emit
    JSON-shaped values in the first place. That is not taken on trust —
    ``lachesis.frontends.checks`` builds a snapshot both ways and requires them to
    agree element for element.
    """
    tiers = []
    for tier in manifest.get("tiers", []):
        tier_name = tier.get("tier")
        if not tier_name:
            raise ContractError("manifest tier is missing `tier`")
        if tier_name not in payloads:
            raise ContractError(f"frontend emitted no payload for tier {tier_name}")
        tiers.append((tier_name, payloads[tier_name]))
    nodes, edges = _merge_tiers(tiers)
    return _snapshot(manifest, nodes, edges, stdout, stderr)
