"""Pluggable, language-neutral compiler frontend contract.

Frontends should run in the ecosystem that gives them the strongest semantic
information (TypeScript in Node, Clang in C++, Pyright in Python, and so on).
They communicate with Arachne through a versioned JSON fact graph instead of
sharing parser-specific objects.

This module is intentionally not wired into ``file_reader.analyze_files`` yet.
It provides the migration boundary needed to replace fragile manual parsing one
capability at a time while preserving Arachne's language-neutral overlays.
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple


FRONTEND_CONTRACT_VERSION = 1
CAPABILITY_COMPLETE = "complete"
CAPABILITY_PARTIAL = "partial"
CAPABILITY_NONE = "none"
VALID_CAPABILITY_LEVELS = {
    CAPABILITY_COMPLETE, CAPABILITY_PARTIAL, CAPABILITY_NONE,
}

# These facts should be owned by a compiler/language frontend. Once a frontend
# reports a capability as complete, the corresponding manual discovery pass can
# be retired for that language.
FRONTEND_OWNED_CAPABILITIES = {
    "lexical": (
        "tokens", "comments", "strings", "regex literals", "source offsets",
    ),
    "syntax": (
        "declarations", "statements", "expressions", "operators", "source spans",
    ),
    "modules": (
        "imports", "exports", "re-exports", "resolved module targets",
    ),
    "symbols": (
        "scopes", "declarations", "references", "shadowing", "aliases",
    ),
    "types": (
        "declared types", "inferred types", "signatures", "overloads",
        "generic substitutions", "narrowing facts",
    ),
    "calls": (
        "call expressions", "constructors", "selected signatures",
        "static targets", "overload candidates",
    ),
    "control_flow": (
        "execution order", "branches", "loops", "try/catch/finally",
        "break/continue", "merges", "unreachable code",
    ),
    "direct_data_flow": (
        "definitions", "reads", "assignments", "arguments", "parameters", "returns",
    ),
}

# These remain Arachne overlays even when the frontend is compiler-backed. A
# frontend may provide stronger seed facts, but language parsing alone does not
# define the security/runtime policy represented here.
OVERLAY_OWNED_CAPABILITIES = {
    "heap_identity": (
        "allocation identities", "points-to sets", "property locations", "aliases",
    ),
    "context_sensitivity": (
        "per-call parameter instances", "receiver contexts", "contextual returns",
    ),
    "branch_histories": (
        "SSA versions", "phi nodes", "branch-sensitive reaching definitions",
    ),
    "taint_policy": (
        "attacker sources", "sinks", "sanitizers", "trust-boundary policy",
    ),
    "runtime_models": (
        "library effects", "external behavior", "framework behavior",
    ),
    "effects": (
        "function summaries", "argument mutations", "receiver/global/imported state",
    ),
    "async_events": (
        "callbacks", "events", "queues", "timers", "workers", "webhooks",
    ),
    "dynamic_behavior": (
        "eval", "reflection", "proxies", "runtime loading", "monkey patching",
    ),
    "framework_wiring": (
        "routes", "dependency injection", "decorators", "registries", "ORM wiring",
    ),
    "security_roles": (
        "entry points", "boundaries", "guards", "sources", "sinks", "state",
    ),
}


class FrontendError(RuntimeError):
    """A frontend failed or emitted a snapshot that violates the contract."""


@dataclass(frozen=True)
class FrontendSpec:
    """Registration record for an out-of-process language frontend."""

    frontend_id: str
    languages: Tuple[str, ...]
    extensions: Tuple[str, ...]
    command: Tuple[str, ...]
    working_directory: str
    environment: Mapping[str, str] = field(default_factory=dict)
    priority: int = 100

    def supports(self, path: str) -> bool:
        return Path(path).suffix.lower() in self.extensions

    def render_command(self, source_dir: str, output_dir: str) -> List[str]:
        values = {
            "source_dir": os.path.abspath(source_dir),
            "output_dir": os.path.abspath(output_dir),
        }
        return [part.format(**values) for part in self.command]


@dataclass
class FrontendSnapshot:
    """Normalized graph emitted by any registered frontend."""

    frontend_id: str
    contract_version: int
    languages: Tuple[str, ...]
    capabilities: Dict[str, str]
    manifest: dict
    nodes: List[dict]
    edges: List[dict]
    stdout: str = ""
    stderr: str = ""

    @property
    def nodes_by_id(self) -> Dict[str, dict]:
        return {node["id"]: node for node in self.nodes}

    def capability(self, name: str) -> str:
        return self.capabilities.get(name, CAPABILITY_NONE)

    def can_replace(self, capability: str) -> bool:
        return self.capability(capability) == CAPABILITY_COMPLETE

    def replacement_report(self) -> dict:
        """Return an explicit migration decision for every capability family."""
        frontend = {}
        for name, facts in FRONTEND_OWNED_CAPABILITIES.items():
            level = self.capability(name)
            frontend[name] = {
                "status": level,
                "safe_to_replace_manual_pass": level == CAPABILITY_COMPLETE,
                "facts": list(facts),
            }
        overlays = {
            name: {
                "status": "overlay-owned",
                "safe_to_replace_manual_pass": False,
                "facts": list(facts),
            }
            for name, facts in OVERLAY_OWNED_CAPABILITIES.items()
        }
        return {"frontend_owned": frontend, "overlay_owned": overlays}


class FrontendRegistry:
    """Select frontends without teaching Arachne about individual languages."""

    def __init__(self) -> None:
        self._frontends: Dict[str, FrontendSpec] = {}

    def register(self, frontend: FrontendSpec) -> None:
        if frontend.frontend_id in self._frontends:
            raise FrontendError(
                f"frontend already registered: {frontend.frontend_id}"
            )
        self._frontends[frontend.frontend_id] = frontend

    def get(self, frontend_id: str) -> FrontendSpec:
        try:
            return self._frontends[frontend_id]
        except KeyError as error:
            raise FrontendError(f"unknown frontend: {frontend_id}") from error

    def select(self, path: str) -> Optional[FrontendSpec]:
        matches = [
            frontend for frontend in self._frontends.values()
            if frontend.supports(path)
        ]
        return min(matches, key=lambda item: item.priority, default=None)

    def partition(self, paths: Iterable[str]) -> Dict[str, List[str]]:
        """Group a mixed-language source inventory by selected frontend."""
        result: Dict[str, List[str]] = {}
        for path in paths:
            frontend = self.select(path)
            if frontend:
                result.setdefault(frontend.frontend_id, []).append(path)
        for grouped in result.values():
            grouped.sort()
        return result

    @property
    def frontends(self) -> Tuple[FrontendSpec, ...]:
        return tuple(sorted(self._frontends.values(), key=lambda item: item.priority))


def _tier_files(manifest: dict, output_dir: str) -> List[Tuple[str, Path]]:
    result = []
    for tier in manifest.get("tiers", []):
        tier_name = tier.get("tier")
        file_name = tier.get("file")
        if not tier_name or not file_name:
            raise FrontendError("manifest tier is missing `tier` or `file`")
        result.append((tier_name, Path(output_dir) / file_name))
    return result


def load_snapshot(
    output_dir: str, stdout: str = "", stderr: str = "",
) -> FrontendSnapshot:
    """Load and normalize the standard layered frontend interchange format."""
    manifest_path = Path(output_dir) / "manifest.json"
    if not manifest_path.is_file():
        raise FrontendError(f"frontend did not emit {manifest_path}")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    contract_version = manifest.get(
        "frontend_contract_version", manifest.get("version")
    )
    frontend_id = manifest.get("frontend_id") or manifest.get("generator")
    if not frontend_id:
        raise FrontendError("manifest is missing `frontend_id`")

    nodes: List[dict] = []
    edges: List[dict] = []
    for tier_name, tier_path in _tier_files(manifest, output_dir):
        if not tier_path.is_file():
            raise FrontendError(f"missing tier file: {tier_path}")
        payload = json.loads(tier_path.read_text(encoding="utf-8"))
        for node in payload.get("nodes", []):
            nodes.append({**node, "tier": tier_name})
        for collection in ("edges", "expands_to", "links"):
            for edge in payload.get(collection, []):
                edges.append({
                    **edge,
                    "source_tier": tier_name,
                    "relationship_class": collection,
                })

    capabilities = dict(manifest.get("capabilities", {}))
    snapshot = FrontendSnapshot(
        frontend_id=frontend_id,
        contract_version=contract_version,
        languages=tuple(manifest.get("languages", ())),
        capabilities=capabilities,
        manifest=manifest,
        nodes=nodes,
        edges=edges,
        stdout=stdout,
        stderr=stderr,
    )
    validate_snapshot(snapshot)
    return snapshot


def validate_snapshot(snapshot: FrontendSnapshot) -> None:
    """Reject ambiguous or lossy frontend output before overlays consume it."""
    if snapshot.contract_version != FRONTEND_CONTRACT_VERSION:
        raise FrontendError(
            f"unsupported frontend contract {snapshot.contract_version}; "
            f"expected {FRONTEND_CONTRACT_VERSION}"
        )
    invalid_levels = {
        name: level for name, level in snapshot.capabilities.items()
        if level not in VALID_CAPABILITY_LEVELS
    }
    if invalid_levels:
        raise FrontendError(f"invalid capability levels: {invalid_levels}")

    node_ids = [node.get("id") for node in snapshot.nodes]
    missing_ids = sum(node_id is None for node_id in node_ids)
    if missing_ids:
        raise FrontendError(f"{missing_ids} frontend nodes have no id")
    duplicates = len(node_ids) - len(set(node_ids))
    if duplicates:
        raise FrontendError(f"frontend emitted {duplicates} duplicate node ids")
    known = set(node_ids)
    dangling = [
        edge for edge in snapshot.edges
        if edge.get("source") not in known or edge.get("target") not in known
    ]
    if dangling:
        sample = dangling[0]
        raise FrontendError(
            f"frontend emitted {len(dangling)} dangling relationships; "
            f"first is {sample.get('kind')} {sample.get('source')} -> "
            f"{sample.get('target')}"
        )

    expected_nodes = snapshot.manifest.get("node_count")
    expected_edges = snapshot.manifest.get("edge_count")
    if expected_nodes is not None and expected_nodes != len(snapshot.nodes):
        raise FrontendError(
            f"manifest says {expected_nodes} nodes but tiers contain "
            f"{len(snapshot.nodes)}"
        )
    if expected_edges is not None and expected_edges != len(snapshot.edges):
        raise FrontendError(
            f"manifest says {expected_edges} edges but tiers contain "
            f"{len(snapshot.edges)}"
        )

    # Every source-derived fact must retain a file and exact source interval.
    source_kinds = {
        "function", "method", "constructor", "class", "interface", "type", "enum",
        "parameter", "variable", "binding", "property", "statement", "expression",
        "identifier", "call", "construct", "source-span", "token",
    }
    missing_provenance = []
    for node in snapshot.nodes:
        if node.get("kind") not in source_kinds:
            continue
        properties = node.get("properties", {})
        required = ("file", "start_offset", "end_offset", "start_line", "end_line")
        if any(properties.get(key) is None for key in required):
            missing_provenance.append(node["id"])
    if missing_provenance:
        raise FrontendError(
            f"{len(missing_provenance)} source-derived nodes lack exact provenance; "
            f"first is {missing_provenance[0]}"
        )


def run_frontend(
    frontend: FrontendSpec,
    source_dir: str,
    output_dir: Optional[str] = None,
    timeout_seconds: int = 300,
) -> FrontendSnapshot:
    """Execute any command frontend and return its validated canonical snapshot."""
    temporary = None
    if output_dir is None:
        temporary = tempfile.TemporaryDirectory(prefix="arachne-frontend-")
        output_dir = temporary.name
    os.makedirs(output_dir, exist_ok=True)
    environment = os.environ.copy()
    environment.update(frontend.environment)
    command = frontend.render_command(source_dir, output_dir)
    try:
        completed = subprocess.run(
            command,
            cwd=frontend.working_directory,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
            timeout=timeout_seconds,
        )
        if completed.returncode != 0:
            raise FrontendError(
                f"frontend {frontend.frontend_id} exited {completed.returncode}\n"
                f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
            )
        return load_snapshot(output_dir, completed.stdout, completed.stderr)
    except subprocess.TimeoutExpired as error:
        raise FrontendError(
            f"frontend {frontend.frontend_id} exceeded {timeout_seconds}s"
        ) from error
    finally:
        if temporary is not None:
            temporary.cleanup()


def typescript_compiler_frontend(workspace_root: Optional[str] = None) -> FrontendSpec:
    """The first plugin: TypeScript/JavaScript through the official compiler API."""
    root = Path(workspace_root or Path(__file__).resolve().parent.parent).resolve()
    script = root / "compiler_graph" / "build_layered_graph.mjs"
    return FrontendSpec(
        frontend_id="typescript-compiler-api",
        languages=("typescript", "javascript"),
        extensions=(".ts", ".tsx", ".mts", ".cts", ".js", ".jsx"),
        command=(
            "node", str(script), "{source_dir}", "{output_dir}",
        ),
        working_directory=str(root),
        priority=10,
    )


def default_registry(workspace_root: Optional[str] = None) -> FrontendRegistry:
    registry = FrontendRegistry()
    registry.register(typescript_compiler_frontend(workspace_root))
    return registry
