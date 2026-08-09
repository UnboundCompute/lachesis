"""Data objects in the language-neutral frontend interchange contract."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Tuple

from .capabilities import (
    CAPABILITY_COMPLETE,
    CAPABILITY_NONE,
    FRONTEND_OWNED_CAPABILITIES,
    OVERLAY_OWNED_CAPABILITIES,
)


class ContractError(RuntimeError):
    """A frontend or overlay violated the canonical graph contract."""


@dataclass(frozen=True)
class FrontendSpec:
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
            "source_dir": str(Path(source_dir).resolve()),
            "output_dir": str(Path(output_dir).resolve()),
        }
        return [part.format(**values) for part in self.command]


@dataclass
class FrontendSnapshot:
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
