"""Identity, source positions, and the graph accumulator for the Python frontend.

Nothing here interprets Python semantics; it only turns what ``ast`` reports into
the canonical provenance shape every Lachesis frontend emits.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Dict, List, Optional

from lachesis.core.composition import _EdgeKeys

CONTRACT_VERSION = 2
FRONTEND_ID = "cpython-ast"
LANGUAGE = "python"

# Deprecated along with the tier concept itself; see docs/DEPRECATED.md. Still here
# because the names are the tier file names in every bundle ever written.
TIERS = {
    "T0": "perimeter", "T1": "reachability", "T2": "path",
    "T3": "body", "T4": "proof",
}

# The single tier lookup for this frontend.
#
# The navigation layer reads no tier property at all (nav/kuzu_index.py does not
# even select one), so tier placement buys navigation nothing. It exists only
# because lachesis/core/validation.py rejects a node whose tier is not a member of
# schema.NODE_KIND_TIERS[kind]. Each kind therefore gets its one legal tier from
# this table and no further design attention. Deprecated for that reason: a new
# node kind needs a line here to satisfy a check that protects nothing.
TIER_OF_KIND = {
    # T0 project structure
    "file": "T0", "module": "T0", "import": "T0", "export": "T0",
    "external-module": "T0", "package": "T0",
    # T1 declarations that are reachability entities
    "declaration": "T1", "function": "T1", "method": "T1",
    "constructor": "T1", "class": "T1",
    # T2 path-level declarations and values
    "scope": "T2", "symbol": "T2", "parameter": "T2", "variable": "T2",
    "binding": "T2", "property": "T2", "constant": "T2", "value": "T2",
    "decorator": "T2", "type-parameter": "T2",
    "definition": "T2", "read": "T2", "write": "T2", "release": "T2", "literal": "T2",
    "property-path": "T2", "allocation": "T2", "type-refinement": "T2",
    "generic-substitution": "T2",
    "argument": "T2", "call-value": "T2", "return": "T2", "return-value": "T2",
    # T3 executable body
    "statement": "T3", "expression": "T3", "operation": "T3", "identifier": "T3",
    "call": "T3", "construct": "T3", "throw": "T3",
    "dynamic-behavior": "T3", "module-initializer": "T3",
    "static-initializer": "T3",
    # T4 evidence
    "diagnostic": "T4", "source-span": "T4", "token": "T4",
}

# Structural relationships are reified as EXPANDS_TO when they cross a tier
# boundary, matching the C frontend and the `via` unwrapping every reader already
# performs (lachesis/core/query.py, lachesis/kuzu_store.py, nav/graph_store.py).
STRUCTURAL_EDGE_KINDS = frozenset({
    "DECLARES", "DECLARES_MEMBER", "DECLARES_VALUE", "DECLARES_SCOPE",
    "DECLARES_SYMBOL", "CONTAINS_BODY", "AST_CHILD", "EVIDENCED_BY",
    "HAS_ARGUMENT", "HAS_DIAGNOSTIC", "HAS_PROPERTY_PATH",
})

_CONTENT_HASHES: Dict[str, str] = {}


def stable_id(kind: str, *parts: object) -> str:
    """The canonical v2 frontend identity (lachesis/core/identities.py, byte for byte)."""
    raw = "\0".join(str(part) for part in parts)
    digest = hashlib.sha256(
        f"v2\0frontend\0{FRONTEND_ID}\0{kind}\0{raw}".encode("utf-8")
    ).hexdigest()[:20]
    return f"v2:frontend:{FRONTEND_ID}:{kind}:{digest}"


def content_hash(absolute: str) -> str:
    if absolute not in _CONTENT_HASHES:
        try:
            payload = Path(absolute).read_bytes()
        except OSError:
            payload = b""
        _CONTENT_HASHES[absolute] = hashlib.sha256(payload).hexdigest()
    return _CONTENT_HASHES[absolute]


def compact(value: object, limit: int = 200) -> str:
    """One-line, length-capped rendering of a source fragment (labels only)."""
    text = " ".join(str(value if value is not None else "").split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


class SourceFile:
    """One decoded source file, and the offset arithmetic every node needs.

    The important detail is the byte-versus-character split. ``ast`` reports
    ``col_offset``/``end_col_offset`` as UTF-8 *byte* offsets into the physical
    line, while nav/graphlib.py slices the decoded text by *character*
    (``text[start_offset:end_offset]``). On any line containing a non-ASCII
    character the two disagree, and ``read_body`` would silently return the wrong
    slice. Every position emitted by this frontend is converted to character
    offsets here, once, so no caller has to remember.
    """

    def __init__(self, absolute: Path, display: str, text: str) -> None:
        self.absolute = str(absolute)
        self.display = display
        self.text = text
        self.content_hash = content_hash(self.absolute)
        # Universal-newline decoding already collapsed \r\n and \r, and the Python
        # compiler treats only \n as a line separator, so splitting on it is exact.
        # (str.splitlines would also split on \x0b/\x0c/ , which Python source
        # does not treat as line breaks, and would desync every line number.)
        self._lines = text.split("\n")
        starts: List[int] = [0]
        running = 0
        for line in self._lines:
            running += len(line) + 1
            starts.append(running)
        self._line_start = starts
        self._byte_to_char: Dict[int, Optional[Dict[int, int]]] = {}

    @property
    def line_count(self) -> int:
        return len(self._lines)

    def _column_map(self, index: int) -> Optional[Dict[int, int]]:
        """Byte column -> character column for one line, or None when ASCII-only."""
        if index in self._byte_to_char:
            return self._byte_to_char[index]
        line = self._lines[index] if 0 <= index < len(self._lines) else ""
        mapping: Optional[Dict[int, int]] = None
        if not line.isascii():
            mapping = {}
            byte_column = 0
            for character_column, character in enumerate(line):
                mapping[byte_column] = character_column
                byte_column += len(character.encode("utf-8"))
            mapping[byte_column] = len(line)
        self._byte_to_char[index] = mapping
        return mapping

    def character_column(self, line: int, byte_column: int) -> int:
        """Character column (0-based) for a 1-based line and a byte column."""
        index = min(max(line, 1), len(self._lines)) - 1
        mapping = self._column_map(index)
        if mapping is None:
            return min(max(byte_column, 0), len(self._lines[index]))
        if byte_column in mapping:
            return mapping[byte_column]
        # A byte column that lands mid-character or past the line end can only come
        # from a malformed span; clamp rather than emit an offset that slices text.
        candidates = [key for key in mapping if key <= byte_column]
        return mapping[max(candidates)] if candidates else 0

    def offset(self, line: int, byte_column: int) -> int:
        index = min(max(line, 1), len(self._lines)) - 1
        return self._line_start[index] + self.character_column(line, byte_column)

    def position(self, node: object, end: object = None) -> dict:
        """The 11 SOURCE_PROVENANCE_FIELDS for an AST node (or a start/end pair)."""
        end = end if end is not None else node
        start_line = int(getattr(node, "lineno", 1) or 1)
        start_byte_column = int(getattr(node, "col_offset", 0) or 0)
        end_line = int(getattr(end, "end_lineno", None) or start_line)
        end_byte_column = getattr(end, "end_col_offset", None)
        if end_byte_column is None:
            end_byte_column = start_byte_column
        start_column = self.character_column(start_line, start_byte_column)
        end_column = self.character_column(end_line, int(end_byte_column))
        start_offset = self._line_start[min(start_line, self.line_count) - 1] + start_column
        end_offset = self._line_start[min(end_line, self.line_count) - 1] + end_column
        return {
            "file": self.display, "absolute_file": self.absolute,
            "content_hash": self.content_hash,
            "start_offset": start_offset, "end_offset": max(start_offset, end_offset),
            "start_line": start_line, "start_column": start_column + 1,
            "end_line": end_line, "end_column": end_column + 1,
        }

    def whole_file_position(self) -> dict:
        return {
            "file": self.display, "absolute_file": self.absolute,
            "content_hash": self.content_hash,
            "start_offset": 0, "end_offset": len(self.text),
            "start_line": 1, "start_column": 1,
            "end_line": self.line_count, "end_column": len(self._lines[-1]) + 1,
        }

    def excerpt(self, node: object) -> str:
        position = self.position(node)
        return self.text[position["start_offset"]:position["end_offset"]]


class Graph:
    """Node/edge accumulator that fills canonical provenance for every fact."""

    def __init__(self) -> None:
        self.nodes: Dict[str, dict] = {}
        self.node_tier: Dict[str, str] = {}
        self.edges: List[dict] = []
        self.dropped_edges = 0  # endpoints that never became nodes; reported, never silent
        self._edge_keys = _EdgeKeys()

    def node(self, node_id: str, kind: str, label: str, **properties) -> str:
        canonical = {
            "fact_origin": "compiler", "confidence": "exact", "evidence_ids": [],
            **{name: value for name, value in properties.items() if value is not None},
        }
        if canonical.get("absolute_file"):
            canonical.update({
                "frontend_id": FRONTEND_ID,
                "language": LANGUAGE,
                "content_hash": canonical.get("content_hash")
                    or content_hash(canonical["absolute_file"]),
                "compiler_node_id": canonical.get("compiler_node_id") or node_id,
            })
        if node_id in self.nodes:
            self.nodes[node_id]["properties"].update(canonical)
            return node_id
        self.nodes[node_id] = {
            "id": node_id, "kind": kind, "label": label, "properties": canonical,
        }
        self.node_tier[node_id] = TIER_OF_KIND[kind]
        return node_id

    def annotate(self, node_id: str, **properties) -> None:
        """Add properties to an already-emitted node.

        A later pass often learns something about a node the declaration pass had
        no way to know (that a local is captured by a closure, that a scope could
        not be correlated). Annotating in place keeps that fact on the node the
        navigation layer will actually load, rather than in a parallel structure
        nothing reads.
        """
        node = self.nodes.get(node_id)
        if node is None:
            return
        node["properties"].update({
            name: value for name, value in properties.items() if value is not None
        })

    def edge(
        self, kind: str, source: Optional[str], target: Optional[str], **properties
    ) -> None:
        if not source or not target or source == target:
            return
        canonical = {
            "fact_origin": "compiler", "confidence": "exact", "evidence_ids": [],
            **{name: value for name, value in properties.items() if value is not None},
        }
        edge = {
            "kind": kind, "source": source, "target": target, "properties": canonical,
        }
        if self._edge_keys.add(edge):
            self.edges.append(edge)

    def tier_payloads(self) -> Dict[str, dict]:
        """Split the flat graph into the on-disk tier files.

        Cross-tier structural relationships become EXPANDS_TO(via=<kind>) and every
        other cross-tier relationship becomes a link. Unlike the C frontend this
        keeps the original properties on an EXPANDS_TO wrapper rather than
        replacing them with ``via`` alone, because ``AST_CHILD.role`` is a real
        input to lachesis/core/overlays/control_flow.py and dispatch.py and must
        survive the crossing.
        """
        payloads = {
            tier: {
                "tier": tier, "name": name,
                "nodes": [], "edges": [], "expands_to": [], "links": [],
            }
            for tier, name in TIERS.items()
        }
        for node_id, node in self.nodes.items():
            payloads[self.node_tier[node_id]]["nodes"].append(node)
        for edge in self.edges:
            source_tier = self.node_tier.get(edge["source"])
            target_tier = self.node_tier.get(edge["target"])
            if not source_tier or not target_tier:
                self.dropped_edges += 1
                continue
            if source_tier == target_tier:
                payloads[source_tier]["edges"].append(edge)
            elif edge["kind"] in STRUCTURAL_EDGE_KINDS:
                payloads[source_tier]["expands_to"].append({
                    "kind": "EXPANDS_TO",
                    "source": edge["source"], "target": edge["target"],
                    "properties": dict(edge["properties"], via=edge["kind"]),
                })
            else:
                payloads[source_tier]["links"].append({
                    **edge,
                    "properties": dict(edge["properties"], target_tier=target_tier),
                })
        for payload in payloads.values():
            payload["nodes"].sort(key=lambda item: item["id"])
            for collection in ("edges", "expands_to", "links"):
                payload[collection].sort(
                    key=lambda item: (item["kind"], item["source"], item["target"])
                )
        return payloads
