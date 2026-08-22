"""Shared substrate for the navigation primitives.

Wraps the canonical Lachesis graph with the typed helpers the nav layer needs.
Reuses ``lachesis.core.query.GraphIndex`` for adjacency/indexing — this module only
adds what the nav movers need on top: offset-accurate source excerpts, owner-function climb,
structural family builders, and a generic security-lexicon *scoring* helper.

Design invariant (non-negotiable): nothing here is hardcoded to a codebase under
analysis. No package names, interface names, or vendor tokens appear in logic.
Families are discovered from graph structure; the security lexicon only *weights*
how security-relevant a called symbol looks — it never gates family membership or
decides a verdict.
"""
from __future__ import annotations

import os
import re
import sys
from functools import lru_cache
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lachesis.core.query import GraphIndex


CALLABLE_KINDS = ("function", "method", "constructor")
CALL_EDGE_KINDS = ("CALLS", "INVOKES", "MAY_INVOKE")


# Generic security vocabulary. This is a RANKING aid only: it scores how
# security-relevant a symbol name looks so a differential can prefer guard-shaped
# calls. It is NOT a membership gate and NOT a verdict — a member is flagged
# because it is weaker than its own peers, never because it fails this list.
_SECURITY_HIGH = re.compile(
    r"verif|hmac|\bsign|signature|digest|sanit|escape|\bhash\b", re.IGNORECASE,
)
_SECURITY_MED = re.compile(
    r"valid|auth|token|assert|allow|deny|permit|forbid|trust|scope|origin"
    r"|redirect|secret|cred|\bcheck|guard|authoriz|permission|owner\b|tenant",
    re.IGNORECASE,
)
# One shared regex for "does this name look security-relevant at all" (either tier).
SECURITY_LEXICON = re.compile(
    _SECURITY_HIGH.pattern + "|" + _SECURITY_MED.pattern, re.IGNORECASE,
)

# camelCase / PascalCase / snake_case tokenizer.
_TOKEN = re.compile(r"[A-Z]+(?![a-z])|[A-Z][a-z]+|[a-z]+|[0-9]+")
# split a path segment into its own sub-tokens (driver-mysql -> driver, mysql).
_SEG_SPLIT = re.compile(r"[^A-Za-z0-9]+|(?<=[a-z])(?=[A-Z])")


@lru_cache(maxsize=8)
def _parse_source_map(spec: str) -> tuple[tuple[str, str], ...]:
    """Parse ``old=new,old2=new2`` prefix rewrites (trailing slashes stripped)."""
    pairs = []
    for chunk in spec.replace(os.pathsep, ",").split(","):
        chunk = chunk.strip()
        if "=" not in chunk:
            continue
        old, _, new = chunk.partition("=")
        old, new = old.strip().rstrip("/"), new.strip().rstrip("/")
        if old and new:
            pairs.append((old, new))
    return tuple(pairs)


def resolve_source_path(path: str) -> str:
    """Map a build-time source path to one readable on the machine reading the graph.

    A graph built in one environment (e.g. a Docker container that mounted the tree
    under ``/src``) records absolute build paths that need not exist where the graph
    is later queried. Two env vars bridge that gap, consulted *only when the recorded
    path is missing* — so behaviour is byte-for-byte identical whenever the source is
    already local:

      LACHESIS_SOURCE_MAP   comma-separated ``old=new`` prefix rewrites, e.g.
                            ``/src=/Users/me/targets/nifti_clib``
      LACHESIS_SOURCE_ROOT  a local root; the recorded path's trailing segments are
                            matched under it, longest tail that exists winning (so a
                            container ``/src/nifti2/x.c`` resolves against a root whose
                            layout is ``<root>/nifti2/x.c`` without naming the prefix)

    The build mounts sources read-only, so the local file is the same bytes as the one
    the frontend parsed — recorded byte offsets stay valid against the resolved path.
    """
    if not path or os.path.exists(path):
        return path
    for old, new in _parse_source_map(os.environ.get("LACHESIS_SOURCE_MAP", "")):
        if path == old or path.startswith(old + "/"):
            candidate = new + path[len(old):]
            if os.path.exists(candidate):
                return candidate
    root = os.environ.get("LACHESIS_SOURCE_ROOT", "").rstrip("/")
    if root:
        parts = [p for p in Path(path).parts if p not in ("/", "")]
        for i in range(len(parts)):  # longest trailing sub-path first
            candidate = os.path.join(root, *parts[i:])
            if os.path.exists(candidate):
                return candidate
    return path


def camel_tokens(name: str) -> list[str]:
    """Lowercased word tokens of an identifier (readMysqlRecord -> read mysql record)."""
    return [tok.lower() for tok in _TOKEN.findall(name or "")]


def segment_tokens(segment: str) -> frozenset[str]:
    """Lowercased sub-tokens of a path segment (driver-mysql -> {driver, mysql})."""
    return frozenset(
        part.lower() for part in _SEG_SPLIT.split(segment or "") if part
    )


def security_weight(name: str) -> float:
    """Weight a symbol name by how security-relevant it looks (0.0, 0.6, or 1.0)."""
    if not name:
        return 0.0
    if _SECURITY_HIGH.search(name):
        return 1.0
    if _SECURITY_MED.search(name):
        return 0.6
    return 0.0


class GraphLib:
    """Typed convenience layer over a canonical graph for the nav primitives."""

    def __init__(self, graph: dict) -> None:
        self.graph = graph
        self.index = GraphIndex(graph)
        self.nodes = self.index.nodes
        self._source_cache: dict[str, str | None] = {}
        self._exported: frozenset[str] | None = None
        self._endpoint_cache: dict[tuple[str, ...], frozenset[str]] = {}

    @classmethod
    def from_index(cls, index) -> "GraphLib":
        """Wrap a prebuilt index (e.g. a disk-backed ``KuzuGraphIndex``) that already
        satisfies the ``GraphIndex`` accessor surface, without a graph dict. Every
        ``GraphLib`` method reads ``self.index``/``self.nodes`` only; ``self.graph`` is
        never consulted, so a store-less wrapper is safe."""
        self = cls.__new__(cls)
        self.graph = None
        self.index = index
        self.nodes = index.nodes
        self._source_cache = {}
        self._exported = None
        self._endpoint_cache = {}
        return self

    @classmethod
    def load(cls, path: str) -> "GraphLib":
        """Open a Kùzu store directory without materializing it: every ``GraphLib``
        method reads through the index, so the store answers them directly."""
        from lachesis.nav.kuzu_index import KuzuGraphIndex
        return cls.from_index(KuzuGraphIndex(path))

    # -- basic node access ---------------------------------------------------

    def kind(self, node_id: str) -> str | None:
        node = self.nodes.get(node_id)
        return node.get("kind") if node else None

    def label(self, node: dict) -> str:
        return str(node.get("label", ""))

    def prop(self, node: dict, key: str, default=None):
        return node.get("properties", {}).get(key, default)

    def loc(self, node: dict) -> tuple[str | None, int | None, int | None]:
        """(repo-relative file, start_line, end_line) for a node."""
        properties = node.get("properties", {})
        return (
            properties.get("file"),
            properties.get("start_line"),
            properties.get("end_line"),
        )

    def source_excerpt(self, node: dict, max_len: int = 400) -> str:
        """Full operand/definition text via byte offsets — never the 80-char label.

        Reads ``absolute_file[start_offset:end_offset]``. Returns "" when the
        file or offsets are unavailable (the label is deliberately not used as a
        fallback in analysis *logic*; callers may still read ``node['label']``).
        """
        properties = node.get("properties", {})
        path = properties.get("absolute_file") or properties.get("file")
        start = properties.get("start_offset")
        end = properties.get("end_offset")
        if not path or start is None or end is None:
            return ""
        text = self._read_file(path)
        if text is None:
            return ""
        excerpt = text[start:end]
        if len(excerpt) > max_len:
            excerpt = excerpt[:max_len] + "…"
        return excerpt

    def source_text(self, node: dict) -> str:
        """Full, untruncated offset text for a node (for classification, not display)."""
        properties = node.get("properties", {})
        path = properties.get("absolute_file") or properties.get("file")
        start = properties.get("start_offset")
        end = properties.get("end_offset")
        if not path or start is None or end is None:
            return ""
        text = self._read_file(path)
        return "" if text is None else text[start:end]

    def _read_file(self, path: str) -> str | None:
        if path not in self._source_cache:
            try:
                resolved = resolve_source_path(path)
                self._source_cache[path] = Path(resolved).read_text(encoding="utf-8")
            except (OSError, UnicodeError):
                self._source_cache[path] = None
        return self._source_cache[path]

    # -- structural adjacency helpers ---------------------------------------

    def calls_from(self, function_id: str) -> tuple[dict, ...]:
        """Callee nodes invoked from a function (CALLS/INVOKES/MAY_INVOKE)."""
        return tuple(self.index.targets(function_id, *CALL_EDGE_KINDS))

    def owner_function(self, node: dict) -> dict | None:
        """Climb to the enclosing function/method/constructor node."""
        if node.get("kind") in CALLABLE_KINDS:
            return node
        seen: set[str] = set()
        current = node
        while current is not None:
            properties = current.get("properties", {})
            owner_id = properties.get("owner_function_id") or properties.get("function_id")
            if not owner_id or owner_id in seen:
                break
            seen.add(owner_id)
            owner = self.nodes.get(owner_id)
            if owner is None:
                break
            if owner.get("kind") in CALLABLE_KINDS:
                return owner
            current = owner
        # fall back to the scope chain
        scope_id = node.get("properties", {}).get("scope_id")
        hops = 0
        while scope_id and scope_id in self.nodes and hops < 32:
            scope = self.nodes[scope_id]
            if scope.get("kind") in CALLABLE_KINDS:
                return scope
            scope_id = scope.get("properties", {}).get("scope_id")
            hops += 1
        return None

    def body_nodes(self, function_id: str) -> tuple[dict, ...]:
        """Nodes owned by a function (by owner_function_id / function_id)."""
        return self.index.nodes_owned_by(function_id)

    def edge_endpoint_nodes(self, *edge_kinds: str) -> frozenset[str]:
        """All node ids that are an endpoint of any edge of these kinds (cached).

        One pass over the edges per distinct kind-set — lets a per-function guard
        check become a set intersection instead of a full edge scan per member.
        """
        key = tuple(sorted(edge_kinds))
        cached = self._endpoint_cache.get(key)
        if cached is None:
            endpoints: set[str] = set()
            for edge in self.index.edges_of_kind(*edge_kinds):
                endpoints.add(edge.get("source"))
                endpoints.add(edge.get("target"))
            endpoints.discard(None)
            cached = frozenset(endpoints)
            self._endpoint_cache[key] = cached
        return cached

    @property
    def exported_ids(self) -> frozenset[str]:
        if self._exported is None:
            self._exported = frozenset(
                edge["target"] for edge in self.index.edges_of_kind("EXPORTS")
            )
        return self._exported

    def is_exported(self, node_id: str) -> bool:
        return node_id in self.exported_ids

    # -- family builders (structural compatibility, and parallel-module) ----

    def struct_compat_components(
        self, endpoint_kinds: frozenset[str] = frozenset({"class", "interface"}),
    ) -> list[list[str]]:
        """Connected components over STRUCTURALLY_COMPATIBLE_WITH, endpoint-filtered."""
        adjacency: dict[str, set[str]] = {}
        for edge in self.index.edges_of_kind("STRUCTURALLY_COMPATIBLE_WITH"):
            source, target = edge.get("source"), edge.get("target")
            snode, tnode = self.nodes.get(source), self.nodes.get(target)
            if not snode or not tnode:
                continue
            if snode.get("kind") not in endpoint_kinds or tnode.get("kind") not in endpoint_kinds:
                continue
            adjacency.setdefault(source, set()).add(target)
            adjacency.setdefault(target, set()).add(source)
        seen: set[str] = set()
        components: list[list[str]] = []
        for start in sorted(adjacency):
            if start in seen:
                continue
            stack, component = [start], []
            seen.add(start)
            while stack:
                current = stack.pop()
                component.append(current)
                for neighbour in adjacency[current]:
                    if neighbour not in seen:
                        seen.add(neighbour)
                        stack.append(neighbour)
            if len(component) > 1:
                components.append(sorted(component))
        return components

    def declared_members(self, type_id: str) -> tuple[dict, ...]:
        """Member nodes a class/interface DECLARES_MEMBER."""
        return tuple(self.index.targets(type_id, "DECLARES_MEMBER"))

    def directory_template_families(self) -> list[dict]:
        """Family formation from repeated directory templates + name-stems.

        A *template* is a set of directories identical except in exactly one path
        segment (the package segment). Exported free functions living under the
        same template are aligned into *roles* by their name tokens with the
        package segment's tokens removed. A role with members from >=2 distinct
        package segments is a family. Purely structural — no package name is
        referenced in logic.
        """
        # exported, top-level (owner-less) callables
        funcs: list[dict] = []
        for node in self.index.nodes_of_kind(*CALLABLE_KINDS):
            if not self.is_exported(node["id"]):
                continue
            if node.get("properties", {}).get("owner_function_id"):
                continue
            path = node.get("properties", {}).get("file")
            if path:
                funcs.append(node)

        # group functions by containing directory
        by_dir: dict[tuple[str, ...], list[dict]] = {}
        for node in funcs:
            segments = tuple(node["properties"]["file"].split("/")[:-1])
            by_dir.setdefault(segments, []).append(node)

        # cluster directories that differ in exactly one segment index
        # key = (length, varying_index, tuple_with_that_index_blanked)
        template_dirs: dict[tuple, set[tuple[str, ...]]] = {}
        dirs = list(by_dir)
        for segments in dirs:
            for idx in range(len(segments)):
                blanked = segments[:idx] + ("*",) + segments[idx + 1:]
                key = (len(segments), idx, blanked)
                template_dirs.setdefault(key, set()).add(segments)

        families: list[dict] = []
        emitted_roles: set[tuple] = set()
        for (length, idx, blanked), dir_set in template_dirs.items():
            varying = {d[idx] for d in dir_set}
            if len(varying) < 2:
                continue  # not a repeated template
            # align functions under this template into roles
            roles: dict[tuple[str, ...], list[dict]] = {}
            for segments in dir_set:
                pkg_tokens = segment_tokens(segments[idx])
                for node in by_dir[segments]:
                    tokens = tuple(
                        tok for tok in camel_tokens(node["label"])
                        if tok not in pkg_tokens
                    )
                    if tokens:
                        roles.setdefault(tokens, []).append((segments[idx], node))
            for role_key, members in roles.items():
                packages = {pkg for pkg, _node in members}
                if len(packages) < 2:
                    continue
                dedup = (blanked, idx, role_key)
                if dedup in emitted_roles:
                    continue
                emitted_roles.add(dedup)
                families.append({
                    "role": "".join(role_key),
                    "template": "/".join(blanked),
                    "package_segment_index": idx,
                    "members": [
                        {"package": pkg, "node": node} for pkg, node in
                        sorted(members, key=lambda pn: pn[1]["id"])
                    ],
                })
        return families
