"""Deterministic code-comprehension views over the canonical graph.

These queries deliberately stop at graph facts.  They do not generate prose, rank
security anomalies, or retain session state; callers can compose the small, stable
answers into whatever narrative they need.
"""
from __future__ import annotations

from collections import Counter, defaultdict, deque
import json
import os
from pathlib import PurePosixPath
from pathlib import Path
import re
import subprocess

from .graphlib import CALLABLE_KINDS, CALL_EDGE_KINDS
from .graphlib import camel_tokens


TYPE_KINDS = frozenset({"class", "interface", "type", "record", "enum"})
FIELD_KINDS = frozenset({"property", "property-path", "variable"})
FLOW_KINDS = frozenset({
    "DEFINES", "READS_FROM", "WRITES_TO", "VALUE_FLOWS_TO", "PROPERTY_READ",
    "READ_EVIDENCED_BY", "WRITES_HEAP", "READS_HEAP", "REACHING_DEF",
})
CONTROL_KINDS = frozenset({
    "CONDITION", "TRUE_BRANCH", "FALSE_BRANCH", "SHORT_CIRCUIT_LEFT",
    "SHORT_CIRCUIT_RIGHT", "SWITCH_CASE", "LOOP_TRUE", "EXCEPTION_BRANCH",
})
_TEST_FILE = re.compile(
    r"(^|/)(tests?|__tests__)/|(^|/)(test_[^/]+|[^/]+[._](test|spec))\.[^.]+$",
    re.IGNORECASE,
)
_TEXT_EXTENSIONS = frozenset({
    ".c", ".h", ".cc", ".cpp", ".py", ".pyi", ".js", ".jsx", ".ts", ".tsx",
    ".go", ".rs", ".java", ".kt", ".md", ".rst", ".txt", ".adoc",
})
DEFAULT_DETAIL_LIMIT = 100
COMMUNITY_FILE_LIMIT = 50


def _loc(gl, node: dict) -> dict:
    file, line, _ = gl.loc(node)
    return {
        "node_id": node["id"], "name": gl.label(node), "kind": node.get("kind"),
        "file": file, "line": line,
    }


def _owner(gl, node: dict) -> dict | None:
    owner = gl.owner_function(node)
    return _loc(gl, owner) if owner else None


def _matches(gl, token: str, kinds=frozenset()) -> list[dict]:
    if token in gl.nodes:
        node = gl.nodes[token]
        return [node] if not kinds or node.get("kind") in kinds else []
    exact = [n for n in gl.index.nodes_named(token)
             if not kinds or n.get("kind") in kinds]
    return exact


def _semantic(edge: dict) -> str:
    if edge.get("kind") == "EXPANDS_TO":
        return edge.get("properties", {}).get("via") or "EXPANDS_TO"
    return edge.get("kind", "")


def _component(path: str | None, depth: int = 1) -> str | None:
    if not path:
        return None
    parts = [p for p in PurePosixPath(path).parts if p not in ("/", ".")]
    directories = parts[:-1]
    if not directories:
        return "."
    return "/".join(directories[:max(1, depth)])


def _page(rows: list, offset: int, limit: int) -> tuple[list, dict]:
    """Return a stable offset page plus enough metadata to fetch the next page."""
    start, size = max(0, offset), max(1, limit)
    window = rows[start:start + size]
    next_offset = start + len(window)
    has_more = next_offset < len(rows)
    return window, {
        "total": len(rows), "offset": start, "returned": len(window),
        "has_more": has_more, "next_offset": next_offset if has_more else None,
    }


class Comprehension:
    """Cached indexes and deterministic views for the comprehension MCP profile."""

    def __init__(self, store) -> None:
        self.store = store
        self.gl = store.gl
        self.index = store.index
        self._cached_source_root: Path | None | bool = False
        self._cached_source_file_list: tuple[Path, ...] | None = None

    def _source_root(self) -> Path | None:
        if self._cached_source_root is not False:
            return self._cached_source_root
        explicit = getattr(self.store, "source_dir", None)
        if explicit and os.path.isdir(explicit):
            self._cached_source_root = Path(explicit).resolve()
            return self._cached_source_root
        graph_path = getattr(self.store, "_core_path", None)
        if graph_path:
            try:
                from lachesis.kuzu_store import read_store_manifest
                recorded = read_store_manifest(graph_path).get("source_dir")
                if recorded and os.path.isdir(recorded):
                    self._cached_source_root = Path(recorded).resolve()
                    return self._cached_source_root
            except (OSError, ValueError, TypeError):
                pass
            # Graphs built through the user cache carry the source root in the cache
            # entry's metadata even when an older store manifest omitted it.  Reading
            # that tiny file avoids a 50-second Kuzu scan over every file node merely
            # to rediscover a path the builder already recorded.
            metadata_path = Path(graph_path).resolve().parent / "meta.json"
            try:
                recorded = json.loads(metadata_path.read_text(encoding="utf-8")).get(
                    "source_dir",
                )
                if recorded and os.path.isdir(recorded):
                    self._cached_source_root = Path(recorded).resolve()
                    return self._cached_source_root
            except (OSError, ValueError, TypeError, json.JSONDecodeError):
                pass
        absolute = []
        for file_node in self.index.nodes_of_kind("file"):
            path = file_node.get("properties", {}).get("absolute_file")
            if path and os.path.isabs(path):
                absolute.append(path)
        if not absolute:
            self._cached_source_root = None
            return None
        common = Path(os.path.commonpath(absolute))
        self._cached_source_root = common if common.is_dir() else common.parent
        return self._cached_source_root

    def _relative_path(self, path: str | None) -> str | None:
        """Normalize graph locations to the recorded repository root when possible."""
        if not path:
            return None
        root = self._source_root()
        candidate = Path(path)
        if root is not None and candidate.is_absolute():
            try:
                return candidate.resolve().relative_to(root).as_posix()
            except (OSError, ValueError):
                pass
        return path.strip("./")

    def _source_files(self):
        root = self._source_root()
        if root is None:
            return None, []
        if self._cached_source_file_list is not None:
            return root, list(self._cached_source_file_list)
        files = []
        skipped = {".git", ".hg", ".svn", "node_modules", "vendor", "dist", "build",
                   ".venv", "venv", "__pycache__"}
        for directory, names, filenames in os.walk(root):
            names[:] = [name for name in names if name not in skipped and not name.startswith(".")]
            base = Path(directory)
            for filename in filenames:
                path = base / filename
                if path.suffix.lower() in _TEXT_EXTENSIONS:
                    files.append(path)
        self._cached_source_file_list = tuple(sorted(files))
        return root, list(self._cached_source_file_list)

    def _source_matches(self, symbol: str, wanted: int,
                        accept, ignore_case: bool = False) -> tuple[list[dict], bool]:
        """Use ripgrep's streaming JSON as the source-reference index.

        Reading every source file in Python made one documentation lookup take about
        a minute on Django.  Ripgrep searches the same recorded source tree in a
        fraction of a second, while JSON output keeps paths containing colons safe.
        Stop after one row beyond the requested page so a broad identifier cannot
        create an unbounded captured response.  The fallback preserves portability
        when ripgrep is unavailable.
        """
        root, files = self._source_files()
        if root is None:
            return [], True
        target = max(1, wanted + 1)
        command = ["rg", "--json", "--max-filesize", "2M", "--hidden",
                   "--glob", "!.git/**", "--glob", "!node_modules/**",
                   "--glob", "!vendor/**"]
        if ignore_case:
            command.append("--ignore-case")
        command.extend(["-e", rf"\b{re.escape(symbol)}\b", str(root)])
        try:
            process = subprocess.Popen(
                command, text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            )
        except OSError:
            process = None
        matches: list[dict] = []
        exhausted = True
        if process is not None and process.stdout is not None:
            try:
                for raw in process.stdout:
                    try:
                        event = json.loads(raw)
                        if event.get("type") != "match":
                            continue
                        data = event["data"]
                        path = Path(data["path"]["text"])
                        line = data["lines"]["text"].rstrip("\r\n")
                        number = int(data["line_number"])
                    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
                        continue
                    try:
                        relative = path.resolve().relative_to(root).as_posix()
                    except ValueError:
                        continue
                    row = accept(path, relative, number, line)
                    if row is None:
                        continue
                    matches.append(row)
                    if len(matches) >= target:
                        exhausted = False
                        process.terminate()
                        break
            finally:
                process.stdout.close()
                if process.poll() is None:
                    process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            return matches, exhausted

        pattern = re.compile(rf"\b{re.escape(symbol)}\b",
                             re.IGNORECASE if ignore_case else 0)
        for path in files:
            try:
                if path.stat().st_size > 2_000_000:
                    continue
                lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            relative = path.relative_to(root).as_posix()
            for number, line in enumerate(lines, 1):
                if not pattern.search(line):
                    continue
                row = accept(path, relative, number, line)
                if row is not None:
                    matches.append(row)
                if len(matches) >= target:
                    return matches, False
        return matches, True

    def _declared_fields(self, typ: dict) -> list[dict]:
        """Type members, with a source-backed fallback for frontend ownership gaps."""
        members = [n for n in self.index.targets(typ["id"], "DECLARES_MEMBER")
                   if n.get("kind") in FIELD_KINDS]
        if members:
            return members
        source = self.gl.source_text(typ)
        if not source:
            return []
        names = []
        if typ.get("kind") == "record" and "{" in source and "}" in source:
            body = source[source.find("{") + 1:source.rfind("}")]
            body = re.sub(r"/\*.*?\*/|//[^\n]*", " ", body, flags=re.DOTALL)
            for declaration in body.split(";"):
                declaration = re.sub(r"#[^\n]*", " ", declaration).strip()
                if not declaration:
                    continue
                match = re.search(r"\(\s*\*\s*([A-Za-z_]\w*)\s*\)", declaration)
                if match is None:
                    match = re.search(
                        r"([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*(?::\s*\d+)?\s*$",
                        declaration,
                    )
                if match and match.group(1) not in names:
                    names.append(match.group(1))
        else:
            # Python and JS/TS frontends can represent ``self.x`` / ``this.x`` as
            # ordinary variables without a DECLARES_MEMBER edge. The field node is
            # still graph-addressable, so recover only names whose evidence lies
            # inside this recorded class definition.
            found = set()
            for match in re.finditer(
                    r"\b(?:self|this)\.([A-Za-z_$][A-Za-z0-9_$]*)", source):
                if re.match(r"\s*\(", source[match.end():]):
                    continue  # method invocation, not field evidence
                found.add(match.group(1))
            names = sorted(found)
        type_file, start, end = self.gl.loc(typ)
        fields = []
        for name in names:
            candidates = _matches(self.gl, name, FIELD_KINDS)
            local = []
            for node in candidates:
                file, line, _ = self.gl.loc(node)
                if file == type_file and (start is None or line is None or
                                          start <= line <= (end or start)):
                    local.append(node)
            fields.extend(local or candidates[:1])
        unique = {node["id"]: node for node in fields}
        return sorted(unique.values(), key=lambda node: (
            self.gl.loc(node)[0] or "", self.gl.loc(node)[1] or 0, self.gl.label(node)))

    def unknowns(self, function: str | None = None, limit: int = 100,
                 offset: int = 0) -> dict:
        """Return explicit graph frontiers, never turn absence into success."""
        owner_ids = None
        owner_nodes = []
        if function:
            owner_nodes = _matches(self.gl, function, frozenset(CALLABLE_KINDS))
            if not owner_nodes:
                return {"error": f"no function named {function!r}"}
            owner_ids = {n["id"] for n in owner_nodes}

        rows = []
        seen = set()
        calls = (n for owner_id in owner_ids
                 for n in self.index.nodes_owned_by(owner_id, "call", "construct")) \
            if owner_ids is not None else self.index.nodes_of_kind("call", "construct")
        for call in calls:
            owner = self.gl.owner_function(call)
            if owner_ids is not None and (not owner or owner["id"] not in owner_ids):
                continue
            outgoing = self.index.outgoing.get(call["id"], ())
            resolved = any(_semantic(e) in {"INVOKES", "MAY_INVOKE"} for e in outgoing)
            props = call.get("properties", {})
            resolution = props.get("resolution")
            if resolved or resolution in {"exact", "compiler-local", "binding"}:
                continue
            key = ("unresolved-call", call["id"])
            if key not in seen:
                seen.add(key)
                rows.append({**_loc(self.gl, call), "frontier": "unresolved-call",
                             "resolution": resolution or "missing-target",
                             "owner": _owner(self.gl, call)})
        behaviors = (n for owner_id in owner_ids
                     for n in self.index.nodes_owned_by(owner_id, "dynamic-behavior")) \
            if owner_ids is not None else self.index.nodes_of_kind("dynamic-behavior")
        for behavior in behaviors:
            props = behavior.get("properties", {})
            owner_id = props.get("owner_function_id")
            if owner_ids is not None and owner_id not in owner_ids:
                continue
            site_id = props.get("site_id")
            if site_id and ("unresolved-call", site_id) in seen:
                continue
            key = ("dynamic-behavior", behavior["id"])
            if key not in seen:
                seen.add(key)
                rows.append({**_loc(self.gl, behavior), "frontier": "dynamic-behavior",
                             "resolution": props.get("resolution", "runtime")})
        for diagnostic in self.index.nodes_of_kind("diagnostic"):
            if owner_ids is not None:
                continue
            rows.append({**_loc(self.gl, diagnostic), "frontier": "diagnostic",
                         "resolution": diagnostic.get("properties", {}).get("category")})
        for owner in owner_nodes:
            if self.index.nodes_owned_by(owner["id"]):
                continue
            rows.append({**_loc(self.gl, owner), "frontier": "missing-body",
                         "resolution": "declaration-only"})

        rows.sort(key=lambda r: (r["frontier"], r.get("file") or "", r.get("line") or 0))
        counts = Counter(r["frontier"] for r in rows)
        page, paging = _page(rows, offset, limit)
        return {
            "move": "unknowns", "scope": function or "graph",
            "status": "could-not-cross" if rows else "proven-absent",
            "counts": dict(sorted(counts.items())), "total": len(rows),
            "unknowns": page, "page": paging,
        }

    def coverage_map(self, component_depth: int = 1,
                     limit: int = DEFAULT_DETAIL_LIMIT, offset: int = 0) -> dict:
        """Describe graph coverage, not mutable client/session activity."""
        files = list(self.index.nodes_of_kind("file"))
        functions = list(self.index.nodes_of_kind(*CALLABLE_KINDS))
        body_owners = {
            n.get("properties", {}).get("owner_function_id")
            for n in self.index.nodes_of_kind("statement", "expression", "call", "construct")
        }
        body_owners.discard(None)
        diagnostics_by_file = Counter(
            n.get("properties", {}).get("file") for n in self.index.nodes_of_kind("diagnostic")
        )
        components = Counter()
        for node in functions:
            path = self._relative_path(self.gl.loc(node)[0])
            components[_component(path, component_depth) or "(unknown)"] += 1
        unresolved = self.unknowns(limit=1)
        component_rows = [{"component": name, "functions": count}
                          for name, count in sorted(components.items())]
        diagnostic_rows = [{"file": self._relative_path(name), "count": count}
                           for name, count in sorted(
                               diagnostics_by_file.items(), key=lambda item: item[0] or "",
                           ) if name]
        component_page, component_paging = _page(component_rows, offset, limit)
        diagnostic_page, diagnostic_paging = _page(diagnostic_rows, offset, limit)
        return {
            "move": "coverage_map", "basis": "indexed-graph",
            "counts": {
                "files": len(files), "functions": len(functions),
                "functions_with_body": len(body_owners & {n["id"] for n in functions}),
                "functions_without_body": len({n["id"] for n in functions} - body_owners),
                "diagnostics": sum(diagnostics_by_file.values()),
                "unmodeled_frontiers": unresolved.get("total", 0),
            },
            "components": component_page,
            "component_count": len(component_rows),
            "diagnostic_files": diagnostic_page,
            "diagnostic_file_count": len(diagnostic_rows),
            "pages": {"components": component_paging,
                      "diagnostic_files": diagnostic_paging},
            "interpretation": "graph coverage only; this does not track per-client reads",
        }

    def field_history(self, field: str, owner_type: str | None = None,
                      limit: int = DEFAULT_DETAIL_LIMIT, offset: int = 0) -> dict:
        matches = _matches(self.gl, field, FIELD_KINDS)
        if owner_type:
            type_nodes = _matches(self.gl, owner_type, TYPE_KINDS)
            type_ids = {n["id"] for n in type_nodes}
            member_ids = {e["target"] for tid in type_ids
                          for e in self.index.outgoing_of_kind(tid, "DECLARES_MEMBER")}
            member_ids.update(field_node["id"] for typ in type_nodes
                              for field_node in self._declared_fields(typ))
            matches = [n for n in matches if n["id"] in member_ids
                       or n.get("properties", {}).get("base_value_id") in type_ids]
        if not matches:
            return {"error": f"no field named {field!r}"}
        field_ids = {n["id"] for n in matches}
        # Walk only the field's local value-flow cone.  This is both more accurate than
        # inspecting every similarly named node and safe for a disk-backed large graph.
        related_ids = set(field_ids)
        frontier = list(field_ids)
        for _depth in range(4):
            following = []
            for node_id in frontier:
                for edge in (*self.index.incoming.get(node_id, ()),
                             *self.index.outgoing.get(node_id, ())):
                    if _semantic(edge) not in FLOW_KINDS:
                        continue
                    other = edge["source"] if edge["target"] == node_id else edge["target"]
                    if other not in related_ids and other in self.gl.nodes:
                        related_ids.add(other)
                        following.append(other)
            frontier = following
            if not frontier:
                break

        events = []
        for node_id in related_ids - field_ids:
            node = self.gl.nodes[node_id]
            if node["id"] in field_ids:
                continue
            props = node.get("properties", {})
            incoming = self.index.incoming.get(node["id"], ())
            outgoing = self.index.outgoing.get(node["id"], ())
            touches = [e for e in (*incoming, *outgoing)
                       if (e.get("source") in field_ids or e.get("target") in field_ids)
                       and _semantic(e) in FLOW_KINDS | CONTROL_KINDS]
            kinds = {_semantic(e) for e in touches}
            for edge in (*incoming, *outgoing):
                if _semantic(edge) in CONTROL_KINDS:
                    kinds.add(_semantic(edge))
            if node.get("kind") == "write" or "WRITES_TO" in kinds:
                role = "modified"
                if props.get("write_kind") in {"declaration", "initialization"}:
                    role = "initialized"
            elif node.get("kind") == "read" or "READS_FROM" in kinds:
                role = "read"
            elif kinds & CONTROL_KINDS:
                role = "checked"
            else:
                role = "flows"
            events.append({**_loc(self.gl, node), "role": role,
                           "owner": _owner(self.gl, node),
                           "via": sorted(kinds & (FLOW_KINDS | CONTROL_KINDS))})
        events.sort(key=lambda r: (r.get("file") or "", r.get("line") or 0, r["role"]))
        page, paging = _page(events, offset, limit)
        return {"move": "field_history", "field": field,
                "matches": [_loc(self.gl, n) for n in matches],
                "counts": dict(sorted(Counter(e["role"] for e in events).items())),
                "event_count": len(events), "events": page, "page": paging}

    def sibling_compare(self, symbol: str, limit: int = DEFAULT_DETAIL_LIMIT,
                        offset: int = 0, call_offset: int = 0) -> dict:
        """Structural peer diff without security vocabulary or adjudication."""
        from .siblings import _anchor
        hits = _matches(self.gl, symbol, frozenset(CALLABLE_KINDS))
        if not hits:
            return {"error": f"no callable named {symbol!r}"}
        seed = hits[0]
        seed_entry = next((e for e in self.store.entries if e["node_id"] == seed["id"]), None)
        if not seed_entry:
            return {"error": f"no index entry for {symbol!r}"}
        verb, nouns = _anchor(seed_entry)
        members = []
        for entry in self.store.entries:
            if entry.get("granularity") not in ("function", "method", "constructor"):
                continue
            other_verb, other_nouns = _anchor(entry)
            if entry["node_id"] != seed["id"] and (other_verb != verb or not nouns & other_nouns):
                continue
            node = self.gl.nodes[entry["node_id"]]
            callees = sorted({self.gl.label(n) for n in self.gl.calls_from(node["id"])})
            controls = Counter(
                n.get("properties", {}).get("control_kind")
                for n in self.gl.body_nodes(node["id"])
                if n.get("properties", {}).get("control_kind")
            )
            call_page, call_paging = _page(callees, call_offset, limit)
            members.append({**_loc(self.gl, node), "call_count": len(callees),
                            "calls": call_page, "calls_page": call_paging,
                            "control": dict(sorted(controls.items()))})
        all_calls = Counter(c for member in members for c in member["calls"])
        for member in members:
            member["differences"] = {
                "calls_unique": [c for c in member["calls"] if all_calls[c] == 1],
                "calls_missing": [c for c, count in sorted(all_calls.items())
                                  if count == len(members) - 1 and c not in member["calls"]],
            }
        family_size = len(members)
        page, paging = _page(members, offset, limit)
        return {"move": "sibling_compare", "symbol": symbol,
                "family_key": {"verb": verb, "nouns": sorted(nouns)},
                "family_size": family_size, "members": page, "page": paging}

    def type_explain(self, type_name: str, limit: int = DEFAULT_DETAIL_LIMIT,
                     offset: int = 0, member_offset: int = 0) -> dict:
        matches = _matches(self.gl, type_name, TYPE_KINDS)
        if not matches:
            return {"error": f"no type named {type_name!r}"}
        declarations = sorted((_loc(self.gl, node) for node in matches), key=lambda row: (
            row.get("file") or "", row.get("line") or 0))
        declarations_page, declarations_paging = _page(declarations, member_offset, limit)
        # C emits one record node per forward declaration. Consolidate those into the
        # body-bearing definition; reporting each as a separate type repeats the same
        # 1,600 consumers and can turn one explanation into a multi-minute response.
        if matches and all(node.get("kind") == "record" for node in matches):
            matches = [max(matches, key=lambda node: len(self.gl.source_text(node)))]
        def node_id(item):
            return item["id"] if isinstance(item, dict) else item

        write_ids = {node_id(item) for item in self.index.by_kind.get("write", ())}
        mutation_sources = {edge["source"] for edge in self.index.edges_of_kind(
            "WRITES_TO", "WRITES_PARAMETER_PROPERTY", "MUTATES")}
        types = []
        for typ in matches:
            member_nodes = list(self.index.targets(typ["id"], "DECLARES_MEMBER"))
            fields = [_loc(self.gl, n) for n in self._declared_fields(typ)]
            methods = [n for n in member_nodes if n.get("kind") in CALLABLE_KINDS]
            # Some frontends encode ownership as a property rather than DECLARES_MEMBER.
            methods.extend(n for n in self.index.nodes_owned_by(typ["id"], *CALLABLE_KINDS)
                           if n not in methods)
            # C has free functions rather than methods. A typed parameter is the
            # deterministic relationship between such a function and its record.
            type_label = self.gl.label(typ).casefold()
            for parameter in self.index.nodes_of_kind("parameter"):
                declared = str(parameter.get("properties", {}).get("type") or
                               parameter.get("properties", {}).get("declared_type") or "")
                if type_label not in declared.casefold():
                    continue
                owner = self.gl.owner_function(parameter)
                if owner and owner not in methods:
                    methods.append(owner)
            roles = defaultdict(list)
            for method in methods:
                name = self.gl.label(method).casefold()
                if method.get("kind") == "constructor" or name in {"__init__", "new", "create"}:
                    role = "constructor"
                elif any(tok in name for tok in ("free", "destroy", "dispose", "close", "release")):
                    role = "destructor"
                elif (method["id"] in mutation_sources
                      or any(node_id(item) in write_ids
                             for item in self.index.by_owner.get(method["id"], ()))):
                    role = "mutator"
                else:
                    role = "consumer"
                roles[role].append(_loc(self.gl, method))
            field_page, field_paging = _page(fields, member_offset, limit)
            role_pages = {k: _page(v, member_offset, limit) for k, v in roles.items()}
            types.append({**_loc(self.gl, typ), "field_count": len(fields),
                          "fields": field_page, "fields_page": field_paging,
                          "roles": {k: role_pages[k][0] for k in sorted(role_pages)},
                          "role_pages": {k: role_pages[k][1] for k in sorted(role_pages)},
                          "role_counts": {k: len(v) for k, v in sorted(roles.items())},
                          })
        page, paging = _page(types, offset, limit)
        return {"move": "type_explain", "query": type_name,
                "type_count": len(types), "types": page, "page": paging,
                "declaration_count": len(declarations),
                "declarations": declarations_page,
                "declarations_page": declarations_paging}

    def component_boundary(self, source: str, target: str,
                           limit: int = DEFAULT_DETAIL_LIMIT, offset: int = 0) -> dict:
        """Facts crossing two path components in either direction."""
        def belongs(path, component):
            if not path:
                return False
            clean = (self._relative_path(path) or "").strip("./")
            component = component.strip("./")
            return clean == component or clean.startswith(component + "/")

        rows, seen = [], set()
        boundary_edges = list(self.index.edges_of_kind("CALLS"))
        boundary_edges.extend(self.index.edges_of_kind(
            "INVOKES", "MAY_INVOKE", "PASSES_CALLBACK", "TYPE_REFERS_TO", "HAS_TYPE"))
        for edge in boundary_edges:
            left, right = self.gl.nodes.get(edge.get("source")), self.gl.nodes.get(edge.get("target"))
            if not left or not right:
                continue
            left_owner, right_owner = self.gl.owner_function(left), self.gl.owner_function(right)
            left = left_owner or left
            right = right_owner or right
            lf, _, _ = self.gl.loc(left)
            rf, _, _ = self.gl.loc(right)
            direction = None
            if belongs(lf, source) and belongs(rf, target):
                direction = f"{source}->{target}"
            elif belongs(lf, target) and belongs(rf, source):
                direction = f"{target}->{source}"
            if not direction:
                continue
            semantic = _semantic(edge)
            category = "call" if semantic in CALL_EDGE_KINDS else semantic
            key = (left["id"], right["id"], category)
            if key in seen:
                continue
            seen.add(key)
            rows.append({"direction": direction, "kind": _semantic(edge),
                         "source": _loc(self.gl, left), "target": _loc(self.gl, right),
                         "confidence": edge.get("properties", {}).get("confidence")})
        rows.sort(key=lambda r: (r["direction"], r["kind"], r["source"]["name"],
                                 r["target"]["name"]))
        page, paging = _page(rows, offset, limit)
        return {"move": "component_boundary", "from": source, "to": target,
                "count": len(rows), "crossings": page, "page": paging}

    def indirect_targets(self, function: str,
                         limit: int = DEFAULT_DETAIL_LIMIT, offset: int = 0,
                         target_offset: int = 0) -> dict:
        """Resolve each indirect call site separately and preserve undecidable slots."""
        hits = _matches(self.gl, function, frozenset(CALLABLE_KINDS))
        if not hits:
            return {"error": f"no function named {function!r}"}
        sites = []
        for owner in hits:
            for call in self.index.nodes_owned_by(owner["id"], "call", "construct"):
                edges = [e for e in self.index.outgoing.get(call["id"], ())
                         if _semantic(e) in {"INVOKES", "MAY_INVOKE", "READS_CALLEE",
                                             "PASSES_CALLBACK", "CONTEXT_CALLS"}]
                indirect = [e for e in edges if _semantic(e) != "INVOKES"
                            or e.get("properties", {}).get("dispatch")]
                # Registration APIs commonly receive an ops table as an argument.
                # The MAY_INVOKE edges live on that table variable, not on this call
                # site, so follow the argument's small value/reference cone back to it.
                argument_ids = [e["target"] for e in self.index.outgoing.get(call["id"], ())
                                if _semantic(e) == "HAS_ARGUMENT"]
                cone, arg_frontier = set(argument_ids), list(argument_ids)
                for _depth in range(4):
                    following = []
                    for node_id in arg_frontier:
                        for edge in (*self.index.incoming.get(node_id, ()),
                                     *self.index.outgoing.get(node_id, ())):
                            if _semantic(edge) not in {"VALUE_FLOWS_TO", "REFERS_TO",
                                                       "READS_FROM", "DEFINES"}:
                                continue
                            other = (edge["source"] if edge["target"] == node_id
                                     else edge["target"])
                            if other not in cone and other in self.gl.nodes:
                                cone.add(other)
                                following.append(other)
                    arg_frontier = following
                    if not arg_frontier:
                        break
                for node_id in cone:
                    indirect.extend(e for e in self.index.outgoing.get(node_id, ())
                                    if _semantic(e) in {"MAY_INVOKE", "PASSES_CALLBACK"})
                props = call.get("properties", {})
                if not indirect and props.get("resolution") not in {
                    "dynamic", "dynamic-or-unresolved", "function-pointer", "over-cap",
                    "local-value", "unresolved",
                }:
                    continue
                targets = []
                target_keys = set()
                for edge in indirect:
                    target = self.gl.nodes.get(edge.get("target"))
                    if not target:
                        continue
                    ep = edge.get("properties", {})
                    target_key = (target["id"], _semantic(edge), ep.get("slot"))
                    if target_key in target_keys:
                        continue
                    target_keys.add(target_key)
                    targets.append({**_loc(self.gl, target), "via": _semantic(edge),
                                    "dispatch": ep.get("dispatch"),
                                    "slot": ep.get("slot"),
                                    "confidence": ep.get("confidence")})
                if targets and not any(_semantic(e) != "INVOKES" for e in edges):
                    resolution = "registration"
                else:
                    resolution = props.get("resolution") or ("resolved" if targets else "unresolved")
                target_page, target_paging = _page(targets, target_offset, limit)
                sites.append({**_loc(self.gl, call), "owner": _loc(self.gl, owner),
                              "resolution": resolution,
                              "slot": props.get("method_name") or props.get("callee"),
                              "target_count": len(targets),
                              "targets": target_page, "targets_page": target_paging,
                              "resolved": bool(targets)})
        sites.sort(key=lambda r: (r.get("file") or "", r.get("line") or 0))
        page, paging = _page(sites, offset, limit)
        return {"move": "indirect_targets", "function": function,
                "sites": page, "page": paging,
                "counts": {
                    "sites": len(sites), "resolved": sum(s["resolved"] for s in sites),
                    "unresolved": sum(not s["resolved"] for s in sites),
                }}

    def architecture_map(self, component_depth: int = 2, max_communities: int = 30,
                         max_files_per_community: int = COMMUNITY_FILE_LIMIT,
                         offset: int = 0, file_offset: int = 0) -> dict:
        """Deterministic label-propagation communities over call + include edges."""
        files = {n["id"]: self._relative_path(
            self.gl.loc(n)[0] or self.gl.prop(n, "file"))
                 for n in self.index.nodes_of_kind("file")}
        path_to_id = {path: node_id for node_id, path in files.items() if path}
        adjacency: dict[str, Counter] = defaultdict(Counter)
        call_degree = Counter()

        def file_id(node):
            path = self._relative_path(self.gl.loc(node)[0])
            if path in path_to_id:
                return path_to_id[path]
            # File nodes can use a relative path while declarations carry an absolute one.
            return next((fid for p, fid in path_to_id.items()
                         if path and (path.endswith("/" + p) or p.endswith("/" + path))), None)

        for edge in self.index.edges_of_kind("CALLS", "DEPENDS_ON", "RUNTIME_DEPENDS_ON",
                                             "RE_EXPORTS"):
            left, right = self.gl.nodes.get(edge["source"]), self.gl.nodes.get(edge["target"])
            if not left or not right:
                continue
            lf = left["id"] if left.get("kind") == "file" else file_id(left)
            rf = right["id"] if right.get("kind") == "file" else file_id(right)
            if not lf or not rf or lf == rf:
                continue
            adjacency[lf][rf] += 1
            adjacency[rf][lf] += 1
            if _semantic(edge) == "CALLS":
                call_degree[left["id"]] += 1
                call_degree[right["id"]] += 1

        labels = {fid: _component(path, component_depth) or fid
                  for fid, path in files.items()}
        for _round in range(12):
            changed = False
            for fid in sorted(files, key=lambda x: (-sum(adjacency[x].values()), files[x] or x)):
                scores = Counter()
                for neighbor, weight in adjacency[fid].items():
                    scores[labels[neighbor]] += weight
                if not scores:
                    continue
                best = min(scores, key=lambda label: (-scores[label], files.get(label) or label))
                if best != labels[fid]:
                    labels[fid] = best
                    changed = True
            if not changed:
                break
        # Collapse label chains created by an update round.
        for fid in labels:
            seen = set()
            label = labels[fid]
            while label in labels and label not in seen and labels[label] != label:
                seen.add(label)
                label = labels[label]
            labels[fid] = label

        grouped = defaultdict(list)
        for fid, label in labels.items():
            grouped[label].append(fid)
        functions_by_file = defaultdict(list)
        for fn in self.index.nodes_of_kind(*CALLABLE_KINDS):
            functions_by_file[file_id(fn)].append(fn)
        communities = []
        for _label, member_ids in grouped.items():
            member_paths = sorted(files[fid] for fid in member_ids if files[fid])
            member_set = set(member_ids)
            internal = sum(weight for fid in member_ids
                           for neighbor, weight in adjacency[fid].items()
                           if neighbor in member_set) // 2
            crossing = sum(weight for fid in member_ids
                           for neighbor, weight in adjacency[fid].items()
                           if neighbor not in member_set)
            functions = [fn for fid in member_ids for fn in functions_by_file.get(fid, ())]
            hubs = sorted(functions, key=lambda n: (-call_degree[n["id"]], self.gl.label(n)))[:5]
            file_page, file_paging = _page(
                member_paths, file_offset, max_files_per_community)
            communities.append({
                "id": min(member_paths) if member_paths else str(_label),
                "file_count": len(member_paths), "files": file_page,
                "files_page": file_paging,
                "internal_edges": internal,
                "boundary_edges": crossing,
                "hubs": [{**_loc(self.gl, n), "call_degree": call_degree[n["id"]]}
                         for n in hubs if call_degree[n["id"]]],
            })
        communities.sort(key=lambda c: (-c["file_count"], c["id"]))
        page, paging = _page(communities, offset, max_communities)
        return {"move": "architecture_map", "algorithm": "weighted-label-propagation",
                "inputs": ["CALLS", "DEPENDS_ON", "RUNTIME_DEPENDS_ON", "RE_EXPORTS"],
                "counts": {"files": len(files), "communities": len(communities)},
                "communities": page, "page": paging}

    def execution_story(self, entry: str, max_depth: int = 5,
                        max_steps: int = 100) -> dict:
        """Forward call/branch trace.  The result is structure, never narrative prose."""
        hits = _matches(self.gl, entry, frozenset(CALLABLE_KINDS))
        if not hits:
            return {"error": f"no function named {entry!r}"}
        root = hits[0]
        queue = deque([(root, 0, None, "entry")])
        visited, steps, frontier = set(), [], []
        while queue and len(steps) < max(1, max_steps):
            function, depth, caller, via = queue.popleft()
            if function["id"] in visited:
                continue
            visited.add(function["id"])
            body = self.index.nodes_owned_by(function["id"])
            branches = [{**_loc(self.gl, n),
                         "control": n.get("properties", {}).get("control_kind")}
                        for n in body if n.get("properties", {}).get("control_kind")
                        in {"if", "switch", "while", "for", "for-each", "try"}]
            branch_limit = min(20, max(1, max_steps))
            step = {"sequence": len(steps), "depth": depth,
                    "function": _loc(self.gl, function),
                    "caller": _loc(self.gl, caller) if caller else None,
                    "via": via, "branch_count": len(branches),
                    "branches": branches[:branch_limit],
                    "branches_truncated": len(branches) > branch_limit}
            steps.append(step)
            callees = [(n, "direct") for n in self.index.targets(function["id"], "CALLS")]
            for call in self.index.nodes_owned_by(function["id"], "call", "construct"):
                for edge in self.index.outgoing.get(call["id"], ()):
                    kind = _semantic(edge)
                    if kind not in {"INVOKES", "MAY_INVOKE", "CONTEXT_CALLS"}:
                        continue
                    target = self.gl.nodes.get(edge["target"])
                    if target and target.get("kind") in CALLABLE_KINDS:
                        dispatch = edge.get("properties", {}).get("dispatch") or kind.lower()
                        callees.append((target, f"indirect:{dispatch}"))
            deduped = {}
            for callee, call_via in callees:
                deduped.setdefault(callee["id"], (callee, call_via))
            if depth >= max(0, max_depth):
                frontier.extend(_loc(self.gl, callee) for callee, _ in deduped.values()
                                if callee["id"] not in visited)
                continue
            for callee, call_via in sorted(
                    deduped.values(), key=lambda item: (self.gl.loc(item[0])[0] or "",
                                                        self.gl.loc(item[0])[1] or 0)):
                queue.append((callee, depth + 1, function, call_via))
        if queue:
            frontier.extend(_loc(self.gl, fn) for fn, _depth, _caller, _via in queue)
        return {"move": "execution_story", "entry": _loc(self.gl, root),
                "algorithm": "bounded-forward-call-and-branch-trace",
                "limits": {"max_depth": max_depth, "max_steps": max_steps},
                "steps": steps, "frontier": frontier[:max(1, max_steps)],
                "frontier_count": len(frontier),
                "frontier_truncated": len(frontier) > max(1, max_steps),
                "complete": not queue and not frontier}

    def change_context(self, symbol: str, limit: int = 12) -> dict:
        """Join a graph symbol to Git history without interpreting commit intent."""
        hits = _matches(self.gl, symbol)
        if not hits:
            return {"error": f"no symbol named {symbol!r}"}
        root = self._source_root()
        if root is None:
            return {"error": "source tree unavailable; graph manifest has no usable source_dir"}
        files = []
        for node in hits:
            path = self.gl.loc(node)[0]
            if not path:
                continue
            candidate = Path(path)
            if candidate.is_absolute():
                try:
                    path = candidate.resolve().relative_to(root).as_posix()
                except ValueError:
                    continue
            if path not in files:
                files.append(path)
        if not files:
            return {"error": f"symbol {symbol!r} has no source file"}
        command = ["git", "-C", str(root), "log", f"-n{max(1, limit)}",
                   "--format=%H%x1f%an%x1f%aI%x1f%s", "--", *files]
        completed = subprocess.run(command, text=True, capture_output=True, check=False)
        if completed.returncode != 0:
            return {"error": "source tree is not readable as a Git worktree",
                    "detail": completed.stderr.strip()[:500]}
        commits = []
        for line in completed.stdout.splitlines():
            parts = line.split("\x1f", 3)
            if len(parts) == 4:
                commits.append({"commit": parts[0], "author": parts[1],
                                "date": parts[2], "subject": parts[3]})
        return {"move": "change_context", "symbol": symbol,
                "matches": [_loc(self.gl, n) for n in hits],
                "files": files, "commits": commits,
                "status": "history-found" if commits else "no-history"}

    def tests_for(self, symbol: str, limit: int = 50, offset: int = 0) -> dict:
        """Find test references in the source tree that the production graph excludes."""
        root, files = self._source_files()
        if root is None:
            return {"error": "source tree unavailable; graph manifest has no usable source_dir"}
        test_files = [path for path in files
                      if _TEST_FILE.search(path.relative_to(root).as_posix())]
        line_cache: dict[Path, list[str]] = {}

        def accept(path: Path, relative: str, number: int, line: str):
            if not _TEST_FILE.search(relative):
                return None
            try:
                lines = line_cache.get(path)
                if lines is None:
                    lines = path.read_text(
                        encoding="utf-8", errors="replace",
                    ).splitlines()
                    line_cache[path] = lines
            except OSError:
                return None
            nearby = " ".join(lines[max(0, number - 2):min(len(lines), number + 1)])
            return {"file": relative, "line": number, "snippet": line.strip()[:300],
                    "assertion_nearby": bool(re.search(
                        r"\b(assert|expect|should|require|CHECK|ASSERT)", nearby,
                        re.IGNORECASE))}

        start, size = max(0, offset), max(1, limit)
        found, exhausted = self._source_matches(symbol, start + size, accept)
        references = found[start:start + size]
        has_more = len(found) > start + len(references)
        pagination = {"total": len(found) if exhausted else None,
                      "total_at_least": len(found), "offset": start,
                      "returned": len(references), "has_more": has_more,
                      "next_offset": start + len(references) if has_more else None}
        return {"move": "tests_for", "symbol": symbol,
                "test_files_searched": len(test_files), "references": references,
                "pagination": pagination, "truncated": has_more}

    def spec_links(self, symbol: str, limit: int = 50, offset: int = 0) -> dict:
        """Link a symbol to docs, format definitions, standards URLs, and comments."""
        root, files = self._source_files()
        if root is None:
            return {"error": "source tree unavailable; graph manifest has no usable source_dir"}
        doc_suffixes = {".md", ".rst", ".txt", ".adoc"}
        docs_searched = sum(path.suffix.lower() in doc_suffixes for path in files)

        def accept(path: Path, relative: str, number: int, line: str):
            is_doc = path.suffix.lower() in {".md", ".rst", ".txt", ".adoc"}
            if not is_doc and _TEST_FILE.search(relative):
                return None
            stripped = line.strip()
            is_comment = stripped.startswith(("//", "/*", "*", "#", "--"))
            if not is_doc and not is_comment:
                return None
            urls = re.findall(r"https?://[^\s)>\]}]+", line)
            return {"file": relative, "line": number,
                    "kind": "documentation" if is_doc else "comment",
                    "snippet": stripped[:300], "urls": urls}

        start, size = max(0, offset), max(1, limit)
        found, exhausted = self._source_matches(
            symbol, start + size, accept, ignore_case=True,
        )
        references = found[start:start + size]
        has_more = len(found) > start + len(references)
        pagination = {"total": len(found) if exhausted else None,
                      "total_at_least": len(found), "offset": start,
                      "returned": len(references), "has_more": has_more,
                      "next_offset": start + len(references) if has_more else None}
        return {"move": "spec_links", "symbol": symbol,
                "docs_searched": docs_searched, "references": references,
                "pagination": pagination, "truncated": has_more}

    def context_pack(self, question: str, max_symbols: int = 6,
                     max_neighbors: int = 30, semantic_hits=None,
                     semantic_status: str | None = None) -> dict:
        """Compose a minimal factual neighborhood around question-relevant symbols."""
        query_tokens = set(camel_tokens(question))
        query_tokens.update(re.findall(r"[A-Za-z_][A-Za-z0-9_]+", question.casefold()))
        stop = {"a", "an", "and", "are", "does", "for", "from", "how", "in", "is",
                "of", "the", "this", "to", "what", "where", "which", "why", "with"}
        query_tokens -= stop
        score_by_id = {}
        entries = self.store.entries
        entry_by_id = {entry["node_id"]: entry for entry in entries}
        for entry in entries:
            if entry.get("granularity") not in ("function", "method", "type"):
                continue
            name_tokens = set(entry.get("tokens") or camel_tokens(entry.get("name", "")))
            overlap = query_tokens & name_tokens
            if not overlap:
                continue
            exact = entry.get("name", "").casefold() in question.casefold()
            score = len(overlap) * 10 + (20 if exact else 0) + min(entry.get("degree", 0), 10)
            score_by_id[entry["node_id"]] = (float(score), entry)
        for hit in semantic_hits or ():
            node = self.gl.nodes.get(hit.get("node_id"))
            if not node or node.get("kind") not in set(CALLABLE_KINDS) | TYPE_KINDS:
                continue
            entry = entry_by_id.get(node["id"])
            if not entry:
                continue
            semantic_score = max(0.0, float(hit.get("score", 0.0))) * 100.0
            prior = score_by_id.get(node["id"], (0.0, entry))[0]
            score_by_id[node["id"]] = (prior + semantic_score, entry)
        scored = list(score_by_id.values())
        scored.sort(key=lambda item: (-item[0], item[1].get("file") or "",
                                      item[1].get("line") or 0))
        selected = scored[:max(1, max_symbols)]
        seeds = [entry for _score, entry in selected]
        if not seeds:
            return {"move": "context_pack", "question": question,
                    "status": "no-identifier-match", "selection_basis": "identifier-tokens",
                    "semantic_search": semantic_status or
                                       "unavailable: configure concept_search embeddings",
                    "symbols": [], "relationships": [], "conditions": [], "unknowns": []}

        included = {entry["node_id"] for entry in seeds}
        relationships = []
        for entry in seeds:
            node_id = entry["node_id"]
            for edge in (*self.index.outgoing_of_kind(node_id, "CALLS"),
                         *self.index.incoming_of_kind(node_id, "CALLS")):
                other_id = edge["target"] if edge["source"] == node_id else edge["source"]
                other = self.gl.nodes.get(other_id)
                if not other:
                    continue
                included.add(other_id)
                relationships.append({"kind": "CALLS", "source": _loc(
                    self.gl, self.gl.nodes[edge["source"]]),
                    "target": _loc(self.gl, self.gl.nodes[edge["target"]])})
                if len(relationships) >= max(1, max_neighbors):
                    break
            if len(relationships) >= max(1, max_neighbors):
                break

        conditions = []
        for node_id in included:
            node = self.gl.nodes.get(node_id)
            if not node or node.get("kind") not in CALLABLE_KINDS:
                continue
            for body in self.index.nodes_owned_by(node_id):
                control = body.get("properties", {}).get("control_kind")
                if control in {"if", "switch", "while", "for", "for-each", "try"}:
                    conditions.append({**_loc(self.gl, body), "control": control,
                                       "owner": _loc(self.gl, node)})

        unknown_rows = []
        for seed in seeds:
            if seed.get("granularity") not in ("function", "method"):
                continue
            answer = self.unknowns(seed["node_id"], limit=20)
            unknown_rows.extend(answer.get("unknowns", ()))
        test_refs = self.tests_for(seeds[0]["name"], limit=20)
        if "error" in test_refs:
            test_refs = {"status": "source-unavailable", "references": []}
        spec_refs = self.spec_links(seeds[0]["name"], limit=20)
        if "error" in spec_refs:
            spec_refs = {"status": "source-unavailable", "references": []}
        symbols = [_loc(self.gl, self.gl.nodes[node_id]) for node_id in included
                   if node_id in self.gl.nodes]
        symbols.sort(key=lambda row: (row.get("file") or "", row.get("line") or 0))
        return {"move": "context_pack", "question": question, "status": "complete",
                "selection_basis": ("semantic-plus-identifier" if semantic_hits
                                    else "identifier-token-relevance"),
                "semantic_search": semantic_status or
                                   "unavailable: configure concept_search embeddings",
                "seeds": [{**_loc(self.gl, self.gl.nodes[entry["node_id"]]),
                           "score": score} for score, entry in selected],
                "symbols": symbols, "relationships": relationships,
                "conditions": conditions, "tests": test_refs.get("references", []),
                "specs": spec_refs.get("references", []), "unknowns": unknown_rows,
                "limits": {"max_symbols": max_symbols, "max_neighbors": max_neighbors}}
