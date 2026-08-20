"""Deterministic code-comprehension views over the canonical graph.

These queries deliberately stop at graph facts.  They do not generate prose, rank
security anomalies, or retain session state; callers can compose the small, stable
answers into whatever narrative they need.
"""
from __future__ import annotations

from collections import Counter, defaultdict, deque
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


class Comprehension:
    """Cached indexes and deterministic views for the comprehension MCP profile."""

    def __init__(self, store) -> None:
        self.store = store
        self.gl = store.gl
        self.index = store.index

    def _source_root(self) -> Path | None:
        explicit = getattr(self.store, "source_dir", None)
        if explicit and os.path.isdir(explicit):
            return Path(explicit).resolve()
        graph_path = getattr(self.store, "_core_path", None)
        if graph_path:
            try:
                from lachesis.kuzu_store import read_store_manifest
                recorded = read_store_manifest(graph_path).get("source_dir")
                if recorded and os.path.isdir(recorded):
                    return Path(recorded).resolve()
            except (OSError, ValueError, TypeError):
                pass
        absolute = []
        for file_node in self.index.nodes_of_kind("file"):
            path = file_node.get("properties", {}).get("absolute_file")
            if path and os.path.isabs(path):
                absolute.append(path)
        if not absolute:
            return None
        common = Path(os.path.commonpath(absolute))
        return common if common.is_dir() else common.parent

    def _source_files(self):
        root = self._source_root()
        if root is None:
            return None, []
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
        return root, sorted(files)

    def unknowns(self, function: str | None = None, limit: int = 100) -> dict:
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
        return {
            "move": "unknowns", "scope": function or "graph",
            "status": "could-not-cross" if rows else "proven-absent",
            "counts": dict(sorted(counts.items())), "total": len(rows),
            "unknowns": rows[:max(1, limit)], "truncated": len(rows) > max(1, limit),
        }

    def coverage_map(self, component_depth: int = 1) -> dict:
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
            components[_component(self.gl.loc(node)[0], component_depth) or "(unknown)"] += 1
        unresolved = self.unknowns(limit=1)
        return {
            "move": "coverage_map", "basis": "indexed-graph",
            "counts": {
                "files": len(files), "functions": len(functions),
                "functions_with_body": len(body_owners & {n["id"] for n in functions}),
                "functions_without_body": len({n["id"] for n in functions} - body_owners),
                "diagnostics": sum(diagnostics_by_file.values()),
                "unmodeled_frontiers": unresolved.get("total", 0),
            },
            "components": [{"component": name, "functions": count}
                           for name, count in sorted(components.items())],
            "diagnostic_files": [{"file": name, "count": count}
                                 for name, count in sorted(diagnostics_by_file.items()) if name],
            "interpretation": "graph coverage only; this does not track per-client reads",
        }

    def field_history(self, field: str, owner_type: str | None = None) -> dict:
        matches = _matches(self.gl, field, FIELD_KINDS)
        if owner_type:
            type_ids = {n["id"] for n in _matches(self.gl, owner_type, TYPE_KINDS)}
            member_ids = {e["target"] for tid in type_ids
                          for e in self.index.outgoing_of_kind(tid, "DECLARES_MEMBER")}
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
        return {"move": "field_history", "field": field,
                "matches": [_loc(self.gl, n) for n in matches],
                "counts": dict(sorted(Counter(e["role"] for e in events).items())),
                "events": events}

    def sibling_compare(self, symbol: str) -> dict:
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
            members.append({**_loc(self.gl, node), "calls": callees,
                            "control": dict(sorted(controls.items()))})
        all_calls = Counter(c for member in members for c in member["calls"])
        for member in members:
            member["differences"] = {
                "calls_unique": [c for c in member["calls"] if all_calls[c] == 1],
                "calls_missing": [c for c, count in sorted(all_calls.items())
                                  if count == len(members) - 1 and c not in member["calls"]],
            }
        return {"move": "sibling_compare", "symbol": symbol,
                "family_key": {"verb": verb, "nouns": sorted(nouns)},
                "family_size": len(members), "members": members}

    def type_explain(self, type_name: str) -> dict:
        matches = _matches(self.gl, type_name, TYPE_KINDS)
        if not matches:
            return {"error": f"no type named {type_name!r}"}
        types = []
        for typ in matches:
            member_nodes = list(self.index.targets(typ["id"], "DECLARES_MEMBER"))
            fields = [_loc(self.gl, n) for n in member_nodes if n.get("kind") in FIELD_KINDS]
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
                elif (any(_semantic(e) in {"WRITES_TO", "WRITES_PARAMETER_PROPERTY", "MUTATES"}
                          for e in self.index.outgoing.get(method["id"], ()))
                      or any(n.get("kind") == "write"
                             for n in self.gl.body_nodes(method["id"]))):
                    role = "mutator"
                else:
                    role = "consumer"
                roles[role].append(_loc(self.gl, method))
            types.append({**_loc(self.gl, typ), "fields": fields,
                          "roles": {k: v for k, v in sorted(roles.items())}})
        return {"move": "type_explain", "query": type_name, "types": types}

    def component_boundary(self, source: str, target: str) -> dict:
        """Facts crossing two path components in either direction."""
        def belongs(path, component):
            if not path:
                return False
            clean = path.strip("./")
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
        return {"move": "component_boundary", "from": source, "to": target,
                "count": len(rows), "crossings": rows}

    def indirect_targets(self, function: str) -> dict:
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
                sites.append({**_loc(self.gl, call), "owner": _loc(self.gl, owner),
                              "resolution": resolution,
                              "slot": props.get("method_name") or props.get("callee"),
                              "targets": targets, "resolved": bool(targets)})
        sites.sort(key=lambda r: (r.get("file") or "", r.get("line") or 0))
        return {"move": "indirect_targets", "function": function,
                "sites": sites, "counts": {
                    "sites": len(sites), "resolved": sum(s["resolved"] for s in sites),
                    "unresolved": sum(not s["resolved"] for s in sites),
                }}

    def architecture_map(self, component_depth: int = 2, max_communities: int = 30) -> dict:
        """Deterministic label-propagation communities over call + include edges."""
        files = {n["id"]: self.gl.loc(n)[0] or self.gl.prop(n, "file")
                 for n in self.index.nodes_of_kind("file")}
        path_to_id = {path: node_id for node_id, path in files.items() if path}
        adjacency: dict[str, Counter] = defaultdict(Counter)
        call_degree = Counter()

        def file_id(node):
            path = self.gl.loc(node)[0]
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
            communities.append({
                "id": min(member_paths) if member_paths else str(_label),
                "files": member_paths, "internal_edges": internal,
                "boundary_edges": crossing,
                "hubs": [{**_loc(self.gl, n), "call_degree": call_degree[n["id"]]}
                         for n in hubs if call_degree[n["id"]]],
            })
        communities.sort(key=lambda c: (-len(c["files"]), c["id"]))
        return {"move": "architecture_map", "algorithm": "weighted-label-propagation",
                "inputs": ["CALLS", "DEPENDS_ON", "RUNTIME_DEPENDS_ON", "RE_EXPORTS"],
                "counts": {"files": len(files), "communities": len(communities)},
                "communities": communities[:max(1, max_communities)],
                "truncated": len(communities) > max(1, max_communities)}

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
            step = {"sequence": len(steps), "depth": depth,
                    "function": _loc(self.gl, function),
                    "caller": _loc(self.gl, caller) if caller else None,
                    "via": via, "branches": branches}
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
                "steps": steps, "frontier": frontier,
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

    def tests_for(self, symbol: str, limit: int = 50) -> dict:
        """Find test references in the source tree that the production graph excludes."""
        root, files = self._source_files()
        if root is None:
            return {"error": "source tree unavailable; graph manifest has no usable source_dir"}
        pattern = re.compile(rf"\b{re.escape(symbol)}\b")
        references = []
        searched = 0
        for path in files:
            relative = path.relative_to(root).as_posix()
            if not _TEST_FILE.search(relative):
                continue
            searched += 1
            try:
                if path.stat().st_size > 2_000_000:
                    continue
                lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            for number, line in enumerate(lines, 1):
                if not pattern.search(line):
                    continue
                nearby = " ".join(lines[max(0, number - 2):min(len(lines), number + 1)])
                references.append({"file": relative, "line": number,
                                   "snippet": line.strip()[:300],
                                   "assertion_nearby": bool(re.search(
                                       r"\b(assert|expect|should|require|CHECK|ASSERT)", nearby,
                                       re.IGNORECASE))})
                if len(references) >= max(1, limit):
                    break
            if len(references) >= max(1, limit):
                break
        return {"move": "tests_for", "symbol": symbol,
                "test_files_searched": searched, "references": references,
                "truncated": len(references) >= max(1, limit)}

    def spec_links(self, symbol: str, limit: int = 50) -> dict:
        """Link a symbol to docs, format definitions, standards URLs, and comments."""
        root, files = self._source_files()
        if root is None:
            return {"error": "source tree unavailable; graph manifest has no usable source_dir"}
        pattern = re.compile(rf"\b{re.escape(symbol)}\b", re.IGNORECASE)
        references = []
        docs_searched = 0
        for path in files:
            relative = path.relative_to(root).as_posix()
            is_doc = path.suffix.lower() in {".md", ".rst", ".txt", ".adoc"}
            if not is_doc and _TEST_FILE.search(relative):
                continue
            try:
                if path.stat().st_size > 2_000_000:
                    continue
                lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            if is_doc:
                docs_searched += 1
            for number, line in enumerate(lines, 1):
                stripped = line.strip()
                is_comment = stripped.startswith(("//", "/*", "*", "#", "--"))
                if not pattern.search(line) or (not is_doc and not is_comment):
                    continue
                urls = re.findall(r"https?://[^\s)>\]}]+", line)
                references.append({"file": relative, "line": number,
                                   "kind": "documentation" if is_doc else "comment",
                                   "snippet": stripped[:300], "urls": urls})
                if len(references) >= max(1, limit):
                    break
            if len(references) >= max(1, limit):
                break
        return {"move": "spec_links", "symbol": symbol,
                "docs_searched": docs_searched, "references": references,
                "truncated": len(references) >= max(1, limit)}

    def context_pack(self, question: str, max_symbols: int = 6,
                     max_neighbors: int = 30) -> dict:
        """Compose a minimal factual neighborhood around question-relevant symbols."""
        query_tokens = set(camel_tokens(question))
        query_tokens.update(re.findall(r"[A-Za-z_][A-Za-z0-9_]+", question.casefold()))
        stop = {"a", "an", "and", "are", "does", "for", "from", "how", "in", "is",
                "of", "the", "this", "to", "what", "where", "which", "why", "with"}
        query_tokens -= stop
        scored = []
        for entry in self.store.entries:
            if entry.get("granularity") not in ("function", "method", "type"):
                continue
            name_tokens = set(entry.get("tokens") or camel_tokens(entry.get("name", "")))
            overlap = query_tokens & name_tokens
            if not overlap:
                continue
            exact = entry.get("name", "").casefold() in question.casefold()
            score = len(overlap) * 10 + (20 if exact else 0) + min(entry.get("degree", 0), 10)
            scored.append((score, entry))
        scored.sort(key=lambda item: (-item[0], item[1].get("file") or "",
                                      item[1].get("line") or 0))
        selected = scored[:max(1, max_symbols)]
        seeds = [entry for _score, entry in selected]
        if not seeds:
            return {"move": "context_pack", "question": question,
                    "status": "no-identifier-match", "selection_basis": "identifier-tokens",
                    "semantic_search": "unavailable: configure concept_search embeddings",
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
                "selection_basis": "identifier-token-relevance",
                "semantic_search": "unavailable: configure concept_search embeddings",
                "seeds": [{**_loc(self.gl, self.gl.nodes[entry["node_id"]]),
                           "score": score} for score, entry in selected],
                "symbols": symbols, "relationships": relationships,
                "conditions": conditions, "tests": test_refs.get("references", []),
                "specs": spec_refs.get("references", []), "unknowns": unknown_rows,
                "limits": {"max_symbols": max_symbols, "max_neighbors": max_neighbors}}
