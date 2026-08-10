#!/usr/bin/env python3
"""Compact text rendering of nav-tool results — the token-economy layer.

Every nav tool returns a rich result dict (see `mcp_server.call_tool`). For a
programmatic caller that JSON is the contract; for an LLM consumer it is mostly
waste — a 20-char hex `node_id` the agent never re-addresses, a `handle` that
duplicates `file:line`, absolute-ish paths repeated on every row, and `null` /
empty-list fields. This module renders the SAME result dict as terse text so a
per-call payload drops ~3-5x, while `mcp_server` keeps emitting full JSON whenever
`format="json"` is asked (byte-identical to the pre-render behavior).

The single entry point is `render(tool_name, result, root=None, offset=0, limit=40)`.
It strips, in priority order: (1) `node_id`, (2) `handle`, (3) absolute paths
(relativized to a project root, collapsing to `basename:line`), (4) `null` /
empty-list fields, and renders lists one item per line. Every list is capped at
`limit` items with a `… +K more (offset=N)` footer so a single call on a
400-caller hub can never blow the budget. Truncation is a TEXT concern only —
JSON is always the full, un-paged result.

A per-tool template exists for the high-traffic tools; any tool without one falls
through to `_generic`, which applies the same strip rules to an arbitrary dict so
compaction is never silently skipped for a newer tool.
"""
from __future__ import annotations

import os
from typing import Iterable, List, Optional

DEFAULT_LIMIT = 40


# --------------------------------------------------------------------------- #
# path relativization
# --------------------------------------------------------------------------- #

def project_root(paths: Iterable[Optional[str]]) -> str:
    """Longest common `/`-delimited *directory* prefix over the given file paths.

    Node file paths are already repo-relative, but a real subsystem still shares a
    deep prefix (e.g. `drivers/net/ethernet/broadcom/bnxt/`); stripping it is what
    lets a row collapse to `bnxt.c:725`. Returns "" when there is no shared prefix
    (or fewer than two distinct paths), so relativization is a no-op in that case.
    """
    dirs = []
    for p in paths:
        if not p or "/" not in p:
            # a bare basename contributes no shared *directory* — a single top-level
            # file must not force the common prefix down to "".
            continue
        dirs.append(p.rsplit("/", 1)[0].split("/"))
    if len(dirs) < 2:
        return ""
    common: List[str] = []
    for parts in zip(*dirs):
        first = parts[0]
        if all(p == first for p in parts):
            common.append(first)
        else:
            break
    return "/".join(common)


def _basename(path: str) -> str:
    return path.rsplit("/", 1)[-1]


def _strip_root(path: str, root: str) -> str:
    if root and path.startswith(root + "/"):
        return path[len(root) + 1:]
    return path


class _Loc:
    """Renders a node's `file:line` in the shortest unambiguous form for one result.

    Built once per render from every file path in the result set. A basename that is
    unique across the set prints as `basename:line`; a colliding basename keeps its
    root-relative path so two same-named files in different dirs stay distinct.
    """

    def __init__(self, paths: Iterable[Optional[str]]):
        real = [p for p in paths if p]
        self.root = project_root(real)
        counts: dict[str, int] = {}
        for p in real:
            counts[_basename(p)] = counts.get(_basename(p), 0) + 1
        self._unique = {b for b, c in counts.items() if c == 1}

    def of(self, file: Optional[str], line=None) -> str:
        if not file:
            return "?"
        short = _basename(file) if _basename(file) in self._unique else _strip_root(file, self.root)
        return f"{short}:{line}" if line else short


# --------------------------------------------------------------------------- #
# truncation
# --------------------------------------------------------------------------- #

def _window(items: List, offset: int, limit: int):
    """(window, footer|None) — the [offset, offset+limit) slice plus a paging footer."""
    offset = max(0, offset)
    limit = max(1, limit)
    window = items[offset:offset + limit]
    shown_end = offset + len(window)
    footer = None
    if shown_end < len(items):
        footer = f"    … +{len(items) - shown_end} more (offset={shown_end})"
    return window, footer


def _lines(header: str, rows: List[str], footer: Optional[str]) -> str:
    out = [header]
    out.extend(rows)
    if footer:
        out.append(footer)
    return "\n".join(out)


# --------------------------------------------------------------------------- #
# via / dispatch label (the graph's reverse-dispatch differentiator)
# --------------------------------------------------------------------------- #

def _via(row: dict) -> str:
    """Compact dispatch label: direct | ops-struct[.slot] | <indirect-kind>.

    `dispatch`/`slot` are present only when the move was called with_dispatch=True
    (text path); otherwise fall back to the raw `via` string, mapping the verbose
    `indirect(x)` form to a bare `x`."""
    if row.get("dispatch") == "ops-struct":
        slot = row.get("slot")
        return f"ops-struct[.{slot}]" if slot else "ops-struct"
    via = row.get("via") or "direct"
    if via.startswith("indirect(") and via.endswith(")"):
        via = via[len("indirect("):-1]
    tail = "" if row.get("resolved", True) else " [unresolved]"
    return via + tail


# --------------------------------------------------------------------------- #
# per-tool templates
# --------------------------------------------------------------------------- #

def _r_hubs(result: dict, offset: int, limit: int) -> str:
    rows = result.get("ranked") or []
    loc = _Loc(r.get("file") for r in rows)
    window, footer = _window(rows, offset, limit)
    lines = []
    for i, r in enumerate(window, start=offset + 1):
        flags = ",".join(r.get("flags") or [])
        flags = f"  {flags}" if flags else ""
        lines.append(f"  {i:>2}. {r.get('name'):<24} {loc.of(r.get('file'), r.get('line')):<20} "
                     f"in={r.get('fan_in'):<4} out={r.get('fan_out')}{flags}")
    return _lines(f"HUBS — top {len(rows)} by degree", lines, footer)


def _r_moves(result: dict, key: str, offset: int, limit: int) -> str:
    rows = result.get(key) or []
    of = result.get("of")
    loc = _Loc(r.get("file") for r in rows)
    window, footer = _window(rows, offset, limit)
    lines = [f"    {r.get('name'):<24} {loc.of(r.get('file'), r.get('line')):<20} "
             f"via={_via(r)}" for r in window]
    header = f"{key.upper()} of {of} ({len(rows)}):"
    if not rows:
        return header + "\n    (none)"
    return _lines(header, lines, footer)


def _r_search(result: dict, offset: int, limit: int) -> str:
    hits = result.get("hits") or []
    total = result.get("total", len(hits))
    loc = _Loc(h.get("file") for h in hits)
    # search_page already windowed the hits (json paging); render them as-is.
    lines = [f"    {h.get('name'):<24} {h.get('kind'):<10} {loc.of(h.get('file'), h.get('line'))}"
             for h in hits]
    q = result.get("query")
    footer = None
    if result.get("has_more"):
        nxt = result.get("offset", 0) + result.get("returned", len(hits))
        footer = f"    … more (offset={nxt})"
    return _lines(f"SEARCH '{q}' — {total} hits (showing {len(hits)}):", lines, footer)


def _r_read_body(result: dict, *_ignored) -> str:
    loc = _Loc([result.get("file")])
    span = f"{loc.of(result.get('file'))}:{result.get('start_line')}-{result.get('end_line')}"
    head = f"{result.get('name')}   {span}"
    if result.get("truncated"):
        head += "  (truncated)"
    return f"{head}\n{result.get('body', '')}"


def _r_file_graph(result: dict, offset: int, limit: int) -> str:
    """open_file — the file's declared symbols, one per line (kind:line)."""
    manifest = result.get("manifest") or {}
    nodes = result.get("nodes") or []
    decls = [n for n in nodes if n.get("kind") not in ("file",)]
    loc = _Loc(_node_file(n) for n in decls)
    window, footer = _window(decls, offset, limit)
    base = _basename(manifest.get("file") or "?")
    lines = [f"    {n.get('label'):<24} {n.get('kind')}:{_node_line(n)}" for n in window]
    return _lines(f"FILE {base} — {len(decls)} symbols:", lines, footer)


def _r_folder_graph(result: dict, offset: int, limit: int) -> str:
    """open_folder — the files under the root, with a per-file declaration count."""
    manifest = result.get("manifest") or {}
    nodes = result.get("nodes") or []
    files = [n for n in nodes if n.get("kind") == "file"]
    # count DECLARES targets per file id
    decl_count: dict[str, int] = {}
    for e in result.get("edges") or []:
        if e.get("kind") == "DECLARES":
            decl_count[e.get("source")] = decl_count.get(e.get("source"), 0) + 1
    window, footer = _window(files, offset, limit)
    lines = [f"    {f.get('label'):<24} (functions: {decl_count.get(f.get('id'), 0)})"
             for f in window]
    root = manifest.get("root") or "?"
    return _lines(f"FOLDER {root} — {len(files)} files:", lines, footer)


def _r_path_shape(result: dict, offset: int, limit: int) -> str:
    """flow / reaches / sources_of / points_to / aliases — one labeled path list."""
    manifest = result.get("manifest") or {}
    nodes = result.get("nodes") or []
    edges = result.get("edges") or []
    move = manifest.get("move", "path")
    # edge kind by target, so each node line can carry the hop that reached it
    kind_by_tgt = {e.get("tgt"): e.get("kind") for e in edges}
    loc = _Loc(n.get("file") for n in nodes)
    window, footer = _window(nodes, offset, limit)
    lines = []
    for n in window:
        edge = kind_by_tgt.get(n.get("id"))
        edge = f"  {edge}" if edge else ""
        lines.append(f"    {n.get('name'):<24} {loc.of(n.get('file'), n.get('line'))}{edge}")
    if move == "reaches":
        reachable = manifest.get("reachable")
        head = f"REACHES {'yes' if reachable else 'no'} — {manifest.get('hops', 0)} hops"
        if not reachable:
            return head + f"\n    ({manifest.get('note', 'no path')})"
        return _lines(head + f" ({len(nodes)} nodes):", lines, footer)
    head = f"{move.upper()} ({len(nodes)} nodes"
    if manifest.get("truncated"):
        head += ", truncated"
    return _lines(head + "):", lines, footer)


# --------------------------------------------------------------------------- #
# generic fallback + shared node accessors
# --------------------------------------------------------------------------- #

_STRIP_KEYS = {"node_id", "handle", "id", "tokens", "degree"}


def _node_file(n: dict) -> Optional[str]:
    props = n.get("properties") or {}
    return props.get("file") or n.get("file")


def _node_line(n: dict):
    props = n.get("properties") or {}
    loc = n.get("location") or {}
    return props.get("start_line") or loc.get("start_line") or n.get("line")


def _compact(value, loc: _Loc):
    """Recursively drop stripped/empty keys and relativize any `file`+`line` pair."""
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if k in _STRIP_KEYS or v is None or v == [] or v == {}:
                continue
            out[k] = _compact(v, loc)
        return out
    if isinstance(value, list):
        return [_compact(v, loc) for v in value]
    return value


def _generic(tool_name: str, result: dict, offset: int, limit: int) -> str:
    """Strip + flatten an arbitrary result dict so no tool is left un-compacted."""
    all_paths = []

    def _gather(v):
        if isinstance(v, dict):
            if v.get("file"):
                all_paths.append(v["file"])
            for x in v.values():
                _gather(x)
        elif isinstance(v, list):
            for x in v:
                _gather(x)

    _gather(result)
    loc = _Loc(all_paths)
    compact = _compact(result, loc)
    lines = [tool_name.upper()]
    for k, v in compact.items():
        if isinstance(v, list):
            window, footer = _window(v, offset, limit)
            lines.append(f"{k} ({len(v)}):")
            for item in window:
                if isinstance(item, dict):
                    parts = []
                    for ik, iv in item.items():
                        if ik == "file":
                            parts.append(loc.of(iv, item.get("line")))
                        elif ik == "line" and "file" in item:
                            continue
                        else:
                            parts.append(f"{ik}={iv}")
                    lines.append("    " + "  ".join(parts))
                else:
                    lines.append(f"    {item}")
            if footer:
                lines.append(footer)
        else:
            lines.append(f"{k}: {v}")
    return "\n".join(lines)


_TEMPLATES = {
    "hubs": lambda r, o, l: _r_hubs(r, o, l),
    "callers": lambda r, o, l: _r_moves(r, "callers", o, l),
    "callees": lambda r, o, l: _r_moves(r, "callees", o, l),
    "search": lambda r, o, l: _r_search(r, o, l),
    "read_body": lambda r, o, l: _r_read_body(r),
    "open_file": lambda r, o, l: _r_file_graph(r, o, l),
    "open_folder": lambda r, o, l: _r_folder_graph(r, o, l),
    "flow": lambda r, o, l: _r_path_shape(r, o, l),
    "reaches": lambda r, o, l: _r_path_shape(r, o, l),
    "sources_of": lambda r, o, l: _r_path_shape(r, o, l),
    "points_to": lambda r, o, l: _r_path_shape(r, o, l),
    "aliases": lambda r, o, l: _r_path_shape(r, o, l),
}


def render(tool_name: str, result: dict, root: Optional[str] = None,
           offset: int = 0, limit: int = DEFAULT_LIMIT) -> str:
    """Render a nav-tool result dict as compact text (the LLM-facing form).

    `root` is accepted for API symmetry; relativization is computed per-result from
    the paths actually present, so a caller need not supply it. An `{"error": ...}`
    result renders as a one-line error. Any tool without a specific template falls
    through to `_generic`, which still strips ids/handles/nulls and paginates lists.
    """
    if not isinstance(result, dict):
        return str(result)
    if "error" in result and len(result) == 1:
        return f"error: {result['error']}"
    tmpl = _TEMPLATES.get(tool_name)
    if tmpl is None:
        return _generic(tool_name, result, offset, limit)
    return tmpl(result, offset, limit)


def default_format() -> str:
    """The process-wide default output format (env ARACHNE_FORMAT, else 'text')."""
    fmt = os.environ.get("ARACHNE_FORMAT", "text").lower()
    return "json" if fmt == "json" else "text"
