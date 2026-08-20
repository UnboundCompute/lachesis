"""Name-keyed indices over a graph's nodes: declarations, and call sites.

Two maps, both from a *name* to the rows that bear it:

``decl_index``      name -> every declaration in the tree with that name
``callsite_index``  callee name -> every call site that spells that name

They exist so that resolution can be a lookup instead of a scan. A name-join over
209k nodes is the thing eager enrichment does eight times over; done once, at write
time, into a persisted table, it becomes a dictionary hit — and the same dictionary
serves the query side, where "which of the four ``funcA``s did this call mean" is
otherwise a full pass over the graph per question.

Both builders are **pure functions of a node list**. That is the point: every node
carries the file that emitted it (``kuzu_store._node_unit``), so rebuilding the index
for one changed file is a filter on the input rather than a different code path. The
builders are therefore usable at write time, at query time, and — later — per unit.

They live at the top level, not under a frontend, because the three frontends spell a
callee three different ways: Python stamps an already-normalized ``callee_name``, C
stamps a clang ``callee`` plus ``method_name``, TypeScript stamps the full callee
*expression* (``router.get``, ``this.handlers[k]``) plus a ``method_name`` when the key
is literal. ``last_name`` reconciles them, and it does so once, here, rather than three
times — once of them in JavaScript.

This module imports nothing from the rest of the package, deliberately: ``core`` and
``nav`` both import *from* it (``dispatch`` for ``last_name``, ``symbol_index`` for
``INDEXED_KINDS``), so there is exactly one definition of each and the two sides cannot
drift apart.
"""
from __future__ import annotations

from typing import Iterable, Mapping, Sequence


# node kinds that are addressable jump targets, mapped to a granularity label. Kinds
# are a normalized cross-language vocabulary, so this is a language-agnostic superset:
# the TS-shaped kinds plus the C declaration kinds (record = struct+union, type =
# typedef, variable = globals, property = struct fields / ops-struct slots, constant).
# Making globals and ops-struct slots addressable is what lets `search`/`open_file`
# reach the things a C/kernel reader navigates by.
#
# Known limits (documented, not fixable here):
#  - `macro` is NOT emitted by the C frontend (macros appear only as raw `token`
#    nodes), so macro names are unindexable — a frontend gap, not a symbol-index one.
#  - `variable`/`property` are high-volume (a large C tree has thousands of globals /
#    struct fields); external + test filtering still applies, but expect a bigger index.
INDEXED_KINDS = {
    "file": "file",
    "class": "type", "interface": "type", "enum": "type", "type": "type",
    "function": "function", "method": "method", "constructor": "method",
    "record": "type", "union": "type",
    "variable": "variable", "property": "property", "constant": "constant",
    "macro": "macro",
}

# The kinds a call site is emitted as. `construct` is a call whose target happens to be
# a class; both own the callee name a caller looks up.
CALLSITE_KINDS = ("call", "construct")

# Relationship that marks a declaration as visible outside its file.
EXPORTS = "EXPORTS"


def last_name(value: str) -> str:
    """The bare name at the end of a callee expression.

    ``a?.b.c(x)`` -> ``c``; ``handlers['run']`` -> ``run``; ``foo(`` -> ``foo``. Three
    frontends produce three spellings of a callee and this is where they meet.
    """
    normalized = value.split("?.")[-1]
    if "." in normalized:
        normalized = normalized.rsplit(".", 1)[-1]
    if "[" in normalized:
        normalized = normalized.rsplit("[", 1)[-1]
    if "(" in normalized:
        normalized = normalized.split("(", 1)[0]
    return normalized.strip("'\"`] ")


def _properties(node: Mapping) -> Mapping:
    return node.get("properties") or {}


def signature_of(properties: Mapping):
    """The declaration's signature as the frontend recorded it — never synthesized.

    A signature assembled here from parameter nodes would be this module's opinion of
    the declaration rather than the compiler's, and it would differ per language in
    ways nobody could predict from the schema. Absent is a better answer than invented.
    """
    return properties.get("signature") or properties.get("type") or None


def exported_ids(edges: Iterable[Mapping]) -> frozenset:
    """Ids on the target end of an EXPORTS edge — the same set ``GraphLib`` uses."""
    return frozenset(
        edge["target"] for edge in edges
        if edge.get("kind") == EXPORTS and edge.get("target")
    )


def build_decl_index(
    nodes: Iterable[Mapping],
    exported: Sequence | frozenset | set = frozenset(),
) -> dict:
    """name -> declaration rows, over ``INDEXED_KINDS``.

    Keyed on the node ``label``, which is what ``search`` resolves against; using
    ``properties.name`` instead would make the two disagree about which nodes are
    reachable by name, and a search hit nothing can look up is worse than no hit.
    """
    exported = frozenset(exported)
    index: dict[str, list[dict]] = {}
    for node in nodes:
        row = _decl_row(node, exported)
        if row is not None:
            index.setdefault(row["name"], []).append(row)
    return _ordered(index)


def build_callsite_index(nodes: Iterable[Mapping]) -> dict:
    """callee name -> call-site rows, over ``CALLSITE_KINDS``.

    ``owner_id`` is the declaration the call site sits inside, stamped by all three
    frontends as ``owner_function_id``. Carrying it is what makes ``callers(f)`` a
    lookup — find the sites that name ``f``, read their owners — instead of a walk
    from every declaration in the tree down into its body.
    """
    index: dict[str, list[dict]] = {}
    for node in nodes:
        row = _callsite_row(node)
        if row is not None:
            index.setdefault(row["callee_name"], []).append(row)
    return _ordered(index)


def build_decl_and_callsite_index(
    nodes: Iterable[Mapping],
    exported: Sequence | frozenset | set = frozenset(),
) -> tuple[dict, dict]:
    """Build both persisted indices in one pass over ``nodes``.

    Streamed Kùzu publication stores only index candidates in a temporary protobuf
    file. Reading and decoding that file once for declarations and again for call
    sites was pure duplicate work (and doubled protobuf/property allocations). This
    fused variant keeps the same independent ordered outputs while allowing callers
    to retain bounded memory and make one forward pass.
    """
    exported = frozenset(exported)
    declarations: dict[str, list[dict]] = {}
    callsites: dict[str, list[dict]] = {}
    for node in nodes:
        decl = _decl_row(node, exported)
        if decl is not None:
            declarations.setdefault(decl["name"], []).append(decl)
        callsite = _callsite_row(node)
        if callsite is not None:
            callsites.setdefault(callsite["callee_name"], []).append(callsite)
    return _ordered(declarations), _ordered(callsites)


def _decl_row(node: Mapping, exported: frozenset) -> dict | None:
    kind = node.get("kind")
    granularity = INDEXED_KINDS.get(kind)
    if granularity is None:
        return None
    name = str(node.get("label") or "")
    if not name:
        return None
    properties = _properties(node)
    node_id = node.get("id")
    return {
        "name": name,
        "node_id": node_id,
        "kind": kind,
        "granularity": granularity,
        "file": properties.get("file"),
        "line": properties.get("start_line"),
        "signature": signature_of(properties),
        "unit": properties.get("file"),
        "exported": node_id in exported,
        "declaration_only": bool(properties.get("declaration_only")),
    }


def _callsite_row(node: Mapping) -> dict | None:
    if node.get("kind") not in CALLSITE_KINDS:
        return None
    properties = _properties(node)
    name = callee_name(node)
    if not name:
        return None
    return {
        "callee_name": name,
        "node_id": node.get("id"),
        "owner_id": properties.get("owner_function_id"),
        "file": properties.get("file"),
        "line": properties.get("start_line"),
        "unit": properties.get("file"),
        "form": properties.get("callee_form") or properties.get("form"),
        "receiver": (properties.get("receiver")
                     or properties.get("receiver_expression")),
    }


def callee_name(node: Mapping) -> str:
    """The normalized name a call site is calling.

    Prefers whatever the frontend already normalized — Python's ``callee_name``, and
    the ``method_name`` that C and TypeScript stamp when they know it — and falls back
    to ``last_name`` over the raw callee expression. Preferring the frontend's answer
    matters: TypeScript's ``method_name`` comes from the property access the compiler
    resolved, whereas its ``callee`` is source text, and for a computed key the two
    genuinely differ.
    """
    properties = _properties(node)
    for key in ("callee_name", "method_name"):
        value = properties.get(key)
        if value:
            return str(value)
    raw = properties.get("callee") or node.get("label") or ""
    return last_name(str(raw))


def _ordered(index: dict) -> dict:
    """Total order on the whole structure, so two builds of one graph are one file.

    The rows are written to a store and hashed by callers; leaving them in node order
    would make the index depend on frontend scheduling, which is the sort of
    difference that shows up months later as a cache that never hits.
    """
    return {
        name: sorted(
            rows,
            key=lambda row: (row.get("file") or "", row.get("line") or 0,
                             row.get("node_id") or ""),
        )
        for name, rows in sorted(index.items())
    }


def index_rows(index: Mapping) -> list:
    """The flat row list a table wants, in the index's own order."""
    return [row for rows in index.values() for row in rows]
