#!/usr/bin/env python3
"""A3 — entrypoint anchoring: where does external control actually enter this code?

A candidate's guard often does not live in the function that performs the effect. It
lives in the thing that was *registered*: the route wrapper, the callback the
framework holds, the exported shim. Running a dominance check from the impl symbol
therefore reports "unguarded" for code whose guard is one hop up, which is the
single largest false-positive class in the whole pipeline.

This module resolves, for any function, the set of **anchors** it is reachable from:

  * ``route`` — a registered route, found through ``ENTRY_POINT_OF`` /
    ``ROUTE_HANDLED_BY`` (the framework model already materializes these). This is
    the strongest anchor: the framework itself named the handler.
  * ``callback-registration`` — a function handed to a registration call as a
    callback (``PASSES_CALLBACK``). Method-style registration (``register(name, fn)``)
    appears this way and has no route node.
  * ``object-literal-registration`` — a function registered as a *property* of an
    object literal handed to a registration call (``register({ deleteUser })``,
    ``register({ deleteUser() { ... } })``). The frontend's callback resolution does
    not descend into object-literal properties, so these emit no ``PASSES_CALLBACK``
    and no route: without this recognition a whole method-registration convention is
    invisible and every handler in it is silently never scanned.
  * ``exported-entry`` — an exported callable with no in-repo caller. Something
    outside the analyzed tree must be calling it, so it is an entry by elimination.
    Conservative by construction: absence of a caller is absence of *evidence* of a
    caller, and an unresolved dynamic dispatch looks exactly the same.

``anchors_for`` climbs callers within a small radius, so an impl whose registered
wrapper carries the guard is anchored at the wrapper, not at itself. The climb goes
through ``nav.symbol_index.callers`` rather than raw ``CALLS`` edges, so a function
reached only through dispatch still finds its anchor.

Every anchor row carries how it was recognized and the graph ids that witness it;
nothing here returns a bare boolean.

  python3 planner/entrypoints.py graph.kuzu --stat
  python3 planner/entrypoints.py graph.kuzu --fn <function-id|name>
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from nav.graph_store import GraphStore
from nav.graphlib import CALLABLE_KINDS
from nav import symbol_index as si

# How far up the call graph an anchor may live. Two hops covers the shapes that
# actually occur — impl <- registered wrapper, and impl <- helper <- wrapper — while
# staying cheap enough to run over every candidate. A deeper climb would start
# anchoring a utility at every entrypoint in the tree, which is not an anchor at all.
ANCHOR_RADIUS = 2

# Anchor recognitions, strongest first. The order is the tie-break used when one
# function is anchored several ways: a framework-named handler beats a callback
# passed to an unknown callee, which beats "nothing in the tree calls it".
ANCHOR_KINDS = ("route", "callback-registration", "object-literal-registration",
                "exported-entry")

_CONFIDENCE_RANK = {"exact": 0, "high": 1, "medium": 2, "conservative": 3, "low": 4}


class EntryPoints:
    """The anchor set of a graph, and the anchors any one function sits under."""

    def __init__(self, store: GraphStore) -> None:
        self.store = store
        self.gl = store.gl
        self.index = store.index
        self._by_handler: dict[str, list[dict]] | None = None
        self._called: frozenset[str] | None = None
        self._spans: dict[str, list] | None = None
        self._by_name: dict[str, list[dict]] = {}

    # -- the four recognitions ----------------------------------------------

    def _route_anchors(self) -> list[dict]:
        """Routes the framework model already resolved to a handler."""
        out: list[dict] = []
        seen: set[tuple[str, str]] = set()
        for kind in ("ENTRY_POINT_OF", "ROUTE_HANDLED_BY"):
            for edge in self.index.edges_of_kind(kind):
                anchor_id, handler_id = edge.get("source"), edge.get("target")
                if not anchor_id or not handler_id:
                    continue
                if (anchor_id, handler_id) in seen:
                    continue
                seen.add((anchor_id, handler_id))
                anchor = self.gl.nodes.get(anchor_id)
                if anchor is None:
                    continue
                props = anchor.get("properties") or {}
                # A route node is a derived fact and carries no location of its own;
                # the registration call site is the file:line a reader would open.
                out.append(self._row(
                    anchor, handler_id, "route",
                    props.get("confidence") or "conservative",
                    [anchor_id, props.get("callsite_id"), handler_id],
                    extra={"method": props.get("method"), "path": props.get("path")},
                    located_at=self.gl.nodes.get(props.get("callsite_id")),
                ))
        return out

    def _callback_anchors(self, route_handlers: set[str]) -> list[dict]:
        """Functions handed to a registration call as a callback.

        The anchor is the *call* that received the callback, not the argument node:
        that is the thing a reader would point at as "where this gets registered".
        A handler the route model already claimed is skipped, so the same
        registration is not counted twice under a weaker recognition."""
        out: list[dict] = []
        for edge in self.index.edges_of_kind("PASSES_CALLBACK"):
            handler_id = edge.get("target")
            if not handler_id or handler_id in route_handlers:
                continue
            if self.gl.kind(handler_id) not in CALLABLE_KINDS:
                continue
            argument = self.gl.nodes.get(edge.get("source"))
            if argument is None:
                continue
            callsite_id = (argument.get("properties") or {}).get("callsite_id")
            anchor = self.gl.nodes.get(callsite_id) if callsite_id else None
            if anchor is None:
                anchor = argument
            out.append(self._row(
                anchor, handler_id, "callback-registration", "conservative",
                [anchor["id"], argument["id"], handler_id],
            ))
        return out

    def _object_literal_anchors(self, claimed: set[str]) -> list[dict]:
        """Handlers registered as properties of an object literal argument.

        Two property shapes occur and both are read from structure, never from
        source text: a callable *declared inside* the literal (``{ deleteUser() {}
        }``, ``{ deleteUser: async () => {} }``), found by span containment in the
        literal's allocation, and a *shorthand reference* to a callable declared
        elsewhere (``{ deleteUser }``), found from the literal expression's
        identifier children and resolved by name.

        The shorthand route resolves by name and so is only taken when exactly one
        callable declaration answers to it, preferring the file the registration is
        in. An ambiguous name is left unanchored rather than anchored at a guess:
        a wrong anchor would import a stranger's guard."""
        out: list[dict] = []
        spans = self._callable_spans()
        for argument in self.index.nodes_of_kind("argument"):
            props = argument.get("properties") or {}
            if props.get("literal"):
                continue
            callsite_id = props.get("callsite_id")
            anchor = self.gl.nodes.get(callsite_id) if callsite_id else None
            if anchor is None or self.gl.kind(callsite_id) not in ("call", "construct"):
                continue
            for expression in self.index.targets(argument["id"], "EXPANDS_TO"):
                for allocation in self.index.targets(expression["id"], "ALLOCATES"):
                    allocated = allocation.get("properties") or {}
                    if allocated.get("allocation_kind") != "object":
                        continue
                    for handler, how in self._literal_handlers(expression, allocated,
                                                               spans):
                        if handler["id"] in claimed:
                            continue
                        claimed.add(handler["id"])
                        out.append(self._row(
                            anchor, handler["id"], "object-literal-registration",
                            "conservative",
                            [callsite_id, argument["id"], handler["id"]],
                            extra={"registered_as": self.gl.label(handler),
                                   "property_shape": how},
                        ))
        return out

    def _literal_handlers(self, expression: dict, allocated: dict, spans) -> list:
        """(callable, shape) for every property of one object literal."""
        found: list = []
        seen: set[str] = set()
        for callable_node in self._declared_inside(allocated, spans):
            seen.add(callable_node["id"])
            found.append((callable_node, "declared-inline"))
        for child in self.index.targets(expression["id"], "AST_CHILD"):
            if self.gl.kind(child["id"]) != "identifier":
                continue
            resolved = self._one_callable_named(self.gl.label(child),
                                                (child.get("properties") or {}))
            if resolved is not None and resolved["id"] not in seen:
                seen.add(resolved["id"])
                found.append((resolved, "shorthand-reference"))
        return found

    def _declared_inside(self, allocated: dict, spans) -> list[dict]:
        """Callables whose source span sits inside the literal, outermost only.

        Outermost only because an inner arrow function inside a registered handler
        is not a second registration; it is part of the first."""
        path = allocated.get("absolute_file")
        start, end = allocated.get("start_offset"), allocated.get("end_offset")
        if not path or start is None or end is None:
            return []
        inside = [(s, e, node) for s, e, node in spans.get(path, ())
                  if s > start and e <= end]
        out: list[dict] = []
        for s, e, node in inside:
            if any(os_ < s and e <= oe for os_, oe, _ in inside):
                continue  # nested in another property's callable
            out.append(node)
        return out

    def _callable_spans(self):
        """absolute file -> (start_offset, end_offset, node) for every callable."""
        if self._spans is None:
            spans: dict[str, list] = {}
            for node in self.index.nodes_of_kind(*CALLABLE_KINDS):
                props = node.get("properties") or {}
                path = props.get("absolute_file")
                start, end = props.get("start_offset"), props.get("end_offset")
                if path and start is not None and end is not None:
                    spans.setdefault(path, []).append((start, end, node))
            self._spans = spans
        return self._spans

    def _one_callable_named(self, name: str, near: dict) -> dict | None:
        """The single callable declaration a shorthand property names, or None."""
        if not name:
            return None
        cached = self._by_name.get(name)
        if cached is None:
            cached = [self.gl.nodes[hit["node_id"]]
                      for hit in self.store.resolve(name)
                      if hit.get("name") == name
                      and hit["node_id"] in self.gl.nodes
                      and self.gl.kind(hit["node_id"]) in CALLABLE_KINDS]
            self._by_name[name] = cached
        if len(cached) == 1:
            return cached[0]
        here = [node for node in cached
                if (node.get("properties") or {}).get("absolute_file")
                == near.get("absolute_file")]
        return here[0] if len(here) == 1 else None

    def _exported_anchors(self, claimed: set[str]) -> list[dict]:
        """Exported callables nothing in the tree calls — entries by elimination."""
        out: list[dict] = []
        for node in self.index.nodes_of_kind(*CALLABLE_KINDS):
            node_id = node["id"]
            if node_id in claimed or node_id in self._called_ids():
                continue
            if not self.gl.is_exported(node_id):
                continue
            out.append(self._row(node, node_id, "exported-entry", "conservative",
                                 [node_id]))
        return out

    def _called_ids(self) -> frozenset[str]:
        """Every declaration something in the tree calls, direct or by dispatch.

        Computed in one edge pass rather than by asking ``callers`` per function:
        the question here is only "is this set empty", and a per-function query over
        a million-node graph would dominate the whole build."""
        if self._called is None:
            called: set[str] = set()
            for edge in self.index.edges_of_kind(*si.CALL_EDGES,
                                                 *si.INDIRECT_CALL_EDGES):
                target = edge.get("target")
                if target:
                    called.add(target)
            self._called = frozenset(called)
        return self._called

    def _row(self, anchor: dict, handler_id: str, how: str, confidence: str,
             evidence_ids, extra: dict | None = None,
             located_at: dict | None = None) -> dict:
        file, line, _ = self.gl.loc(located_at or anchor)
        row = {
            "anchor_id": anchor["id"],
            "anchor_label": self.gl.label(anchor),
            "anchor_kind": self.gl.kind(anchor["id"]),
            "handler_id": handler_id,
            "how": how,
            "confidence": confidence,
            "file": file,
            "line": line,
            "evidence_ids": [e for e in evidence_ids if e],
        }
        if extra:
            row.update({k: v for k, v in extra.items() if v is not None})
        return row

    # -- the index -----------------------------------------------------------

    def by_handler(self) -> dict[str, list[dict]]:
        """handler node id -> the anchors that register it, strongest first."""
        if self._by_handler is None:
            rows = self._route_anchors()
            route_handlers = {r["handler_id"] for r in rows}
            rows += self._callback_anchors(route_handlers)
            claimed = {r["handler_id"] for r in rows}
            rows += self._object_literal_anchors(claimed)
            rows += self._exported_anchors(claimed)
            index: dict[str, list[dict]] = {}
            for row in rows:
                index.setdefault(row["handler_id"], []).append(row)
            for anchors in index.values():
                anchors.sort(key=_anchor_strength)
            self._by_handler = index
        return self._by_handler

    def anchors_for(self, fn_id: str, radius: int = ANCHOR_RADIUS) -> list[dict]:
        """Anchors this function sits under, including ones on its callers.

        ``distance`` is how many call hops separate the anchored handler from
        ``fn_id``: 0 means this function is itself what was registered. A caller's
        anchor is a weaker claim than one's own, so distance is the first sort key —
        the nearest registration wins, and the climb is visible in the output rather
        than being flattened into "it's an entrypoint"."""
        index = self.by_handler()
        out: list[dict] = []
        seen_anchor: set[str] = set()
        seen_fn = {fn_id}
        frontier = [fn_id]
        for distance in range(radius + 1):
            nxt: list[str] = []
            for current in frontier:
                for anchor in index.get(current, ()):
                    if anchor["anchor_id"] in seen_anchor:
                        continue
                    seen_anchor.add(anchor["anchor_id"])
                    out.append({**anchor, "distance": distance,
                                "anchored_function_id": current})
                if distance == radius:
                    continue
                for caller in si.callers(self.gl, current):
                    cid = caller["node_id"]
                    if cid in seen_fn:
                        continue
                    seen_fn.add(cid)
                    nxt.append(cid)
            frontier = nxt
        out.sort(key=lambda a: (a["distance"], _anchor_strength(a)))
        return out

    def stat(self) -> dict:
        index = self.by_handler()
        counts = dict.fromkeys(ANCHOR_KINDS, 0)
        for anchors in index.values():
            for anchor in anchors:
                counts[anchor["how"]] += 1
        return {"handlers": len(index), "anchors": sum(counts.values()),
                "by_how": counts}


def _anchor_strength(anchor: dict) -> tuple:
    return (ANCHOR_KINDS.index(anchor["how"]),
            _CONFIDENCE_RANK.get(anchor.get("confidence"), 9),
            anchor["anchor_id"])


def _resolve_fn(store: GraphStore, token: str) -> str | None:
    if store.node(token):
        return token
    hits = store.resolve(token)
    return hits[0]["node_id"] if hits else None


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="A3 — entrypoint anchoring")
    p.add_argument("graph")
    p.add_argument("--stat", action="store_true", help="anchor census for the graph")
    p.add_argument("--fn", metavar="ID|NAME", help="anchors one function sits under")
    p.add_argument("--radius", type=int, default=ANCHOR_RADIUS,
                   help=f"how far up the call graph to climb (default {ANCHOR_RADIUS})")
    return p


def main(argv: list[str]) -> int:
    args = _parser().parse_args(argv)
    store = GraphStore.load(args.graph)
    store.ensure_dataflow_tier()
    entry_points = EntryPoints(store)
    if args.fn:
        fn = _resolve_fn(store, args.fn)
        if not fn:
            print(f"no function for {args.fn!r}", file=sys.stderr)
            return 2
        print(json.dumps({"function": fn,
                          "name": store.gl.label(store.node(fn)),
                          "anchors": entry_points.anchors_for(fn, args.radius)},
                         indent=2, ensure_ascii=False))
        return 0
    print(json.dumps(entry_points.stat(), indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
