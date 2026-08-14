"""Flow a buffer-filling C call's write back into the buffer's other uses.

``read(fd, buf, n)`` / ``recv(sock, buf, ...)`` / ``fgets(buf, n, fp)`` do not
*read* their buffer argument, they *fill* it: the untrusted bytes land in ``buf``
and travel onward through every later use of ``buf``. The C frontend, however,
only ever wires a variable's value *into* an argument position (``variable ->
use``), because for an ordinary call that is the true direction. So the argument
node a source model stamps -- the ``buf`` expression at the ``read`` callsite --
is a value-flow *leaf*: taint starts there and has nowhere to go, and the copy
that ``read`` performed into ``buf`` never reaches the ``buf`` a later ``memcpy``
or ``system`` consumes.

This overlay repairs exactly that reversal, in the enrich flow, without touching
the base build. For each out-parameter source (an argument the catalog marks as
an untrusted-input *source* -- i.e. the call writes it), it emits one additive
``VALUE_FLOWS_TO`` edge from that argument node back to the variable it
references. The frontend already carries ``variable -> use`` for every use, so
that single back-edge lets the write reach every sibling use: ``read`` fills
``buf`` -> ``buf`` -> the ``system(buf)`` argument.

It is driven by the resolved source set, never by a name list: only an argument a
model actually bound as a source is treated as an out-parameter, so an argument
that is a plain input is never reversed. The variable is found by walking the
existing ``VALUE_FLOWS_TO`` edges backward to the nearest ``variable`` node; when
that is ambiguous (more than one variable equally near) the overlay emits
nothing rather than guess a flow it cannot place on exactly one variable.
"""
from __future__ import annotations

from collections import defaultdict, deque
from typing import Any, Iterable

from ..composition import GraphDelta

FLOW_KIND = "VALUE_FLOWS_TO"


class COutParamWriteback:
    """Additive overlay: an out-parameter's write -> the variable it fills."""

    overlay_id = "c-out-param-writeback"

    def __init__(self, source_arg_ids: Iterable[str]) -> None:
        self._targets = set(source_arg_ids)

    def applies(self, graph: dict, index: Any = None) -> bool:
        return bool(self._targets)

    def enrich(self, graph: dict, index: Any = None) -> GraphDelta:
        nodes_by_id = {n["id"]: n for n in graph.get("nodes", ())}
        vft_in: dict[str, list] = defaultdict(list)
        existing: set = set()
        for edge in graph.get("edges", ()):
            if edge.get("kind") == FLOW_KIND:
                vft_in[edge["target"]].append(edge["source"])
                existing.add((edge["source"], edge["target"]))

        edges = []
        for arg_id in self._targets:
            variable = self._nearest_variable(arg_id, vft_in, nodes_by_id)
            if variable is None or (arg_id, variable) in existing:
                continue
            edges.append({
                "kind": FLOW_KIND,
                "source": arg_id, "target": variable,
                "properties": {
                    "fact_origin": "core-inference",
                    "confidence": "high",
                    "evidence_ids": [arg_id, variable],
                    "inference": "c-out-param-writeback",
                },
            })
        return GraphDelta(self.overlay_id, [], edges)

    @staticmethod
    def _nearest_variable(start: str, vft_in: dict, nodes_by_id: dict):
        """Nearest ``variable`` reached walking ``VALUE_FLOWS_TO`` backward.

        Returns the unique nearest variable, or ``None`` if there is none or the
        shallowest level holding a variable holds more than one (ambiguous).
        """
        seen = {start}
        frontier = deque([start])
        while frontier:
            level_vars = []
            for _ in range(len(frontier)):
                node = frontier.popleft()
                for src in vft_in.get(node, ()):
                    if src in seen:
                        continue
                    seen.add(src)
                    if nodes_by_id.get(src, {}).get("kind") == "variable":
                        level_vars.append(src)
                    else:
                        frontier.append(src)
            if level_vars:
                return level_vars[0] if len(level_vars) == 1 else None
        return None
