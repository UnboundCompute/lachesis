"""Async, callback and event flow derived from modeled canonical calls."""
from __future__ import annotations

from collections import defaultdict

from ..composition import GraphDelta
from ..identities import stable_id
from ..query import GraphIndex


def _fact(evidence_ids: list[str], confidence: str = "high") -> dict:
    return {
        "fact_origin": "core-inference", "confidence": confidence,
        "evidence_ids": list(dict.fromkeys(evidence_ids)),
    }


class AsyncEvents:
    overlay_id = "async-events"

    def applies(self, graph: dict) -> bool:
        return any(
            node.get("kind") == "function-effect"
            and node.get("properties", {}).get("effect_kind") == "runtime-call"
            for node in graph.get("nodes", [])
        ) or any(
            node.get("properties", {}).get("operator") == "await"
            for node in graph.get("nodes", [])
        )

    def enrich(self, graph: dict) -> GraphDelta:
        index = GraphIndex(graph)
        nodes = []
        edges = []
        emitted_nodes: set[str] = set()
        emitted_edges: set[tuple[str, str, str]] = set()
        arguments_by_call: dict[str, list[dict]] = defaultdict(list)
        ast_parent: dict[str, str] = {}
        cfg_successors: dict[str, list[str]] = defaultdict(list)

        for argument in index.nodes_of_kind("argument"):
            callsite = argument.get("properties", {}).get("callsite_id")
            if callsite:
                arguments_by_call[callsite].append(argument)
        for edge in graph.get("edges", []):
            kind = index.semantic_edge_kind(edge)
            if kind == "AST_CHILD":
                ast_parent[edge["target"]] = edge["source"]
            elif kind in {"CFG_NEXT", "TRUE_BRANCH", "FALSE_BRANCH", "SWITCH_CASE"}:
                cfg_successors[edge["source"]].append(edge["target"])

        def add_edge(kind: str, source: str, target: str, evidence: list[str], **properties) -> None:
            if not source or not target or source == target:
                return
            key = (kind, source, target)
            if key in emitted_edges:
                return
            emitted_edges.add(key)
            edges.append({
                "kind": kind, "source": source, "target": target,
                "properties": {**_fact(evidence), **properties},
            })

        def event_node(category: str, receiver_id: str | None, name, evidence: list[str]) -> str:
            event_name = str(name) if name is not None else "*"
            event_id = stable_id(
                "core", self.overlay_id, "async-event",
                category, receiver_id or "global", event_name,
            )
            if event_id not in emitted_nodes:
                emitted_nodes.add(event_id)
                nodes.append({
                    "id": event_id, "kind": "async-event",
                    "label": f"{category}:{event_name}",
                    "properties": {
                        **_fact(evidence), "event_kind": category,
                        "event_name": event_name, "receiver_value_id": receiver_id,
                    },
                })
            return event_id

        for effect in index.nodes_of_kind("function-effect"):
            properties = effect.get("properties", {})
            if properties.get("effect_kind") != "runtime-call":
                continue
            call_id = properties.get("callsite_id")
            call = index.nodes.get(call_id)
            if not call:
                continue
            arguments = sorted(
                arguments_by_call.get(call_id, []),
                key=lambda node: node.get("properties", {}).get("position", -1),
            )
            behaviors = set(properties.get("behaviors", []))
            callback_position = properties.get("callback_argument")
            if isinstance(callback_position, int) and callback_position < 0:
                callback_position += len(arguments)
            callback = arguments[callback_position] if isinstance(
                callback_position, int,
            ) and 0 <= callback_position < len(arguments) else None
            targets = list(index.targets(callback["id"], "PASSES_CALLBACK")) if callback else []
            if callback and not targets:
                targets = [callback]
            evidence = [effect["id"], call_id, *(target["id"] for target in targets)]
            for target in targets:
                add_edge(
                    "REGISTERS_CALLBACK", call_id, target["id"], evidence,
                    effect_id=effect["id"], callback_position=callback_position,
                )
                if behaviors.intersection({"timer", "microtask"}):
                    queue = "microtask" if "microtask" in behaviors else "timer"
                    add_edge("SCHEDULES", call_id, target["id"], evidence, queue=queue)
                completion = "fulfilled" if "promise-continuation" in behaviors else \
                    "rejected" if "promise-rejection" in behaviors else \
                    "finally" if "promise-finalizer" in behaviors else None
                if completion:
                    add_edge(
                        "ASYNC_CONTINUES_AT",
                        call.get("properties", {}).get("value_id") or call_id,
                        target["id"], evidence, completion=completion,
                    )

            receiver_id = properties.get("receiver_value_id")
            event_name = properties.get("event_name", "*")
            if "event-registration" in behaviors and targets:
                event = event_node("event", receiver_id, event_name, evidence)
                for target in targets:
                    add_edge(
                        "HANDLED_BY", event, target["id"], evidence,
                        registration_call_id=call_id,
                    )
            if "queue-consumer" in behaviors and targets:
                event = event_node("message-queue", receiver_id, event_name, evidence)
                for target in targets:
                    add_edge(
                        "HANDLED_BY", event, target["id"], evidence,
                        registration_call_id=call_id,
                    )
            if "emits-event" in behaviors:
                category = "worker-message" if "worker-message" in behaviors else \
                    "message-queue" if "message-publish" in behaviors else "event"
                event = event_node(category, receiver_id, event_name, evidence)
                add_edge("EMITS_EVENT", call_id, event, evidence, effect_id=effect["id"])
            if behaviors.intersection({"message-send", "message-publish"}):
                event = event_node("message-queue", receiver_id, event_name, evidence)
                add_edge("SCHEDULES", call_id, event, evidence, queue="message")
            if behaviors.intersection({"stream-pipe", "stream-transform"}):
                position = properties.get("destination_argument", 0)
                if isinstance(position, int) and 0 <= position < len(arguments):
                    add_edge(
                        "SCHEDULES", call_id, arguments[position]["id"], evidence,
                        queue="stream",
                    )
            if "worker-spawn" in behaviors:
                worker = event_node("worker", call_id, call_id, evidence)
                add_edge("SCHEDULES", call_id, worker, evidence, queue="worker-thread")

        for operation in index.nodes_of_kind("expression", "operation"):
            if operation.get("properties", {}).get("operator") != "await":
                continue
            statement_id = operation["id"]
            while statement_id in ast_parent and index.nodes.get(
                statement_id, {},
            ).get("kind") != "statement":
                statement_id = ast_parent[statement_id]
            if index.nodes.get(statement_id, {}).get("kind") != "statement":
                continue
            for successor in cfg_successors.get(statement_id, []):
                add_edge(
                    "ASYNC_CONTINUES_AT", operation["id"], successor,
                    [operation["id"], statement_id, successor],
                    suspension="await", statement_id=statement_id,
                )

        return GraphDelta(self.overlay_id, nodes, edges)

