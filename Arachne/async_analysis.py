"""Manual async continuation, callback, event, stream, and worker flow."""
import hashlib
from collections import defaultdict
from typing import Iterable, Optional


def stable_id(kind: str, *parts) -> str:
    raw = ":".join(str(part) for part in parts)
    return f"{kind}:{hashlib.sha256((kind + ':' + raw).encode()).hexdigest()[:16]}"


def literal_name(expression: str) -> str:
    value = expression.strip()
    if len(value) >= 2 and value[0] in "'\"`" and value[-1] == value[0]:
        return value[1:-1]
    return value or "*"


def analyze_async_flow(files: Iterable[dict]) -> None:
    file_list = list(files)
    functions_by_name = defaultdict(list)
    for info in file_list:
        info["async_nodes"] = []
        info["async_edges"] = []
        for function in info["functions"]:
            functions_by_name[function["name"]].append((info, function))

    event_nodes = {}

    def event_node(info: dict, category: str, name: str) -> str:
        key = (category, name)
        node_id = stable_id("async-event", category, name)
        if key not in event_nodes:
            event_nodes[key] = node_id
            info["async_nodes"].append({
                "id": node_id, "kind": category, "label": f"{category}:{name}",
                "name": name,
            })
        return node_id

    def add_edge(info: dict, kind: str, source: str, target: str, **properties):
        edge = {"kind": kind, "source": source, "target": target, "properties": properties}
        if source and target and edge not in info["async_edges"]:
            info["async_edges"].append(edge)

    def callback_target(info: dict, argument: Optional[dict]) -> Optional[str]:
        if not argument:
            return None
        inline = [
            function for function in info["functions"]
            if argument["start_offset"] <= function["start_offset"]
            and function["end_offset"] <= argument["end_offset"]
        ]
        if inline:
            return min(
                inline, key=lambda item: item["end_offset"] - item["start_offset"]
            )["id"]
        expression = argument["expression"].strip()
        if expression in functions_by_name:
            local = [pair for pair in functions_by_name[expression] if pair[0] is info]
            return (local or functions_by_name[expression])[0][1]["id"]
        return argument["id"]  # Explicit unresolved callback value.

    for info in file_list:
        arguments_by_call = defaultdict(list)
        for argument in info["arguments"]:
            arguments_by_call[argument["call_id"]].append(argument)
        models_by_call = {model["call_id"]: model for model in info["runtime_models"]}
        calls_by_id = {call["id"]: call for call in info["function_calls"]}

        for call in info["function_calls"]:
            model = models_by_call.get(call["id"])
            if not model:
                continue
            arguments = sorted(
                arguments_by_call.get(call["id"], []),
                key=lambda item: item["position"],
            )
            callback_position = model.get("callback_argument")
            callback = (
                arguments[callback_position]
                if isinstance(callback_position, int)
                and -len(arguments) <= callback_position < len(arguments)
                else None
            )
            target = callback_target(info, callback)
            if target:
                add_edge(
                    info, "REGISTERS_CALLBACK", call["id"], target,
                    model=model["model"], callback_position=callback_position,
                )
                if "timer" in model["behaviors"] or "microtask" in model["behaviors"]:
                    add_edge(info, "SCHEDULES", call["id"], target, queue=model["behaviors"][0])
                if "promise-continuation" in model["behaviors"]:
                    add_edge(
                        info, "ASYNC_CONTINUES_AT", call["return_value_id"], target,
                        completion="fulfilled",
                    )
                elif "promise-rejection" in model["behaviors"]:
                    add_edge(
                        info, "ASYNC_CONTINUES_AT", call["return_value_id"], target,
                        completion="rejected",
                    )

            event_name = model.get("event_name")
            event_position = model.get("event_argument")
            if event_name is None and isinstance(event_position, int) and event_position < len(arguments):
                event_name = literal_name(arguments[event_position]["expression"])
            if "event-registration" in model["behaviors"] and target:
                event = event_node(info, "event", event_name or "*")
                add_edge(info, "HANDLED_BY", event, target, registration_call_id=call["id"])
            if "queue-consumer" in model["behaviors"] and target:
                event = event_node(info, "message-queue", event_name or "*")
                add_edge(info, "HANDLED_BY", event, target, registration_call_id=call["id"])
            if "emits-event" in model["behaviors"]:
                category = "worker-message" if "worker-message" in model["behaviors"] else "event"
                event = event_node(info, category, event_name or "*")
                add_edge(info, "EMITS_EVENT", call["id"], event, model=model["model"])
            if "message-send" in model["behaviors"] or "message-publish" in model["behaviors"]:
                event = event_node(info, "message-queue", event_name or "*")
                add_edge(info, "SCHEDULES", call["id"], event, model=model["model"])
            if "stream-pipe" in model["behaviors"] or "stream-transform" in model["behaviors"]:
                position = model.get("destination_argument", 0)
                if position < len(arguments):
                    add_edge(
                        info, "SCHEDULES", call["id"], arguments[position]["id"],
                        queue="stream",
                    )
            if "worker-spawn" in model["behaviors"]:
                worker = event_node(info, "worker", f"line-{call['line']}")
                add_edge(info, "SCHEDULES", call["id"], worker, queue="worker-thread")

        # Await suspends the containing statement and resumes at its CFG
        # successor. The operation node remains the exact suspension point.
        for operation in info["operations"]:
            if operation["kind"] != "await":
                continue
            statement = min(
                (
                    item for item in info["statements"]
                    if item["start_offset"] <= operation["start_offset"]
                    and operation["end_offset"] <= item["end_offset"]
                ),
                key=lambda item: item["end_offset"] - item["start_offset"],
                default=None,
            )
            if not statement:
                continue
            successors = [
                edge["target"] for edge in info["cfg_edges"]
                if edge["source"] == statement["id"]
                and edge["kind"] in {"CFG_NEXT", "CFG_EXIT", "CFG_RETURN"}
            ]
            for successor in successors:
                add_edge(
                    info, "ASYNC_CONTINUES_AT", operation["id"], successor,
                    suspension="await", statement_id=statement["id"],
                )

        # Exported request handlers are event entrypoints even when no direct
        # caller appears in the analyzed source tree.
        exports = set(info["exports"])
        for function in info["functions"]:
            if function["name"] not in exports:
                continue
            lowered = function["name"].lower()
            if not any(part in lowered for part in ("handler", "handle", "webhook", "route")):
                continue
            event = event_node(info, "webhook", function["name"])
            add_edge(info, "HANDLED_BY", event, function["id"], external_entry=True)
