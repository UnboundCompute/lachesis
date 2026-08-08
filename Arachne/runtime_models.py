"""Central behavior models for JavaScript, host-runtime, and library calls."""
import hashlib
import re
from typing import Iterable, List


def stable_id(kind: str, *parts) -> str:
    raw = ":".join(str(part) for part in parts)
    return f"{kind}:{hashlib.sha256((kind + ':' + raw).encode()).hexdigest()[:16]}"


# Models are deliberately data, not call-specific conditionals. More packages
# can be added without changing graph construction or taint propagation.
EXACT_MODELS = {
    "fetch": {"behaviors": ["network-request", "async"], "url_argument": 0},
    "JSON.parse": {"behaviors": ["parse", "derives-return"], "derives_return_from": [0]},
    "JSON.stringify": {"behaviors": ["serialize", "derives-return"], "derives_return_from": [0]},
    "String": {"behaviors": ["coerce", "derives-return"], "derives_return_from": [0]},
    "Number": {"behaviors": ["coerce", "derives-return"], "derives_return_from": [0]},
    "Boolean": {"behaviors": ["coerce", "derives-return"], "derives_return_from": [0]},
    "Buffer.from": {"behaviors": ["decode-or-copy", "derives-return"], "derives_return_from": [0]},
    "parseInt": {"behaviors": ["parse", "derives-return"], "derives_return_from": [0]},
    "parseFloat": {"behaviors": ["parse", "derives-return"], "derives_return_from": [0]},
    "decodeURI": {"behaviors": ["decode", "derives-return"], "derives_return_from": [0]},
    "decodeURIComponent": {"behaviors": ["decode", "derives-return"], "derives_return_from": [0]},
    "encodeURI": {"behaviors": ["encode", "derives-return"], "derives_return_from": [0]},
    "encodeURIComponent": {"behaviors": ["encode", "derives-return"], "derives_return_from": [0]},
    "setTimeout": {"behaviors": ["timer", "registers-callback", "async"], "callback_argument": 0},
    "setInterval": {"behaviors": ["timer", "registers-callback", "async"], "callback_argument": 0},
    "setImmediate": {"behaviors": ["timer", "registers-callback", "async"], "callback_argument": 0},
    "queueMicrotask": {"behaviors": ["microtask", "registers-callback", "async"], "callback_argument": 0},
    "Worker": {"behaviors": ["worker-spawn", "async"], "worker_argument": 0},
    "readFile": {"behaviors": ["filesystem-read", "registers-callback", "async"], "callback_argument": -1},
    "fs.readFile": {"behaviors": ["filesystem-read", "registers-callback", "async"], "callback_argument": -1},
    "writeFile": {"behaviors": ["filesystem-write", "registers-callback", "async"], "callback_argument": -1},
    "fs.writeFile": {"behaviors": ["filesystem-write", "registers-callback", "async"], "callback_argument": -1},
    "exec": {"behaviors": ["process-execution", "registers-callback", "async"], "callback_argument": -1},
}

METHOD_MODELS = {
    "get": {"behaviors": ["reads-receiver"], "receiver_read": "keyed", "key_argument": 0},
    "has": {"behaviors": ["reads-receiver"], "receiver_read": "keyed", "key_argument": 0},
    "set": {"behaviors": ["mutates-receiver"], "receiver_write": "keyed", "key_argument": 0, "value_arguments": [1]},
    "add": {"behaviors": ["mutates-receiver"], "receiver_write": "collection", "value_arguments": [0]},
    "delete": {"behaviors": ["mutates-receiver"], "receiver_write": "keyed", "key_argument": 0},
    "clear": {"behaviors": ["mutates-receiver"], "receiver_write": "all"},
    "push": {"behaviors": ["mutates-receiver"], "receiver_write": "elements", "value_arguments": "all"},
    "pop": {"behaviors": ["mutates-receiver", "reads-receiver"], "receiver_write": "elements"},
    "text": {"behaviors": ["response-body", "async", "derives-return-from-receiver"], "derives_return_from_receiver": True},
    "json": {"behaviors": ["response-body", "parse", "async", "derives-return-from-receiver"], "derives_return_from_receiver": True},
    "arrayBuffer": {"behaviors": ["response-body", "async", "derives-return-from-receiver"], "derives_return_from_receiver": True},
    "then": {"behaviors": ["promise-continuation", "registers-callback", "async"], "callback_argument": 0},
    "catch": {"behaviors": ["promise-rejection", "registers-callback", "async"], "callback_argument": 0},
    "finally": {"behaviors": ["promise-finalizer", "registers-callback", "async"], "callback_argument": 0},
    "addEventListener": {"behaviors": ["event-registration", "registers-callback"], "event_argument": 0, "callback_argument": 1},
    "on": {"behaviors": ["event-registration", "registers-callback"], "event_argument": 0, "callback_argument": 1},
    "once": {"behaviors": ["event-registration", "registers-callback"], "event_argument": 0, "callback_argument": 1},
    "subscribe": {"behaviors": ["subscription", "registers-callback", "async"], "callback_argument": 0},
    "consume": {"behaviors": ["queue-consumer", "registers-callback", "async"], "callback_argument": 1},
    "emit": {"behaviors": ["emits-event"], "event_argument": 0},
    "dispatchEvent": {"behaviors": ["emits-event"], "event_argument": 0},
    "publish": {"behaviors": ["message-publish", "emits-event", "async"], "event_argument": 0},
    "send": {"behaviors": ["message-send", "async"], "value_arguments": "all"},
    "postMessage": {"behaviors": ["worker-message", "emits-event", "async"], "event_name": "message", "value_arguments": [0]},
    "pipe": {"behaviors": ["stream-pipe", "async"], "destination_argument": 0},
    "pipeThrough": {"behaviors": ["stream-transform", "async"], "destination_argument": 0},
}

for _method in {
    "at", "concat", "normalize", "padEnd", "padStart", "repeat", "replace",
    "replaceAll", "slice", "split", "substring", "substr", "toLowerCase",
    "toString", "toUpperCase", "trim", "trimEnd", "trimStart", "valueOf",
}:
    METHOD_MODELS.setdefault(_method, {
        "behaviors": ["derives-return-from-receiver"],
        "derives_return_from_receiver": True,
    })


def model_for_call(call: dict) -> dict:
    callee = call.get("callee", "").replace("?.", ".")
    method = call.get("method_name") or callee.split(".")[-1]
    template = EXACT_MODELS.get(callee) or METHOD_MODELS.get(method)
    if not template:
        return {}
    return {"name": callee if callee in EXACT_MODELS else f"*.{method}", **template}


def analyze_runtime_models(files: Iterable[dict]) -> None:
    for info in files:
        arguments_by_call = {}
        for argument in info["arguments"]:
            arguments_by_call.setdefault(argument["call_id"], []).append(argument)
        models = []
        for call in info["function_calls"]:
            suffix = info["text"][call.get("arguments_end_offset", call["end_offset"]) + 1:]
            if re.match(r"\s*:\s*[^;{]+;", suffix):
                continue  # Type/method signature, not an executed call.
            template = model_for_call(call)
            if not template:
                continue
            arguments = sorted(
                arguments_by_call.get(call["id"], []),
                key=lambda item: item["position"],
            )
            model = {
                "id": stable_id("runtime-model-application", call["id"], template["name"]),
                "call_id": call["id"], "model": template["name"],
                "behaviors": list(template["behaviors"]),
                "line": call["line"], "return_value_id": call["return_value_id"],
                "receiver_definition_id": (call.get("receiver") or {}).get("definition_id"),
                "argument_ids": [argument["id"] for argument in arguments],
            }
            for key, value in template.items():
                if key not in {"name", "behaviors"}:
                    model[key] = value
            models.append(model)
        info["runtime_models"] = models
