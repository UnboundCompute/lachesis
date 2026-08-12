"""Declarative host/library behavior models over canonical call facts."""
from __future__ import annotations

from ...core.composition import GraphDelta
from ...core.identities import stable_id
from ...core.query import GraphIndex


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
    "consume": {"behaviors": ["queue-consumer", "registers-callback", "async"], "callback_argument": 1, "event_argument": 0},
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


class GenericRuntimeModel:
    model_id = "generic-runtime-behaviors"
    supported_languages = ("typescript", "javascript")
    required_capabilities = ("calls", "direct_data_flow")
    exact_models = EXACT_MODELS
    method_models = METHOD_MODELS

    def applies(self, graph: dict, package_inventory: frozenset[str]) -> bool:
        del package_inventory
        return any(
            node.get("kind") in {"call", "construct"}
            and self._template(node.get("properties", {}))
            for node in graph.get("nodes", [])
        )

    def _template(self, properties: dict) -> tuple[str, dict] | None:
        # A model is a claim about one language's runtime, and a composed graph
        # holds several. `send` is a message send in Node and a value pushed into
        # a generator in Python; matching on the name alone would put the wrong
        # one in the store, so the node's own language decides.
        if properties.get("language") not in self.supported_languages:
            return None
        callee = str(properties.get("callee") or "").replace("?.", ".")
        method = str(properties.get("method_name") or callee.rsplit(".", 1)[-1])
        if callee in self.exact_models:
            return callee, self.exact_models[callee]
        if method in self.method_models:
            return f"*.{method}", self.method_models[method]
        return None

    def enrich(self, graph: dict) -> GraphDelta:
        index = GraphIndex(graph)
        nodes = []
        edges = []
        arguments_by_call: dict[str, list[dict]] = {}
        for argument in index.nodes_of_kind("argument"):
            callsite_id = argument.get("properties", {}).get("callsite_id")
            if callsite_id:
                arguments_by_call.setdefault(callsite_id, []).append(argument)

        for call in index.nodes_of_kind("call", "construct"):
            matched = self._template(call.get("properties", {}))
            if not matched:
                continue
            name, template = matched
            arguments = sorted(
                arguments_by_call.get(call["id"], []),
                key=lambda node: node.get("properties", {}).get("position", -1),
            )
            evidence = [call["id"], *(argument["id"] for argument in arguments)]
            fact = {
                "fact_origin": "runtime-model", "confidence": "high",
                "evidence_ids": evidence,
            }
            effect_id = stable_id(
                "runtime-model", self.model_id, "function-effect", call["id"], name,
            )
            properties = {
                **fact, "model_id": self.model_id, "model": name,
                "effect_kind": "runtime-call", "callsite_id": call["id"],
                "behaviors": list(template["behaviors"]),
                "receiver_value_id": call.get("properties", {}).get("receiver_value_id"),
                **{key: value for key, value in template.items() if key != "behaviors"},
            }
            event_position = properties.get("event_argument")
            if isinstance(event_position, int) and 0 <= event_position < len(arguments):
                argument = arguments[event_position]
                if argument.get("properties", {}).get("literal"):
                    properties["event_name"] = argument["properties"].get("literal_value")
            nodes.append({
                "id": effect_id, "kind": "function-effect",
                "label": f"runtime:{name}", "properties": properties,
            })
            edges.extend([
                {"kind": "APPLIES_EFFECT", "source": call["id"], "target": effect_id,
                 "properties": dict(fact)},
                {"kind": "EVIDENCED_BY", "source": effect_id, "target": call["id"],
                 "properties": dict(fact)},
            ])
            call_value_id = call.get("properties", {}).get("value_id")
            for position in template.get("derives_return_from", []):
                if call_value_id and position < len(arguments):
                    edges.append({
                        "kind": "VALUE_FLOWS_TO", "source": arguments[position]["id"],
                        "target": call_value_id,
                        "properties": {**fact, "reason": "runtime-derived-return"},
                    })
            receiver_id = properties.get("receiver_value_id")
            if call_value_id and receiver_id and template.get("derives_return_from_receiver"):
                edges.append({
                    "kind": "VALUE_FLOWS_TO", "source": receiver_id,
                    "target": call_value_id,
                    "properties": {**fact, "reason": "runtime-derived-return"},
                })
            if receiver_id and "mutates-receiver" in template["behaviors"]:
                edges.append({
                    "kind": "MUTATES", "source": call["id"], "target": receiver_id,
                    "properties": {**fact, "effect_id": effect_id},
                })
        return GraphDelta(self.model_id, nodes, edges)


# What the standard library does, restricted to calls whose behaviour is decided
# by the name rather than by the type of whatever it was called on. `read` and
# `write` are absent for that reason: on an arbitrary object they mean nothing in
# particular, and a model that fires on every `.read()` is noise, not a fact.
PYTHON_EXACT_MODELS = {
    "os.system": {"behaviors": ["process-execution"]},
    "os.popen": {"behaviors": ["process-execution"]},
    "subprocess.run": {"behaviors": ["process-execution"]},
    "subprocess.call": {"behaviors": ["process-execution"]},
    "subprocess.check_call": {"behaviors": ["process-execution"]},
    "subprocess.check_output": {"behaviors": ["process-execution"]},
    "subprocess.Popen": {"behaviors": ["process-execution"]},
    "open": {"behaviors": ["filesystem-access"]},
    "json.loads": {"behaviors": ["parse", "derives-return"], "derives_return_from": [0]},
    "json.load": {"behaviors": ["parse", "derives-return"], "derives_return_from": [0]},
    "json.dumps": {"behaviors": ["serialize", "derives-return"], "derives_return_from": [0]},
    "str": {"behaviors": ["coerce", "derives-return"], "derives_return_from": [0]},
    "int": {"behaviors": ["parse", "derives-return"], "derives_return_from": [0]},
    "float": {"behaviors": ["parse", "derives-return"], "derives_return_from": [0]},
    "bytes": {"behaviors": ["coerce", "derives-return"], "derives_return_from": [0]},
    "eval": {"behaviors": ["dynamic-evaluation"]},
    "exec": {"behaviors": ["dynamic-evaluation"]},
}

PYTHON_METHOD_MODELS = {
    # `"...".format(x)` and `sep.join(parts)` are how a string is built out of
    # something else, which is the same interpolation shape an f-string has and
    # the reason either one is worth following.
    "format": {"behaviors": ["derives-return-from-receiver"],
               "derives_return_from_receiver": True},
    "join": {"behaviors": ["derives-return-from-receiver"],
             "derives_return_from_receiver": True},
    "encode": {"behaviors": ["encode", "derives-return-from-receiver"],
               "derives_return_from_receiver": True},
    "decode": {"behaviors": ["decode", "derives-return-from-receiver"],
               "derives_return_from_receiver": True},
    "append": {"behaviors": ["mutates-receiver"], "value_arguments": [0]},
    "extend": {"behaviors": ["mutates-receiver"], "value_arguments": [0]},
    "update": {"behaviors": ["mutates-receiver"], "value_arguments": "all"},
}
for _method in ("lower", "upper", "strip", "lstrip", "rstrip", "replace",
                "split", "splitlines", "title", "casefold"):
    PYTHON_METHOD_MODELS.setdefault(_method, {
        "behaviors": ["derives-return-from-receiver"],
        "derives_return_from_receiver": True,
    })


class PythonRuntimeModel(GenericRuntimeModel):
    """The same machinery over the standard library instead of over Node's."""

    model_id = "python-runtime-behaviors"
    supported_languages = ("python",)
    exact_models = PYTHON_EXACT_MODELS
    method_models = PYTHON_METHOD_MODELS

    def _template(self, properties: dict) -> tuple[str, dict] | None:
        if properties.get("language") not in self.supported_languages:
            return None
        # The Python frontend records the callee in two pieces, the receiver text
        # and the attribute, because a dotted name there is an attribute access
        # and not a qualified identifier the way it is in Node.
        name = str(properties.get("callee_name") or "")
        receiver = properties.get("receiver")
        callee = f"{receiver}.{name}" if receiver else name
        if callee in self.exact_models:
            return callee, self.exact_models[callee]
        if receiver and name in self.method_models:
            return f"*.{name}", self.method_models[name]
        return None
