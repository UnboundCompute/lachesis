"""Interprocedural read/write summaries and call-site effect application."""
import hashlib
import re
from collections import defaultdict
from typing import Iterable

from .function_analysis import mask_non_code


def stable_id(kind: str, *parts) -> str:
    raw = ":".join(str(part) for part in parts)
    return f"{kind}:{hashlib.sha256((kind + ':' + raw).encode()).hexdigest()[:16]}"


def analyze_effects(files: Iterable[dict]) -> None:
    file_list = list(files)
    summaries = {}
    function_owner = {}
    symbols = {}
    properties = {}
    definitions = {}
    for info in file_list:
        info["effect_summaries"] = []
        info["applied_effects"] = []
        for function in info["functions"]:
            function_owner[function["id"]] = info
        symbols.update({symbol["id"]: symbol for symbol in info["symbols"]})
        properties.update({prop["id"]: prop for prop in info["properties"]})
        definitions.update({definition["id"]: definition for definition in info["definitions"]})

    def base_symbol(symbol_or_property_id):
        prop = properties.get(symbol_or_property_id)
        return symbols.get(prop["base_symbol_id"] if prop else symbol_or_property_id), prop

    def effect_key(effect):
        return (
            effect["kind"], effect.get("parameter_position"),
            effect.get("target_symbol_id"), effect.get("path", ""),
        )

    def add_effect(summary, kind, **properties_data):
        effect = {"kind": kind, **properties_data}
        if effect_key(effect) in {effect_key(item) for item in summary["effects"]}:
            return False
        effect["id"] = stable_id(
            "function-effect", summary["function_id"], *effect_key(effect)
        )
        summary["effects"].append(effect)
        return True

    for info in file_list:
        returns_by_function = defaultdict(list)
        for returned in info["returns"]:
            returns_by_function[returned.get("function_id")].append(returned)
        for function in info["functions"]:
            returned = returns_by_function.get(function["id"], [])
            declared_return = (function.get("return_type") or "").strip()
            summary = {
                "id": stable_id("effect-summary", function["id"]),
                "function_id": function["id"], "function_name": function["name"],
                "returns": (
                    "void" if declared_return in {"void", "Promise<void>"} or not returned
                    else "never" if returned and all(item["kind"] == "throw" for item in returned)
                    else "value"
                ),
                "async": function.get("form", "").startswith("async")
                or declared_return.startswith("Promise<"),
                "effects": [],
            }
            summaries[function["id"]] = summary
            info["effect_summaries"].append(summary)

        for read in info["reads"]:
            definition = definitions.get(read.get("definition_id"))
            symbol, prop = base_symbol(read["symbol_id"])
            if not symbol:
                continue
            function_id = symbol.get("owner_function_id")
            # A property read can occur in a different function than the base
            # declaration; use the read's enclosing function when available.
            enclosing = min(
                (
                    function for function in info["functions"]
                    if function["start_offset"] <= read["offset"] <= function["end_offset"]
                ),
                key=lambda item: item["end_offset"] - item["start_offset"],
                default=None,
            )
            function_id = enclosing["id"] if enclosing else function_id
            summary = summaries.get(function_id)
            if not summary:
                continue
            path = prop["path"] if prop else ""
            if symbol["kind"] == "parameter" and symbol.get("owner_function_id") == function_id:
                add_effect(
                    summary, "reads-parameter", parameter_position=symbol.get("position", 0),
                    parameter_symbol_id=symbol["id"], path=path,
                )
            elif symbol["kind"] == "import":
                add_effect(summary, "reads-imported-state", target_symbol_id=symbol["id"], path=path)
            elif symbol.get("owner_function_id") is None and symbol["kind"] in {"const", "let", "var"}:
                add_effect(summary, "reads-global-state", target_symbol_id=symbol["id"], path=path)

        for definition in info["definitions"]:
            if definition["kind"] != "property-write":
                continue
            symbol, prop = base_symbol(definition["symbol_id"])
            if not symbol or not prop:
                continue
            enclosing = min(
                (
                    function for function in info["functions"]
                    if function["start_offset"] <= definition["offset"] <= function["end_offset"]
                ),
                key=lambda item: item["end_offset"] - item["start_offset"],
                default=None,
            )
            summary = summaries.get((enclosing or {}).get("id"))
            if not summary:
                continue
            if symbol["kind"] == "parameter" and symbol.get("owner_function_id") == summary["function_id"]:
                add_effect(
                    summary, "reads-parameter",
                    parameter_position=symbol.get("position", 0),
                    parameter_symbol_id=symbol["id"], path="",
                )
                add_effect(
                    summary, "writes-parameter", parameter_position=symbol.get("position", 0),
                    parameter_symbol_id=symbol["id"], path=prop["path"],
                    value_source_ids=definition.get("origin_definition_ids", []),
                )
            elif symbol["kind"] == "import":
                add_effect(summary, "writes-imported-state", target_symbol_id=symbol["id"], path=prop["path"])
            elif symbol.get("owner_function_id") is None:
                add_effect(summary, "writes-global-state", target_symbol_id=symbol["id"], path=prop["path"])

        # `this` is a keyword rather than a normal variable symbol, so retain
        # receiver effects with a small direct pass over each method body.
        masked = mask_non_code(info["text"])
        for function in info["functions"]:
            summary = summaries[function["id"]]
            body = masked[function["body_start_offset"]:function["end_offset"] + 1]
            for match in re.finditer(
                r"\bthis(?:\.|\?\.)\s*([A-Za-z_$][\w$]*)\s*"
                r"(?P<write>\+\+|--|\?\?=|&&=|\|\|=|\+=|-=|\*=|/=|%=|=(?!=|>))?",
                body,
            ):
                add_effect(
                    summary,
                    "writes-receiver" if match.group("write") else "reads-receiver",
                    path=match.group(1), owner_type_id=function.get("owner_type_id"),
                )

        calls_by_id = {call["id"]: call for call in info["function_calls"]}
        for model in info.get("runtime_models", []):
            call = calls_by_id.get(model["call_id"])
            summary = summaries.get((call or {}).get("caller_function_id"))
            if not call or not summary:
                continue
            receiver_definition = definitions.get(model.get("receiver_definition_id"))
            receiver_symbol = symbols.get((receiver_definition or {}).get("symbol_id"))
            path = str(model.get("receiver_write") or model.get("receiver_read") or model["model"])
            if receiver_symbol:
                if receiver_symbol["kind"] == "parameter" and receiver_symbol.get("owner_function_id") == summary["function_id"]:
                    if "reads-receiver" in model["behaviors"]:
                        add_effect(
                            summary, "reads-parameter",
                            parameter_position=receiver_symbol.get("position", 0),
                            parameter_symbol_id=receiver_symbol["id"], path=path,
                        )
                    if "mutates-receiver" in model["behaviors"]:
                        add_effect(
                            summary, "writes-parameter",
                            parameter_position=receiver_symbol.get("position", 0),
                            parameter_symbol_id=receiver_symbol["id"], path=path,
                        )
                elif receiver_symbol["kind"] == "import":
                    action = "writes" if "mutates-receiver" in model["behaviors"] else "reads"
                    add_effect(summary, f"{action}-imported-state", target_symbol_id=receiver_symbol["id"], path=path)
                elif receiver_symbol.get("owner_function_id") is None:
                    action = "writes" if "mutates-receiver" in model["behaviors"] else "reads"
                    add_effect(summary, f"{action}-global-state", target_symbol_id=receiver_symbol["id"], path=path)
            for behavior, effect_kind in (
                ("network-request", "performs-network-request"),
                ("filesystem-read", "performs-filesystem-read"),
                ("filesystem-write", "performs-filesystem-write"),
                ("process-execution", "performs-process-execution"),
                ("message-send", "sends-message"),
                ("message-publish", "publishes-message"),
                ("worker-spawn", "spawns-worker"),
            ):
                if behavior in model["behaviors"]:
                    add_effect(summary, effect_kind, path=model["model"])

    # Compose summaries through source-linked calls. Parameter effects are
    # remapped when the callee argument is itself a caller parameter.
    changed = True
    while changed:
        changed = False
        for info in file_list:
            arguments_by_call = defaultdict(list)
            for argument in info["arguments"]:
                arguments_by_call[argument["call_id"]].append(argument)
            for call in info["function_calls"]:
                caller = summaries.get(call.get("caller_function_id"))
                callees = [
                    summaries[target_id]
                    for target_id in (
                        call.get("dispatch_target_ids")
                        or [call.get("declaration_symbol_id")]
                    )
                    if target_id in summaries
                ]
                if not caller or not callees:
                    continue
                arguments = sorted(arguments_by_call.get(call["id"], []), key=lambda item: item["position"])
                for effect in [item for callee in callees for item in callee["effects"]]:
                    copied = {key: value for key, value in effect.items() if key != "id"}
                    if "parameter_position" in copied:
                        position = copied["parameter_position"]
                        if position >= len(arguments):
                            continue
                        argument = arguments[position]
                        reads = [
                            read for read in info["reads"]
                            if argument["start_offset"] <= read["offset"]
                            and read.get("end_offset", read["offset"] + 1) <= argument["end_offset"]
                        ]
                        if len(reads) != 1:
                            continue
                        source_definition = definitions.get(reads[0]["definition_id"])
                        candidate_definitions = [source_definition] if source_definition else []
                        candidate_definitions.extend(
                            definitions[origin_id]
                            for origin_id in (source_definition or {}).get("origin_definition_ids", [])
                            if origin_id in definitions
                        )
                        source_symbol = next(
                            (
                                symbols.get(candidate.get("symbol_id"))
                                for candidate in candidate_definitions
                                if symbols.get(candidate.get("symbol_id"), {}).get("kind") == "parameter"
                                and symbols.get(candidate.get("symbol_id"), {}).get("owner_function_id") == caller["function_id"]
                            ),
                            None,
                        )
                        if not source_symbol or source_symbol["kind"] != "parameter" or source_symbol.get("owner_function_id") != caller["function_id"]:
                            continue
                        copied["parameter_position"] = source_symbol.get("position", 0)
                        copied["parameter_symbol_id"] = source_symbol["id"]
                    elif "receiver" in copied["kind"]:
                        receiver_definition = definitions.get(
                            (call.get("receiver") or {}).get("definition_id")
                        )
                        candidate_definitions = (
                            [receiver_definition] if receiver_definition else []
                        )
                        candidate_definitions.extend(
                            definitions[origin_id]
                            for origin_id in (receiver_definition or {}).get(
                                "origin_definition_ids", []
                            )
                            if origin_id in definitions
                        )
                        receiver_symbol = next(
                            (
                                symbols.get(candidate.get("symbol_id"))
                                for candidate in candidate_definitions
                                if symbols.get(candidate.get("symbol_id"), {}).get("kind") == "parameter"
                                and symbols.get(candidate.get("symbol_id"), {}).get("owner_function_id") == caller["function_id"]
                            ),
                            None,
                        )
                        if receiver_symbol:
                            copied["kind"] = copied["kind"].replace(
                                "receiver", "parameter"
                            )
                            copied["parameter_position"] = receiver_symbol.get("position", 0)
                            copied["parameter_symbol_id"] = receiver_symbol["id"]
                    copied["via_call_id"] = call["id"]
                    changed |= add_effect(caller, copied.pop("kind"), **copied)

    # Instantiate each summary at each concrete call context.
    for info in file_list:
        contexts = {context["call_id"]: context for context in info["call_contexts"]}
        for call in info["function_calls"]:
            call_summaries = [
                summaries[target_id]
                for target_id in (
                    call.get("dispatch_target_ids")
                    or [call.get("declaration_symbol_id")]
                )
                if target_id in summaries
            ]
            context = contexts.get(call["id"])
            if not call_summaries or not context:
                continue
            for summary in call_summaries:
                for effect in summary["effects"]:
                    target_ids = []
                    if "parameter_position" in effect:
                        binding = next(
                            (
                                item for item in context["parameter_bindings"]
                                if item["position"] == effect["parameter_position"]
                                and item.get("target_function_id", summary["function_id"])
                                == summary["function_id"]
                            ),
                            None,
                        )
                        if binding:
                            target_ids = [binding["id"], *binding.get("points_to", [])]
                    elif "receiver" in effect["kind"] and context.get("receiver_binding"):
                        receiver = context["receiver_binding"]
                        target_ids = [receiver["id"], *receiver.get("points_to", [])]
                    elif effect.get("target_symbol_id"):
                        target_ids = [effect["target_symbol_id"]]
                    applied = {
                        "id": stable_id("applied-effect", context["id"], effect["id"]),
                        "context_id": context["id"], "call_id": call["id"],
                        "summary_id": summary["id"], "effect_id": effect["id"],
                        "kind": effect["kind"], "path": effect.get("path", ""),
                        "target_ids": target_ids,
                    }
                    if not any(item["id"] == applied["id"] for item in info["applied_effects"]):
                        info["applied_effects"].append(applied)
