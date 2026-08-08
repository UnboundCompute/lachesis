"""Create distinct call-site contexts and contextual receiver dispatches."""
import hashlib
from typing import Dict, Iterable, List


def stable_id(kind: str, *parts) -> str:
    raw = ":".join(str(part) for part in parts)
    digest = hashlib.sha256(f"{kind}:{raw}".encode("utf-8")).hexdigest()[:16]
    return f"{kind}:{digest}"


def analyze_call_contexts(files: Iterable[dict]) -> None:
    file_list = list(files)
    functions_by_id = {
        function["id"]: (info, function)
        for info in file_list for function in info["functions"]
    }
    definitions_by_id = {
        definition["id"]: definition
        for info in file_list for definition in info["definitions"]
    }
    contexts_by_callee: Dict[str, List[dict]] = {}

    for info in file_list:
        contexts = []
        for call in info["function_calls"]:
            context_id = stable_id("call-context", call["id"])
            target_ids = list(dict.fromkeys(
                target_id for target_id in (
                    call.get("dispatch_target_ids", [])
                    or [call.get("declaration_symbol_id")]
                )
                if target_id in functions_by_id
            ))
            if call.get("method_name") == "bind":
                target_ids = []
            target_pairs = [
                (target_id, functions_by_id[target_id]) for target_id in target_ids
            ]
            target_info, target_function = (
                target_pairs[0][1] if len(target_pairs) == 1 else (None, None)
            )
            context = {
                "id": context_id, "call_id": call["id"],
                "caller_function_id": call.get("caller_function_id"),
                "callee_function_id": target_function["id"] if target_function else None,
                "callee_function_ids": target_ids,
                "callee_file": target_info["path"] if target_info else None,
                "resolution": call.get("resolution"), "line": call["line"],
                "parameter_bindings": [], "receiver_binding": None,
                "return_value_id": stable_id("context-return", context_id),
                "dispatch_target_ids": call.get("dispatch_target_ids", []),
                "dispatch_status": call.get("dispatch_status", "unresolved"),
            }
            arguments = sorted(
                (argument for argument in info["arguments"] if argument["call_id"] == call["id"]),
                key=lambda argument: argument["position"],
            )
            if call.get("method_name") in {"call", "apply"}:
                arguments = arguments[1:]
            for target_function_id, (candidate_info, candidate_function) in target_pairs:
                parameter_symbols = sorted(
                    (
                        symbol for symbol in candidate_info["symbols"]
                        if symbol["kind"] == "parameter"
                        and symbol.get("owner_function_id") == target_function_id
                    ),
                    key=lambda symbol: symbol.get("position", 0),
                )
                parameter_definitions = {
                    definition["symbol_id"]: definition
                    for definition in candidate_info["definitions"]
                    if definition["origin"] == "parameter"
                }
                for argument, parameter in zip(arguments, parameter_symbols):
                    parameter_definition = parameter_definitions.get(parameter["id"])
                    reads = [
                        read for read in info["reads"]
                        if argument["start_offset"] <= read["offset"]
                        and read.get("end_offset", read["offset"] + 1) <= argument["end_offset"]
                    ]
                    source_definition_ids = list(dict.fromkeys(
                        read["definition_id"] for read in reads
                    ))
                    inferred_types = [
                        definitions_by_id[source_id].get("inferred_type")
                        for source_id in source_definition_ids
                        if source_id in definitions_by_id
                        and definitions_by_id[source_id].get("inferred_type")
                    ]
                    binding = {
                        "id": stable_id("context-parameter", context_id, parameter["id"]),
                        "position": parameter.get("position", 0),
                        "argument_position": argument["position"],
                        "argument_id": argument["id"],
                        "parameter_symbol_id": parameter["id"],
                        "parameter_definition_id": (
                            parameter_definition["id"] if parameter_definition else None
                        ),
                        "target_function_id": target_function_id,
                        "source_definition_ids": source_definition_ids,
                        "origin_definition_ids": argument.get("origin_definition_ids", []),
                        "inferred_type": inferred_types[0] if inferred_types else None,
                        "points_to": [],
                    }
                    context["parameter_bindings"].append(binding)

            receiver = call.get("receiver")
            if receiver:
                context["receiver_binding"] = {
                    "id": stable_id("context-receiver", context_id),
                    "expression": receiver["expression"],
                    "definition_id": receiver.get("definition_id"),
                    "symbol_id": receiver.get("symbol_id"),
                    "inferred_type": (
                        {
                            "name": receiver.get("type"),
                            "type_id": receiver.get("type_id"),
                            "kind": receiver.get("kind"),
                        }
                        if receiver.get("type") else None
                    ),
                    "points_to": [],
                }
            contexts.append(context)
            for target_function_id in target_ids:
                contexts_by_callee.setdefault(target_function_id, []).append(context)
        info["call_contexts"] = contexts

    # Specialize member dispatch when an enclosing function's receiver is a
    # parameter whose concrete type differs between call sites.
    methods_by_type_name = {}
    for info in file_list:
        types_by_id = {declared_type["id"]: declared_type for declared_type in info["types"]}
        for function in info["functions"]:
            owner = types_by_id.get(function.get("owner_type_id"))
            if owner:
                methods_by_type_name[(owner["name"], function["name"])] = (info, function)

    for info in file_list:
        dispatches = []
        for call in info["function_calls"]:
            receiver = call.get("receiver") or {}
            receiver_definition_id = receiver.get("definition_id")
            caller_function_id = call.get("caller_function_id")
            if not receiver_definition_id or not caller_function_id:
                continue
            for parent_context in contexts_by_callee.get(caller_function_id, []):
                binding = next(
                    (
                        item for item in parent_context["parameter_bindings"]
                        if item["parameter_definition_id"] == receiver_definition_id
                    ),
                    None,
                )
                if not binding:
                    continue
                inferred_type = binding.get("inferred_type") or {}
                type_name = inferred_type.get("name")
                target_pair = methods_by_type_name.get((type_name, call.get("method_name")))
                dispatches.append({
                    "id": stable_id("context-dispatch", call["id"], parent_context["id"]),
                    "call_id": call["id"], "parent_context_id": parent_context["id"],
                    "receiver_binding_id": binding["id"], "receiver_type": type_name,
                    "target_function_id": target_pair[1]["id"] if target_pair else None,
                    "target_file": target_pair[0]["path"] if target_pair else None,
                    "confidence": "high" if target_pair else "unresolved",
                })
        info["context_dispatches"] = dispatches
