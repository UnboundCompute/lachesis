"""Connect intraprocedural variable histories across function boundaries."""
from typing import Iterable


def link_data_flow(files: Iterable[dict]) -> None:
    file_list = list(files)
    functions_by_id = {
        function["id"]: (info, function)
        for info in file_list for function in info["functions"]
    }

    for info in file_list:
        arguments_by_call = {}
        for argument in info["arguments"]:
            arguments_by_call.setdefault(argument["call_id"], []).append(argument)

        for call in info["function_calls"]:
            target_function_id = call.get("declaration_symbol_id")
            target_pair = functions_by_id.get(target_function_id)
            if not target_pair:
                if call.get("resolution") in {"language-runtime", "external"}:
                    for argument in arguments_by_call.get(call["id"], []):
                        info["data_flows"].append({
                            "kind": "ARGUMENT_TO_CALL_RETURN",
                            "source": argument["id"],
                            "target": call["return_value_id"],
                            "properties": {"call_id": call["id"]},
                        })
                continue
            target_info, target_function = target_pair
            parameter_symbols = sorted(
                (
                    symbol for symbol in target_info["symbols"]
                    if symbol["kind"] == "parameter"
                    and symbol.get("owner_function_id") == target_function_id
                ),
                key=lambda symbol: symbol.get("position", 0),
            )
            parameter_definitions = {
                definition["symbol_id"]: definition
                for definition in target_info["definitions"]
                if definition["origin"] == "parameter"
            }
            for argument, parameter in zip(
                sorted(arguments_by_call.get(call["id"], []), key=lambda item: item["position"]),
                parameter_symbols,
            ):
                parameter_definition = parameter_definitions.get(parameter["id"])
                if parameter_definition:
                    info["data_flows"].append({
                        "kind": "ARGUMENT_TO_PARAMETER",
                        "source": argument["id"],
                        "target": parameter_definition["id"],
                        "properties": {
                            "position": argument["position"], "call_id": call["id"],
                        },
                    })

            for return_value in target_info["returns"]:
                if return_value["function_id"] == target_function_id:
                    info["data_flows"].append({
                        "kind": "RETURN_TO_CALLER",
                        "source": return_value["id"],
                        "target": call["return_value_id"],
                        "properties": {"call_id": call["id"]},
                    })

    # Captures point to every known version because closures retain a live
    # binding, not a snapshot of only the version present at declaration time.
    definitions_by_symbol = {}
    for info in file_list:
        for definition in info["definitions"]:
            definitions_by_symbol.setdefault(definition["symbol_id"], []).append(definition)
    for info in file_list:
        for function in info["functions"]:
            for captured_symbol_id in function.get("captures", []):
                for definition in definitions_by_symbol.get(captured_symbol_id, []):
                    info["data_flows"].append({
                        "kind": "CAPTURE_FLOW",
                        "source": definition["id"],
                        "target": function["id"],
                        "properties": {"symbol_id": captured_symbol_id},
                    })

    propagate_origins(file_list)


def propagate_origins(files: Iterable[dict]) -> None:
    file_list = list(files)
    origins = {}
    records = {}
    for info in file_list:
        for collection_name in ("definitions", "arguments", "returns"):
            for record in info[collection_name]:
                records[record["id"]] = record
                origins.setdefault(record["id"], set())
        for call in info["function_calls"]:
            origins.setdefault(call["return_value_id"], set())
        for definition in info["definitions"]:
            if definition["origin"] not in {"expression", "uninitialized"}:
                origins[definition["id"]].add(definition["id"])
        for collection_name in ("arguments", "returns"):
            for record in info[collection_name]:
                if record.get("origin") == "literal":
                    origins[record["id"]].add(record["id"])

    flows = [flow for info in file_list for flow in info["data_flows"]]
    changed = True
    while changed:
        changed = False
        for flow in flows:
            source_origins = origins.setdefault(flow["source"], set())
            target_origins = origins.setdefault(flow["target"], set())
            before = len(target_origins)
            target_origins.update(source_origins)
            if len(target_origins) != before:
                changed = True

    for record_id, record in records.items():
        record["origin_definition_ids"] = sorted(origins.get(record_id, set()))
