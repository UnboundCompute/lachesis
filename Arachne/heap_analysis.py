"""Allocation-site heap identity, points-to sets, and mutation summaries."""
import hashlib
import re
from typing import Dict, Iterable, List, Optional, Set, Tuple

from .receiver_analysis import clean_type_name


PRIMITIVE_TYPES = {
    "bigint", "boolean", "Boolean", "number", "Number", "string", "String",
    "symbol", "Symbol", "null", "undefined", "void", "never",
}
COLLECTION_WRITES = {"set", "add", "delete", "clear", "push", "pop", "shift", "unshift", "splice"}
COLLECTION_READS = {"get", "has", "at", "find", "includes", "values", "keys", "entries"}


def stable_id(kind: str, *parts) -> str:
    raw = ":".join(str(part) for part in parts)
    digest = hashlib.sha256(f"{kind}:{raw}".encode("utf-8")).hexdigest()[:16]
    return f"{kind}:{digest}"


def latest_definition(info: dict, symbol_id: str, offset: int) -> Optional[dict]:
    return max(
        (
            definition for definition in info["definitions"]
            if definition["symbol_id"] == symbol_id and definition["offset"] <= offset
        ),
        key=lambda definition: definition["offset"],
        default=None,
    )


def analyze_heap(files: Iterable[dict]) -> None:
    file_list = list(files)
    info_by_function = {
        function["id"]: info for info in file_list for function in info["functions"]
    }
    definitions_by_id = {
        definition["id"]: (info, definition)
        for info in file_list for definition in info["definitions"]
    }
    operations_by_id = {
        operation["id"]: (info, operation)
        for info in file_list for operation in info["operations"]
    }
    calls_by_id = {
        call["id"]: (info, call)
        for info in file_list for call in info["function_calls"]
    }
    contexts = [context for info in file_list for context in info["call_contexts"]]
    context_owner = {
        context["id"]: info for info in file_list for context in info["call_contexts"]
    }
    value_owner = {}
    for info in file_list:
        for collection in ("definitions", "operations", "arguments", "returns", "reads"):
            for record in info[collection]:
                value_owner[record["id"]] = info
        for call in info["function_calls"]:
            value_owner[call["return_value_id"]] = info
        for context in info["call_contexts"]:
            value_owner[context["return_value_id"]] = info
            for binding in context["parameter_bindings"]:
                value_owner[binding["id"]] = info
            if context.get("receiver_binding"):
                value_owner[context["receiver_binding"]["id"]] = info

    heap_objects: Dict[str, dict] = {}
    object_owner: Dict[str, dict] = {}
    points: Dict[str, Set[str]] = {}

    def add_object(info: dict, object_id: str, kind: str, **properties) -> dict:
        if object_id not in heap_objects:
            record = {"id": object_id, "kind": kind, **properties}
            heap_objects[object_id] = record
            object_owner[object_id] = info
            info["heap_objects"].append(record)
        return heap_objects[object_id]

    def add_points(value_id: Optional[str], object_ids: Iterable[str]) -> bool:
        if not value_id:
            return False
        target = points.setdefault(value_id, set())
        before = len(target)
        target.update(object_ids)
        return len(target) != before

    for info in file_list:
        info["heap_objects"] = []
        info["heap_locations"] = []
        info["points_to"] = []
        info["heap_accesses"] = []
        info["heap_effects"] = []
        info["context_heap_effects"] = []

    # Every construction expression is a concrete allocation site.
    for info in file_list:
        attachments_by_operation = {}
        for attachment in info["operation_attachments"]:
            attachments_by_operation.setdefault(attachment["operation_id"], []).append(attachment)
        for operation in info["operations"]:
            if operation["kind"] not in {"object-construction", "array-construction"}:
                continue
            allocated_type = None
            construction_kind = "array" if operation["kind"] == "array-construction" else "object"
            constructor = re.match(r"\s*new\s+([A-Za-z_$][\w$\.]*)", operation["text"])
            if constructor:
                allocated_type = constructor.group(1).split(".")[-1]
                construction_kind = "collection" if allocated_type in {"Map", "Set", "WeakMap", "WeakSet"} else "instance"
            for attachment in attachments_by_operation.get(operation["id"], []):
                if attachment["entity_kind"] != "DEFINITION":
                    continue
                pair = definitions_by_id.get(attachment["entity_id"])
                inferred = pair[1].get("inferred_type") if pair else None
                allocated_type = allocated_type or (inferred or {}).get("name")
            object_id = stable_id("heap-object", operation["id"])
            add_object(
                info, object_id, construction_kind,
                allocation_operation_id=operation["id"],
                allocation_expression_id=operation["expression_id"],
                allocated_type=allocated_type,
                line=operation["line"], context_id=None,
            )
            add_points(operation["id"], [object_id])

    # Parameters receive abstract objects. A call context later substitutes
    # these with the concrete objects passed by that particular call site.
    parameter_objects_by_definition = {}
    for info in file_list:
        symbols_by_id = {symbol["id"]: symbol for symbol in info["symbols"]}
        for definition in info["definitions"]:
            if definition["origin"] != "parameter":
                continue
            symbol = symbols_by_id.get(definition["symbol_id"])
            annotation = clean_type_name((symbol or {}).get("declared_type"))
            if annotation in PRIMITIVE_TYPES:
                continue
            object_id = stable_id("heap-parameter", definition["id"])
            add_object(
                info, object_id, "parameter",
                parameter_definition_id=definition["id"],
                parameter_symbol_id=definition["symbol_id"],
                function_id=(symbol or {}).get("owner_function_id"),
                allocated_type=annotation, line=definition["line"], context_id=None,
            )
            parameter_objects_by_definition[definition["id"]] = object_id
            add_points(definition["id"], [object_id])

    # Operation results carry allocation identity to definitions, arguments,
    # returns, and nested operation results.
    op_attachment_pairs = []
    for info in file_list:
        for attachment in info["operation_attachments"]:
            if attachment["entity_kind"] in {"DEFINITION", "ARGUMENT", "RETURN_VALUE"}:
                op_attachment_pairs.append((attachment["operation_id"], attachment["entity_id"]))

    # Pure aliases preserve identity. Do not treat arbitrary dependencies as
    # aliases: an object used as a function argument is not the call result.
    alias_pairs = []
    for info in file_list:
        for definition in info["definitions"]:
            start = definition.get("expression_start")
            end = definition.get("expression_end")
            if start is None or end is None:
                continue
            expression = info["text"][start:end].strip()
            if not re.fullmatch(
                r"(?:await\s+)?[A-Za-z_$][\w$]*(?:\??\.[A-Za-z_$][\w$]*|\[[^\]]+\])*",
                expression,
            ):
                continue
            reads = [
                read for read in info["reads"]
                if start <= read["offset"]
                and read.get("end_offset", read["offset"] + 1) <= end
            ]
            if len(reads) == 1:
                alias_pairs.append((reads[0]["definition_id"], definition["id"]))
        for argument in info["arguments"]:
            reads = [
                read for read in info["reads"]
                if argument["start_offset"] <= read["offset"]
                and read.get("end_offset", read["offset"] + 1) <= argument["end_offset"]
            ]
            if len(reads) == 1:
                alias_pairs.append((reads[0]["definition_id"], argument["id"]))
        for returned in info["returns"]:
            reads = [
                read for read in info["reads"]
                if returned["start_offset"] <= read["offset"]
                and read.get("end_offset", read["offset"] + 1) <= returned["end_offset"]
            ]
            if len(reads) == 1:
                alias_pairs.append((reads[0]["definition_id"], returned["id"]))

    call_return_pairs = []
    for info in file_list:
        for flow in info["data_flows"]:
            if flow["kind"] == "CALL_RETURN_TO":
                call_return_pairs.append((flow["source"], flow["target"]))

    # Link a call operation with its semantic call-return value.
    for info in file_list:
        calls_for_operation = {
            attachment["operation_id"]: attachment["entity_id"]
            for attachment in info["operation_attachments"]
            if attachment["entity_kind"] == "CALL"
        }
        for operation_id, call_id in calls_for_operation.items():
            call_pair = calls_by_id.get(call_id)
            if call_pair:
                call_return_pairs.append((call_pair[1]["return_value_id"], operation_id))

    changed = True
    while changed:
        changed = False
        for source, target in op_attachment_pairs + alias_pairs + call_return_pairs:
            changed |= add_points(target, points.get(source, set()))
        for context in contexts:
            for binding in context["parameter_bindings"]:
                for source_id in binding["source_definition_ids"]:
                    changed |= add_points(binding["id"], points.get(source_id, set()))
                binding["points_to"] = sorted(points.get(binding["id"], set()))
            receiver = context.get("receiver_binding")
            if receiver:
                changed |= add_points(
                    receiver["id"], points.get(receiver.get("definition_id"), set())
                )
                receiver["points_to"] = sorted(points.get(receiver["id"], set()))

            call_pair = calls_by_id.get(context["call_id"])
            target_function_ids = context.get("callee_function_ids", []) or (
                [context["callee_function_id"]] if context.get("callee_function_id") else []
            )
            if not call_pair or not target_function_ids:
                continue
            caller_info, call = call_pair
            binding_by_parameter_object = {}
            for binding in context["parameter_bindings"]:
                parameter_object = parameter_objects_by_definition.get(
                    binding["parameter_definition_id"]
                )
                if parameter_object:
                    binding_by_parameter_object[parameter_object] = points.get(binding["id"], set())
            returned_objects = set()
            for target_function_id in target_function_ids:
                callee_info = info_by_function.get(target_function_id)
                if not callee_info:
                    continue
                for returned in callee_info["returns"]:
                    if returned.get("function_id") != target_function_id:
                        continue
                    for object_id in points.get(returned["id"], set()):
                        if object_id in binding_by_parameter_object:
                            returned_objects.update(binding_by_parameter_object[object_id])
                            continue
                        heap_object = heap_objects[object_id]
                        if heap_object.get("function_id") == target_function_id or (
                            heap_object.get("allocation_operation_id")
                            and operations_by_id.get(heap_object["allocation_operation_id"], (None, {}))[1].get("function_id")
                            == target_function_id
                        ):
                            instance_id = stable_id(
                                "context-heap", context["id"], target_function_id, object_id
                            )
                            add_object(
                                caller_info, instance_id, heap_object["kind"],
                                allocation_operation_id=heap_object.get("allocation_operation_id"),
                                allocation_expression_id=heap_object.get("allocation_expression_id"),
                                allocated_type=heap_object.get("allocated_type"),
                                line=call["line"], context_id=context["id"],
                                allocation_template_id=object_id,
                            )
                            returned_objects.add(instance_id)
                        else:
                            returned_objects.add(object_id)
            changed |= add_points(context["return_value_id"], returned_objects)
            changed |= add_points(call["return_value_id"], returned_objects)

    # Heap locations are keyed by object identity, so aliases converge on the
    # same property even when different variable names were used.
    locations: Dict[Tuple[str, str], dict] = {}
    location_values: Dict[str, Set[str]] = {}

    def location(object_id: str, path: str) -> dict:
        key = (object_id, path)
        if key not in locations:
            owner = object_owner[object_id]
            record = {
                "id": stable_id("heap-location", object_id, path),
                "object_id": object_id, "path": path,
            }
            locations[key] = record
            owner["heap_locations"].append(record)
        return locations[key]

    def path_parts(path: str) -> List[str]:
        return [
            match.group(1) or match.group(2)
            for match in re.finditer(r"(?:^|\.)([A-Za-z_$][\w$]*)|(\[[^\]]+\])", path)
        ] or [path]

    def target_locations(object_id: str, path: str) -> List[dict]:
        parts = path_parts(path)
        current_objects = {object_id}
        for part in parts[:-1]:
            next_objects = set()
            for current_object in current_objects:
                intermediate = location(current_object, part)
                next_objects.update(location_values.get(intermediate["id"], set()))
            if not next_objects:
                return [location(object_id, path)]
            current_objects = next_objects
        return [location(current_object, parts[-1]) for current_object in current_objects]

    # Initialize object properties and array elements from literal expression
    # structure. Nested construction operations already point to their own
    # allocation objects, so child locations retain exact identity.
    for info in file_list:
        operations_by_expression = {
            operation["expression_id"]: operation for operation in info["operations"]
        }
        expressions = {expression["id"]: expression for expression in info["expressions"]}
        links_by_parent = {}
        for link in info["expression_links"]:
            links_by_parent.setdefault(link["parent"], []).append(link)
        attachments_by_expression = {}
        for attachment in info["body_attachments"]:
            attachments_by_expression.setdefault(attachment.get("expression_id"), []).append(attachment)
        for operation in info["operations"]:
            if operation["kind"] not in {"object-construction", "array-construction"}:
                continue
            parent_objects = points.get(operation["id"], set())
            if not parent_objects:
                continue
            links = links_by_parent.get(operation["expression_id"], [])
            keys = {
                link.get("position"): expressions[link["child"]]["text"].strip().strip("'\"")
                for link in links if link["role"] == "PROPERTY_KEY"
            }
            values = [
                link for link in links
                if link["role"] in {"PROPERTY_VALUE", "ELEMENT"}
            ]
            for link in values:
                position = link.get("position", 0)
                value_expression = expressions[link["child"]]["text"].strip()
                shorthand = (
                    value_expression
                    if operation["kind"] == "object-construction"
                    and re.fullmatch(r"[A-Za-z_$][\w$]*", value_expression)
                    else None
                )
                path = keys.get(position, shorthand or f"[{position}]")
                child_operation = operations_by_expression.get(link["child"])
                value_objects = set(
                    points.get((child_operation or {}).get("id"), set())
                )
                for attachment in attachments_by_expression.get(link["child"], []):
                    if attachment["entity_kind"] == "READ":
                        read = next(
                            (item for item in info["reads"] if item["id"] == attachment["entity_id"]),
                            None,
                        )
                        if read:
                            value_objects.update(points.get(read["definition_id"], set()))
                for parent_object in parent_objects:
                    heap_location = location(parent_object, path)
                    location_values.setdefault(heap_location["id"], set()).update(value_objects)
                    info["heap_accesses"].append({
                        "id": stable_id("heap-access", operation["id"], heap_location["id"], position),
                        "kind": "initialize", "location_id": heap_location["id"],
                        "object_id": parent_object, "path": path,
                        "entity_id": operation["id"],
                        "function_id": operation.get("function_id"),
                        "value_source_ids": [child_operation["id"]] if child_operation else [],
                    })

    for info in file_list:
        properties_by_id = {item["id"]: item for item in info["properties"]}
        flows_to_target = {}
        for flow in info["data_flows"]:
            if flow["kind"] == "FLOWS_TO":
                flows_to_target.setdefault(flow["target"], []).append(flow["source"])
        for definition in info["definitions"]:
            property_info = properties_by_id.get(definition["symbol_id"])
            if not property_info or definition["kind"] != "property-write":
                continue
            base_definition = latest_definition(
                info, property_info["base_symbol_id"], definition["offset"]
            )
            for object_id in points.get((base_definition or {}).get("id"), set()):
                for heap_location in target_locations(object_id, property_info["path"]):
                    sources = list(dict.fromkeys(
                        [definition["id"], *flows_to_target.get(definition["id"], [])]
                    ))
                    values = set().union(*(points.get(source, set()) for source in sources)) if sources else set()
                    location_values.setdefault(heap_location["id"], set()).update(values)
                    info["heap_accesses"].append({
                        "id": stable_id("heap-access", definition["id"], heap_location["id"]),
                        "kind": "write", "location_id": heap_location["id"],
                        "object_id": heap_location["object_id"], "path": heap_location["path"],
                        "entity_id": definition["id"], "function_id": (
                            next((symbol.get("owner_function_id") for symbol in info["symbols"] if symbol["id"] == property_info["base_symbol_id"]), None)
                        ),
                        "value_source_ids": sources,
                    })
        for read in info["reads"]:
            property_info = properties_by_id.get(read["symbol_id"])
            if not property_info:
                continue
            base_definition = latest_definition(
                info, property_info["base_symbol_id"], read["offset"]
            )
            for object_id in points.get((base_definition or {}).get("id"), set()):
                for heap_location in target_locations(object_id, property_info["path"]):
                    info["heap_accesses"].append({
                        "id": stable_id("heap-access", read["id"], heap_location["id"]),
                        "kind": "read", "location_id": heap_location["id"],
                        "object_id": heap_location["object_id"], "path": heap_location["path"],
                        "entity_id": read["id"], "function_id": (
                            next((symbol.get("owner_function_id") for symbol in info["symbols"] if symbol["id"] == property_info["base_symbol_id"]), None)
                        ),
                        "value_source_ids": [],
                    })
                    stored_objects = location_values.get(heap_location["id"], set())
                    add_points(read["id"], stored_objects)
                    add_points(read["definition_id"], stored_objects)

    # Property reads can create new alias points-to facts after locations are
    # known. Drain those aliases before producing graph edges.
    changed = True
    while changed:
        changed = False
        for source, target in alias_pairs + call_return_pairs:
            changed |= add_points(target, points.get(source, set()))

    # Reads can reveal the object behind an aliased property, enabling a later
    # write through that alias. Iterate property reads/writes and aliases until
    # heap identity stops changing.
    changed = True
    while changed:
        changed = False
        for info in file_list:
            properties_by_id = {item["id"]: item for item in info["properties"]}
            flows_to_target = {}
            for flow in info["data_flows"]:
                if flow["kind"] == "FLOWS_TO":
                    flows_to_target.setdefault(flow["target"], []).append(flow["source"])
            for read in info["reads"]:
                property_info = properties_by_id.get(read["symbol_id"])
                if not property_info:
                    continue
                base_definition = latest_definition(
                    info, property_info["base_symbol_id"], read["offset"]
                )
                for object_id in points.get((base_definition or {}).get("id"), set()):
                    for heap_location in target_locations(object_id, property_info["path"]):
                        stored = location_values.get(heap_location["id"], set())
                        changed |= add_points(read["id"], stored)
                        changed |= add_points(read["definition_id"], stored)
                        access_id = stable_id("heap-access", read["id"], heap_location["id"])
                        if not any(item["id"] == access_id for item in info["heap_accesses"]):
                            info["heap_accesses"].append({
                                "id": access_id, "kind": "read",
                                "location_id": heap_location["id"],
                                "object_id": heap_location["object_id"],
                                "path": heap_location["path"], "entity_id": read["id"],
                                "function_id": next(
                                    (
                                        symbol.get("owner_function_id")
                                        for symbol in info["symbols"]
                                        if symbol["id"] == property_info["base_symbol_id"]
                                    ),
                                    None,
                                ),
                                "value_source_ids": [],
                            })
            for source, target in alias_pairs:
                changed |= add_points(target, points.get(source, set()))
            for definition in info["definitions"]:
                property_info = properties_by_id.get(definition["symbol_id"])
                if not property_info or definition["kind"] != "property-write":
                    continue
                base_definition = latest_definition(
                    info, property_info["base_symbol_id"], definition["offset"]
                )
                for object_id in points.get((base_definition or {}).get("id"), set()):
                    for heap_location in target_locations(object_id, property_info["path"]):
                        sources = list(dict.fromkeys(
                            [definition["id"], *flows_to_target.get(definition["id"], [])]
                        ))
                        values = set().union(
                            *(points.get(source, set()) for source in sources)
                        ) if sources else set()
                        stored = location_values.setdefault(heap_location["id"], set())
                        before = len(stored)
                        stored.update(values)
                        changed |= len(stored) != before
                        access_id = stable_id(
                            "heap-access", definition["id"], heap_location["id"]
                        )
                        if not any(item["id"] == access_id for item in info["heap_accesses"]):
                            info["heap_accesses"].append({
                                "id": access_id, "kind": "write",
                                "location_id": heap_location["id"],
                                "object_id": heap_location["object_id"],
                                "path": heap_location["path"],
                                "entity_id": definition["id"],
                                "function_id": next(
                                    (
                                        symbol.get("owner_function_id")
                                        for symbol in info["symbols"]
                                        if symbol["id"] == property_info["base_symbol_id"]
                                    ),
                                    None,
                                ),
                                "value_source_ids": sources,
                            })

    # Collection methods mutate/read receiver heap objects directly.
    for info in file_list:
        arguments_by_call = {}
        for argument in info["arguments"]:
            arguments_by_call.setdefault(argument["call_id"], []).append(argument)
        for call in info["function_calls"]:
            method = call.get("method_name")
            if method not in COLLECTION_WRITES | COLLECTION_READS:
                continue
            receiver = call.get("receiver") or {}
            receiver_objects = points.get(receiver.get("definition_id"), set())
            arguments = sorted(arguments_by_call.get(call["id"], []), key=lambda item: item["position"])
            path = f"[[{method}:{arguments[0]['expression'] if arguments else '*'}]]"
            for object_id in receiver_objects:
                heap_location = location(object_id, path)
                kind = "collection-write" if method in COLLECTION_WRITES else "collection-read"
                sources = [argument["id"] for argument in arguments[1:] or arguments]
                if kind == "collection-write":
                    values = set().union(*(points.get(source, set()) for source in sources)) if sources else set()
                    location_values.setdefault(heap_location["id"], set()).update(values)
                else:
                    add_points(call["return_value_id"], location_values.get(heap_location["id"], set()))
                info["heap_accesses"].append({
                    "id": stable_id("heap-access", call["id"], heap_location["id"]),
                    "kind": kind, "location_id": heap_location["id"],
                    "object_id": object_id, "path": path,
                    "entity_id": call["id"],
                    "function_id": call.get("caller_function_id"),
                    "value_source_ids": sources,
                })

    # Summarize effects performed through abstract parameter objects.
    for info in file_list:
        for access in info["heap_accesses"]:
            heap_object = heap_objects[access["object_id"]]
            if heap_object["kind"] != "parameter" or not access.get("function_id"):
                continue
            effect = {
                "id": stable_id("heap-effect", access["function_id"], access["kind"], access["path"]),
                "function_id": access["function_id"], "kind": access["kind"],
                "parameter_definition_id": heap_object["parameter_definition_id"],
                "path": access["path"], "access_id": access["id"],
                "value_source_ids": access["value_source_ids"],
            }
            if not any(existing["id"] == effect["id"] for existing in info["heap_effects"]):
                info["heap_effects"].append(effect)

    # Apply parameter effects separately to each call context.
    effects_by_function = {}
    for info in file_list:
        for effect in info["heap_effects"]:
            effects_by_function.setdefault(effect["function_id"], []).append(effect)
    for context in contexts:
        owner = context_owner[context["id"]]
        target_function_ids = context.get("callee_function_ids", []) or (
            [context["callee_function_id"]] if context.get("callee_function_id") else []
        )
        for target_function_id in target_function_ids:
            for effect in effects_by_function.get(target_function_id, []):
                binding = next(
                    (
                        item for item in context["parameter_bindings"]
                        if item["parameter_definition_id"] == effect["parameter_definition_id"]
                    ),
                    None,
                )
                if not binding:
                    continue
                for object_id in points.get(binding["id"], set()):
                    heap_location = location(object_id, effect["path"])
                    owner["context_heap_effects"].append({
                        "id": stable_id("context-heap-effect", context["id"], effect["id"], object_id),
                        "context_id": context["id"], "effect_id": effect["id"],
                        "kind": effect["kind"], "object_id": object_id,
                        "location_id": heap_location["id"], "path": effect["path"],
                        "binding_id": binding["id"],
                    })

    for value_id, object_ids in points.items():
        if not object_ids:
            continue
        owner = value_owner.get(value_id)
        if owner:
            for object_id in sorted(object_ids):
                owner["points_to"].append({"source": value_id, "target": object_id})
