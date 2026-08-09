"""Candidate-based dynamic dispatch for TypeScript and JavaScript calls."""
import hashlib
import re
from collections import defaultdict
from typing import Iterable, List, Optional, Set

from .source_analysis import mask_non_code
from .receiver_analysis import split_top_level


def stable_id(kind: str, *parts) -> str:
    raw = ":".join(str(part) for part in parts)
    return f"{kind}:{hashlib.sha256((kind + ':' + raw).encode()).hexdigest()[:16]}"


def type_names(annotation: Optional[str]) -> List[str]:
    if not annotation:
        return []
    result = []
    for alternative in split_top_level(annotation, "|"):
        value = alternative.strip()
        if value in {"null", "undefined", "void", "never"}:
            continue
        match = re.match(r"(?:typeof\s+)?([A-Za-z_$][\w$\.]*)", value)
        if match:
            result.append(match.group(1).split(".")[-1])
    return list(dict.fromkeys(result))


def analyze_dispatch(files: Iterable[dict], include_callbacks: bool = False) -> None:
    file_list = list(files)
    types_by_name = {
        declared_type["name"]: (info, declared_type)
        for info in file_list for declared_type in info["types"]
    }
    types_by_id = {
        declared_type["id"]: (info, declared_type)
        for info in file_list for declared_type in info["types"]
    }
    functions_by_id = {
        function["id"]: (info, function)
        for info in file_list for function in info["functions"]
    }
    functions_by_name = defaultdict(list)
    methods = defaultdict(list)
    for function_id, pair in functions_by_id.items():
        functions_by_name[pair[1]["name"]].append(pair)
        if pair[1].get("owner_type_id"):
            methods[(pair[1]["owner_type_id"], pair[1]["name"])].append(pair)

    prototype_methods = defaultdict(list)
    class_function_properties = defaultdict(set)
    for info in file_list:
        masked = mask_non_code(info["text"])
        for match in re.finditer(
            r"\b([A-Za-z_$][\w$]*)\.prototype\.([A-Za-z_$][\w$]*)\s*=",
            masked,
        ):
            expression_end = masked.find(";", match.end())
            if expression_end < 0:
                expression_end = len(masked)
            expression = info["text"][match.end():expression_end].strip()
            named = re.fullmatch(r"([A-Za-z_$][\w$]*)", expression)
            targets = list(functions_by_name.get(named.group(1), [])) if named else []
            targets.extend(
                (info, function) for function in info["functions"]
                if match.end() <= function["start_offset"] <= expression_end
            )
            for target in targets:
                if target not in prototype_methods[(match.group(1), match.group(2))]:
                    prototype_methods[(match.group(1), match.group(2))].append(target)

        for declared_type in info["types"]:
            if declared_type["kind"] != "class":
                continue
            body_start, body_end = declared_type["start_offset"], declared_type["end_offset"]
            body_masked = masked[body_start:body_end + 1]
            for match in re.finditer(
                r"(?:^|[;{}\n])\s*(?:public|private|protected|readonly|static\s+)*"
                r"([A-Za-z_$][\w$]*)\s*=\s*([A-Za-z_$][\w$]*)\s*(?:;|$)",
                body_masked,
            ):
                for _target_info, target in functions_by_name.get(match.group(2), []):
                    class_function_properties[(
                        declared_type["id"], match.group(1)
                    )].add(target["id"])

    if not include_callbacks:
        for info in file_list:
            info["dispatch_candidates"] = []
            info["dispatch_relations"] = []
            info["dispatch_members"] = []

    # Explicit interface/abstract method nodes remain valid candidates even
    # when no concrete implementation is present in the analyzed files.
    for info in file_list:
        if include_callbacks:
            continue
        masked = mask_non_code(info["text"])
        for declared_type in info["types"]:
            if declared_type["kind"] not in {"interface", "class"}:
                continue
            body = info["text"][declared_type["start_offset"]:declared_type["end_offset"] + 1]
            for match in re.finditer(
                r"(?:^|[;{}\n])\s*(?P<abstract>abstract\s+)?"
                r"(?P<name>[A-Za-z_$][\w$]*)\s*\([^;{}]*\)\s*(?::[^;{}]+)?;",
                body,
            ):
                if declared_type["kind"] != "interface" and not match.group("abstract"):
                    continue
                member = {
                    "id": stable_id("dispatch-member", declared_type["id"], match.group("name")),
                    "owner_type_id": declared_type["id"], "name": match.group("name"),
                    "kind": "abstract-method" if match.group("abstract") else "interface-method",
                    "line": declared_type["start_line"] + body.count("\n", 0, match.start()),
                }
                if not any(item["id"] == member["id"] for item in info["dispatch_members"]):
                    info["dispatch_members"].append(member)

    members = {
        (item["owner_type_id"], item["name"]): (info, item)
        for info in file_list for item in info["dispatch_members"]
    }

    parents = defaultdict(list)
    implementors = defaultdict(set)
    for _info, declared_type in types_by_name.values():
        for parent_name in declared_type.get("extends", []):
            normalized = parent_name.split("<", 1)[0].strip()
            if normalized in types_by_name:
                parents[declared_type["name"]].append(normalized)
        for interface_name in declared_type.get("implements", []):
            normalized = interface_name.split("<", 1)[0].strip()
            implementors[normalized].add(declared_type["name"])

    # ES5-style prototype inheritance supplements `extends`.
    for info in file_list:
        if include_callbacks:
            continue
        masked = mask_non_code(info["text"])
        patterns = (
            r"([A-Za-z_$][\w$]*)\.prototype\s*=\s*Object\.create\(\s*([A-Za-z_$][\w$]*)\.prototype\s*\)",
            r"Object\.setPrototypeOf\(\s*([A-Za-z_$][\w$]*)\.prototype\s*,\s*([A-Za-z_$][\w$]*)\.prototype\s*\)",
        )
        for pattern in patterns:
            for match in re.finditer(pattern, masked):
                child, parent = match.group(1), match.group(2)
                parents[child].append(parent)
                info["dispatch_relations"].append({
                    "kind": "PROTOTYPE_INHERITS", "source_name": child,
                    "target_name": parent,
                    "source_type_id": types_by_name.get(child, (None, {}))[1].get("id"),
                    "target_type_id": types_by_name.get(parent, (None, {}))[1].get("id"),
                    "line": info["text"].count("\n", 0, match.start()) + 1,
                })

    def ancestors(name: str) -> List[str]:
        result, queue = [], list(parents.get(name, []))
        while queue:
            current = queue.pop(0)
            if current in result:
                continue
            result.append(current)
            queue.extend(parents.get(current, []))
        return result

    descendants = defaultdict(set)
    for name in set(types_by_name) | set(parents):
        for ancestor in ancestors(name):
            descendants[ancestor].add(name)

    def concrete_method(type_name: str, method_name: str):
        current_names = [type_name, *ancestors(type_name)]
        for current in current_names:
            prototype = prototype_methods.get((current, method_name), [])
            if prototype:
                return prototype[0]
            pair = types_by_name.get(current)
            if not pair:
                continue
            found = methods.get((pair[1]["id"], method_name), [])
            if found:
                return found[0]
        return None

    if not include_callbacks:
        # Record override/interface relationships once.
        for type_name, (_info, declared_type) in types_by_name.items():
            if declared_type["kind"] != "class":
                continue
            for (owner_id, method_name), method_pairs in methods.items():
                if owner_id != declared_type["id"]:
                    continue
                method = method_pairs[0][1]
                for parent_name in ancestors(type_name):
                    parent_method = concrete_method(parent_name, method_name)
                    if parent_method:
                        method_pairs[0][0]["dispatch_relations"].append({
                            "kind": "OVERRIDES", "source": method["id"],
                            "target": parent_method[1]["id"],
                        })
                        break
                    parent = types_by_name.get(parent_name)
                    abstract_member = members.get(
                        (((parent or (None, {}))[1]).get("id"), method_name)
                    )
                    if abstract_member:
                        method_pairs[0][0]["dispatch_relations"].append({
                            "kind": "OVERRIDES", "source": method["id"],
                            "target": abstract_member[1]["id"],
                        })
                        break
                interface_names = []
                for owner_name in [type_name, *ancestors(type_name)]:
                    owner = types_by_name.get(owner_name)
                    interface_names.extend(
                        (owner or (None, {}))[1].get("implements", [])
                    )
                for interface_name in interface_names:
                    interface = types_by_name.get(interface_name.split("<", 1)[0].strip())
                    interface_member = members.get(((interface or (None, {}))[1].get("id"), method_name))
                    if interface_member:
                        method_pairs[0][0]["dispatch_relations"].append({
                            "kind": "IMPLEMENTS_METHOD", "source": method["id"],
                            "target": interface_member[1]["id"],
                        })

    function_values = defaultdict(set)
    function_properties = defaultdict(set)
    for info in file_list:
        symbols_by_id = {symbol["id"]: symbol for symbol in info["symbols"]}
        properties_by_id = {prop["id"]: prop for prop in info["properties"]}
        for definition in info["definitions"]:
            start, end = definition.get("expression_start"), definition.get("expression_end")
            if start is None or end is None:
                continue
            expression = info["text"][start:end].strip()
            named = re.fullmatch(r"([A-Za-z_$][\w$]*)", expression)
            if named and named.group(1) in functions_by_name:
                function_values[definition["symbol_id"]].update(
                    pair[1]["id"] for pair in functions_by_name[named.group(1)]
                )
            for function in info["functions"]:
                if start <= function["start_offset"] and function["end_offset"] <= end:
                    function_values[definition["symbol_id"]].add(function["id"])
            if expression.startswith("{"):
                for property_match in re.finditer(
                    r"(?:^|[{,])\s*([A-Za-z_$][\w$]*)\s*:\s*([A-Za-z_$][\w$]*)",
                    expression,
                ):
                    function_name = property_match.group(2)
                    if function_name in functions_by_name:
                        function_properties[(
                            definition["symbol_id"], property_match.group(1)
                        )].update(
                            pair[1]["id"] for pair in functions_by_name[function_name]
                        )
            prop = properties_by_id.get(definition["symbol_id"])
            if prop and named and named.group(1) in functions_by_name:
                function_properties[(prop["base_symbol_id"], prop["path"])].update(
                    pair[1]["id"] for pair in functions_by_name[named.group(1)]
                )

    def symbol_for_name(info: dict, name: str, offset: int):
        return max(
            (symbol for symbol in info["symbols"] if symbol["name"] == name and symbol["start_offset"] <= offset),
            key=lambda item: item["start_offset"], default=None,
        )

    def targets_for_value(info: dict, expression: str, offset: int) -> Set[str]:
        value = expression.strip()
        if value in functions_by_name:
            return {pair[1]["id"] for pair in functions_by_name[value]}
        symbol = symbol_for_name(info, value, offset)
        if not symbol:
            return set()
        targets = set(function_values.get(symbol["id"], set()))
        if symbol["kind"] == "function" and symbol.get("declaration_id"):
            targets.add(symbol["declaration_id"])
        return targets

    def add_candidate(info, call, target_id, kind, confidence="high", **properties):
        target_pair = functions_by_id.get(target_id)
        target_member = next(
            (pair for pair in members.values() if pair[1]["id"] == target_id), None
        )
        target_info, target_record = target_pair or target_member or (None, {})
        candidate = {
            "id": stable_id("dispatch-candidate", call["id"], target_id, kind),
            "call_id": call["id"], "target_id": target_id,
            "target_function_id": target_id if target_id in functions_by_id else None,
            "target_name": target_record.get("name", target_id),
            "target_file": target_info.get("path") if target_info else None,
            "target_line": target_record.get("start_line", target_record.get("line")),
            "kind": kind, "confidence": confidence, "properties": properties,
        }
        if not any(item["id"] == candidate["id"] for item in info["dispatch_candidates"]):
            info["dispatch_candidates"].append(candidate)

    # Bound functions carry their original target into later variable calls.
    for info in file_list:
        for call in info["function_calls"]:
            if call.get("method_name") != "bind":
                continue
            receiver_expression = (call.get("receiver") or {}).get("expression") or call.get("receiver_expression", "")
            targets = targets_for_value(info, receiver_expression, call["start_offset"])
            for target in targets:
                add_candidate(info, call, target, "bind-target")
            for definition in info["definitions"]:
                if definition.get("expression_start", -1) <= call["start_offset"] <= definition.get("expression_end", -1):
                    function_values[definition["symbol_id"]].update(targets)

    contexts_by_callee = defaultdict(list)
    if include_callbacks:
        for info in file_list:
            for context in info.get("call_contexts", []):
                if context.get("callee_function_id"):
                    contexts_by_callee[context["callee_function_id"]].append((info, context))

    for info in file_list:
        properties_by_id = {prop["id"]: prop for prop in info["properties"]}
        symbols_by_id = {symbol["id"]: symbol for symbol in info["symbols"]}
        for call in info["function_calls"]:
            # Preserve any exact target as one candidate in the complete set.
            if call.get("declaration_symbol_id"):
                add_candidate(info, call, call["declaration_symbol_id"], "direct-or-receiver")

            if call.get("method_name") in {"call", "apply", "bind"}:
                receiver_expression = (call.get("receiver") or {}).get("expression") or call.get("receiver_expression", "")
                kind = f"function-{call['method_name']}"
                for target in targets_for_value(info, receiver_expression, call["start_offset"]):
                    add_candidate(info, call, target, kind)

            if call.get("form") in {"computed-call", "optional-computed-call"}:
                receiver = call.get("receiver") or {}
                possible_types = [receiver.get("type")] if receiver.get("type") else []
                receiver_symbol = symbols_by_id.get(receiver.get("symbol_id"))
                possible_types.extend(type_names((receiver_symbol or {}).get("declared_type")))
                keys = []
                key_expression = call.get("computed_key_expression", "")
                if re.fullmatch(r"['\"`][^'\"`]+['\"`]", key_expression):
                    keys = [key_expression[1:-1]]
                else:
                    key_symbol = symbol_for_name(info, key_expression, call["start_offset"])
                    if key_symbol:
                        keys = [
                            item[1:-1] for item in split_top_level(key_symbol.get("declared_type") or "", "|")
                            if re.fullmatch(r"['\"`][^'\"`]+['\"`]", item.strip())
                        ]
                receiver_symbol_id = receiver.get("symbol_id")
                if receiver_symbol_id in properties_by_id:
                    receiver_symbol_id = properties_by_id[receiver_symbol_id]["base_symbol_id"]
                for key_name in keys:
                    for target in function_properties.get(
                        (receiver_symbol_id, key_name), set()
                    ):
                        add_candidate(
                            info, call, target, "computed-function-property",
                            "high", key=key_name,
                        )
                for type_name in list(dict.fromkeys(item for item in possible_types if item)):
                    candidate_types = [type_name]
                    pair = types_by_name.get(type_name)
                    if pair and pair[1]["kind"] == "interface":
                        direct_implementors = implementors.get(type_name, set())
                        candidate_types.extend(sorted(direct_implementors))
                        for implementor in direct_implementors:
                            candidate_types.extend(sorted(descendants.get(implementor, set())))
                    elif (receiver.get("evidence") or "") != "constructor":
                        candidate_types.extend(sorted(descendants.get(type_name, set())))
                    method_names = keys or sorted({name for owner_id, name in methods if owner_id in {types_by_name.get(t, (None, {}))[1].get("id") for t in candidate_types}})
                    for candidate_type in candidate_types:
                        for method_name in method_names:
                            candidate_type_info = types_by_name.get(candidate_type)
                            for target in class_function_properties.get(
                                (((candidate_type_info or (None, {}))[1]).get("id"), method_name),
                                set(),
                            ):
                                add_candidate(
                                    info, call, target, "computed-function-property",
                                    "high" if keys else "conditional",
                                    receiver_type=candidate_type, key=method_name,
                                )
                            target = concrete_method(candidate_type, method_name)
                            if target:
                                add_candidate(
                                    info, call, target[1]["id"], "computed-method",
                                    "high" if keys else "conditional",
                                    receiver_type=candidate_type, key=method_name,
                                )

            receiver = call.get("receiver") or {}
            method_name = call.get("method_name")
            receiver_symbol_id = receiver.get("symbol_id")
            if receiver_symbol_id in properties_by_id:
                receiver_symbol_id = properties_by_id[receiver_symbol_id]["base_symbol_id"]
            if receiver_symbol_id and method_name:
                for target in function_properties.get((receiver_symbol_id, method_name), set()):
                    add_candidate(info, call, target, "function-valued-property")
            if receiver and method_name and call.get("form") not in {"computed-call", "optional-computed-call"}:
                receiver_symbol = symbols_by_id.get(receiver.get("symbol_id"))
                possible_types = type_names((receiver_symbol or {}).get("declared_type"))
                if receiver.get("type"):
                    possible_types.insert(0, receiver["type"])
                for type_name in list(dict.fromkeys(possible_types)):
                    pair = types_by_name.get(type_name)
                    candidate_types = [type_name]
                    if pair and pair[1]["kind"] == "interface":
                        direct_implementors = implementors.get(type_name, set())
                        candidate_types.extend(sorted(direct_implementors))
                        for implementor in direct_implementors:
                            candidate_types.extend(sorted(descendants.get(implementor, set())))
                    elif receiver.get("evidence") != "constructor":
                        candidate_types.extend(sorted(descendants.get(type_name, set())))
                    for candidate_type in candidate_types:
                        candidate_type_info = types_by_name.get(candidate_type)
                        for target_id in class_function_properties.get(
                            (((candidate_type_info or (None, {}))[1]).get("id"), method_name),
                            set(),
                        ):
                            add_candidate(
                                info, call, target_id, "function-valued-class-property",
                                receiver_type=candidate_type,
                            )
                        target = concrete_method(candidate_type, method_name)
                        if target:
                            add_candidate(
                                info, call, target[1]["id"], "virtual-method",
                                receiver_type=candidate_type,
                            )
                    if pair and not any(
                        item["call_id"] == call["id"] for item in info["dispatch_candidates"]
                    ):
                        abstract = members.get((pair[1]["id"], method_name))
                        if abstract:
                            add_candidate(info, call, abstract[1]["id"], "abstract-method", "conditional")

            if "." not in call["callee"] and "[" not in call["callee"]:
                for target in targets_for_value(info, call["callee"], call["start_offset"]):
                    add_candidate(info, call, target, "function-value")

                if include_callbacks:
                    callback_symbol = symbol_for_name(info, call["callee"], call["start_offset"])
                    if callback_symbol and callback_symbol["kind"] == "parameter":
                        owner_function_id = callback_symbol.get("owner_function_id")
                        for caller_info, context in contexts_by_callee.get(owner_function_id, []):
                            binding = next(
                                (item for item in context["parameter_bindings"] if item["position"] == callback_symbol.get("position", 0)),
                                None,
                            )
                            if not binding:
                                continue
                            argument = next(
                                (item for item in caller_info["arguments"] if item["id"] == binding["argument_id"]),
                                None,
                            )
                            for target in targets_for_value(
                                caller_info, (argument or {}).get("expression", ""),
                                (argument or {}).get("start_offset", 0),
                            ):
                                add_candidate(
                                    info, call, target, "callback-argument", "high",
                                    parent_context_id=context["id"],
                                )

            call_candidates = [
                item for item in info["dispatch_candidates"] if item["call_id"] == call["id"]
            ]
            call["dispatch_candidate_ids"] = [item["id"] for item in call_candidates]
            call["dispatch_target_ids"] = list(dict.fromkeys(item["target_id"] for item in call_candidates))
            call["dispatch_status"] = (
                "exact" if len(call["dispatch_target_ids"]) == 1
                else "polymorphic" if call["dispatch_target_ids"]
                else "unresolved"
            )
            function_targets = [
                target_id for target_id in call["dispatch_target_ids"]
                if target_id in functions_by_id
            ]
            if (
                len(function_targets) == 1
                and call.get("method_name") != "bind"
                and call.get("resolution") in {
                    None, "unresolved", "declaration-not-found", "receiver-method"
                }
            ):
                target_info, target_function = functions_by_id[function_targets[0]]
                call.update({
                    "resolution": "dynamic-dispatch",
                    "declaration_symbol_id": target_function["id"],
                    "declaration_file": target_info["path"],
                    "declaration_file_hash": target_info["path_hash"],
                    "declaration_line": target_function["start_line"],
                    "declaration_end_line": target_function["end_line"],
                })
            if include_callbacks:
                context = next(
                    (
                        item for item in info.get("call_contexts", [])
                        if item["call_id"] == call["id"]
                    ),
                    None,
                )
                if context:
                    context["dispatch_target_ids"] = call["dispatch_target_ids"]
                    context["dispatch_status"] = call["dispatch_status"]
