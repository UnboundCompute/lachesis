"""Flow-sensitive TypeScript type facts beyond declaration discovery."""
import hashlib
import re
from collections import defaultdict
from typing import Iterable, List

from .source_analysis import mask_non_code, matching_delimiter


def stable_id(kind: str, *parts) -> str:
    raw = ":".join(str(part) for part in parts)
    return f"{kind}:{hashlib.sha256((kind + ':' + raw).encode()).hexdigest()[:16]}"


def split_top_level(value: str, separator: str = ",") -> List[str]:
    pieces, start = [], 0
    depth = 0
    for index, char in enumerate(value):
        if char in "<({[":
            depth += 1
        elif char in ">)}]" and depth:
            depth -= 1
        elif char == separator and depth == 0:
            pieces.append(value[start:index].strip())
            start = index + 1
    pieces.append(value[start:].strip())
    return [piece for piece in pieces if piece]


def generic_parameters(raw: str, owner_id: str) -> List[dict]:
    match = re.search(r"<([\s\S]*)>", raw)
    if not match:
        return []
    result = []
    for position, piece in enumerate(split_top_level(match.group(1))):
        parsed = re.match(
            r"(?P<name>[A-Za-z_$][\w$]*)(?:\s+extends\s+(?P<constraint>[^=]+?))?"
            r"(?:\s*=\s*(?P<default>[\s\S]+))?$",
            piece,
        )
        if parsed:
            result.append({
                "id": stable_id("type-parameter", owner_id, position, parsed.group("name")),
                "owner_id": owner_id, "position": position,
                "name": parsed.group("name"),
                "constraint": (parsed.group("constraint") or "").strip() or None,
                "default": (parsed.group("default") or "").strip() or None,
            })
    return result


def inferred_argument_type(info: dict, argument: dict) -> str:
    expression = argument["expression"].strip()
    if re.fullmatch(r"['\"`][\s\S]*['\"`]", expression):
        return "string"
    if re.fullmatch(r"\d+(?:\.\d+)?", expression):
        return "number"
    if expression in {"true", "false"}:
        return "boolean"
    reads = [
        read for read in info["reads"]
        if argument["start_offset"] <= read["offset"]
        and read.get("end_offset", read["offset"] + 1) <= argument["end_offset"]
    ]
    definitions = {definition["id"]: definition for definition in info["definitions"]}
    for read in reads:
        inferred = definitions.get(read["definition_id"], {}).get("inferred_type") or {}
        if inferred.get("name"):
            return inferred["name"]
    return "unknown"


def analyze_type_system(files: Iterable[dict]) -> None:
    file_list = list(files)
    functions = {function["id"]: (info, function) for info in file_list for function in info["functions"]}
    functions_by_name = defaultdict(list)
    for function_id, pair in functions.items():
        functions_by_name[pair[1]["name"]].append(pair)

    all_parameters = []
    for info in file_list:
        info["type_parameters"] = []
        info["type_refinements"] = []
        info["generic_substitutions"] = []
        info["overloads"] = []
        info["type_compatibilities"] = []
        text, masked = info["text"], mask_non_code(info["text"])

        for declared_type in info["types"]:
            cursor = declared_type["start_offset"] + len(declared_type["name"])
            header_end_candidates = [
                value for value in (
                    masked.find("{", cursor), masked.find("=", cursor), masked.find(";", cursor)
                ) if value >= 0
            ]
            header_end = min(header_end_candidates) if header_end_candidates else cursor
            header = text[cursor:header_end].strip()
            params = generic_parameters(header, declared_type["id"])
            declared_type["type_parameter_ids"] = [item["id"] for item in params]
            info["type_parameters"].extend(params)
            all_parameters.extend(params)

            declared_type["members"] = []
            opening = masked.find("{", cursor, declared_type["end_offset"] + 1)
            if opening >= 0:
                closing = matching_delimiter(masked, opening, "{", "}")
                if closing is not None:
                    body = text[opening + 1:closing]
                    for member in re.finditer(
                        r"(?:^|[;\n])\s*(?:readonly\s+)?(?P<name>[A-Za-z_$][\w$]*)"
                        r"(?P<optional>\?)?\s*(?::|\()",
                        body,
                    ):
                        declared_type["members"].append({
                            "name": member.group("name"),
                            "optional": bool(member.group("optional")),
                        })

            if declared_type["kind"] == "type":
                equals = masked.find("=", cursor, declared_type["end_offset"] + 1)
                if equals >= 0:
                    alias = text[equals + 1:declared_type["end_offset"]].strip().rstrip(";")
                    declared_type["alias_expression"] = alias
                    declared_type["union_members"] = split_top_level(alias, "|") if "|" in alias else []
                    declared_type["conditional"] = bool(
                        re.search(r"\bextends\b[\s\S]*\?[\s\S]*:", alias)
                    )
                    declared_type["mapped"] = bool(
                        re.search(r"\[\s*[A-Za-z_$][\w$]*\s+in\s+[^\]]+\]", alias)
                    )

        for function in info["functions"]:
            name_end = function["start_offset"] + len(function["name"])
            parameter_start = function.get("parameters_start_offset") or name_end
            generic_header = text[name_end:parameter_start]
            params = generic_parameters(generic_header, function["id"])
            function["type_parameter_ids"] = [item["id"] for item in params]
            info["type_parameters"].extend(params)
            all_parameters.extend(params)

            end = function.get("parameters_end_offset")
            body_start = function.get("body_start_offset")
            if end is not None and body_start is not None:
                return_header = text[end + 1:body_start]
                predicate = re.search(
                    r":\s*(?:(?P<asserts>asserts)\s+)?(?P<parameter>[A-Za-z_$][\w$]*)"
                    r"(?:\s+is\s+(?P<type>[^={]+))?",
                    return_header,
                )
                if predicate and (predicate.group("asserts") or predicate.group("type")):
                    function["type_predicate"] = {
                        "asserts": bool(predicate.group("asserts")),
                        "parameter": predicate.group("parameter"),
                        "type": (predicate.group("type") or "truthy").strip(),
                    }

        # Body-less declarations sharing a name with an implementation are
        # overload signatures rather than dropped functions.
        for match in re.finditer(
            r"(?:^|\n)\s*(?:export\s+)?(?:declare\s+)?function\s+"
            r"(?P<name>[A-Za-z_$][\w$]*)\s*(?P<generic><[^;({]+>)?"
            r"(?P<parameters>\([^;{]*\))\s*(?P<return>:[^;{]+)?;",
            masked,
        ):
            implementation = next(
                (function for function in info["functions"] if function["name"] == match.group("name")),
                None,
            )
            overload = {
                "id": stable_id("overload", info["path_hash"], match.start()),
                "name": match.group("name"), "line": text.count("\n", 0, match.start()) + 1,
                "signature": text[match.start():match.end()].strip(),
                "implementation_id": implementation["id"] if implementation else None,
            }
            info["overloads"].append(overload)

        # Narrowing facts attach to the condition expression and true/false CFG
        # branches; they do not overwrite the declared symbol type globally.
        symbols_by_name = defaultdict(list)
        for symbol in info["symbols"]:
            symbols_by_name[symbol["name"]].append(symbol)
        for expression in info["expressions"]:
            if "condition" not in expression.get("roles", []):
                continue
            condition = expression["text"].strip()
            facts = []
            typeof = re.search(
                r"typeof\s+([A-Za-z_$][\w$]*)\s*(===|==|!==|!=)\s*['\"]([^'\"]+)['\"]",
                condition,
            )
            if typeof:
                facts.append((typeof.group(1), "typeof", typeof.group(3), typeof.group(2) in {"===", "=="}))
            instance = re.search(r"([A-Za-z_$][\w$]*)\s+instanceof\s+([A-Za-z_$][\w$]*)", condition)
            if instance:
                facts.append((instance.group(1), "instanceof", instance.group(2), True))
            discriminant = re.search(
                r"([A-Za-z_$][\w$]*)\.([A-Za-z_$][\w$]*)\s*(===|==)\s*(['\"][^'\"]+['\"])",
                condition,
            )
            if discriminant:
                facts.append((discriminant.group(1), "discriminant", f"{discriminant.group(2)}={discriminant.group(4)}", True))
            null_check = re.search(r"([A-Za-z_$][\w$]*)\s*(?:!==|!=)\s*(?:null|undefined)", condition)
            if null_check:
                facts.append((null_check.group(1), "non-null", "NonNullable", True))
            for name, kind, narrowed_type, positive in facts:
                candidates = symbols_by_name.get(name, [])
                symbol = max(
                    (item for item in candidates if item["start_offset"] <= expression["start_offset"]),
                    key=lambda item: item["start_offset"], default=None,
                )
                if not symbol:
                    continue
                info["type_refinements"].append({
                    "id": stable_id("type-refinement", expression["id"], symbol["id"], kind),
                    "expression_id": expression["id"], "symbol_id": symbol["id"],
                    "kind": kind, "narrowed_type": narrowed_type,
                    "true_branch": positive, "false_excludes": narrowed_type,
                    "line": expression["start_line"],
                })

        for statement in info["statements"]:
            if statement["kind"] != "switch-statement":
                continue
            condition = min(
                (
                    expression for expression in info["expressions"]
                    if "condition" in expression.get("roles", [])
                    and statement["start_offset"] <= expression["start_offset"]
                    and expression["end_offset"] <= statement["end_offset"]
                ),
                key=lambda item: item["end_offset"] - item["start_offset"],
                default=None,
            )
            access = re.fullmatch(
                r"\s*([A-Za-z_$][\w$]*)\.([A-Za-z_$][\w$]*)\s*",
                (condition or {}).get("text", ""),
            )
            if not condition or not access:
                continue
            candidates = symbols_by_name.get(access.group(1), [])
            symbol = max(
                (item for item in candidates if item["start_offset"] <= condition["start_offset"]),
                key=lambda item: item["start_offset"], default=None,
            )
            if not symbol:
                continue
            cases = [
                item for item in info["statements"]
                if item["kind"] == "case-statement"
                and statement["start_offset"] < item["start_offset"] < statement["end_offset"]
            ]
            for case in cases:
                label = case["text"].strip().removeprefix("case").rstrip(":").strip()
                info["type_refinements"].append({
                    "id": stable_id("type-refinement", condition["id"], symbol["id"], label),
                    "expression_id": condition["id"], "symbol_id": symbol["id"],
                    "kind": "discriminated-union-case",
                    "narrowed_type": f"{access.group(2)}={label}",
                    "true_branch": True, "false_excludes": f"{access.group(2)}={label}",
                    "line": case["start_line"], "case_statement_id": case["id"],
                })

    # Infer generic substitutions separately at each call site.
    params_by_owner = defaultdict(list)
    for parameter in all_parameters:
        params_by_owner[parameter["owner_id"]].append(parameter)
    for info in file_list:
        arguments_by_call = defaultdict(list)
        for argument in info["arguments"]:
            arguments_by_call[argument["call_id"]].append(argument)
        for call in info["function_calls"]:
            target = functions.get(call.get("declaration_symbol_id"))
            if not target:
                continue
            target_info, target_function = target
            type_params = params_by_owner.get(target_function["id"], [])
            if not type_params:
                continue
            target_symbols = sorted(
                (
                    symbol for symbol in target_info["symbols"]
                    if symbol["kind"] == "parameter"
                    and symbol.get("owner_function_id") == target_function["id"]
                ),
                key=lambda item: item.get("position", 0),
            )
            arguments = sorted(arguments_by_call.get(call["id"], []), key=lambda item: item["position"])
            bindings = {}
            for argument, parameter_symbol in zip(arguments, target_symbols):
                declared = parameter_symbol.get("declared_type") or ""
                for type_parameter in type_params:
                    if re.search(rf"\b{re.escape(type_parameter['name'])}\b", declared):
                        bindings[type_parameter["name"]] = inferred_argument_type(info, argument)
            info["generic_substitutions"].append({
                "id": stable_id("generic-substitution", call["id"]),
                "call_id": call["id"], "function_id": target_function["id"],
                "bindings": bindings,
            })

    # Structural compatibility is directional: A is compatible with B when A
    # contains every required member of B.
    declared_types = [(info, item) for info in file_list for item in info["types"]]
    types_by_name = {item["name"]: item for _info, item in declared_types}

    def all_members(declared_type, visited=None):
        visited = set(visited or ())
        if declared_type["id"] in visited:
            return declared_type.get("members", [])
        visited.add(declared_type["id"])
        result = list(declared_type.get("members", []))
        for parent_name in declared_type.get("extends", []):
            parent = types_by_name.get(parent_name.split("<", 1)[0].strip())
            if parent:
                result.extend(all_members(parent, visited))
        return result

    for source_info, source in declared_types:
        source_members = {member["name"] for member in all_members(source)}
        for target_info, target in declared_types:
            if source["id"] == target["id"]:
                continue
            required = {
                member["name"] for member in all_members(target)
                if not member.get("optional")
            }
            if required and required <= source_members:
                source_info["type_compatibilities"].append({
                    "id": stable_id("structural-compatibility", source["id"], target["id"]),
                    "source_type_id": source["id"], "target_type_id": target["id"],
                    "matched_members": sorted(required), "kind": "structural",
                })
