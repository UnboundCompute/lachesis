"""Manual receiver/type inference and member-call resolution."""
import hashlib
import re
from typing import Dict, Iterable, List, Optional

from .source_analysis import mask_non_code
from .value_utils import access_parts


BUILTIN_TYPES = {
    "Array", "BigInt", "Boolean", "Buffer", "Date", "Error", "FormData",
    "Headers", "Hmac", "JSON", "Map", "Number", "Object", "Promise", "RegExp", "Request",
    "Response", "Set", "String", "Symbol", "URL", "URLSearchParams",
    "WeakMap", "WeakSet",
}
METHOD_RETURNS = {
    ("Hmac", "update"): "Hmac",
    ("Hmac", "digest"): "Buffer",
    ("Response", "text"): "Promise<String>",
    ("Response", "json"): "Promise<Object>",
}
BUILTIN_CALL_RETURNS = {
    "Array": "Array", "BigInt": "BigInt", "Boolean": "Boolean",
    "Buffer.from": "Buffer", "Date": "Date", "FormData": "FormData",
    "Headers": "Headers", "Map": "Map", "Number": "Number",
    "Object": "Object", "Object.create": "Object", "RegExp": "RegExp",
    "Request": "Request", "Response": "Response", "Set": "Set",
    "String": "String", "URL": "URL", "URLSearchParams": "URLSearchParams",
    "WeakMap": "WeakMap", "WeakSet": "WeakSet", "fetch": "Promise<Response>",
    "createHmac": "Hmac",
}
LITERAL_TYPES = (
    (re.compile(r"^['\"`]"), "String"),
    (re.compile(r"^(?:true|false)\b"), "Boolean"),
    (re.compile(r"^[+-]?(?:\d+(?:\.\d*)?|\.\d+)\b"), "Number"),
    (re.compile(r"^\["), "Array"),
    (re.compile(r"^\{"), "Object"),
)


def reference_id(kind: str, label: str) -> str:
    digest = hashlib.sha256(f"{kind}:{label}".encode("utf-8")).hexdigest()[:16]
    return f"{kind}:{digest}"


def split_top_level(text: str, delimiter: str = ",") -> List[str]:
    pieces = []
    start = 0
    stack = []
    pairs = {")": "(", "]": "[", "}": "{", ">": "<"}
    for index, char in enumerate(text):
        if char in "([{<":
            stack.append(char)
        elif char in ")]}>" and stack and stack[-1] == pairs[char]:
            stack.pop()
        elif char == delimiter and not stack:
            pieces.append(text[start:index])
            start = index + 1
    pieces.append(text[start:])
    return pieces


def top_level_colon(text: str) -> Optional[int]:
    stack = []
    pairs = {")": "(", "]": "[", "}": "{", ">": "<"}
    for index, char in enumerate(text):
        if char in "([{<":
            stack.append(char)
        elif char in ")]}>" and stack and stack[-1] == pairs[char]:
            stack.pop()
        elif char == ":" and not stack:
            return index
    return None


def clean_type_name(annotation: Optional[str], unwrap_promise: bool = False) -> Optional[str]:
    if not annotation:
        return None
    value = re.sub(r"\s+", " ", annotation.strip())
    value = re.sub(r"^(?:readonly\s+)", "", value)
    alternatives = [
        item.strip() for item in split_top_level(value, "|")
        if item.strip() not in {"null", "undefined", "void", "never"}
    ]
    value = alternatives[0] if alternatives else value
    if unwrap_promise:
        promise = re.match(r"Promise\s*<([\s\S]+)>$", value)
        if promise:
            value = promise.group(1).strip()
    if value.endswith("[]"):
        return "Array"
    generic = re.match(r"([A-Za-z_$][\w$\.]*)\s*<", value)
    if generic:
        return generic.group(1).split(".")[-1]
    named = re.match(r"(?:typeof\s+)?([A-Za-z_$][\w$\.]*)", value)
    return named.group(1).split(".")[-1] if named else "Object" if value.startswith("{") else None


def annotate_signatures(info: dict) -> None:
    """Attach manually parsed parameter and return annotations."""
    text = info["text"]
    symbols = info["symbols"]
    for function in info["functions"]:
        start = function.get("parameters_start_offset")
        end = function.get("parameters_end_offset")
        body_start = function.get("body_start_offset")
        if start is None or end is None:
            continue
        raw = text[start + 1:end] if text[start:start + 1] == "(" else text[start:end + 1]
        parameter_symbols = sorted(
            (
                symbol for symbol in symbols
                if symbol.get("owner_function_id") == function["id"]
                and symbol["kind"] == "parameter"
            ),
            key=lambda symbol: symbol.get("position", 0),
        )
        annotations = []
        for piece in split_top_level(raw):
            piece = piece.split("=", 1)[0].strip()
            colon = top_level_colon(piece)
            annotation = piece[colon + 1:].strip() if colon is not None else None
            names = re.findall(r"[A-Za-z_$][\w$]*", piece[:colon] if colon is not None else piece)
            binding_count = max(1, len(names))
            annotations.extend([annotation] * binding_count)
        for symbol, annotation in zip(parameter_symbols, annotations):
            symbol["declared_type"] = annotation

        if body_start is not None and end < body_start:
            between = text[end + 1:body_start]
            between = between.split("=>", 1)[0]
            return_match = re.search(r":\s*([\s\S]+?)\s*$", between)
            if return_match:
                function["return_type"] = return_match.group(1).strip()


def declared_variable_types(info: dict) -> Dict[str, str]:
    text = info["text"]
    result = {}
    for definition in info["definitions"]:
        if definition["kind"] != "declaration":
            continue
        symbol = next(
            (item for item in info["symbols"] if item["id"] == definition["symbol_id"]),
            None,
        )
        if not symbol:
            continue
        start = symbol.get("start_offset", definition["offset"]) + len(symbol["name"])
        end = definition.get("expression_start", start)
        header = text[start:end]
        match = re.search(r":\s*([\s\S]+?)\s*(?:=|\bof\b|\bin\b)\s*$", header)
        if match:
            result[definition["id"]] = match.group(1).strip()
            definition["declared_type"] = match.group(1).strip()
    return result


def visible_symbol(info: dict, name: str, offset: int, scope_id: str) -> Optional[dict]:
    scopes = {scope["id"]: scope for scope in info["scopes"]}
    current = scope_id
    while current:
        candidates = [
            symbol for symbol in info["symbols"]
            if symbol["scope_id"] == current and symbol["name"] == name
            and (symbol.get("start_offset", 0) <= offset or symbol["kind"] in {
                "function", "import", "class", "interface", "type", "enum", "parameter",
            })
        ]
        if candidates:
            return max(candidates, key=lambda symbol: symbol.get("start_offset", 0))
        current = scopes[current]["parent_scope_id"]
    return None


def latest_definition(info: dict, target_id: str, offset: int) -> Optional[dict]:
    candidates = [
        definition for definition in info["definitions"]
        if definition["symbol_id"] == target_id and definition["offset"] <= offset
    ]
    return max(candidates, key=lambda definition: definition["offset"], default=None)


def imported_binding(info: dict, local_name: str) -> Optional[tuple]:
    for imported in info["imports"]:
        for binding in imported["bindings"]:
            if binding["local"] == local_name:
                return imported, binding
    return None


def type_record(
    info: dict, name: str, files_by_path: Dict[str, dict], types_by_name: Dict[str, List[tuple]],
    evidence: str,
) -> dict:
    local = next((item for item in info["types"] if item["name"] == name), None)
    owner_info = info
    if not local:
        imported = imported_binding(info, name)
        if imported:
            import_info, binding = imported
            target_info = files_by_path.get(import_info.get("resolved_path"))
            imported_name = binding["imported"] if binding["imported"] != "default" else name
            if target_info:
                local = next(
                    (item for item in target_info["types"] if item["name"] == imported_name),
                    None,
                )
                owner_info = target_info
    if not local and len(types_by_name.get(name, [])) == 1:
        owner_info, local = types_by_name[name][0]
    if local:
        return {
            "kind": local["kind"], "name": local["name"], "type_id": local["id"],
            "declaration_file": owner_info["path"], "evidence": evidence,
        }
    kind = "builtin" if name in BUILTIN_TYPES else "type-reference"
    return {
        "kind": kind, "name": name,
        "type_id": reference_id("receiver-type", name),
        "declaration_file": None, "evidence": evidence,
    }


def annotation_type_record(
    info: dict, annotation: str, files_by_path: Dict[str, dict],
    types_by_name: Dict[str, List[tuple]], evidence: str,
) -> Optional[dict]:
    name = clean_type_name(annotation)
    if not name:
        return None
    record = type_record(info, name, files_by_path, types_by_name, evidence)
    promise = re.match(r"\s*Promise\s*<([\s\S]+)>\s*$", annotation)
    if promise:
        wrapped = clean_type_name(promise.group(1))
        if wrapped:
            record["wrapped_type"] = wrapped
    return record


def expression_type(
    expression: str, info: dict, files_by_path: Dict[str, dict],
    types_by_name: Dict[str, List[tuple]], call_types: Dict[str, dict],
    expression_start: int = 0,
) -> Optional[dict]:
    value = expression.strip()
    awaited = bool(re.match(r"^await\b", value))
    value = re.sub(r"^(?:await\s+)+", "", value)
    constructed = re.match(r"new\s+([A-Za-z_$][\w$\.]*)", value)
    if constructed:
        return type_record(
            info, constructed.group(1).split(".")[-1], files_by_path, types_by_name,
            "constructor",
        )
    assertion = re.search(r"\bas\s+([A-Za-z_$][\w$]*(?:\s*<[^>]+>)?)\s*$", value)
    if assertion:
        name = clean_type_name(assertion.group(1))
        if name:
            return type_record(info, name, files_by_path, types_by_name, "type-assertion")
    contained_calls = [
        call for call in info["function_calls"]
        if expression_start <= call["start_offset"] < expression_start + len(expression)
    ]
    if contained_calls:
        call = contained_calls[-1]
        inferred = call_types.get(call["id"])
        if inferred:
            if awaited and inferred["name"] == "Promise" and inferred.get("wrapped_type"):
                return type_record(
                    info, inferred["wrapped_type"], files_by_path, types_by_name,
                    "awaited-call-return",
                )
            return dict(inferred, evidence="call-return")
    for pattern, name in LITERAL_TYPES:
        if pattern.match(value):
            return type_record(info, name, files_by_path, types_by_name, "literal")
    return None


def resolve_receivers(files: Iterable[dict]) -> None:
    file_list = list(files)
    files_by_path = {info["path"]: info for info in file_list}
    functions_by_id = {
        function["id"]: (info, function)
        for info in file_list for function in info["functions"]
    }
    types_by_name: Dict[str, List[tuple]] = {}
    types_by_id = {}
    for info in file_list:
        annotate_signatures(info)
        declared_variable_types(info)
        for declared_type in info["types"]:
            types_by_name.setdefault(declared_type["name"], []).append((info, declared_type))
            types_by_id[declared_type["id"]] = (info, declared_type)

    method_by_owner = {}
    object_method_by_owner = {}
    for info in file_list:
        for function in info["functions"]:
            if function.get("owner_type_id"):
                method_by_owner[(function["owner_type_id"], function["name"])] = (info, function)
        for definition in info["definitions"]:
            start = definition.get("expression_start")
            end = definition.get("expression_end")
            if start is None or end is None or not info["text"][start:end].lstrip().startswith("{"):
                continue
            for function in info["functions"]:
                if start <= function["start_offset"] and function["end_offset"] <= end:
                    function["owner_object_symbol_id"] = definition["symbol_id"]
                    object_method_by_owner[(definition["symbol_id"], function["name"])] = (info, function)

    definition_types: Dict[str, dict] = {}
    call_types: Dict[str, dict] = {}

    # Seed types stated directly in source or guaranteed by constructors/literals.
    for info in file_list:
        for symbol in info["symbols"]:
            annotation = clean_type_name(symbol.get("declared_type"))
            if annotation:
                initial = latest_definition(info, symbol["id"], symbol.get("start_offset", 0))
                if initial:
                    definition_types[initial["id"]] = annotation_type_record(
                        info, symbol["declared_type"], files_by_path, types_by_name,
                        "parameter-annotation",
                    )
            elif symbol["kind"] == "language-global" and symbol["name"] in BUILTIN_TYPES:
                initial = latest_definition(info, symbol["id"], len(info["text"]))
                if initial:
                    definition_types[initial["id"]] = type_record(
                        info, symbol["name"], files_by_path, types_by_name,
                        "language-global",
                    )
        for definition in info["definitions"]:
            annotation = clean_type_name(definition.get("declared_type"))
            if annotation:
                definition_types[definition["id"]] = annotation_type_record(
                    info, definition["declared_type"], files_by_path, types_by_name,
                    "variable-annotation",
                )
            start = definition.get("expression_start")
            end = definition.get("expression_end")
            if start is not None and end is not None:
                inferred = expression_type(
                    info["text"][start:end], info, files_by_path, types_by_name,
                    call_types, start,
                )
                if inferred:
                    definition_types.setdefault(definition["id"], inferred)

    flow_by_kind = {}
    for info in file_list:
        for flow in info["data_flows"]:
            flow_by_kind.setdefault(flow["kind"], []).append(flow)
    return_types: Dict[str, dict] = {}
    changed = True
    while changed:
        changed = False

        for info in file_list:
            for call in info["function_calls"]:
                inferred = None
                if call["form"] == "constructor":
                    inferred = type_record(
                        info, call["callee"].split(".")[-1], files_by_path,
                        types_by_name, "constructor-call",
                    )
                elif call["callee"] in BUILTIN_CALL_RETURNS:
                    raw_name = BUILTIN_CALL_RETURNS[call["callee"]]
                    wrapped = re.match(r"Promise<(.+)>$", raw_name)
                    name = "Promise" if wrapped else raw_name
                    inferred = type_record(
                        info, name, files_by_path, types_by_name, "runtime-return",
                    )
                    if wrapped:
                        inferred["wrapped_type"] = wrapped.group(1)
                else:
                    receiver_call_type = call_types.get(call.get("receiver_call_id"))
                    method_return = (
                        METHOD_RETURNS.get((receiver_call_type["name"], call["callee"]))
                        if receiver_call_type else None
                    )
                    if method_return:
                        wrapped = re.match(r"Promise<(.+)>$", method_return)
                        inferred = type_record(
                            info, "Promise" if wrapped else method_return,
                            files_by_path, types_by_name, "method-return",
                        )
                        if wrapped:
                            inferred["wrapped_type"] = wrapped.group(1)
                    target_pair = functions_by_id.get(call.get("declaration_symbol_id"))
                    if target_pair and not inferred:
                        target_info, target_function = target_pair
                        annotation = clean_type_name(target_function.get("return_type"))
                        if annotation:
                            inferred = annotation_type_record(
                                target_info, target_function["return_type"], files_by_path,
                                types_by_name, "function-return-annotation",
                            )
                        else:
                            candidates = [
                                return_types[returned["id"]]
                                for returned in target_info["returns"]
                                if returned.get("function_id") == target_function["id"]
                                and returned["id"] in return_types
                            ]
                            names = {candidate["name"] for candidate in candidates}
                            if len(names) == 1 and candidates:
                                inferred = dict(
                                    candidates[0], evidence="inferred-function-return"
                                )
                if inferred and call_types.get(call["id"]) != inferred:
                    call_types[call["id"]] = inferred
                    changed = True

        for info in file_list:
            for definition in info["definitions"]:
                if definition["id"] in definition_types:
                    continue
                start = definition.get("expression_start")
                end = definition.get("expression_end")
                if start is not None and end is not None:
                    inferred = expression_type(
                        info["text"][start:end], info, files_by_path, types_by_name,
                        call_types, start,
                    )
                    if inferred:
                        definition_types[definition["id"]] = inferred
                        changed = True

                # A plain alias preserves the source's type. Other expressions
                # may merely use a value as an argument, so they must not copy
                # that value's type onto their result.
                if definition["id"] not in definition_types and start is not None and end is not None:
                    expression = info["text"][start:end].strip()
                    if re.fullmatch(
                        r"(?:await\s+)?[A-Za-z_$][\w$]*(?:\??\.[A-Za-z_$][\w$]*)*",
                        expression,
                    ):
                        source_reads = [
                            read for read in info["reads"]
                            if start <= read["offset"] < end
                            and read["definition_id"] in definition_types
                        ]
                        if source_reads:
                            definition_types[definition["id"]] = dict(
                                definition_types[source_reads[0]["definition_id"]],
                                evidence="alias",
                            )
                            changed = True

            for returned in info["returns"]:
                if returned["id"] in return_types:
                    continue
                start = returned["start_offset"]
                end = returned["end_offset"]
                inferred = expression_type(
                    info["text"][start:end], info, files_by_path, types_by_name,
                    call_types, start,
                )
                if not inferred:
                    source_reads = [
                        read for read in info["reads"]
                        if start <= read["offset"] < end
                        and read["definition_id"] in definition_types
                    ]
                    if len(source_reads) == 1:
                        inferred = dict(
                            definition_types[source_reads[0]["definition_id"]],
                            evidence="returned-value",
                        )
                if inferred:
                    return_types[returned["id"]] = inferred
                    changed = True

        value_types = dict(definition_types)
        value_types.update(return_types)
        for info in file_list:
            for call in info["function_calls"]:
                if call["id"] in call_types:
                    value_types[call["return_value_id"]] = call_types[call["id"]]
        for kind in ("CALL_RETURN_TO", "PREVIOUS_VERSION"):
            for flow in flow_by_kind.get(kind, []):
                inferred = value_types.get(flow["source"])
                if inferred and flow["target"] not in definition_types:
                    definition_types[flow["target"]] = dict(
                        inferred, evidence="call-return" if kind == "CALL_RETURN_TO" else "assignment-history",
                    )
                    changed = True

    for info in file_list:
        properties_by_key = {
            (item["base_symbol_id"], item["path"]): item for item in info["properties"]
        }
        for call in info["function_calls"]:
            normalized = call["callee"].replace("?.", ".")
            parts = normalized.split(".")
            computed_key = call.get("computed_key_expression")
            literal_key = (
                computed_key[1:-1]
                if computed_key and len(computed_key) >= 2
                and computed_key[0] in "'\"`" and computed_key[-1] == computed_key[0]
                else None
            )
            call["method_name"] = literal_key or parts[-1]
            call["receiver"] = None
            receiver_call_id = call.get("receiver_call_id")
            if len(parts) < 2 and not receiver_call_id and not call.get("receiver_expression"):
                if call["id"] in call_types:
                    call["return_type"] = call_types[call["id"]]
                continue
            receiver_expression = call.get("receiver_expression") or ".".join(parts[:-1])
            receiver = {
                "expression": receiver_expression, "kind": "unresolved",
                "symbol_id": None, "definition_id": None, "type": None,
                "type_id": None, "declaration_file": None,
                "evidence": "receiver-not-found", "confidence": "low",
            }
            target_definition = None

            if receiver_call_id:
                receiver_call = next(
                    (
                        candidate for candidate in info["function_calls"]
                        if candidate["id"] == receiver_call_id
                    ),
                    None,
                )
                inferred = call_types.get(receiver_call_id)
                receiver.update({
                    "kind": inferred["kind"] if inferred else "call-return",
                    "definition_id": (
                        receiver_call["return_value_id"] if receiver_call else None
                    ),
                    "type": inferred["name"] if inferred else None,
                    "type_id": inferred["type_id"] if inferred else None,
                    "declaration_file": (
                        inferred.get("declaration_file") if inferred else None
                    ),
                    "evidence": "call-return",
                    "confidence": "high" if inferred else "medium",
                })
            elif receiver_expression == "this":
                owner_pair = functions_by_id.get(call.get("caller_function_id"))
                owner_type_id = owner_pair[1].get("owner_type_id") if owner_pair else None
                if owner_type_id and owner_type_id in types_by_id:
                    owner_info, declared_type = types_by_id[owner_type_id]
                    receiver.update({
                        "kind": "this", "type": declared_type["name"],
                        "type_id": owner_type_id, "declaration_file": owner_info["path"],
                        "evidence": "enclosing-class", "confidence": "high",
                    })
                elif owner_pair and owner_pair[1].get("owner_object_symbol_id"):
                    object_symbol_id = owner_pair[1]["owner_object_symbol_id"]
                    target_definition = latest_definition(
                        info, object_symbol_id, call["start_offset"]
                    )
                    receiver.update({
                        "kind": "object-literal", "symbol_id": object_symbol_id,
                        "definition_id": (
                            target_definition["id"] if target_definition else None
                        ),
                        "evidence": "enclosing-object", "confidence": "high",
                    })
            else:
                root, path, _dynamic = access_parts(receiver_expression)
                symbol = visible_symbol(info, root, call["start_offset"], call["scope_id"])
                if symbol:
                    target_id = symbol["id"]
                    if path and (symbol["id"], path) in properties_by_key:
                        target_id = properties_by_key[(symbol["id"], path)]["id"]
                    target_definition = latest_definition(info, target_id, call["start_offset"])
                    receiver.update({
                        "kind": "property" if path else "variable",
                        "symbol_id": target_id,
                        "definition_id": target_definition["id"] if target_definition else None,
                        "evidence": "scoped-definition", "confidence": "medium",
                    })
                    inferred = definition_types.get(target_definition["id"]) if target_definition else None
                    if inferred:
                        receiver.update({
                            "kind": inferred["kind"], "type": inferred["name"],
                            "type_id": inferred["type_id"],
                            "declaration_file": inferred.get("declaration_file"),
                            "evidence": inferred["evidence"], "confidence": "high",
                        })
                    imported = imported_binding(info, root)
                    if imported and not inferred:
                        import_info, binding = imported
                        receiver.update({
                            "kind": "imported-module" if binding["imported"] == "*" else "imported-value",
                            "type": binding["imported"],
                            "declaration_file": import_info.get("resolved_path"),
                            "evidence": "import-binding", "confidence": "high",
                        })

            call["receiver"] = receiver
            if call["id"] in call_types:
                call["return_type"] = call_types[call["id"]]

            target_pair = None
            if receiver.get("type_id"):
                target_pair = method_by_owner.get((receiver["type_id"], call["method_name"]))
            if not target_pair and receiver.get("symbol_id"):
                target_pair = object_method_by_owner.get(
                    (receiver["symbol_id"], call["method_name"])
                )
            if not target_pair and receiver["kind"] == "imported-module":
                target_info = files_by_path.get(receiver.get("declaration_file"))
                if target_info:
                    target_function = next(
                        (function for function in target_info["functions"] if function["name"] == call["method_name"]),
                        None,
                    )
                    if target_function:
                        target_pair = (target_info, target_function)
            if target_pair:
                target_info, target_function = target_pair
                call.update({
                    "resolution": "receiver-method",
                    "declaration_symbol_id": target_function["id"],
                    "declaration_file": target_info["path"],
                    "declaration_file_hash": target_info["path_hash"],
                    "declaration_line": target_function["start_line"],
                    "declaration_end_line": target_function["end_line"],
                })

    for info in file_list:
        for definition in info["definitions"]:
            inferred = definition_types.get(definition["id"])
            if inferred:
                definition["inferred_type"] = inferred
