"""Manual variable histories and intraprocedural data-flow extraction."""
import hashlib
import re
from typing import Dict, List, Optional, Tuple

from .source_analysis import mask_non_code
from .scope_utils import VARIABLE_RE, binding_names, innermost_scope_at

ASSIGNMENT_RE = re.compile(
    r"(?P<left>[A-Za-z_$][\w$]*(?:"
    r"\s*(?:\?\.|\.)\s*[A-Za-z_$][\w$]*|\s*\[[^\]\n]+\])*)"
    r"\s*(?P<operator>\?\?=|&&=|\|\|=|\*\*=|\+=|-=|\*=|/=|%=|=(?!=|>))"
)
UPDATE_RE = re.compile(
    r"(?:(?P<prefix>\+\+|--)\s*(?P<prefix_name>[A-Za-z_$][\w$]*)|"
    r"(?P<suffix_name>[A-Za-z_$][\w$]*)\s*(?P<suffix>\+\+|--))"
)
RETURN_RE = re.compile(r"\b(?P<kind>return|throw)\b")
REFERENCE_RE = re.compile(
    r"[A-Za-z_$][\w$]*(?:\s*(?:\?\.|\.)\s*[A-Za-z_$][\w$]*|"
    r"\s*\[[^\]\n]+\])*"
)
RESERVED = {
    "as", "async", "await", "break", "case", "catch", "class", "const",
    "continue", "debugger", "default", "delete", "do", "else", "enum",
    "export", "extends", "false", "finally", "for", "from", "function", "if",
    "implements", "import", "in", "instanceof", "interface", "let", "new",
    "null", "of", "private", "protected", "public", "return", "static", "super",
    "switch", "this", "throw", "true", "try", "type", "typeof", "undefined",
    "var", "void", "while", "with", "yield", "any", "bigint", "boolean",
    "keyof", "never", "number", "object", "readonly", "string", "symbol",
    "unknown",
}
LANGUAGE_IDENTIFIERS = {
    "Array", "BigInt", "Boolean", "Buffer", "Date", "Error", "FormData",
    "Function", "Headers", "JSON", "Map", "Math", "Number", "Object", "Promise",
    "Reflect", "RegExp", "Request", "Response", "Set", "String", "Symbol", "URL",
    "URLSearchParams", "WeakMap", "WeakSet", "console", "fetch", "process",
    "setInterval", "setTimeout", "clearInterval", "clearTimeout",
}


def stable_id(kind: str, *parts) -> str:
    raw = ":".join(str(part) for part in parts)
    return f"{kind}:{hashlib.sha256((kind + ':' + raw).encode('utf-8')).hexdigest()[:16]}"


def expression_end(masked: str, start: int) -> int:
    parens = brackets = braces = 0
    cursor = start
    while cursor < len(masked):
        char = masked[cursor]
        if char == "(":
            parens += 1
        elif char == ")":
            if parens == 0:
                break
            parens -= 1
        elif char == "[":
            brackets += 1
        elif char == "]":
            if brackets == 0:
                break
            brackets -= 1
        elif char == "{":
            braces += 1
        elif char == "}":
            if braces == 0:
                break
            braces -= 1
        elif parens == brackets == braces == 0 and char == ";":
            break
        elif parens == brackets == braces == 0 and char == "\n":
            break
        cursor += 1
    return cursor


def declaration_operator(masked: str, start: int) -> Tuple[Optional[str], int]:
    angle = parens = brackets = braces = 0
    cursor = start
    while cursor < len(masked):
        char = masked[cursor]
        if char == "<":
            angle += 1
        elif char == ">" and angle:
            angle -= 1
        elif char == "(":
            parens += 1
        elif char == ")":
            if parens == brackets == braces == 0:
                return None, cursor
            parens = max(0, parens - 1)
        elif char == "[":
            brackets += 1
        elif char == "]":
            brackets = max(0, brackets - 1)
        elif char == "{":
            braces += 1
        elif char == "}":
            braces = max(0, braces - 1)
        if angle == parens == brackets == braces == 0:
            if char == "=" and masked[cursor:cursor + 2] not in {"=>", "=="}:
                return "=", cursor + 1
            word = re.match(r"\s+(of|in)\b", masked[cursor:])
            if word:
                return word.group(1), cursor + word.end()
            if char in ";\n":
                return None, cursor
        cursor += 1
    return None, cursor


def destructured_targets(binding: str) -> List[Tuple[str, str]]:
    binding = binding.strip()
    if binding.startswith("{"):
        result = []
        for part in binding[1:-1].split(","):
            part = part.strip()
            if not part:
                continue
            pair = part.split("=", 1)[0].split(":", 1)
            source_path = pair[0].strip()
            local = pair[-1].strip()
            if re.fullmatch(r"[A-Za-z_$][\w$]*", local):
                result.append((local, source_path))
        return result
    if binding.startswith("["):
        return [
            (name, str(index))
            for index, name in enumerate(binding_names(binding))
        ]
    names = binding_names(binding)
    return [(names[0], "")] if names else []


def split_arguments(text: str, start: int, end: int) -> List[Tuple[int, int]]:
    if end is None or end <= start:
        return []
    masked = mask_non_code(text)
    ranges = []
    depth = 0
    piece_start = start + 1
    for cursor in range(start + 1, end):
        char = masked[cursor]
        if char in "([{<":
            depth += 1
        elif char in ")]}>":
            depth = max(0, depth - 1)
        elif char == "," and depth == 0:
            ranges.append((piece_start, cursor))
            piece_start = cursor + 1
    if text[piece_start:end].strip():
        ranges.append((piece_start, end))
    return ranges


def owner_function(functions: List[dict], line: int) -> Optional[str]:
    candidates = [
        function for function in functions
        if function["start_line"] <= line <= function["end_line"]
    ]
    if not candidates:
        return None
    return min(candidates, key=lambda f: f["end_line"] - f["start_line"])["id"]


def expression_code(text: str, masked: str, start: int, end: int) -> str:
    """Restore code inside template-literal ${...} regions into the code mask."""
    result = list(masked[start:end])
    raw = text[start:end]
    cursor = 0
    while cursor < len(raw) - 1:
        if raw[cursor:cursor + 2] != "${":
            cursor += 1
            continue
        depth = 1
        inner_start = cursor + 2
        inner_end = inner_start
        while inner_end < len(raw) and depth:
            if raw[inner_end] == "{":
                depth += 1
            elif raw[inner_end] == "}":
                depth -= 1
                if depth == 0:
                    break
            inner_end += 1
        inner_mask = mask_non_code(raw[inner_start:inner_end])
        result[inner_start:inner_end] = inner_mask
        cursor = inner_end + 1
    return "".join(result)


def access_parts(token: str) -> Tuple[str, str, List[str]]:
    normalized = re.sub(r"\s+", "", token).replace("?.", ".")
    root_match = re.match(r"[A-Za-z_$][\w$]*", normalized)
    if not root_match:
        return normalized, "", []
    root = root_match.group(0)
    suffix = normalized[root_match.end():]
    path_parts = []
    dynamic_parts = []
    for match in re.finditer(r"\.([A-Za-z_$][\w$]*)|\[([^\]]+)\]", suffix):
        if match.group(1):
            path_parts.append(match.group(1))
        else:
            inner = match.group(2)
            if re.fullmatch(r"['\"][^'\"]+['\"]", inner):
                path_parts.append(inner[1:-1])
            else:
                path_parts.append(f"[{inner}]")
                dynamic_parts.append(inner)
    path = ""
    for part in path_parts:
        if part.startswith("["):
            path += part
        else:
            path += ("." if path else "") + part
    return root, path, dynamic_parts


def analyze_variable_flow(info: dict) -> None:
    text = info["text"]
    masked = mask_non_code(text)
    scopes = info["scopes"]
    scopes_by_id = {scope["id"]: scope for scope in scopes}
    symbols = info["symbols"]
    symbols_by_id = {symbol["id"]: symbol for symbol in symbols}
    properties = []
    properties_by_key = {}
    definitions = []
    definitions_by_symbol: Dict[str, List[dict]] = {}
    reads = []
    arguments = []
    returns = []
    flows = []
    aliases = []
    type_ranges = [
        (declared_type.get("start_offset", 0), declared_type.get("end_offset", 0))
        for declared_type in info["types"]
    ]

    def add_flow(kind: str, source: str, target: str, **properties_data):
        flows.append({
            "kind": kind, "source": source, "target": target,
            "properties": properties_data,
        })

    def visible_symbol(name: str, offset: int, scope_id_value: str) -> dict:
        current_scope_id = scope_id_value
        while current_scope_id:
            candidates = [
                symbol for symbol in symbols
                if symbol["scope_id"] == current_scope_id and symbol["name"] == name
                and (
                    symbol["start_offset"] <= offset
                    or symbol["kind"] in {
                        "function", "import", "interface", "type", "class", "enum",
                        "parameter",
                    }
                )
            ]
            if candidates:
                return max(candidates, key=lambda symbol: symbol["start_offset"])
            current_scope_id = scopes_by_id[current_scope_id]["parent_scope_id"]

        # Preserve unknown/global identifiers as explicit symbols instead of
        # dropping the reference from the graph.
        existing = next(
            (symbol for symbol in symbols if symbol["name"] == name and symbol["kind"] in {
                "implicit", "language-global",
            }),
            None,
        )
        if existing:
            return existing
        kind = "language-global" if name in LANGUAGE_IDENTIFIERS else "implicit"
        symbol = {
            "id": stable_id("symbol", info["path_hash"], kind, name),
            "name": name, "kind": kind, "line": 1,
            "start_offset": 0, "scope_id": scopes[0]["id"],
            "declaration_id": None, "duplicate_of": None, "shadows": None,
            "owner_function_id": None,
        }
        symbols.append(symbol)
        symbols_by_id[symbol["id"]] = symbol
        return symbol

    def property_record(base_symbol: dict, path: str) -> dict:
        key = (base_symbol["id"], path)
        if key not in properties_by_key:
            record = {
                "id": stable_id("property", base_symbol["id"], path),
                "base_symbol_id": base_symbol["id"], "path": path,
                "name": f"{base_symbol['name']}.{path}",
            }
            properties_by_key[key] = record
            properties.append(record)
        return properties_by_key[key]

    def add_definition(symbol_or_property_id: str, kind: str, offset: int, origin: str, **extra):
        history = definitions_by_symbol.setdefault(symbol_or_property_id, [])
        definition = {
            "id": stable_id(
                "definition", info["path_hash"], symbol_or_property_id, len(history), offset
            ),
            "symbol_id": symbol_or_property_id,
            "version": len(history),
            "kind": kind,
            "origin": origin,
            "line": text.count("\n", 0, max(offset, 0)) + 1,
            "offset": offset,
            "previous_definition_id": history[-1]["id"] if history else None,
        }
        definition.update(extra)
        history.append(definition)
        definitions.append(definition)
        if definition["previous_definition_id"]:
            add_flow(
                "PREVIOUS_VERSION", definition["previous_definition_id"], definition["id"]
            )
        return definition

    def current_definition(symbol_or_property_id: str, offset: int, origin="unknown") -> dict:
        history = definitions_by_symbol.get(symbol_or_property_id, [])
        available = [definition for definition in history if definition["offset"] <= offset]
        if available:
            return available[-1]
        return add_definition(symbol_or_property_id, "implicit", 0, origin)

    def access_definition(symbol: dict, path: str, offset: int) -> Tuple[str, dict]:
        if not path:
            return symbol["id"], current_definition(
                symbol["id"], offset,
                "language-runtime" if symbol["kind"] == "language-global" else "unknown",
            )
        property_info = property_record(symbol, path)
        target_id = property_info["id"]
        if definitions_by_symbol.get(target_id):
            return target_id, current_definition(target_id, offset, "property-read")
        base_definition = current_definition(
            symbol["id"], offset,
            "language-runtime" if symbol["kind"] == "language-global" else "unknown",
        )
        definition = add_definition(target_id, "property-read", offset, "property-read")
        add_flow("PROPERTY_READ", base_definition["id"], definition["id"])
        return target_id, definition

    # Seed parameters, imports, functions, types, and catch bindings.
    seeded_kinds = {
        "parameter": "parameter", "import": "import", "function": "function",
        "interface": "type", "type": "type", "class": "type", "enum": "type",
        "catch-parameter": "catch",
    }
    for symbol in sorted(symbols, key=lambda item: item["start_offset"]):
        if symbol["kind"] in seeded_kinds:
            add_definition(
                symbol["id"], "initial", symbol["start_offset"], seeded_kinds[symbol["kind"]]
            )

    def references(start: int, end: int, context_id: str) -> List[dict]:
        expression = expression_code(text, masked, start, end)
        scope = innermost_scope_at(
            scopes, start, text.count("\n", 0, start) + 1
        )
        result = []
        for match in REFERENCE_RE.finditer(expression):
            token = re.sub(r"\s+", "", match.group(0)).replace("?.", ".")
            root, property_path, dynamic_parts = access_parts(token)
            if root in RESERVED:
                continue
            if expression[:match.start()].rstrip().endswith("."):
                continue  # Continuation of a call/member expression already seen.
            absolute_start = start + match.start()
            after = expression[match.end():].lstrip()
            if not property_path and after.startswith(":"):
                continue  # Object-literal key, not a value read.
            symbol = visible_symbol(root, absolute_start, scope["id"])
            target_id, definition = access_definition(
                symbol, property_path, absolute_start
            )
            read = {
                "id": stable_id("read", context_id, absolute_start, token),
                "symbol_id": target_id, "definition_id": definition["id"],
                "name": token, "line": text.count("\n", 0, absolute_start) + 1,
                "offset": absolute_start,
                "end_offset": start + match.end(),
                "context_id": context_id,
            }
            reads.append(read)
            add_flow("READS_FROM", definition["id"], context_id, read_id=read["id"])
            result.append(read)
            for dynamic_part in dynamic_parts:
                dynamic_offset = absolute_start + token.find(dynamic_part)
                dynamic_scope = innermost_scope_at(
                    scopes, dynamic_offset,
                    text.count("\n", 0, dynamic_offset) + 1,
                )
                dynamic_root, dynamic_path, _nested = access_parts(dynamic_part)
                dynamic_symbol = visible_symbol(
                    dynamic_root, dynamic_offset, dynamic_scope["id"]
                )
                dynamic_id, dynamic_definition = access_definition(
                    dynamic_symbol, dynamic_path, dynamic_offset
                )
                dynamic_read = {
                    "id": stable_id("read", context_id, dynamic_offset, dynamic_part),
                    "symbol_id": dynamic_id,
                    "definition_id": dynamic_definition["id"],
                    "name": dynamic_part,
                    "line": text.count("\n", 0, dynamic_offset) + 1,
                    "offset": dynamic_offset,
                    "end_offset": dynamic_offset + len(dynamic_part),
                    "context_id": context_id,
                }
                reads.append(dynamic_read)
                add_flow(
                    "READS_FROM", dynamic_definition["id"], context_id,
                    read_id=dynamic_read["id"],
                )
                result.append(dynamic_read)
        return result

    declaration_events = []
    declaration_spans = []
    for match in VARIABLE_RE.finditer(masked):
        if any(start <= match.start() <= end for start, end in type_ranges):
            continue
        operator, expression_start = declaration_operator(masked, match.end("binding"))
        expression_stop = expression_end(masked, expression_start) if operator else expression_start
        declaration_spans.append((match.start(), expression_stop))
        declaration_events.append({
            "offset": match.start(), "kind": match.group("kind"),
            "binding": text[match.start("binding"):match.end("binding")],
            "binding_start": match.start("binding"),
            "binding_end": match.end("binding"),
            "operator": operator, "expression_start": expression_start,
            "expression_end": expression_stop,
        })

    assignment_events = []
    for match in ASSIGNMENT_RE.finditer(masked):
        if any(start <= match.start() <= end for start, end in type_ranges):
            continue
        if any(start <= match.start() < end for start, end in declaration_spans):
            continue
        assignment_events.append({
            "offset": match.start(), "left": re.sub(r"\s+", "", match.group("left")),
            "operator": match.group("operator"), "expression_start": match.end(),
            "expression_end": expression_end(masked, match.end()),
        })

    events = [(event["offset"], "declaration", event) for event in declaration_events]
    events += [(event["offset"], "assignment", event) for event in assignment_events]

    for call in info["function_calls"]:
        call_return = {
            "id": stable_id("call-return", call["id"]),
            "call_id": call["id"], "line": call["line"],
            "caller_function_id": call.get("caller_function_id"),
        }
        call["return_value_id"] = call_return["id"]
        for position, (start, end) in enumerate(split_arguments(
            text, call.get("arguments_start_offset"), call.get("arguments_end_offset")
        )):
            argument = {
                "id": stable_id("argument", call["id"], position),
                "call_id": call["id"], "position": position,
                "line": text.count("\n", 0, start) + 1,
                "start_offset": start, "end_offset": end,
                "expression": text[start:end].strip(),
            }
            arguments.append(argument)

    for match in RETURN_RE.finditer(masked):
        start = match.end()
        end = expression_end(masked, start)
        line = text.count("\n", 0, match.start()) + 1
        return_value = {
            "id": stable_id("return-value", info["path_hash"], match.start()),
            "kind": match.group("kind"), "line": line,
            "function_id": owner_function(info["functions"], line),
            "start_offset": start, "end_offset": end,
            "expression": text[start:end].strip(),
        }
        returns.append(return_value)

    for _offset, event_kind, event in sorted(events, key=lambda item: item[0]):
        line = text.count("\n", 0, event["offset"]) + 1
        scope = innermost_scope_at(scopes, event["offset"], line)
        dependency_reads = []
        if event["expression_end"] > event["expression_start"]:
            context_id = stable_id("write-context", info["path_hash"], event["offset"])
            dependency_reads = references(
                event["expression_start"], event["expression_end"], context_id
            )

        if event_kind == "declaration":
            targets = destructured_targets(event["binding"])
            for name, property_path in targets:
                symbol = visible_symbol(name, event["expression_start"], scope["id"])
                expression_text = text[event["expression_start"]:event["expression_end"]].strip()
                origin = "uninitialized"
                if event["operator"] in {"of", "in"}:
                    origin = "iteration"
                elif event["operator"]:
                    origin = "expression" if dependency_reads else "literal"
                definition = add_definition(
                    symbol["id"], "declaration", event["offset"],
                    origin,
                    operator=event["operator"],
                    expression_start=event["expression_start"],
                    expression_end=event["expression_end"],
                )
                selected_reads = dependency_reads
                if property_path and dependency_reads:
                    source_id = dependency_reads[0]["symbol_id"]
                    source_symbol = symbols_by_id.get(source_id)
                    prefix = ""
                    if source_symbol is None:
                        source_property = next(
                            (item for item in properties if item["id"] == source_id), None
                        )
                        if source_property:
                            source_symbol = symbols_by_id.get(source_property["base_symbol_id"])
                            prefix = source_property["path"] + "."
                    if source_symbol:
                        _property_id, source_definition = access_definition(
                            source_symbol, prefix + property_path, event["offset"]
                        )
                        selected_reads = [{"definition_id": source_definition["id"]}]
                for read in selected_reads:
                    add_flow("FLOWS_TO", read["definition_id"], definition["id"])
                if len(dependency_reads) == 1 and re.fullmatch(
                    r"[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*", expression_text
                ):
                    aliases.append({
                        "source": dependency_reads[0]["symbol_id"],
                        "target": symbol["id"], "line": line,
                    })
        else:
            left_root, left_path, dynamic_parts = access_parts(event["left"])
            base_symbol = visible_symbol(left_root, event["offset"], scope["id"])
            target_id = base_symbol["id"]
            if left_path:
                target_id = property_record(base_symbol, left_path)["id"]
            for dynamic_part in dynamic_parts:
                dynamic_root, dynamic_path, _nested = access_parts(dynamic_part)
                dynamic_symbol = visible_symbol(
                    dynamic_root, event["offset"], scope["id"]
                )
                dynamic_id, dynamic_definition = access_definition(
                    dynamic_symbol, dynamic_path, event["offset"]
                )
                dependency_reads.append({
                    "definition_id": dynamic_definition["id"],
                    "symbol_id": dynamic_id,
                })
            if event["operator"] != "=":
                previous = current_definition(target_id, event["offset"])
                dependency_reads.append({"definition_id": previous["id"], "symbol_id": target_id})
            expression_text = text[event["expression_start"]:event["expression_end"]].strip()
            definition = add_definition(
                target_id, "property-write" if left_path else "assignment",
                event["offset"], "expression" if dependency_reads else "literal",
                operator=event["operator"],
                expression_start=event["expression_start"],
                expression_end=event["expression_end"],
            )
            for read in dependency_reads:
                add_flow("FLOWS_TO", read["definition_id"], definition["id"])

    # Update operators create a new version from the previous version.
    for match in UPDATE_RE.finditer(masked):
        name = match.group("prefix_name") or match.group("suffix_name")
        line = text.count("\n", 0, match.start()) + 1
        scope = innermost_scope_at(scopes, match.start(), line)
        symbol = visible_symbol(name, match.start(), scope["id"])
        previous = current_definition(symbol["id"], match.start())
        definition = add_definition(symbol["id"], "update", match.start(), "expression")
        add_flow("FLOWS_TO", previous["id"], definition["id"])

    # Reads are resolved after definitions exist, but still select the latest
    # definition whose offset precedes the argument/return expression.
    for argument in arguments:
        argument_reads = references(
            argument["start_offset"], argument["end_offset"], argument["id"]
        )
        argument["origin"] = "expression" if argument_reads else "literal"
    for return_value in returns:
        return_reads = references(
            return_value["start_offset"], return_value["end_offset"], return_value["id"]
        )
        return_value["origin"] = "expression" if return_reads else "literal"

    # Call returns flow into declarations/assignments whose RHS contains that call.
    for call in info["function_calls"]:
        for definition in definitions:
            if definition["kind"] not in {"declaration", "assignment", "property-write"}:
                continue
            if (
                definition.get("expression_start", definition["offset"])
                <= call["start_offset"]
                <= definition.get("expression_end", definition["offset"])
            ):
                add_flow("CALL_RETURN_TO", call["return_value_id"], definition["id"])
        for argument in arguments:
            if argument["start_offset"] <= call["start_offset"] <= argument["end_offset"]:
                add_flow("CALL_RETURN_TO_VALUE", call["return_value_id"], argument["id"])
        for return_value in returns:
            if (
                return_value["start_offset"]
                <= call["start_offset"]
                <= return_value["end_offset"]
            ):
                add_flow(
                    "CALL_RETURN_TO_VALUE", call["return_value_id"], return_value["id"]
                )

    info["properties"] = properties
    info["definitions"] = definitions
    info["reads"] = reads
    info["arguments"] = arguments
    info["returns"] = returns
    info["data_flows"] = flows
    info["aliases"] = aliases
