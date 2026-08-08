"""JavaScript/TypeScript function discovery and source-range analysis."""
import re
from typing import List, Optional, Tuple

from .types import FunctionCallInfo, FunctionInfo

FUNCTION_KEYWORD_RE = re.compile(
    r"\bfunction\s*(?P<generator>\*)?\s*(?P<name>[A-Za-z_$][\w$]*)?"
)
METHOD_RE = re.compile(
    r"(?P<prefix>^|[,{;])\s*"
    r"(?:(?:public|private|protected|static|abstract|async|override|readonly|declare|get|set)\s+)*"
    r"(?P<generator>\*)?\s*(?P<name>[A-Za-z_$][\w$]*)"
    r"(?:\s*<[^>{};]*>)?\s*(?=\()",
    re.MULTILINE,
)
ARROW_TOKEN_RE = re.compile(r"=>")
CALL_RE = re.compile(
    r"(?P<constructor>\bnew\s+)?"
    r"(?P<callee>[A-Za-z_$][\w$]*"
    r"(?:\s*(?:\?\.|\.)\s*[A-Za-z_$][\w$]*)*)"
    r"\s*(?P<optional>\?\.\s*)?\("
)

JAVASCRIPT_GLOBALS = {
    "Array", "BigInt", "Boolean", "Date", "Error", "EvalError", "Function",
    "Map", "Number", "Object", "Promise", "RangeError", "ReferenceError",
    "RegExp", "Set", "String", "Symbol", "SyntaxError", "TypeError", "URIError",
    "WeakMap", "WeakSet", "decodeURI", "decodeURIComponent", "encodeURI",
    "encodeURIComponent", "eval", "isFinite", "isNaN", "parseFloat", "parseInt",
}
JAVASCRIPT_NAMESPACES = {
    "Array", "BigInt", "Date", "JSON", "Math", "Number", "Object", "Promise",
    "Reflect", "RegExp", "String", "Symbol",
}
NODE_GLOBALS = {"Buffer", "console", "process", "setImmediate", "clearImmediate"}
WEB_GLOBALS = {
    "AbortController", "Blob", "Event", "EventTarget", "FormData", "Headers",
    "Request", "Response", "TextDecoder", "TextEncoder", "URL", "URLSearchParams",
    "fetch", "queueMicrotask", "setInterval", "setTimeout", "clearInterval",
    "clearTimeout",
}
STANDARD_METHODS = {
    "at", "concat", "entries", "every", "filter", "find", "findIndex", "flat",
    "flatMap", "forEach", "get", "has", "includes", "indexOf", "join", "keys",
    "map", "pop", "push", "reduce", "reduceRight", "reverse", "set", "shift",
    "slice", "some", "sort", "splice", "toString", "unshift", "values",
}
NODE_METHODS = {"digest", "update"}
WEB_METHODS = {"arrayBuffer", "blob", "formData", "json", "redirect", "text"}


def classify_language_call(callee: str) -> Optional[str]:
    """Classify calls supplied by the language or common host runtimes."""
    normalized = callee.replace("?.", ".")
    parts = normalized.split(".")
    root = parts[0]
    leaf = parts[-1]
    if root in JAVASCRIPT_GLOBALS or root in JAVASCRIPT_NAMESPACES:
        return "javascript"
    if root in NODE_GLOBALS:
        return "node"
    if root in WEB_GLOBALS:
        return "web"
    if leaf in STANDARD_METHODS:
        return "javascript-method"
    if leaf in NODE_METHODS:
        return "node-method"
    if leaf in WEB_METHODS:
        return "web-method"
    return None


def mask_non_code(text: str) -> str:
    """Blank comments and string contents while preserving character offsets."""
    chars = list(text)
    index = 0
    state = "code"
    quote = ""
    while index < len(chars):
        char = chars[index]
        following = chars[index + 1] if index + 1 < len(chars) else ""
        if state == "code":
            if char == "/" and following == "/":
                chars[index] = chars[index + 1] = " "
                index += 2
                state = "line-comment"
                continue
            if char == "/" and following == "*":
                chars[index] = chars[index + 1] = " "
                index += 2
                state = "block-comment"
                continue
            if char in {"'", '"', "`"}:
                quote = char
                chars[index] = " "
                index += 1
                state = "string"
                continue
        elif state == "line-comment":
            if char == "\n":
                state = "code"
            else:
                chars[index] = " "
        elif state == "block-comment":
            if char == "*" and following == "/":
                chars[index] = chars[index + 1] = " "
                index += 2
                state = "code"
                continue
            chars[index] = " "
        elif state == "string":
            if char == "\\":
                chars[index] = " "
                if index + 1 < len(chars):
                    if chars[index + 1] != "\n":
                        chars[index + 1] = " "
                    index += 2
                    continue
            if char == quote:
                chars[index] = " "
                state = "code"
            else:
                chars[index] = " "
        index += 1
    return "".join(chars)


def matching_delimiter(
    text: str, opening: int, left: str, right: str,
) -> Optional[int]:
    depth = 0
    for index in range(opening, len(text)):
        if text[index] == left:
            depth += 1
        elif text[index] == right:
            depth -= 1
            if depth == 0:
                return index
    return None


def matching_delimiter_backward(
    text: str, closing: int, left: str, right: str,
) -> Optional[int]:
    depth = 0
    for index in range(closing, -1, -1):
        if text[index] == right:
            depth += 1
        elif text[index] == left:
            depth -= 1
            if depth == 0:
                return index
    return None


def arrow_parameter_range(masked: str, arrow_start: int, function_start: int) -> tuple:
    before = masked[function_start:arrow_start].rstrip()
    # Skip an optional return annotation and find the last parameter-list close.
    closing = masked.rfind(")", function_start, arrow_start)
    if closing >= 0:
        opening = matching_delimiter_backward(masked, closing, "(", ")")
        if opening is not None:
            return opening, closing
    identifier = re.search(r"([A-Za-z_$][\w$]*)\s*(?::[^=]+)?$", before)
    if identifier:
        start = function_start + identifier.start(1)
        return start, start + len(identifier.group(1)) - 1
    return function_start, function_start - 1


def function_body_start(masked: str, declaration_end: int) -> Optional[int]:
    parameters_start = masked.find("(", declaration_end)
    if parameters_start < 0:
        return None
    parameters_end = matching_delimiter(masked, parameters_start, "(", ")")
    if parameters_end is None:
        return None
    cursor = parameters_end + 1
    while cursor < len(masked):
        semicolon = masked.find(";", cursor)
        candidate = masked.find("{", cursor)
        if candidate < 0 or (semicolon >= 0 and semicolon < candidate):
            return None
        candidate_end = matching_delimiter(masked, candidate, "{", "}")
        if candidate_end is None:
            return None
        after = candidate_end + 1
        while after < len(masked) and masked[after].isspace():
            after += 1
        if after < len(masked) and masked[after] in "{>|&[":
            cursor = candidate_end + 1
            continue
        return candidate
    return None


def inferred_function_name(
    masked: str, function_start: int, explicit_name: Optional[str],
) -> str:
    if explicit_name:
        return explicit_name
    statement_start = max(
        masked.rfind(";", 0, function_start),
        masked.rfind("{", 0, function_start),
        masked.rfind("}", 0, function_start),
        masked.rfind("\n", 0, function_start),
    ) + 1
    prefix = masked[statement_start:function_start]
    assignment = re.search(
        r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*$", prefix
    )
    if assignment:
        return assignment.group(1)
    property_assignment = re.search(r"([A-Za-z_$][\w$]*)\s*:\s*$", prefix)
    if property_assignment:
        return property_assignment.group(1)
    line = masked.count("\n", 0, function_start) + 1
    return f"<anonymous@{line}>"


def arrow_start_and_name(masked: str, arrow_start: int) -> Tuple[int, str]:
    statement_start = max(
        masked.rfind(";", 0, arrow_start),
        masked.rfind("{", 0, arrow_start),
        masked.rfind("}", 0, arrow_start),
    ) + 1
    prefix = masked[statement_start:arrow_start]
    assignments = list(re.finditer(
        r"(?:(?:export|declare)\s+)*(?:const|let|var)\s+"
        r"(?P<name>[A-Za-z_$][\w$]*)[\s\S]*=",
        prefix,
    ))
    if assignments:
        assignment = assignments[-1]
        return statement_start + assignment.start(), assignment.group("name")

    trimmed = prefix.rstrip()
    parameters_end = statement_start + len(trimmed) - 1
    if parameters_end >= statement_start and masked[parameters_end] == ")":
        depth = 0
        for index in range(parameters_end, statement_start - 1, -1):
            if masked[index] == ")":
                depth += 1
            elif masked[index] == "(":
                depth -= 1
                if depth == 0:
                    before_parameters = masked[statement_start:index]
                    property_name = re.search(
                        r"([A-Za-z_$][\w$]*)\s*:\s*(?:async\s+)?$", before_parameters
                    )
                    if property_name:
                        return statement_start + property_name.start(), property_name.group(1)
                    return index, f"<arrow@{masked.count(chr(10), 0, index) + 1}>"
    identifier = re.search(r"([A-Za-z_$][\w$]*)\s*$", trimmed)
    start = statement_start + identifier.start() if identifier else arrow_start
    return start, f"<arrow@{masked.count(chr(10), 0, start) + 1}>"


def arrow_body_end(masked: str, arrow_end: int) -> Optional[int]:
    cursor = arrow_end
    while cursor < len(masked) and masked[cursor].isspace():
        cursor += 1
    if cursor >= len(masked):
        return arrow_end - 1
    if masked[cursor] == "{":
        return matching_delimiter(masked, cursor, "{", "}")
    parens = brackets = braces = 0
    last_code = cursor
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
        elif parens == brackets == braces == 0 and char in ";,":
            break
        elif parens == brackets == braces == 0 and char == "\n":
            break
        if not char.isspace():
            last_code = cursor
        cursor += 1
    return last_code


def find_functions(text: str) -> List[FunctionInfo]:
    masked = mask_non_code(text)
    functions = []
    occupied = set()
    for match in FUNCTION_KEYWORD_RE.finditer(masked):
        body_start = function_body_start(masked, match.end())
        if body_start is None:
            continue
        body_end = matching_delimiter(masked, body_start, "{", "}")
        if body_end is None:
            continue
        line_start = masked.rfind("\n", 0, match.start()) + 1
        form = "expression" if "=" in masked[line_start:match.start()] else "declaration"
        name = inferred_function_name(masked, match.start(), match.group("name"))
        functions.append({
            "name": name,
            "form": "generator-" + form if match.group("generator") else form,
            "start_line": text.count("\n", 0, match.start()) + 1,
            "end_line": text.count("\n", 0, body_end) + 1,
            "start_offset": match.start(),
            "end_offset": body_end,
            "body_start_offset": body_start,
            "parameters_start_offset": masked.find("(", match.end()),
            "parameters_end_offset": matching_delimiter(
                masked, masked.find("(", match.end()), "(", ")"
            ),
        })
        occupied.add(body_start)

    excluded_methods = {"if", "for", "while", "switch", "catch", "with", "function"}
    for match in METHOD_RE.finditer(masked):
        if match.group("name") in excluded_methods:
            continue
        body_start = function_body_start(masked, match.end())
        if body_start is None or body_start in occupied:
            continue
        body_end = matching_delimiter(masked, body_start, "{", "}")
        if body_end is None:
            continue
        functions.append({
            "name": match.group("name"),
            "form": "generator-method" if match.group("generator") else "method",
            "start_line": text.count("\n", 0, match.start("name")) + 1,
            "end_line": text.count("\n", 0, body_end) + 1,
            "start_offset": match.start("name"),
            "end_offset": body_end,
            "body_start_offset": body_start,
            "parameters_start_offset": masked.find("(", match.end()),
            "parameters_end_offset": matching_delimiter(
                masked, masked.find("(", match.end()), "(", ")"
            ),
        })
        occupied.add(body_start)

    for match in ARROW_TOKEN_RE.finditer(masked):
        statement_start = max(
            masked.rfind(";", 0, match.start()),
            masked.rfind("{", 0, match.start()),
            masked.rfind("}", 0, match.start()),
        ) + 1
        if masked[statement_start:match.start()].strip().startswith(("type ", "interface ")):
            continue
        start, name = arrow_start_and_name(masked, match.start())
        body_end = arrow_body_end(masked, match.end())
        if body_end is None:
            continue
        body_start = masked.find("{", match.end(), body_end + 1)
        if body_start >= 0 and body_start in occupied:
            continue
        parameters_start, parameters_end = arrow_parameter_range(masked, match.start(), start)
        functions.append({
            "name": name,
            "form": "arrow",
            "start_line": text.count("\n", 0, start) + 1,
            "end_line": text.count("\n", 0, body_end) + 1,
            "start_offset": start,
            "end_offset": body_end,
            "body_start_offset": body_start if body_start >= 0 else match.end(),
            "parameters_start_offset": parameters_start,
            "parameters_end_offset": parameters_end,
        })
    return sorted(
        functions,
        key=lambda item: (item["start_line"], item["end_line"], item["name"]),
    )


def function_parameter_starts(masked: str) -> set:
    """Return opening-parenthesis offsets belonging to function definitions."""
    starts = set()
    for match in FUNCTION_KEYWORD_RE.finditer(masked):
        parameters_start = masked.find("(", match.end())
        if parameters_start >= 0 and function_body_start(masked, match.end()) is not None:
            starts.add(parameters_start)
    for match in METHOD_RE.finditer(masked):
        parameters_start = masked.find("(", match.end())
        if parameters_start >= 0 and function_body_start(masked, match.end()) is not None:
            starts.add(parameters_start)
    return starts


def find_function_calls(text: str) -> List[FunctionCallInfo]:
    """Find direct, member, optional, and constructor call expressions."""
    masked = mask_non_code(text)
    definition_parameters = function_parameter_starts(masked)
    non_call_keywords = {
        "catch", "class", "do", "for", "function", "if", "import", "switch",
        "typeof", "while", "with",
    }
    calls = []
    for match in CALL_RE.finditer(masked):
        opening_parenthesis = match.end() - 1
        closing_parenthesis = matching_delimiter(
            masked, opening_parenthesis, "(", ")"
        )
        callee = re.sub(r"\s+", "", match.group("callee"))
        if opening_parenthesis in definition_parameters or callee in non_call_keywords:
            continue
        calls.append({
            "callee": callee,
            "form": (
                "constructor" if match.group("constructor")
                else "optional-call" if match.group("optional") or "?." in callee
                else "call"
            ),
            "line": text.count("\n", 0, match.start("callee")) + 1,
            "start_offset": match.start("callee"),
            "arguments_start_offset": opening_parenthesis,
            "arguments_end_offset": closing_parenthesis,
            "end_offset": closing_parenthesis if closing_parenthesis is not None else match.end(),
        })

    # Connect `.method()` calls whose receiver is another call expression,
    # such as createHmac(...).update(...).digest(...). The ordinary callee
    # regex deliberately stays small; this pass adds the missing chain link.
    by_end_offset = {call["end_offset"]: call for call in calls}
    for call in calls:
        cursor = call["start_offset"] - 1
        while cursor >= 0 and masked[cursor].isspace():
            cursor -= 1
        if cursor < 0 or masked[cursor] != ".":
            continue
        receiver_end = cursor - 1
        while receiver_end >= 0 and masked[receiver_end].isspace():
            receiver_end -= 1
        receiver_call = by_end_offset.get(receiver_end)
        if receiver_call:
            call["receiver_call_start_offset"] = receiver_call["start_offset"]
            call["receiver_expression"] = text[
                receiver_call["start_offset"]:receiver_call["end_offset"] + 1
            ].strip()
    return calls
