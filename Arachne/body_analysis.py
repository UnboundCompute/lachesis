"""Lossless source lines and manual function body/expression replication."""
import hashlib
import re
from typing import Dict, Iterable, List, Optional, Tuple

from .source_analysis import mask_non_code, matching_delimiter, non_code_spans
from .scope_utils import innermost_scope_at
from .variable_analysis import split_arguments


TOKEN_RE = re.compile(
    r"(?P<comment>//[^\n]*|/\*[\s\S]*?\*/)"
    r"|(?P<string>'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\"|`(?:\\.|[^`\\])*`)"
    r"|(?P<number>(?:0[xX][0-9A-Fa-f]+|0[bB][01]+|0[oO][0-7]+|\d+(?:\.\d*)?(?:[eE][+-]?\d+)?n?))"
    r"|(?P<identifier>[A-Za-z_$][\w$]*)"
    r"|(?P<operator>===|!==|>>>|\*\*=|&&=|\|\|=|\?\?=|=>|==|!=|<=|>=|\+\+|--|"
    r"&&|\|\||\?\?|\?\.|\+=|-=|\*=|/=|%=|<<|>>|\*\*|\.\.\.|[+\-*/%=&|^!~<>?:.])"
    r"|(?P<punctuation>[(){}\[\],;@])"
)
KEYWORDS = {
    "as", "async", "await", "break", "case", "catch", "class", "const",
    "continue", "debugger", "default", "delete", "do", "else", "enum",
    "export", "extends", "false", "finally", "for", "from", "function", "if",
    "implements", "import", "in", "instanceof", "interface", "let", "new",
    "null", "of", "return", "static", "super", "switch", "this", "throw",
    "true", "try", "type", "typeof", "undefined", "var", "void", "while",
    "with", "yield",
}
BLOCK_HEADERS = {
    "catch", "class", "do", "else", "finally", "for", "function", "if",
    "switch", "try", "while", "with",
}
UNARY_OPERATORS = ("await", "delete", "new", "typeof", "void", "yield", "!", "~", "+", "-", "++", "--")
BINARY_PRECEDENCE = (
    ("??",), ("||",), ("&&",), ("|",), ("^",), ("&",),
    ("===", "!==", "==", "!="),
    ("<=", ">=", "<", ">", "in", "instanceof"),
    ("<<", ">>", ">>>"), ("+", "-"), ("*", "/", "%"), ("**",),
)


def stable_id(kind: str, *parts) -> str:
    raw = ":".join(str(part) for part in parts)
    digest = hashlib.sha256(f"{kind}:{raw}".encode("utf-8")).hexdigest()[:16]
    return f"{kind}:{digest}"


def line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, max(0, offset)) + 1


def trim_span(text: str, start: int, end: int) -> Tuple[int, int]:
    while start < end and text[start].isspace():
        start += 1
    while end > start and text[end - 1].isspace():
        end -= 1
    return start, end


def lexical_tokens(text: str, functions: List[dict], path_hash: str) -> List[dict]:
    tokens = []
    masked = mask_non_code(text)

    def append_token(start: int, end: int, token_kind: str, value: str) -> None:
        owners = [
            function for function in functions
            if function.get("body_start_offset", function["start_offset"]) < start
            < function["end_offset"]
        ]
        owner = min(
            owners,
            key=lambda function: function["end_offset"] - function["start_offset"],
            default=None,
        )
        if not owner:
            return
        if token_kind == "identifier" and value in KEYWORDS:
            token_kind = "keyword"
        tokens.append({
            "id": stable_id("token", path_hash, start, end, value),
            "kind": token_kind, "value": value,
            "start_offset": start, "end_offset": end,
            "start_line": line_number(text, start),
            "end_line": line_number(text, max(start, end - 1)),
            "function_id": owner["id"],
        })

    # Scan code only; otherwise TOKEN_RE can reinterpret a backtick contained
    # in `/.../` as a template and swallow all later tokens. Non-code spans are
    # then added back as single lossless lexical units.
    for match in TOKEN_RE.finditer(masked):
        append_token(match.start(), match.end(), match.lastgroup, text[match.start():match.end()])
    for start, end, kind in non_code_spans(text):
        append_token(start, end, kind, text[start:end])
    return sorted(tokens, key=lambda item: item["start_offset"])


def source_lines(text: str, path_hash: str) -> List[dict]:
    if not text:
        return []
    result = []
    offset = 0
    for number, raw in enumerate(text.splitlines(keepends=True), 1):
        content = raw.rstrip("\r\n")
        stripped = content.strip()
        result.append({
            "id": stable_id("line", path_hash, number),
            "number": number, "text": content,
            "kind": (
                "blank" if not stripped
                else "comment" if stripped.startswith(("//", "/*", "*", "*/"))
                else "code"
            ),
            "start_offset": offset, "end_offset": offset + len(content),
        })
        offset += len(raw)
    if text and not result:
        result.append({
            "id": stable_id("line", path_hash, 1), "number": 1,
            "text": text, "kind": "code", "start_offset": 0, "end_offset": len(text),
        })
    return result


def statement_kind(tokens: List[dict]) -> str:
    code_tokens = [token for token in tokens if token["kind"] != "comment"]
    if not code_tokens:
        return "comment"
    first = code_tokens[0]["value"]
    if first in {"const", "let", "var"}:
        return "variable-declaration"
    if first in {"return", "throw", "break", "continue"}:
        return first
    if first in BLOCK_HEADERS or first in {"case", "default"}:
        return f"{first}-statement"
    if first in {"function", "class"}:
        return f"{first}-declaration"
    if any(
        token["value"] in {
            "=", "+=", "-=", "*=", "/=", "%=", "&&=", "||=", "??=",
        }
        for token in code_tokens
    ):
        return "assignment"
    return "expression-statement"


def discover_statements(
    text: str, functions: List[dict], tokens: List[dict], path_hash: str,
) -> List[dict]:
    statements = []
    for function in functions:
        owned = [token for token in tokens if token["function_id"] == function["id"]]
        if not owned:
            continue
        current = []
        parens = brackets = 0
        braces = []

        def flush(end_override: Optional[int] = None, forced_kind: Optional[str] = None):
            nonlocal current
            if not current:
                return
            start = current[0]["start_offset"]
            end = end_override if end_override is not None else current[-1]["end_offset"]
            start, end = trim_span(text, start, end)
            if start >= end:
                current = []
                return
            kind = forced_kind or statement_kind(current)
            statements.append({
                "id": stable_id("statement", path_hash, function["id"], start, end),
                "kind": kind, "function_id": function["id"],
                "start_offset": start, "end_offset": end,
                "start_line": line_number(text, start),
                "end_line": line_number(text, max(start, end - 1)),
                "text": text[start:end],
            })
            current = []

        for token in owned:
            if token["kind"] == "comment":
                continue
            value = token["value"]
            if value == "(" and token["kind"] != "string":
                parens += 1
            elif value == ")" and parens:
                parens -= 1
            elif value == "[":
                brackets += 1
            elif value == "]" and brackets:
                brackets -= 1

            current.append(token)
            code_values = [item["value"] for item in current if item["kind"] != "comment"]
            first = code_values[0] if code_values else None
            if value == "{" and parens == brackets == 0:
                if first == "{":
                    current = []
                    braces.append("block")
                elif first in BLOCK_HEADERS:
                    flush(forced_kind=f"{first}-statement")
                    braces.append("block")
                else:
                    braces.append("expression")
                continue
            if value == ";" and parens == brackets == 0 and "expression" not in braces:
                flush()
            elif value == "}" and parens == brackets == 0:
                brace_kind = braces.pop() if braces else "block"
                if brace_kind == "expression":
                    continue
                # A pending semicolon-free return/expression ends at its block.
                content = current[:-1]
                if content:
                    current = content
                    flush(end_override=token["start_offset"])
                else:
                    current = []
            elif value == ":" and parens == brackets == 0 and first in {"case", "default"}:
                flush(forced_kind=f"{first}-statement")
        flush()

    unique = {(item["function_id"], item["start_offset"], item["end_offset"]): item for item in statements}
    result = sorted(unique.values(), key=lambda item: (item["start_offset"], item["end_offset"]))
    by_function: Dict[str, List[dict]] = {}
    for statement in result:
        by_function.setdefault(statement["function_id"], []).append(statement)
    for function_statements in by_function.values():
        function_statements.sort(key=lambda item: (item["start_offset"], item["end_offset"]))
        for position, statement in enumerate(function_statements):
            statement["position"] = position
            statement["previous_statement_id"] = (
                function_statements[position - 1]["id"] if position else None
            )
            statement["next_statement_id"] = (
                function_statements[position + 1]["id"]
                if position + 1 < len(function_statements) else None
            )
    return result


def top_level_operators(masked: str, start: int, end: int) -> List[Tuple[int, str]]:
    result = []
    parens = brackets = braces = 0
    cursor = start
    operators = sorted(
        {operator for group in BINARY_PRECEDENCE for operator in group},
        key=len, reverse=True,
    )
    while cursor < end:
        char = masked[cursor]
        if char == "(": parens += 1
        elif char == ")": parens = max(0, parens - 1)
        elif char == "[": brackets += 1
        elif char == "]": brackets = max(0, brackets - 1)
        elif char == "{": braces += 1
        elif char == "}": braces = max(0, braces - 1)
        if parens == brackets == braces == 0:
            matched = next(
                (operator for operator in operators if masked.startswith(operator, cursor)),
                None,
            )
            if matched:
                before = masked[cursor - 1] if cursor > start else " "
                after = masked[cursor + len(matched)] if cursor + len(matched) < end else " "
                if matched in {"in", "instanceof"}:
                    if before.isalnum() or after.isalnum():
                        cursor += 1
                        continue
                result.append((cursor, matched))
                cursor += len(matched)
                continue
        cursor += 1
    return result


def expression_tree(info: dict, seeds: Iterable[Tuple[int, int, str]]) -> tuple:
    text = info["text"]
    masked = mask_non_code(text)
    expressions = []
    by_range = {}
    links = []
    parsing = set()

    def add(start: int, end: int, kind: str, operator: Optional[str] = None) -> Optional[dict]:
        start, end = trim_span(text, start, end)
        if start >= end:
            return None
        key = (start, end)
        expression = by_range.get(key)
        if expression is None:
            expression = {
                "id": stable_id("expression", info["path_hash"], start, end),
                "kind": kind, "operator": operator,
                "start_offset": start, "end_offset": end,
                "start_line": line_number(text, start),
                "end_line": line_number(text, max(start, end - 1)),
                "text": text[start:end],
                "roles": [kind],
            }
            by_range[key] = expression
            expressions.append(expression)
        elif expression["kind"] in {"expression", "leaf"} and kind not in {"expression", "leaf"}:
            expression["kind"] = kind
            expression["operator"] = operator
        if kind not in expression["roles"]:
            expression["roles"].append(kind)
        return expression

    def link(parent: dict, child: Optional[dict], role: str, position: Optional[int] = None):
        if not child or child["id"] == parent["id"]:
            return
        record = {"parent": parent["id"], "child": child["id"], "role": role}
        if position is not None:
            record["position"] = position
        if record not in links:
            links.append(record)

    def parse(start: int, end: int, seed_kind: str = "expression") -> Optional[dict]:
        start, end = trim_span(text, start, end)
        if start >= end:
            return None
        key = (start, end)
        parent = add(start, end, seed_kind)
        if key in parsing:
            return parent
        parsing.add(key)

        # Remove a single complete grouping pair while preserving a group node.
        if text[start:start + 1] == "(" and masked[end - 1:end] == ")":
            closing = matching_delimiter(masked, start, "(", ")")
            if closing == end - 1:
                parent["kind"] = "group"
                link(parent, parse(start + 1, end - 1), "GROUPED_VALUE")
                parsing.remove(key)
                return parent

        # Ternary is lower precedence than all binary operators handled below.
        depth = 0
        question = colon = None
        for cursor in range(start, end):
            char = masked[cursor]
            if char in "([{": depth += 1
            elif char in ")]}" and depth: depth -= 1
            elif depth == 0 and char == "?" and masked[cursor:cursor + 2] not in {"?.", "??"}:
                question = cursor
            elif depth == 0 and char == ":" and question is not None:
                colon = cursor
                break
        if question is not None and colon is not None:
            parent["kind"] = "conditional"
            parent["operator"] = "?:"
            link(parent, parse(start, question), "CONDITION")
            link(parent, parse(question + 1, colon), "TRUE_VALUE")
            link(parent, parse(colon + 1, end), "FALSE_VALUE")
            parsing.remove(key)
            return parent

        # TypeScript `value as Type` is a value-preserving cast operation.
        depth = 0
        cast_offset = None
        for match in re.finditer(r"\bas\b", masked[start:end]):
            absolute = start + match.start()
            depth = 0
            for char in masked[start:absolute]:
                if char in "([{": depth += 1
                elif char in ")]}" and depth: depth -= 1
            if depth == 0:
                cast_offset = absolute
        if cast_offset is not None:
            parent["kind"] = "cast"
            parent["operator"] = "as"
            parent["cast_type"] = text[cast_offset + 2:end].strip()
            link(parent, parse(start, cast_offset), "CAST_VALUE")
            parsing.remove(key)
            return parent

        operators = top_level_operators(masked, start, end)
        for precedence in BINARY_PRECEDENCE:
            matches = [(offset, operator) for offset, operator in operators if operator in precedence]
            if not matches:
                continue
            offset, operator = matches[-1]
            # A leading + or - is unary, not binary.
            if offset == start and operator in {"+", "-"}:
                continue
            parent["kind"] = "binary"
            parent["operator"] = operator
            link(parent, parse(start, offset), "LEFT_OPERAND")
            link(parent, parse(offset + len(operator), end), "RIGHT_OPERAND")
            parsing.remove(key)
            return parent

        raw = text[start:end]
        unary = next(
            (
                operator for operator in UNARY_OPERATORS
                if re.match(
                    "^" + re.escape(operator) + r"(?:\s|\b|(?=[A-Za-z_$\[({'\"`]))",
                    raw,
                )
            ),
            None,
        )
        if unary:
            operand_start = start + len(unary)
            parent["kind"] = "constructor" if unary == "new" else "unary"
            parent["operator"] = unary
            link(parent, parse(operand_start, end), "OPERAND")
            parsing.remove(key)
            return parent

        if text[start:start + 1] == "[" and masked[end - 1:end] == "]":
            closing = matching_delimiter(masked, start, "[", "]")
            if closing == end - 1:
                parent["kind"] = "array-literal"
                for position, (piece_start, piece_end) in enumerate(
                    split_arguments(text, start, end - 1)
                ):
                    link(parent, parse(piece_start, piece_end), "ELEMENT", position)
                parsing.remove(key)
                return parent

        if text[start:start + 1] == "{" and masked[end - 1:end] == "}":
            closing = matching_delimiter(masked, start, "{", "}")
            if closing == end - 1:
                parent["kind"] = "object-literal"
                for position, (piece_start, piece_end) in enumerate(
                    split_arguments(text, start, end - 1)
                ):
                    piece_masked = masked[piece_start:piece_end]
                    depth = 0
                    colon = None
                    for relative, char in enumerate(piece_masked):
                        if char in "([{": depth += 1
                        elif char in ")]}" and depth: depth -= 1
                        elif char == ":" and depth == 0:
                            colon = piece_start + relative
                            break
                    if colon is None:
                        link(parent, parse(piece_start, piece_end), "PROPERTY_VALUE", position)
                    else:
                        link(parent, parse(piece_start, colon, "property-key"), "PROPERTY_KEY", position)
                        link(parent, parse(colon + 1, piece_end), "PROPERTY_VALUE", position)
                parsing.remove(key)
                return parent

        if text[start:start + 1] == "`" and text[end - 1:end] == "`":
            parent["kind"] = "template-literal"
            cursor = start + 1
            position = 0
            while cursor < end - 1:
                marker = text.find("${", cursor, end - 1)
                if marker < 0:
                    break
                depth = 1
                closing = marker + 2
                while closing < end - 1 and depth:
                    if text[closing] == "{": depth += 1
                    elif text[closing] == "}": depth -= 1
                    closing += 1
                if depth == 0:
                    link(
                        parent, parse(marker + 2, closing - 1),
                        "TEMPLATE_VALUE", position,
                    )
                    position += 1
                cursor = closing
            parsing.remove(key)
            return parent

        # Calls whose opening parenthesis closes at the end of this span.
        opening = None
        depth = 0
        for cursor in range(start, end):
            char = masked[cursor]
            if char == "(" and depth == 0:
                candidate = matching_delimiter(masked, cursor, "(", ")")
                if candidate == end - 1:
                    opening = cursor
                    break
                depth += 1
            elif char == "(" : depth += 1
            elif char == ")" and depth: depth -= 1
        if opening is not None and opening > start:
            parent["kind"] = "call"
            link(parent, parse(start, opening, "callee"), "CALLEE")
            for position, (piece_start, piece_end) in enumerate(
                split_arguments(text, opening, end - 1)
            ):
                link(parent, parse(piece_start, piece_end, "argument"), "ARGUMENT", position)
            parsing.remove(key)
            return parent

        # Split a plain member access into its receiver and member/index value.
        member_match = re.fullmatch(
            r"([A-Za-z_$][\w$]*(?:\??\.[A-Za-z_$][\w$]*|\[[^\]]+\])*)"
            r"(?:\??\.([A-Za-z_$][\w$]*)|\[([^\]]+)\])",
            raw.strip(),
        )
        if member_match:
            normalized_start = start + len(raw) - len(raw.lstrip())
            base_text = member_match.group(1)
            base_start = normalized_start
            base_end = base_start + len(base_text)
            parent["kind"] = "member-access"
            parent["operator"] = (
                "[]" if member_match.group(3) is not None
                else "?." if "?." in raw else "."
            )
            link(parent, parse(base_start, base_end), "RECEIVER")
            if member_match.group(3) is not None:
                index_start = text.find("[", base_end, end) + 1
                link(parent, parse(index_start, end - 1), "PROPERTY_KEY")
            else:
                property_start = end - len(member_match.group(2))
                link(parent, parse(property_start, end, "property-name"), "PROPERTY_NAME")
            parsing.remove(key)
            return parent

        if re.fullmatch(r"(?:true|false|null|undefined|[+-]?\d+(?:\.\d+)?n?|['\"`][\s\S]*['\"`])", raw.strip()):
            parent["kind"] = "literal"
        elif re.fullmatch(r"[A-Za-z_$][\w$]*(?:\??\.[A-Za-z_$][\w$]*|\[[^\]]+\])*", raw.strip()):
            parent["kind"] = "identifier" if not re.search(r"\.|\[", raw) else "member-access"
        parsing.remove(key)
        return parent

    for start, end, kind in seeds:
        parse(start, end, kind)

    # Add lexical nesting for independently seeded expressions not already
    # connected by an operator/call relationship.
    connected = {(item["parent"], item["child"]) for item in links}
    for child in expressions:
        parents = [
            parent for parent in expressions
            if parent["id"] != child["id"]
            and parent["start_offset"] <= child["start_offset"]
            and child["end_offset"] <= parent["end_offset"]
        ]
        if not parents:
            continue
        parent = min(parents, key=lambda item: item["end_offset"] - item["start_offset"])
        if (parent["id"], child["id"]) not in connected:
            link(parent, child, "CONTAINS_EXPRESSION")

    return sorted(expressions, key=lambda item: (item["start_offset"], -item["end_offset"])), links


def analyze_body_structure(info: dict) -> None:
    text = info["text"]
    masked = mask_non_code(text)
    lines = source_lines(text, info["path_hash"])
    tokens = lexical_tokens(text, info["functions"], info["path_hash"])
    statements = discover_statements(
        text, info["functions"], tokens, info["path_hash"]
    )
    # Return/throw statements can be nested in a single-line control statement
    # (`if (x) return y;`). Preserve both the outer statement and nested exit.
    for returned in info["returns"]:
        search_start = max(0, returned["start_offset"] - 16)
        prefix = text[search_start:returned["start_offset"]]
        keyword_match = list(re.finditer(r"\b(?:return|throw)\b", prefix))
        start = (
            search_start + keyword_match[-1].start()
            if keyword_match else returned["start_offset"]
        )
        end = returned["end_offset"]
        cursor = end
        while cursor < len(text) and text[cursor].isspace() and text[cursor] != "\n":
            cursor += 1
        if cursor < len(text) and text[cursor] == ";":
            end = cursor + 1
        if not any(
            item["function_id"] == returned.get("function_id")
            and item["kind"] == returned["kind"]
            and item["start_offset"] == start
            for item in statements
        ):
            statements.append({
                "id": stable_id(
                    "statement", info["path_hash"], returned.get("function_id"), start, end
                ),
                "kind": returned["kind"], "function_id": returned.get("function_id"),
                "start_offset": start, "end_offset": end,
                "start_line": line_number(text, start),
                "end_line": line_number(text, max(start, end - 1)),
                "text": text[start:end],
            })

    # Abrupt statements may likewise be nested in an unbraced control body,
    # for example `if (done) break;` or `if (skip) continue;`.  The outer
    # statement remains useful for its condition while this inner record owns
    # the loop-control CFG edge.
    for abrupt in re.finditer(
        r"\b(?P<kind>break|continue)\b(?:\s+[A-Za-z_$][\w$]*)?\s*;?",
        masked,
    ):
        owners = [
            function for function in info["functions"]
            if function.get("body_start_offset", function["start_offset"])
            <= abrupt.start()
            and abrupt.end() <= function["end_offset"]
        ]
        owner = min(
            owners,
            key=lambda function: function["end_offset"] - function["start_offset"],
            default=None,
        )
        if not owner or any(
            item["function_id"] == owner["id"]
            and item["kind"] == abrupt.group("kind")
            and item["start_offset"] == abrupt.start()
            for item in statements
        ):
            continue
        statements.append({
            "id": stable_id(
                "statement", info["path_hash"], owner["id"],
                abrupt.start(), abrupt.end(),
            ),
            "kind": abrupt.group("kind"),
            "function_id": owner["id"],
            "start_offset": abrupt.start(),
            "end_offset": abrupt.end(),
            "start_line": line_number(text, abrupt.start()),
            "end_line": line_number(text, max(abrupt.start(), abrupt.end() - 1)),
            "text": text[abrupt.start():abrupt.end()],
        })
    symbols_by_id = {symbol["id"]: symbol for symbol in info["symbols"]}
    module_events = []
    for definition in info["definitions"]:
        symbol = symbols_by_id.get(definition["symbol_id"])
        if (
            definition.get("expression_start") is not None
            and symbol and symbol.get("owner_function_id") is None
            and symbol["kind"] in {"const", "let", "var"}
        ):
            module_events.append((definition["offset"], definition["expression_end"], "module-variable-declaration"))
    for call in info["function_calls"]:
        if call.get("caller_function_id") is None:
            module_events.append((call["start_offset"], call["end_offset"] + 1, "module-expression"))
    for event_start, event_end, kind in module_events:
        start = text.rfind("\n", 0, event_start) + 1
        while start < event_start and text[start].isspace():
            start += 1
        semicolon = text.find(";", event_end)
        newline = text.find("\n", event_end)
        if semicolon >= 0 and (newline < 0 or semicolon < newline):
            end = semicolon + 1
        else:
            end = newline if newline >= 0 else len(text)
        if not any(
            statement["start_offset"] == start and statement["end_offset"] == end
            for statement in statements
        ):
            statements.append({
                "id": stable_id("statement", info["path_hash"], info["file_id"], start, end),
                "kind": kind, "function_id": info["file_id"],
                "start_offset": start, "end_offset": end,
                "start_line": line_number(text, start),
                "end_line": line_number(text, max(start, end - 1)),
                "text": text[start:end],
            })
    statements.sort(key=lambda item: (item["start_offset"], -item["end_offset"]))
    for statement in statements:
        parents = [
            candidate for candidate in statements
            if candidate["id"] != statement["id"]
            and candidate["function_id"] == statement["function_id"]
            and candidate["start_offset"] <= statement["start_offset"]
            and statement["end_offset"] <= candidate["end_offset"]
        ]
        parent = min(
            parents,
            key=lambda item: item["end_offset"] - item["start_offset"],
            default=None,
        )
        statement["parent_statement_id"] = parent["id"] if parent else None
        statement["scope_id"] = innermost_scope_at(
            info["scopes"], statement["start_offset"], statement["start_line"]
        )["id"]
    by_function = {}
    for statement in statements:
        by_function.setdefault(statement["function_id"], []).append(statement)
    for function_statements in by_function.values():
        for position, statement in enumerate(function_statements):
            statement["position"] = position
            statement["previous_statement_id"] = (
                function_statements[position - 1]["id"] if position else None
            )
            statement["next_statement_id"] = (
                function_statements[position + 1]["id"]
                if position + 1 < len(function_statements) else None
            )
    seeds = []
    for definition in info["definitions"]:
        start = definition.get("expression_start")
        end = definition.get("expression_end")
        if start is not None and end is not None and start < end:
            seeds.append((start, end, "assigned-value"))
            if definition["kind"] in {"assignment", "property-write"}:
                header = masked[definition["offset"]:start]
                operator_matches = list(re.finditer(r"\?\?=|&&=|\|\|=|\+=|-=|\*=|/=|%=|=(?!=|>)", header))
                if operator_matches:
                    target_end = definition["offset"] + operator_matches[-1].start()
                    seeds.append((definition["offset"], target_end, "assignment-target"))
    for argument in info["arguments"]:
        seeds.append((argument["start_offset"], argument["end_offset"], "argument"))
    for returned in info["returns"]:
        seeds.append((returned["start_offset"], returned["end_offset"], "returned-value"))
    for call in info["function_calls"]:
        seeds.append((call["start_offset"], call["end_offset"] + 1, "call"))
    for match in re.finditer(r"\b(if|while|switch|catch|with|for)\s*\(", masked):
        opening = masked.find("(", match.start())
        closing = matching_delimiter(masked, opening, "(", ")")
        if closing is not None:
            seeds.append((opening + 1, closing, "condition" if match.group(1) != "for" else "loop-header"))
    for statement in statements:
        if statement["kind"] == "expression-statement":
            end = statement["end_offset"]
            if text[max(statement["start_offset"], end - 1):end] == ";":
                end -= 1
            seeds.append((statement["start_offset"], end, "expression"))

    expressions, expression_links = expression_tree(info, seeds)
    for expression in expressions:
        owners = [
            function for function in info["functions"]
            if function.get("body_start_offset", function["start_offset"])
            <= expression["start_offset"]
            and expression["end_offset"] <= function["end_offset"]
        ]
        owner = min(
            owners,
            key=lambda function: function["end_offset"] - function["start_offset"],
            default=None,
        )
        expression["function_id"] = owner["id"] if owner else None

    # Attach every body entity to its smallest enclosing statement/expression.
    attachments = []
    entity_specs = []
    for definition in info["definitions"]:
        if definition.get("expression_start") is not None:
            entity_specs.append((
                definition["id"], definition["expression_start"],
                definition.get("expression_end", definition["expression_start"] + 1),
                "DEFINITION",
            ))
    for read in info["reads"]:
        entity_specs.append((
            read["id"], read["offset"], read.get("end_offset", read["offset"] + 1),
            "READ",
        ))
    for call in info["function_calls"]:
        entity_specs.append((call["id"], call["start_offset"], call["end_offset"] + 1, "CALL"))
    for argument in info["arguments"]:
        entity_specs.append((
            argument["id"], argument["start_offset"], argument["end_offset"], "ARGUMENT"
        ))
    for returned in info["returns"]:
        entity_specs.append((
            returned["id"], returned["start_offset"], returned["end_offset"],
            "RETURN_VALUE",
        ))
    for entity_id, entity_start, entity_end, entity_kind in entity_specs:
        entity_start, entity_end = trim_span(text, entity_start, entity_end)
        expression_candidates = [
            expression for expression in expressions
            if expression["start_offset"] <= entity_start
            and entity_end <= expression["end_offset"]
        ]
        statement_candidates = [
            statement for statement in statements
            if statement["start_offset"] <= entity_start
            and entity_start < statement["end_offset"]
        ]
        expression = min(
            expression_candidates,
            key=lambda item: item["end_offset"] - item["start_offset"],
            default=None,
        )
        statement = min(
            statement_candidates,
            key=lambda item: item["end_offset"] - item["start_offset"],
            default=None,
        )
        attachments.append({
            "entity_id": entity_id, "entity_kind": entity_kind,
            "expression_id": expression["id"] if expression else None,
            "statement_id": statement["id"] if statement else None,
        })

    info["source_lines"] = lines
    info["tokens"] = tokens
    info["statements"] = statements
    info["expressions"] = expressions
    info["expression_links"] = expression_links
    info["body_attachments"] = attachments
