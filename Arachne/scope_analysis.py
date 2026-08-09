"""Lightweight module, function, and control-block scope tracking."""
import hashlib
import re
from typing import List

from .source_analysis import mask_non_code, matching_delimiter

CONTROL_SCOPE_RE = re.compile(
    r"\b(?P<kind>if|for|while|switch|catch|try|else|finally)\b[^;{}]*\{",
    re.MULTILINE,
)
BARE_BLOCK_RE = re.compile(r"^[ \t]*\{", re.MULTILINE)
VARIABLE_RE = re.compile(
    r"\b(?P<kind>const|let|var)\s+"
    r"(?P<binding>[A-Za-z_$][\w$]*|\{[^}\n]*\}|\[[^\]\n]*\])"
)
CATCH_PARAM_RE = re.compile(
    r"\bcatch\s*\(\s*(?P<name>[A-Za-z_$][\w$]*)", re.MULTILINE
)
FOR_HEADER_RE = re.compile(r"\bfor\s*\(", re.MULTILINE)


def scope_id(path_hash: str, kind: str, start_line: int, ordinal: int) -> str:
    raw = f"{path_hash}:scope:{kind}:{start_line}:{ordinal}"
    return f"scope:{hashlib.sha256(raw.encode('utf-8')).hexdigest()[:16]}"


def symbol_id(path_hash: str, kind: str, name: str, line: int, ordinal: int) -> str:
    raw = f"{path_hash}:symbol:{kind}:{name}:{line}:{ordinal}"
    return f"symbol:{hashlib.sha256(raw.encode('utf-8')).hexdigest()[:16]}"


def innermost_scope(scopes: List[dict], line: int) -> dict:
    candidates = [
        scope for scope in scopes
        if scope["start_line"] <= line <= scope["end_line"]
    ]
    return min(
        candidates,
        key=lambda scope: (
            scope["end_line"] - scope["start_line"],
            2 if scope["kind"] == "module" else 1 if scope["kind"] == "function" else 0,
        ),
    )


def innermost_scope_at(scopes: List[dict], offset: int, line: int = None) -> dict:
    candidates = [
        scope for scope in scopes
        if scope.get("start_offset", 0) <= offset < scope.get("end_offset", 0)
    ]
    if not candidates:
        return innermost_scope(scopes, line or 1)
    return min(
        candidates,
        key=lambda scope: (
            scope.get("end_offset", 0) - scope.get("start_offset", 0),
            2 if scope["kind"] == "module" else 1 if scope["kind"] == "function" else 0,
        ),
    )


def binding_names(binding: str) -> List[str]:
    binding = binding.strip()
    if binding.startswith(("{", "[")):
        names = []
        for part in binding[1:-1].split(","):
            part = part.strip()
            if not part:
                continue
            candidate = part.split("=", 1)[0].split(":")[-1].strip()
            if re.fullmatch(r"[A-Za-z_$][\w$]*", candidate):
                names.append(candidate)
        return names
    match = re.match(r"[A-Za-z_$][\w$]*", binding)
    return [match.group(0)] if match else []


def parameter_names(text: str, function: dict) -> List[tuple]:
    start = function.get("parameters_start_offset")
    end = function.get("parameters_end_offset")
    if start is None or end is None or end < start:
        return []
    raw = text[start + 1:end] if text[start] == "(" else text[start:end + 1]
    names = []
    depth = 0
    piece_start = 0
    pieces = []
    for index, char in enumerate(raw):
        if char in "({[<":
            depth += 1
        elif char in ")}]>" and depth:
            depth -= 1
        elif char == "," and depth == 0:
            pieces.append((piece_start, raw[piece_start:index]))
            piece_start = index + 1
    pieces.append((piece_start, raw[piece_start:]))
    for offset, piece in pieces:
        binding = piece.split("=", 1)[0].split(":", 1)[0].strip()
        for name in binding_names(binding):
            absolute = start + 1 + offset + max(piece.find(name), 0)
            names.append((name, text.count("\n", 0, absolute) + 1, absolute))
    return names


def analyze_scopes(
    text: str,
    path_hash: str,
    functions: List[dict],
    calls: List[dict],
    imports: List[dict] = None,
    types: List[dict] = None,
) -> tuple:
    line_count = text.count("\n") + (1 if text and not text.endswith("\n") else 0)
    scopes = [{
        "id": scope_id(path_hash, "module", 1, 0),
        "kind": "module",
        "start_line": 1,
        "end_line": max(line_count, 1),
        "parent_scope_id": None,
        "owner_function_id": None,
        "start_offset": 0,
        "end_offset": len(text) + 1,
    }]

    for ordinal, function in enumerate(functions, 1):
        scope = {
            "id": scope_id(path_hash, "function", function["start_line"], ordinal),
            "kind": "function",
            "start_line": function["start_line"],
            "end_line": function["end_line"],
            "parent_scope_id": None,
            "owner_function_id": function["id"],
            "start_offset": function.get("body_start_offset", function["start_offset"]),
            "end_offset": function["end_offset"] + 1,
        }
        scopes.append(scope)
        function["scope_id"] = scope["id"]

    masked = mask_non_code(text)
    for ordinal, match in enumerate(CONTROL_SCOPE_RE.finditer(masked), 1):
        opening = match.end() - 1
        closing = matching_delimiter(masked, opening, "{", "}")
        if closing is None:
            continue
        scopes.append({
            "id": scope_id(
                path_hash, match.group("kind"), text.count("\n", 0, opening) + 1, ordinal
            ),
            "kind": match.group("kind"),
            "start_line": text.count("\n", 0, opening) + 1,
            "end_line": text.count("\n", 0, closing) + 1,
            "parent_scope_id": None,
            "owner_function_id": None,
            "start_offset": opening,
            "end_offset": closing + 1,
        })

    for ordinal, match in enumerate(FOR_HEADER_RE.finditer(masked), 1):
        opening_paren = match.end() - 1
        closing_paren = matching_delimiter(masked, opening_paren, "(", ")")
        if closing_paren is None:
            continue
        cursor = closing_paren + 1
        while cursor < len(masked) and masked[cursor].isspace():
            cursor += 1
        if cursor < len(masked) and masked[cursor] == "{":
            continue  # The braced control-scope pass already owns this loop.
        statement_end = masked.find(";", cursor)
        if statement_end < 0:
            statement_end = closing_paren
        scopes.append({
            "id": scope_id(
                path_hash, "for", text.count("\n", 0, match.start()) + 1, ordinal + 10000
            ),
            "kind": "for", "start_line": text.count("\n", 0, match.start()) + 1,
            "end_line": text.count("\n", 0, statement_end) + 1,
            "parent_scope_id": None, "owner_function_id": None,
            "start_offset": cursor, "end_offset": statement_end + 1,
        })

    existing_ranges = {
        (scope["start_line"], scope["end_line"]) for scope in scopes
    }
    for ordinal, match in enumerate(BARE_BLOCK_RE.finditer(masked), 1):
        opening = match.end() - 1
        closing = matching_delimiter(masked, opening, "{", "}")
        if closing is None:
            continue
        block_range = (
            text.count("\n", 0, opening) + 1,
            text.count("\n", 0, closing) + 1,
        )
        if block_range in existing_ranges:
            continue
        existing_ranges.add(block_range)
        scopes.append({
            "id": scope_id(path_hash, "block", block_range[0], ordinal),
            "kind": "block", "start_line": block_range[0], "end_line": block_range[1],
            "parent_scope_id": None, "owner_function_id": None,
            "start_offset": opening, "end_offset": closing + 1,
        })

    for scope in scopes[1:]:
        parents = [
            candidate for candidate in scopes
            if candidate is not scope
            and candidate["start_offset"] <= scope["start_offset"]
            and scope["end_offset"] <= candidate["end_offset"]
        ]
        parent = min(
            parents,
            key=lambda candidate: candidate["end_offset"] - candidate["start_offset"],
            default=scopes[0],
        )
        scope["parent_scope_id"] = parent["id"]
        scope["owner_function_id"] = scope.get("owner_function_id") or parent.get(
            "owner_function_id"
        )

    for call in calls:
        call["scope_id"] = innermost_scope_at(
            scopes, call.get("start_offset", 0), call["line"]
        )["id"]

    symbols = []

    def add_symbol(
        name: str, kind: str, line: int, scope: dict,
        declaration_id=None, start_offset: int = 0,
    ):
        symbol = {
            "id": symbol_id(path_hash, kind, name, line, len(symbols)),
            "name": name, "kind": kind, "line": line,
            "scope_id": scope["id"], "declaration_id": declaration_id,
            "start_offset": start_offset,
            "duplicate_of": None, "shadows": None,
        }
        symbols.append(symbol)
        return symbol

    module_scope = scopes[0]
    for imported in imports or []:
        for binding in imported["bindings"]:
            add_symbol(binding["local"], "import", 1, module_scope, start_offset=0)

    for function in functions:
        own_scope = next(scope for scope in scopes if scope["id"] == function["scope_id"])
        parent_scope = next(
            scope for scope in scopes if scope["id"] == own_scope["parent_scope_id"]
        )
        add_symbol(
            function["name"], "function", function["start_line"],
            parent_scope, function["id"], function.get("start_offset", 0),
        )
        for position, (name, line, offset) in enumerate(parameter_names(text, function)):
            parameter = add_symbol(
                name, "parameter", line, own_scope, start_offset=offset
            )
            parameter["position"] = position
            parameter["owner_function_id"] = function["id"]

    for declared_type in types or []:
        add_symbol(
            declared_type["name"], declared_type["kind"], declared_type["start_line"],
            innermost_scope_at(
                scopes, declared_type.get("start_offset", 0), declared_type["start_line"]
            ), declared_type["id"],
            declared_type.get("start_offset", 0),
        )

    for match in VARIABLE_RE.finditer(masked):
        line = text.count("\n", 0, match.start("binding")) + 1
        scope = innermost_scope_at(scopes, match.start("binding"), line)
        if match.group("kind") == "var":
            while scope["kind"] not in {"function", "module"}:
                scope = next(s for s in scopes if s["id"] == scope["parent_scope_id"])
        for name in binding_names(match.group("binding")):
            name_offset = masked.find(name, match.start("binding"), match.end("binding"))
            add_symbol(name, match.group("kind"), line, scope, start_offset=name_offset)

    for match in CATCH_PARAM_RE.finditer(masked):
        line = text.count("\n", 0, match.start("name")) + 1
        add_symbol(
            match.group("name"), "catch-parameter", line,
            innermost_scope_at(scopes, match.start("name"), line),
            start_offset=match.start("name"),
        )

    by_scope_name = {}
    scopes_by_id = {scope["id"]: scope for scope in scopes}
    for symbol in symbols:
        key = (symbol["scope_id"], symbol["name"])
        if key in by_scope_name:
            symbol["duplicate_of"] = by_scope_name[key]["id"]
        else:
            by_scope_name[key] = symbol

    for symbol in symbols:
        parent_id = scopes_by_id[symbol["scope_id"]]["parent_scope_id"]
        while parent_id:
            outer = by_scope_name.get((parent_id, symbol["name"]))
            if outer:
                symbol["shadows"] = outer["id"]
                break
            parent_id = scopes_by_id[parent_id]["parent_scope_id"]

    masked_text = mask_non_code(text)
    symbols_by_scope = {}
    for symbol in symbols:
        symbols_by_scope.setdefault(symbol["scope_id"], []).append(symbol)
    for function in functions:
        function["captures"] = []
        if not function.get("owner_function_id"):
            continue
        own_scope_id = function["scope_id"]
        local_names = {s["name"] for s in symbols_by_scope.get(own_scope_id, [])}
        parent_id = scopes_by_id[own_scope_id]["parent_scope_id"]
        outer_symbols = []
        while parent_id:
            outer_symbols.extend(symbols_by_scope.get(parent_id, []))
            parent_id = scopes_by_id[parent_id]["parent_scope_id"]
        body = masked_text[function["start_offset"]:function["end_offset"] + 1]
        for symbol in outer_symbols:
            if symbol["name"] in local_names:
                continue
            if symbol.get("declaration_id") == function["id"]:
                continue
            if re.search(rf"\b{re.escape(symbol['name'])}\b", body):
                function["captures"].append(symbol["id"])

    for symbol in symbols:
        scope = scopes_by_id[symbol["scope_id"]]
        symbol.setdefault("owner_function_id", scope.get("owner_function_id"))

    return scopes, symbols


def find_scopes(
    text: str, path_hash: str, functions: List[dict], calls: List[dict],
) -> List[dict]:
    scopes, _symbols = analyze_scopes(text, path_hash, functions, calls)
    return scopes
