"""Manual class, interface, type-alias, and enum discovery."""
import hashlib
import re
from typing import List, Optional

from .function_analysis import mask_non_code, matching_delimiter

TYPE_DECLARATION_RE = re.compile(
    r"^[ \t]*(?P<export>export\s+)?(?P<abstract>abstract\s+)?"
    r"(?P<kind>class|interface|type|enum)\s+"
    r"(?P<name>[A-Za-z_$][\w$]*)"
    r"(?P<header>[^;{=]*)",
    re.MULTILINE,
)


def type_id(path_hash: str, kind: str, name: str, line: int) -> str:
    raw = f"{path_hash}:{kind}:{name}:{line}"
    return f"{kind}:{hashlib.sha256(raw.encode('utf-8')).hexdigest()[:16]}"


def names_after(keyword: str, header: str) -> List[str]:
    match = re.search(rf"\b{keyword}\s+(.+?)(?=\bextends\b|\bimplements\b|$)", header)
    if not match:
        return []
    return [name.strip() for name in match.group(1).split(",") if name.strip()]


def without_generic_sections(header: str) -> str:
    chars = list(header)
    depth = 0
    for index, char in enumerate(chars):
        if char == "<":
            depth += 1
        if depth:
            chars[index] = " "
        if char == ">" and depth:
            depth -= 1
    return "".join(chars)


def find_types(text: str, path_hash: str, functions: List[dict]) -> List[dict]:
    masked = mask_non_code(text)
    types = []
    for match in TYPE_DECLARATION_RE.finditer(masked):
        kind = match.group("kind")
        name = match.group("name")
        start_line = text.count("\n", 0, match.start()) + 1
        end_line = start_line
        end_offset = match.end()
        opening = masked.find("{", match.end())
        equals = masked.find("=", match.end())
        semicolon = masked.find(";", match.end())
        if opening >= 0 and not (
            (equals >= 0 and equals < opening) or (semicolon >= 0 and semicolon < opening)
        ):
            closing = matching_delimiter(masked, opening, "{", "}")
            if closing is not None:
                end_line = text.count("\n", 0, closing) + 1
                end_offset = closing
        elif semicolon >= 0:
            end_line = text.count("\n", 0, semicolon) + 1
            end_offset = semicolon

        header = " ".join(match.group("header").split())
        relationship_header = without_generic_sections(header)
        record = {
            "id": type_id(path_hash, kind, name, start_line),
            "kind": kind,
            "name": name,
            "start_line": start_line,
            "start_offset": match.start("name"),
            "end_line": end_line,
            "end_offset": end_offset,
            "exported": bool(match.group("export")),
            "extends": names_after("extends", relationship_header),
            "implements": names_after("implements", relationship_header),
        }
        types.append(record)

    for function in functions:
        owners = [
            declared_type for declared_type in types
            if declared_type["kind"] == "class"
            and declared_type["start_line"] <= function["start_line"]
            and function["end_line"] <= declared_type["end_line"]
        ]
        owner = min(
            owners,
            key=lambda item: item["end_line"] - item["start_line"],
            default=None,
        )
        function["owner_type_id"] = owner["id"] if owner else None
    return types
