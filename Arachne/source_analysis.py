"""Offset-preserving source masking used by semantic overlays.

Declaration, call, import/export and type discovery belong to compiler
frontends. These helpers remain temporarily because several language-neutral
overlays inspect compact source fragments after compiler discovery.
"""
import re
from typing import List, Optional, Tuple


REGEX_PREFIX_KEYWORDS = {
    "await", "case", "delete", "do", "else", "in", "instanceof", "new",
    "of", "return", "throw", "typeof", "void", "yield",
}
VALUE_KEYWORDS = {"false", "null", "super", "this", "true", "undefined"}
CONTROL_PAREN_KEYWORDS = {"catch", "for", "if", "switch", "while", "with"}


def _regex_can_start(previous_kind: Optional[str], previous_value: str) -> bool:
    if previous_kind is None:
        return True
    if previous_kind == "keyword":
        return previous_value in REGEX_PREFIX_KEYWORDS
    if previous_kind == "control-close":
        return True
    if previous_kind in {"identifier", "number", "string", "regex", "close"}:
        return False
    if previous_value in {".", "?.", "++", "--"}:
        return False
    return True


def non_code_spans(text: str) -> List[Tuple[int, int, str]]:
    """Return comment, string/template, and regex spans without shifting text."""
    spans = []
    index = 0
    previous_kind: Optional[str] = None
    previous_value = ""
    pending_control_paren = False
    paren_context = []
    while index < len(text):
        char = text[index]
        following = text[index + 1] if index + 1 < len(text) else ""
        if char.isspace():
            index += 1
            continue
        if char == "/" and following in {"/", "*"}:
            start = index
            if following == "/":
                newline = text.find("\n", index + 2)
                index = len(text) if newline < 0 else newline
            else:
                closing = text.find("*/", index + 2)
                index = len(text) if closing < 0 else closing + 2
            spans.append((start, index, "comment"))
            continue
        if char in {"'", '"', "`"}:
            start = index
            quote = char
            index += 1
            while index < len(text):
                if text[index] == "\\":
                    index = min(len(text), index + 2)
                    continue
                if text[index] == quote:
                    index += 1
                    break
                if quote != "`" and text[index] in "\r\n":
                    break
                index += 1
            spans.append((start, index, "string"))
            previous_kind, previous_value = "string", quote
            pending_control_paren = False
            continue
        if char == "/" and _regex_can_start(previous_kind, previous_value):
            start = index
            cursor = index + 1
            in_character_class = False
            closing = None
            while cursor < len(text):
                current = text[cursor]
                if current == "\\":
                    cursor += 2
                    continue
                if current in "\r\n":
                    break
                if current == "[":
                    in_character_class = True
                elif current == "]":
                    in_character_class = False
                elif current == "/" and not in_character_class:
                    closing = cursor
                    break
                cursor += 1
            if closing is not None:
                index = closing + 1
                while index < len(text) and text[index].isalpha():
                    index += 1
                spans.append((start, index, "regex"))
                previous_kind, previous_value = "regex", "/"
                pending_control_paren = False
                continue
        identifier = re.match(r"[A-Za-z_$][\w$]*", text[index:])
        if identifier:
            value = identifier.group(0)
            previous_kind = (
                "keyword" if value in (
                    REGEX_PREFIX_KEYWORDS | VALUE_KEYWORDS | CONTROL_PAREN_KEYWORDS
                ) else "identifier"
            )
            previous_value = value
            pending_control_paren = value in CONTROL_PAREN_KEYWORDS
            index += len(value)
            continue
        number = re.match(
            r"(?:0[xX][0-9A-Fa-f]+|0[bB][01]+|0[oO][0-7]+|"
            r"\d+(?:\.\d*)?(?:[eE][+-]?\d+)?)n?", text[index:],
        )
        if number:
            previous_kind, previous_value = "number", number.group(0)
            pending_control_paren = False
            index += len(number.group(0))
            continue
        if char == "(":
            paren_context.append(pending_control_paren)
            pending_control_paren = False
            previous_kind, previous_value = "operator", char
            index += 1
            continue
        if char == ")":
            control_close = paren_context.pop() if paren_context else False
            previous_kind = "control-close" if control_close else "close"
            previous_value = char
            pending_control_paren = False
            index += 1
            continue
        if char in "]}":
            previous_kind, previous_value = "close", char
            pending_control_paren = False
            index += 1
            continue
        two = text[index:index + 2]
        if two in {"++", "--", "?.", "=>", "==", "!=", "<=", ">=", "&&", "||", "??"}:
            previous_kind, previous_value = "operator", two
            pending_control_paren = False
            index += 2
            continue
        previous_kind, previous_value = "operator", char
        pending_control_paren = False
        index += 1
    return spans


def mask_non_code(text: str) -> str:
    chars = list(text)
    for start, end, _kind in non_code_spans(text):
        for index in range(start, end):
            if chars[index] not in "\r\n":
                chars[index] = " "
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
