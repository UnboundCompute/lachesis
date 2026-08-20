"""Preprocessor macro recovery for the C frontend.

The Clang JSON AST is *post-preprocessor*: ``#define`` directives are already
expanded and absent from it, so macros — the load-bearing C construct with no
direct TS equivalent — would otherwise be invisible in the graph. This module
recovers macro *definitions* with their exact source sites from a dedicated
preprocessor pass (``clang -E -dD``, which keeps ``#define`` directives in place
and interleaves the standard line-markers clang uses to attribute output back to
its origin file:line).

Parsing is over the compiler's own ``-dD`` output and its line-markers — no
regex, no hand-rolled C lexing — keeping the compiler the single source of truth
(parity with the rest of the C frontend). ``clang`` is invoked by the caller;
this module is a pure function of the captured stdout so it stays trivially
testable.
"""
from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional, Tuple

_DEFINE = "#define "
_IDENTIFIER = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
)


def _parse_line_marker(line: str) -> Optional[Tuple[str, int]]:
    """Decode a preprocessor line-marker ``# <line> "<file>" [flags]``.

    Returns ``(file, line_number)`` where ``line_number`` is the source line the
    *next* emitted output line originates from, or ``None`` if not a marker.
    """
    if not line.startswith("# "):
        return None
    rest = line[2:]
    separator = rest.find(" ")
    number = rest[:separator] if separator >= 0 else rest
    if not number.isdigit():
        return None
    open_quote = rest.find('"')
    close_quote = rest.find('"', open_quote + 1)
    if open_quote < 0 or close_quote < 0:
        return None
    return rest[open_quote + 1:close_quote], int(number)


def _split_definition(rest: str) -> Optional[dict]:
    """Split the text after ``#define `` into name / form / params / body.

    A macro is *function-like* only when ``(`` immediately follows the name with
    no intervening whitespace (the C rule); otherwise it is object-like.
    """
    cursor = 0
    while cursor < len(rest) and rest[cursor] in _IDENTIFIER:
        cursor += 1
    name = rest[:cursor]
    if not name:
        return None
    remainder = rest[cursor:]
    if remainder.startswith("("):
        depth = 0
        for index, character in enumerate(remainder):
            if character == "(":
                depth += 1
            elif character == ")":
                depth -= 1
                if depth == 0:
                    raw_params = remainder[1:index]
                    body = remainder[index + 1:].strip()
                    parameters = [
                        parameter.strip()
                        for parameter in raw_params.split(",")
                        if parameter.strip()
                    ]
                    return {
                        "name": name, "form": "function-like",
                        "parameters": parameters, "body": body,
                    }
        return None  # unbalanced parameter list — leave to the compiler
    return {
        "name": name, "form": "object-like",
        "parameters": [], "body": remainder.strip(),
    }


def parse_macro_definitions(
    preprocessed: str, origin: Path,
) -> List[Dict[str, object]]:
    """Recover macro definitions originating in ``origin`` from ``-dD`` output.

    Only definitions whose line-marker resolves to ``origin`` itself are kept, so
    a header's macros are attributed once — when that header is analyzed as its
    own compiler root — rather than re-counted in every translation unit that
    includes it. Built-in / command-line / system-header macros are filtered out
    for free by the same origin check.
    """
    origin_resolved = origin.resolve()
    current_file: Optional[str] = None
    current_resolved: Optional[Path] = None
    current_line = 0
    resolved_files: Dict[str, Path] = {}
    macros: List[Dict[str, object]] = []
    for line in preprocessed.splitlines():
        marker = _parse_line_marker(line)
        if marker is not None:
            current_file, current_line = marker
            current_resolved = resolved_files.get(current_file)
            if current_resolved is None:
                current_resolved = Path(current_file).resolve()
                resolved_files[current_file] = current_resolved
            continue
        if (
            line.startswith(_DEFINE)
            and current_file is not None
            and current_resolved == origin_resolved
        ):
            definition = _split_definition(line[len(_DEFINE):])
            if definition is not None:
                definition["line"] = current_line
                macros.append(definition)
        current_line += 1
    return macros
