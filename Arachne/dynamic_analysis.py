"""Explicit graph records for dynamic and statically indeterminate behavior."""
import hashlib
import re
from typing import Iterable, Optional

from .function_analysis import mask_non_code, matching_delimiter


def stable_id(kind: str, *parts) -> str:
    raw = ":".join(str(part) for part in parts)
    return f"{kind}:{hashlib.sha256((kind + ':' + raw).encode()).hexdigest()[:16]}"


def analyze_dynamic_behavior(files: Iterable[dict]) -> None:
    for info in files:
        info["dynamic_behaviors"] = []
        text, masked = info["text"], mask_non_code(info["text"])

        def owner_function(offset: int) -> Optional[str]:
            function = min(
                (
                    item for item in info["functions"]
                    if item["start_offset"] <= offset <= item["end_offset"]
                ),
                key=lambda item: item["end_offset"] - item["start_offset"],
                default=None,
            )
            return function["id"] if function else None

        def add(kind: str, offset: int, expression: str, entity_id=None, **properties):
            record = {
                "id": stable_id("dynamic-behavior", info["path_hash"], kind, offset),
                "kind": kind, "line": text.count("\n", 0, offset) + 1,
                "offset": offset, "expression": expression.strip(),
                "entity_id": entity_id, "function_id": owner_function(offset),
                "properties": properties,
            }
            if not any(item["id"] == record["id"] for item in info["dynamic_behaviors"]):
                info["dynamic_behaviors"].append(record)
            return record

        for call in info["function_calls"]:
            normalized = call["callee"].replace("?.", ".")
            if normalized == "eval":
                add("eval", call["start_offset"], normalized, call["id"], static_resolution="none")
            elif normalized == "Function" and call["form"] == "constructor":
                add("function-constructor", call["start_offset"], "new Function", call["id"], static_resolution="none")
            elif normalized.startswith("Reflect."):
                add("reflection", call["start_offset"], normalized, call["id"], operation=normalized.split(".")[-1])
            elif normalized == "Proxy" and call["form"] == "constructor":
                add("proxy-object", call["start_offset"], "new Proxy", call["id"], static_resolution="trap-dependent")
            elif normalized in {"require", "module.require", "createRequire"}:
                arguments = [
                    item for item in info["arguments"] if item["call_id"] == call["id"]
                ]
                expression = arguments[0]["expression"] if arguments else ""
                literal = bool(re.fullmatch(r"['\"][^'\"]+['\"]", expression.strip()))
                add(
                    "runtime-module-load", call["start_offset"], expression,
                    call["id"], static_resolution="literal" if literal else "runtime",
                )
            if call.get("form") in {"computed-call", "optional-computed-call"}:
                add(
                    "computed-call", call["start_offset"], call["callee"], call["id"],
                    key_expression=call.get("computed_key_expression"),
                    dispatch_status=call.get("dispatch_status", "unresolved"),
                    candidate_ids=call.get("dispatch_candidate_ids", []),
                )

        # import() is syntax rather than an ordinary call in the call extractor.
        for match in re.finditer(r"\bimport\s*\(", masked):
            opening = masked.find("(", match.start())
            closing = matching_delimiter(masked, opening, "(", ")")
            if closing is None:
                continue
            expression = text[opening + 1:closing].strip()
            literal_match = re.fullmatch(r"['\"]([^'\"]+)['\"]", expression)
            resolved_path = None
            if literal_match:
                imported = next(
                    (item for item in info["imports"] if item["source"] == literal_match.group(1)),
                    None,
                )
                resolved_path = (imported or {}).get("resolved_path")
            add(
                "dynamic-import", match.start(), text[match.start():closing + 1],
                static_resolution="literal" if literal_match else "runtime",
                source=literal_match.group(1) if literal_match else None,
                resolved_path=resolved_path,
            )

        # require(expr) with a non-literal argument is absent from static import
        # discovery, so scan it independently.
        for match in re.finditer(r"\brequire\s*\(", masked):
            opening = masked.find("(", match.start())
            closing = matching_delimiter(masked, opening, "(", ")")
            if closing is None:
                continue
            expression = text[opening + 1:closing].strip()
            if not re.fullmatch(r"['\"][^'\"]+['\"]", expression):
                add(
                    "runtime-module-load", match.start(), expression,
                    static_resolution="runtime",
                )

        for definition in info["definitions"]:
            if definition["kind"] != "property-write":
                continue
            property_info = next(
                (item for item in info["properties"] if item["id"] == definition["symbol_id"]),
                None,
            )
            if not property_info:
                continue
            base_symbol = next(
                (item for item in info["symbols"] if item["id"] == property_info["base_symbol_id"]),
                None,
            )
            start, end = definition.get("expression_start"), definition.get("expression_end")
            value = text[start:end].strip() if start is not None and end is not None else ""
            function_value = bool(
                re.match(r"(?:async\s+)?function\b|(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>", value)
                or any(function["name"] == value for function in info["functions"])
            )
            if "prototype" in property_info["path"] or function_value:
                add(
                    "monkey-patch", definition["offset"],
                    f"{(base_symbol or {}).get('name', '?')}.{property_info['path']}",
                    definition["id"], function_value=function_value,
                    imported_state=(base_symbol or {}).get("kind") == "import",
                )

        for match in re.finditer(
            r"\bObject\.(?:defineProperty|defineProperties|assign|setPrototypeOf)\s*\(",
            masked,
        ):
            add(
                "reflective-mutation", match.start(),
                text[match.start():masked.find("(", match.start())],
                operation=match.group(0).split(".")[-1].split("(")[0],
            )

        # Dynamic property keys are explicit even when they are reads rather
        # than calls. Literal bracket access remains statically nameable.
        for read in info["reads"]:
            if "[" not in read["name"]:
                continue
            keys = re.findall(r"\[([^\]]+)\]", read["name"])
            dynamic_keys = [
                key for key in keys
                if not re.fullmatch(r"(?:['\"][^'\"]+['\"]|\d+)", key.strip())
            ]
            if dynamic_keys:
                add(
                    "computed-property-read", read["offset"], read["name"], read["id"],
                    key_expressions=dynamic_keys,
                )

        for match in re.finditer(
            r"(?:^|[{,;\n])\s*\[([^\]\n]+)\]\s*(?=:|\()", masked,
        ):
            add(
                "computed-property-name", match.start(1), text[match.start(1):match.end(1)],
                key_expression=text[match.start(1):match.end(1)].strip(),
            )

        for match in re.finditer(
            r"\b([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)"
            r"\s*\[([^\]\n]+)\]\s*=\s*(?!=)", masked,
        ):
            target = text[match.start(1):match.end(2) + 1]
            add(
                "computed-property-write", match.start(), target,
                key_expression=text[match.start(2):match.end(2)].strip(),
                static_resolution="runtime",
            )
