"""Module initialization order and global/singleton state.

Importing a module runs its top-level statements, in order, exactly once — that
side-effecting prelude is where singletons are constructed and mutable module
state is seeded. This pass makes that implicit runtime visible:

  - `module_initializers`: every top-level statement in execution order, tagged
    with the side effect it performs (module-load / binding / call / mutation),
  - `singletons`: module-scoped bindings that hold a single constructed value
    (`new X`, `Object.freeze(...)`, a `Map`/`Set`, or a factory call),
  - `module_state`: module-scoped mutable state — reassignable `let`/`var`,
    mutable containers, and CommonJS `module.exports` / `exports.x` — flagged
    `exported` when it crosses the module boundary,
  - `static_initializers`: `static` class fields and `static { }` blocks,
  - `import_cycles`: circular import groups (strongly connected components of the
    resolved module-import graph), which force a partially-initialized module to
    be observed by its own dependency.
"""
import hashlib
import re
from collections import defaultdict
from typing import Iterable, List, Optional

from .source_analysis import mask_non_code


def stable_id(kind: str, *parts) -> str:
    raw = ":".join(str(part) for part in parts)
    return f"{kind}:{hashlib.sha256((kind + ':' + raw).encode()).hexdigest()[:16]}"


CONSTRUCTION_RE = re.compile(r"^new\s+([A-Za-z_$][\w$.]*)")
COLLECTION_RE = re.compile(r"^new\s+(Map|Set|WeakMap|WeakSet)\b")
FREEZE_RE = re.compile(r"^Object\.freeze\s*\(")
CALL_RE = re.compile(r"^([A-Za-z_$][\w$.]*)\s*\(")
LITERAL_RE = re.compile(r"^[\[{]")
MUTABLE_CONTAINER_RE = re.compile(r"^(?:new\s+(?:Map|Set|WeakMap|WeakSet)|[\[{])")


def _find_import_cycles(file_list: List[dict]) -> List[List[str]]:
    """Strongly-connected components (size > 1, or self-import) of the module graph."""
    by_path = {info["path"]: info for info in file_list}
    graph = defaultdict(set)
    for info in file_list:
        for imported in info["imports"]:
            target = imported.get("resolved_path")
            if target and target in by_path:
                graph[info["path"]].add(target)
        for exported in info["export_details"]:
            target = exported.get("resolved_path")
            if target and target in by_path:
                graph[info["path"]].add(target)

    index_counter = [0]
    indices, lowlink, on_stack, stack = {}, {}, set(), []
    components: List[List[str]] = []

    def strong_connect(node: str) -> None:
        indices[node] = lowlink[node] = index_counter[0]
        index_counter[0] += 1
        stack.append(node)
        on_stack.add(node)
        for neighbour in graph[node]:
            if neighbour not in indices:
                strong_connect(neighbour)
                lowlink[node] = min(lowlink[node], lowlink[neighbour])
            elif neighbour in on_stack:
                lowlink[node] = min(lowlink[node], indices[neighbour])
        if lowlink[node] == indices[node]:
            component = []
            while True:
                member = stack.pop()
                on_stack.discard(member)
                component.append(member)
                if member == node:
                    break
            if len(component) > 1 or node in graph[node]:
                components.append(component)

    for info in file_list:
        if info["path"] not in indices:
            strong_connect(info["path"])
    return components


def analyze_module_init(files: Iterable[dict]) -> None:
    file_list = list(files)

    # Cross-file circular imports, keyed to each participating file.
    cycles = _find_import_cycles(file_list)
    cycle_records_by_path = defaultdict(list)
    file_id_by_path = {info["path"]: info["file_id"] for info in file_list}
    for ordinal, component in enumerate(cycles):
        member_ids = [file_id_by_path[path] for path in component]
        for path in component:
            cycle_records_by_path[path].append({
                "id": stable_id("import-cycle", ordinal, *sorted(component)),
                "member_file_ids": member_ids,
                "size": len(component),
            })

    for info in file_list:
        path_hash = info["path_hash"]
        file_id = info["file_id"]
        exports = set(info["exports"])
        module_initializers = []
        singletons = []
        module_state = []
        static_initializers = []

        calls_by_statement = defaultdict(list)
        for attachment in info["body_attachments"]:
            if attachment["entity_kind"] == "CALL" and attachment.get("statement_id"):
                calls_by_statement[attachment["statement_id"]].append(attachment["entity_id"])

        # Top-level statements execute at import time, in source order.
        module_statements = sorted(
            (
                statement for statement in info["statements"]
                if statement["function_id"] == file_id
                and not statement.get("parent_statement_id")
            ),
            key=lambda item: item["start_offset"],
        )
        previous_id = None
        for order, statement in enumerate(module_statements):
            has_call = bool(calls_by_statement.get(statement["id"]))
            kind = statement["kind"]
            if kind in {"import-statement", "export-statement"}:
                effect = "module-load"
            elif "assignment" in kind or kind == "expression-statement":
                effect = "mutation" if not has_call else "call"
            elif kind in {"const", "let", "var", "variable-declaration", "declaration"}:
                effect = "binding-with-call" if has_call else "binding"
            elif has_call:
                effect = "call"
            else:
                effect = "statement"
            record = {
                "id": stable_id("module-init", path_hash, statement["id"]),
                "statement_id": statement["id"],
                "order": order,
                "line": statement["start_line"],
                "effect": effect,
                "has_call": has_call,
                "previous_id": previous_id,
                "text": " ".join(statement["text"].split())[:200],
            }
            module_initializers.append(record)
            previous_id = record["id"]

        # Module-scoped bindings: singletons and mutable state.
        module_symbols = [
            symbol for symbol in info["symbols"]
            if symbol.get("owner_function_id") is None
            and symbol["kind"] in {"const", "let", "var"}
        ]
        definitions_by_symbol = defaultdict(list)
        for definition in info["definitions"]:
            definitions_by_symbol[definition["symbol_id"]].append(definition)

        for symbol in module_symbols:
            symbol_defs = sorted(
                definitions_by_symbol.get(symbol["id"], []),
                key=lambda item: item.get("version", 0),
            )
            first = symbol_defs[0] if symbol_defs else None
            rhs = ""
            if first and first.get("expression_start") is not None and first.get("expression_end") is not None:
                rhs = info["text"][first["expression_start"]:first["expression_end"]].strip()
            exported = symbol["name"] in exports

            singleton_kind = None
            allocated_type = None
            if COLLECTION_RE.match(rhs):
                singleton_kind = "collection"
                allocated_type = COLLECTION_RE.match(rhs).group(1)
            elif FREEZE_RE.match(rhs):
                singleton_kind = "frozen"
            elif CONSTRUCTION_RE.match(rhs):
                singleton_kind = "construction"
                allocated_type = CONSTRUCTION_RE.match(rhs).group(1)
            elif LITERAL_RE.match(rhs):
                singleton_kind = "literal"
            elif CALL_RE.match(rhs):
                singleton_kind = "factory"

            if singleton_kind and singleton_kind != "literal" or (
                singleton_kind == "literal" and symbol["kind"] == "const"
            ):
                singletons.append({
                    "id": stable_id("singleton", path_hash, symbol["id"]),
                    "symbol_id": symbol["id"],
                    "name": symbol["name"],
                    "line": symbol["line"],
                    "singleton_kind": singleton_kind,
                    "allocated_type": allocated_type,
                    "exported": exported,
                    "definition_id": first["id"] if first else None,
                })

            # Mutable module state: reassignable, a mutable container, or later
            # mutated (a second definition version or a property write).
            reassignable = symbol["kind"] in {"let", "var"}
            container = bool(MUTABLE_CONTAINER_RE.match(rhs)) and not FREEZE_RE.match(rhs)
            mutated = any(
                definition.get("version", 0) > (first or {}).get("version", 0)
                or definition["kind"] == "property-write"
                for definition in definitions_by_symbol.get(symbol["id"], [])
            )
            if reassignable or container or mutated:
                module_state.append({
                    "id": stable_id("module-state", path_hash, symbol["id"]),
                    "symbol_id": symbol["id"],
                    "name": symbol["name"],
                    "line": symbol["line"],
                    "state_kind": (
                        "reassignable" if reassignable
                        else "mutable-container" if container
                        else "mutated"
                    ),
                    "exported": exported,
                    "binding_kind": symbol["kind"],
                })

        # CommonJS module.exports / exports.x assignments (module-boundary state).
        masked = mask_non_code(info["text"])
        for match in re.finditer(
            r"\b(module\.exports|exports\.[A-Za-z_$][\w$]*)\s*=\s*(?!=)", masked
        ):
            line = info["text"].count("\n", 0, match.start()) + 1
            module_state.append({
                "id": stable_id("module-state", path_hash, "cjs", match.start()),
                "symbol_id": None,
                "name": info["text"][match.start(1):match.end(1)],
                "line": line,
                "state_kind": "commonjs-export",
                "exported": True,
                "binding_kind": "commonjs",
            })

        # Static class initialization: `static field = ...` and `static { }`.
        class_ranges = [
            declared for declared in info["types"] if declared["kind"] == "class"
        ]
        for match in re.finditer(
            r"\bstatic\s+(?:(\{)|(?:(?:readonly\s+)?([A-Za-z_$][\w$]*)\s*[=:;(]))",
            masked,
        ):
            offset = match.start()
            owner = min(
                (
                    declared for declared in class_ranges
                    if declared["start_offset"] <= offset <= declared["end_offset"]
                ),
                key=lambda declared: declared["end_offset"] - declared["start_offset"],
                default=None,
            )
            if not owner:
                continue
            static_initializers.append({
                "id": stable_id("static-init", path_hash, offset),
                "type_id": owner["id"],
                "kind": "static-block" if match.group(1) else "static-field",
                "name": match.group(2),
                "line": info["text"].count("\n", 0, offset) + 1,
            })

        info["module_initializers"] = module_initializers
        info["singletons"] = singletons
        info["module_state"] = module_state
        info["static_initializers"] = static_initializers
        info["import_cycles"] = cycle_records_by_path.get(info["path"], [])
