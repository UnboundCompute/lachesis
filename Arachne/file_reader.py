"""File reading, hashing, inventory storage, and source-tree walking."""
import hashlib
import os
from typing import Dict, List, Optional, Tuple

from .function_analysis import classify_language_call, find_function_calls, find_functions
from .import_export_analysis import find_exports, find_imports, reexported_source_name
from .scope_analysis import analyze_scopes
from .type_analysis import find_types
from .variable_analysis import analyze_variable_flow
from .data_flow import link_data_flow
from .receiver_analysis import resolve_receivers
from .body_analysis import analyze_body_structure
from .operation_analysis import analyze_operations
from .context_analysis import analyze_call_contexts
from .heap_analysis import analyze_heap
from .control_flow import build_control_flow
from .branch_analysis import analyze_branch_histories
from .taint_analysis import analyze_taint
from .runtime_models import analyze_runtime_models
from .async_analysis import analyze_async_flow
from .effect_analysis import analyze_effects
from .type_system_analysis import analyze_type_system
from .dispatch_analysis import analyze_dispatch
from .dynamic_analysis import analyze_dynamic_behavior
from .exception_analysis import analyze_exceptions
from .module_init_analysis import analyze_module_init
from .wiring_analysis import analyze_wiring
from .types import FileInfo

# SHA-256(absolute path) -> complete read_file() result.
FILE_MAP: Dict[str, FileInfo] = {}
HOLD_LIST: List[FileInfo] = []


def hash_path(path: str) -> str:
    absolute_path = os.path.abspath(path)
    return hashlib.sha256(absolute_path.encode("utf-8")).hexdigest()


def stable_id(path_hash: str, kind: str, name: str, line: int, ordinal: int = 0) -> str:
    raw = f"{path_hash}:{kind}:{name}:{line}:{ordinal}"
    return f"{kind}:{hashlib.sha256(raw.encode('utf-8')).hexdigest()[:16]}"


def enclosing_function(functions: List[dict], line: int) -> Optional[dict]:
    candidates = [
        function for function in functions
        if function["start_line"] <= line <= function["end_line"]
    ]
    if not candidates:
        return None
    return min(
        candidates,
        key=lambda function: function["end_line"] - function["start_line"],
    )


def add_source_identities(
    path_hash: str, functions: List[dict], calls: List[dict],
) -> None:
    for ordinal, function in enumerate(functions):
        function["id"] = stable_id(
            path_hash, "function", function["name"], function["start_line"], ordinal
        )

    # Assign nested-function ownership after every function has an ID.
    for function in functions:
        parents = [
            candidate for candidate in functions
            if candidate is not function
            and candidate["start_line"] <= function["start_line"]
            and function["end_line"] <= candidate["end_line"]
        ]
        parent = min(
            parents,
            key=lambda candidate: candidate["end_line"] - candidate["start_line"],
            default=None,
        )
        function["owner_function_id"] = parent["id"] if parent else None

    for ordinal, call in enumerate(calls):
        call["id"] = stable_id(
            path_hash, "call", call["callee"], call["line"], ordinal
        )
        owner = enclosing_function(functions, call["line"])
        call["caller_function_id"] = owner["id"] if owner else None

    calls_by_start = {call["start_offset"]: call for call in calls}
    for call in calls:
        receiver_start = call.get("receiver_call_start_offset")
        if receiver_start is not None and receiver_start in calls_by_start:
            call["receiver_call_id"] = calls_by_start[receiver_start]["id"]


def read_file(path: str) -> FileInfo:
    absolute_path = os.path.abspath(path)
    path_hash = hash_path(absolute_path)
    with open(absolute_path, "r", encoding="utf-8") as file_handle:
        text = file_handle.read()

    exports, export_details = find_exports(text, absolute_path)
    functions = find_functions(text)
    function_calls = find_function_calls(text)
    add_source_identities(path_hash, functions, function_calls)
    types = find_types(text, path_hash, functions)
    imports = find_imports(text, absolute_path)
    scopes, symbols = analyze_scopes(
        text, path_hash, functions, function_calls, imports, types
    )
    info: FileInfo = {
        "file_id": f"file:{path_hash}",
        "path": absolute_path,
        "path_hash": path_hash,
        "content_hash": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "lines": text.count("\n") + (1 if text and not text.endswith("\n") else 0),
        "bytes": len(text.encode("utf-8")),
        "imports": imports,
        "exports": exports,
        "export_details": export_details,
        "functions": functions,
        "function_calls": function_calls,
        "scopes": scopes,
        "symbols": symbols,
        "types": types,
        "properties": [],
        "definitions": [],
        "reads": [],
        "arguments": [],
        "returns": [],
        "data_flows": [],
        "aliases": [],
        "source_lines": [],
        "tokens": [],
        "statements": [],
        "expressions": [],
        "expression_links": [],
        "body_attachments": [],
        "operations": [],
        "operation_inputs": [],
        "operation_attachments": [],
        "call_contexts": [],
        "context_dispatches": [],
        "heap_objects": [],
        "heap_locations": [],
        "points_to": [],
        "heap_accesses": [],
        "heap_effects": [],
        "context_heap_effects": [],
        "cfg_nodes": [],
        "cfg_edges": [],
        "unreachable": [],
        "phi_nodes": [],
        "branch_flows": [],
        "taint_sources": [],
        "taint_flows": [],
        "taint_reaches": [],
        "tainted_calls": [],
        "runtime_models": [],
        "async_nodes": [],
        "async_edges": [],
        "effect_summaries": [],
        "applied_effects": [],
        "type_parameters": [],
        "type_refinements": [],
        "generic_substitutions": [],
        "overloads": [],
        "type_compatibilities": [],
        "dispatch_candidates": [],
        "dispatch_relations": [],
        "dispatch_members": [],
        "dynamic_behaviors": [],
        "exception_sites": [],
        "catch_handlers": [],
        "finally_blocks": [],
        "promise_rejections": [],
        "module_initializers": [],
        "singletons": [],
        "module_state": [],
        "static_initializers": [],
        "import_cycles": [],
        "wiring_boundaries": [],
        "text": text,
    }
    analyze_variable_flow(info)
    analyze_body_structure(info)
    analyze_operations(info)
    FILE_MAP[path_hash] = info
    return info


def declared_function(info: FileInfo, name: str) -> Optional[dict]:
    for function in info["functions"]:
        if function["name"] == name:
            return function
    return None


def resolve_exported_function(
    info: FileInfo, name: str, visited: Optional[set] = None,
) -> Tuple[Optional[FileInfo], Optional[dict], bool]:
    """Follow local declarations and re-export chains. Third result means waiting."""
    visited = visited or set()
    visit_key = (info["path_hash"], name)
    if visit_key in visited:
        return None, None, False
    visited.add(visit_key)

    function = declared_function(info, name)
    if function:
        return info, function, False

    for exported in info["export_details"]:
        source = exported["source"]
        resolved_path = exported["resolved_path"]
        if not source or not resolved_path or not os.path.isfile(resolved_path):
            continue
        source_name = reexported_source_name(exported["symbols"], name)
        if source_name is None or source_name == "*":
            continue
        target_info = FILE_MAP.get(hash_path(resolved_path))
        if target_info is None:
            return None, None, True
        found_info, found_function, waiting = resolve_exported_function(
            target_info, source_name, visited
        )
        if found_function or waiting:
            return found_info, found_function, waiting
    return None, None, False


def imported_call_target(info: FileInfo, callee: str) -> Optional[Tuple[dict, str]]:
    parts = callee.replace("?.", ".").split(".")
    local_name = parts[0]
    for imported in info["imports"]:
        if imported["import_kind"] == "type":
            continue
        for binding in imported["bindings"]:
            if binding["local"] != local_name:
                continue
            if binding["imported"] == "*":
                target_name = parts[-1] if len(parts) > 1 else "default"
            elif len(parts) > 1 and binding["imported"] == "default":
                target_name = parts[-1]
            else:
                target_name = binding["imported"]
            return imported, target_name
    return None


def link_call(call: dict, target_info: FileInfo, function: dict, resolution: str) -> None:
    call.update({
        "resolution": resolution,
        "declaration_symbol_id": function["id"],
        "declaration_file": target_info["path"],
        "declaration_file_hash": target_info["path_hash"],
        "declaration_line": function["start_line"],
        "declaration_end_line": function["end_line"],
    })


def terminal_call(call: dict, resolution: str, runtime: Optional[str] = None) -> None:
    call.update({
        "resolution": resolution,
        "runtime": runtime,
        "declaration_symbol_id": None,
        "declaration_file": None,
        "declaration_file_hash": None,
        "declaration_line": None,
        "declaration_end_line": None,
    })


def resolve_file_function_calls(info: FileInfo) -> bool:
    """Resolve calls in one file; return False while an imported file is pending."""
    waiting = False
    for call in info["function_calls"]:
        callee = call["callee"]
        local_name = callee.replace("?.", ".").split(".")[-1]
        local_function = None
        if "." not in callee or callee.startswith(("this.", "this?.")):
            local_function = declared_function(info, local_name)
        if local_function:
            link_call(call, info, local_function, "same-file")
            continue

        target = imported_call_target(info, callee)
        if target is None:
            runtime = classify_language_call(callee)
            terminal_call(
                call,
                "language-runtime" if runtime else "unresolved",
                runtime,
            )
            continue
        imported, target_name = target
        resolved_path = imported["resolved_path"]
        if not resolved_path or not os.path.isfile(resolved_path):
            runtime = "node" if imported["source_kind"] == "builtin" else None
            terminal_call(
                call,
                "language-runtime" if runtime else "external",
                runtime,
            )
            continue

        target_hash = hash_path(resolved_path)
        target_info = FILE_MAP.get(target_hash)
        if target_info is None:
            call.update({
                "resolution": "waiting",
                "declaration_file": resolved_path,
                "declaration_file_hash": target_hash,
                "declaration_line": None,
                "declaration_end_line": None,
            })
            waiting = True
            continue

        declaration_info, target_function, reexport_waiting = resolve_exported_function(
            target_info, target_name
        )
        if reexport_waiting:
            call.update({
                "resolution": "waiting",
                "declaration_file": resolved_path,
                "declaration_file_hash": target_hash,
                "declaration_line": None,
                "declaration_end_line": None,
                "declaration_symbol_id": None,
            })
            waiting = True
            continue
        if target_function:
            resolution = "re-exported" if declaration_info is not target_info else "imported"
            link_call(call, declaration_info or target_info, target_function, resolution)
        else:
            terminal_call(call, "declaration-not-found")
    return not waiting


def analyze_files(paths: List[str]) -> List[FileInfo]:
    """Read once, defer missing targets, then drain the hold list to a fixed point."""
    FILE_MAP.clear()
    HOLD_LIST.clear()
    results = []
    for path in paths:
        info = read_file(path)
        results.append(info)
        if not resolve_file_function_calls(info):
            HOLD_LIST.append(info)

    while HOLD_LIST:
        pending = HOLD_LIST[:]
        HOLD_LIST.clear()
        resolved_count = 0
        for info in pending:
            if resolve_file_function_calls(info):
                resolved_count += 1
            else:
                HOLD_LIST.append(info)

        if HOLD_LIST and resolved_count == 0:
            # No target appeared during this pass. Convert the remaining waits
            # to terminal unresolved links so the hold loop always drains.
            for info in HOLD_LIST:
                for call in info["function_calls"]:
                    if call.get("resolution") == "waiting":
                        terminal_call(call, "unresolved-import")
            HOLD_LIST.clear()
    resolve_receivers(results)
    analyze_dispatch(results)
    link_data_flow(results)
    analyze_call_contexts(results)
    analyze_dispatch(results, include_callbacks=True)
    # Callback dispatch depends on first-pass call contexts. Rebuild the
    # interprocedural links once those callback targets are known.
    link_data_flow(results)
    analyze_call_contexts(results)
    analyze_dynamic_behavior(results)
    analyze_heap(results)
    for info in results:
        build_control_flow(info)
    analyze_branch_histories(results)
    analyze_type_system(results)
    analyze_runtime_models(results)
    analyze_effects(results)
    analyze_async_flow(results)
    analyze_exceptions(results)
    analyze_module_init(results)
    analyze_wiring(results)
    analyze_taint(results)
    return results


def walk(src_dir: str) -> List[str]:
    files = []
    supported_extensions = (".ts", ".tsx", ".js", ".jsx", ".mts", ".cts")
    for root, _dirs, names in os.walk(src_dir):
        for name in sorted(names):
            if name.endswith(supported_extensions):
                files.append(os.path.join(root, name))
    return sorted(files)
