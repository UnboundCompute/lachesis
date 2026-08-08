"""Arachne TypeScript source-inventory package."""
from .file_reader import HOLD_LIST, FILE_MAP, analyze_files, read_file, walk
from .function_analysis import find_function_calls, find_functions
from .graph import CODE_GRAPH, build_graph
from .import_export_analysis import find_exports, find_imports, resolve_import
from .scope_analysis import analyze_scopes, find_scopes
from .type_analysis import find_types
from .variable_analysis import analyze_variable_flow
from .data_flow import link_data_flow, propagate_origins
from .receiver_analysis import resolve_receivers
from .body_analysis import analyze_body_structure
from .operation_analysis import analyze_operations
from .context_analysis import analyze_call_contexts
from .heap_analysis import analyze_heap
from .control_flow import build_control_flow
from .branch_analysis import analyze_branch_histories
from .taint_analysis import analyze_taint, taint_path
from .runtime_models import analyze_runtime_models, model_for_call
from .async_analysis import analyze_async_flow
from .effect_analysis import analyze_effects
from .type_system_analysis import analyze_type_system
from .dispatch_analysis import analyze_dispatch
from .dynamic_analysis import analyze_dynamic_behavior
from .exception_analysis import analyze_exceptions
from .module_init_analysis import analyze_module_init
from .wiring_analysis import analyze_wiring
from .types import (
    CodeGraph, ExportInfo, FileInfo, FunctionCallInfo, FunctionInfo, GraphEdge,
    GraphNode, ImportInfo,
)

__all__ = [
    "FILE_MAP",
    "HOLD_LIST",
    "ExportInfo",
    "FileInfo",
    "FunctionInfo",
    "FunctionCallInfo",
    "GraphEdge",
    "GraphNode",
    "CodeGraph",
    "ImportInfo",
    "analyze_files",
    "build_graph",
    "CODE_GRAPH",
    "find_exports",
    "find_function_calls",
    "find_functions",
    "find_imports",
    "find_scopes",
    "analyze_scopes",
    "find_types",
    "analyze_variable_flow",
    "link_data_flow",
    "propagate_origins",
    "resolve_receivers",
    "analyze_body_structure",
    "analyze_operations",
    "analyze_call_contexts",
    "analyze_heap",
    "build_control_flow",
    "analyze_branch_histories",
    "analyze_taint",
    "taint_path",
    "analyze_runtime_models",
    "model_for_call",
    "analyze_async_flow",
    "analyze_effects",
    "analyze_type_system",
    "analyze_dispatch",
    "analyze_dynamic_behavior",
    "analyze_exceptions",
    "analyze_module_init",
    "analyze_wiring",
    "read_file",
    "resolve_import",
    "walk",
]
