"""Arachne TypeScript source-inventory package."""
from .file_reader import HOLD_LIST, FILE_MAP, analyze_files, read_file, walk
from .graph import CODE_GRAPH, build_graph
from .variable_analysis import analyze_variable_flow
from .data_flow import link_data_flow, propagate_origins
from .receiver_analysis import resolve_receivers
from .compiler_body_adapter import adapt_compiler_body
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
from .security_roles import derive_roles, detect_guards
from .layered_graph import build_layered_graph, write_layered_graph
from .compiler_adapter import (
    analyze_typescript_with_compiler, combine_graphs, merge_overlay_graph,
    run_project_frontends, snapshot_file_infos, snapshot_graph, write_project_graph,
)
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
    "analyze_variable_flow",
    "link_data_flow",
    "propagate_origins",
    "resolve_receivers",
    "adapt_compiler_body",
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
    "derive_roles",
    "detect_guards",
    "build_layered_graph",
    "write_layered_graph",
    "combine_graphs",
    "merge_overlay_graph",
    "snapshot_file_infos",
    "analyze_typescript_with_compiler",
    "run_project_frontends",
    "snapshot_graph",
    "write_project_graph",
    "read_file",
    "walk",
]
