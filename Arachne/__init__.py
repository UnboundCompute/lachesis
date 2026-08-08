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
    "read_file",
    "resolve_import",
    "walk",
]
