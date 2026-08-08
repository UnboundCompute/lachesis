"""Shared result shapes produced by the Arachne source analyzers."""
from typing import List, Optional, TypedDict


class ImportInfo(TypedDict):
    source: str
    symbols: str
    form: str
    source_kind: str
    import_kind: str
    resolved_path: Optional[str]
    bindings: List["ImportBinding"]


class ImportBinding(TypedDict):
    imported: str
    local: str


class ExportInfo(TypedDict):
    symbols: str
    names: List[str]
    form: str
    export_kind: str
    source: Optional[str]
    source_kind: Optional[str]
    resolved_path: Optional[str]


class FunctionInfo(TypedDict, total=False):
    id: str
    name: str
    form: str
    start_line: int
    end_line: int
    owner_function_id: Optional[str]


class FunctionCallInfo(TypedDict, total=False):
    id: str
    callee: str
    form: str
    line: int
    caller_function_id: Optional[str]
    resolution: str
    runtime: Optional[str]
    declaration_symbol_id: Optional[str]
    declaration_file: Optional[str]
    declaration_file_hash: Optional[str]
    declaration_line: Optional[int]
    declaration_end_line: Optional[int]
    method_name: str
    receiver_call_id: str
    receiver: dict
    return_type: dict


class FileInfo(TypedDict):
    file_id: str
    path: str
    path_hash: str
    content_hash: str
    lines: int
    bytes: int
    imports: List[ImportInfo]
    exports: List[str]
    export_details: List[ExportInfo]
    functions: List[FunctionInfo]
    function_calls: List[FunctionCallInfo]
    scopes: List[dict]
    symbols: List[dict]
    types: List[dict]
    properties: List[dict]
    definitions: List[dict]
    reads: List[dict]
    arguments: List[dict]
    returns: List[dict]
    data_flows: List[dict]
    aliases: List[dict]
    source_lines: List[dict]
    tokens: List[dict]
    statements: List[dict]
    expressions: List[dict]
    expression_links: List[dict]
    body_attachments: List[dict]
    text: str


class GraphNode(TypedDict):
    id: str
    kind: str
    label: str
    properties: dict


class GraphEdge(TypedDict):
    kind: str
    source: str
    target: str
    properties: dict


class CodeGraph(TypedDict):
    nodes: List[GraphNode]
    edges: List[GraphEdge]
