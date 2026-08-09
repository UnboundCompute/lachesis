"""Canonical graph and optional file-view result shapes."""
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
    receiver_expression: str
    computed_key_expression: str
    dispatch_candidate_ids: List[str]
    dispatch_target_ids: List[str]
    dispatch_status: str


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
    operations: List[dict]
    operation_inputs: List[dict]
    operation_attachments: List[dict]
    call_contexts: List[dict]
    context_dispatches: List[dict]
    heap_objects: List[dict]
    heap_locations: List[dict]
    points_to: List[dict]
    heap_accesses: List[dict]
    heap_effects: List[dict]
    context_heap_effects: List[dict]
    cfg_nodes: List[dict]
    cfg_edges: List[dict]
    unreachable: List[dict]
    phi_nodes: List[dict]
    branch_flows: List[dict]
    taint_sources: List[dict]
    taint_flows: List[dict]
    taint_reaches: List[dict]
    tainted_calls: List[dict]
    runtime_models: List[dict]
    async_nodes: List[dict]
    async_edges: List[dict]
    effect_summaries: List[dict]
    applied_effects: List[dict]
    type_parameters: List[dict]
    type_refinements: List[dict]
    generic_substitutions: List[dict]
    overloads: List[dict]
    type_compatibilities: List[dict]
    dispatch_candidates: List[dict]
    dispatch_relations: List[dict]
    dispatch_members: List[dict]
    dynamic_behaviors: List[dict]
    exception_sites: List[dict]
    catch_handlers: List[dict]
    finally_blocks: List[dict]
    promise_rejections: List[dict]
    module_initializers: List[dict]
    singletons: List[dict]
    module_state: List[dict]
    static_initializers: List[dict]
    import_cycles: List[dict]
    wiring_boundaries: List[dict]
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
