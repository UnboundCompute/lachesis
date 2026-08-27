//! Native reader for the Pass-1 framed substrate.
//!
//! The Python process writes this file while it still owns the frontend build.
//! Pass 2 does not receive Python dictionaries: Rust reads the framed protobuf
//! records directly and constructs the function inputs in native memory.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Cursor, Read};
use std::path::Path;
use hashbrown::{HashMap, HashSet};
use memmap2::{Mmap, MmapOptions};

use prost::Message;

use crate::{graph_proto, lifetime_proto};

const FRAME_HEADER: usize = 4;

// Temporal preparation only consumes these relations.  The complete Pass-2
// sidecar remains lossless; filtering here prevents unrelated overlay edges
// from being duplicated into every native FunctionInput.
fn retain_lifetime_edge(kind: &str) -> bool {
    matches!(kind, "AST_CHILD" | "REFERS_TO" | "VALUE_FLOWS_TO" | "CFG_NEXT")
}

/// Map the immutable Pass-1 substrate instead of reading a second full byte
/// buffer.  The parser still materializes the compact native request it needs,
/// but the raw protobuf stream is demand-paged and can be reclaimed by the OS.
pub(crate) fn map_path(path: impl AsRef<Path>) -> Result<Mmap, String> {
    let file = File::open(path.as_ref())
        .map_err(|error| format!("cannot open native graph substrate: {error}"))?;
    // SAFETY: Pass-1 sidecars are immutable inputs for the duration of a native
    // call. The file handle remains owned by the mapping until it is dropped.
    unsafe { MmapOptions::new().map(&file) }
        .map_err(|error| format!("cannot map native graph substrate: {error}"))
}

fn scalar(node: &graph_proto::NodeRecord, key: &str) -> Option<String> {
    node.properties.iter().find_map(|field| {
        if field.key != key { return None; }
        let value = field.value.as_ref()?.kind.as_ref()?;
        Some(match value {
            graph_proto::value::Kind::Text(value) => value.clone(),
            graph_proto::value::Kind::Integer(value) => value.to_string(),
            graph_proto::value::Kind::Real(value) => value.to_string(),
            graph_proto::value::Kind::Boolean(value) => value.to_string(),
            graph_proto::value::Kind::Binary(value) => String::from_utf8_lossy(value).into_owned(),
            graph_proto::value::Kind::List(_) |
            graph_proto::value::Kind::Object(_) |
            graph_proto::value::Kind::NullValue(_) => return None,
        })
    })
}

fn scalar_properties(node: &graph_proto::NodeRecord, retain_owner: bool) -> Vec<lifetime_proto::ScalarProperty> {
    node.properties.iter().filter_map(|field| {
        // The lifetime preparer only consumes these substrate attributes.  Do
        // not copy the rest of the frontend's arbitrary property bag into the
        // graph-sized native request: on large inputs that otherwise creates a
        // second allocation for every scalar field before preparation starts.
        // Keep this allow-list in sync with text_property/integer_property in
        // prepare.rs and the call extraction in native_graph.rs.
        let retained = matches!(field.key.as_str(),
            "syntax_kind" |
            "start_offset" |
            "start_line" |
            "operator" |
            "type" |
            "primary_target_id" |
            "callee" |
            "callee_name" |
            "callee_form" |
            "receiver" |
            "target_id" |
            "value_id" |
            "is_alloc" |
            "is_release" |
            "is_realloc" |
            "release_method" |
            "is_aggregate_copy")
            || (retain_owner && matches!(field.key.as_str(),
                "owner_function_id" | "function_id"));
        if !retained {
            return None;
        }
        let value = field.value.as_ref()?.kind.as_ref()?;
        let value = match value {
            graph_proto::value::Kind::Text(value) =>
                lifetime_proto::scalar_property::Value::Text(value.clone()),
            graph_proto::value::Kind::Integer(value) =>
                lifetime_proto::scalar_property::Value::Integer(*value),
            graph_proto::value::Kind::Boolean(value) =>
                lifetime_proto::scalar_property::Value::Boolean(*value),
            _ => return None,
        };
        Some(lifetime_proto::ScalarProperty { key: field.key.clone(), value: Some(value) })
    }).collect()
}

fn node(node: &graph_proto::NodeRecord, retain_owner: bool) -> lifetime_proto::GraphNode {
    lifetime_proto::GraphNode {
        id: node.id.clone(),
        kind: node.kind.clone(),
        label: node.label.clone(),
        properties: scalar_properties(node, retain_owner),
    }
}

fn scalar_edge_value(field: &graph_proto::Field) -> Option<String> {
    let value = field.value.as_ref()?.kind.as_ref()?;
    Some(match value {
        graph_proto::value::Kind::Text(value) => value.clone(),
        graph_proto::value::Kind::Integer(value) => value.to_string(),
        graph_proto::value::Kind::Boolean(value) => value.to_string(),
        _ => return None,
    })
}

fn input_text<'a>(node: &'a lifetime_proto::GraphNode, key: &str) -> Option<&'a str> {
    node.properties.iter().find_map(|property| {
        if property.key != key { return None; }
        match property.value.as_ref()? {
            lifetime_proto::scalar_property::Value::Text(value) => Some(value.as_str()),
            _ => None,
        }
    })
}

fn input_integer(node: &lifetime_proto::GraphNode, key: &str) -> Option<i64> {
    node.properties.iter().find_map(|property| {
        if property.key != key { return None; }
        match property.value.as_ref()? {
            lifetime_proto::scalar_property::Value::Integer(value) => Some(*value),
            lifetime_proto::scalar_property::Value::Text(value) => value.parse().ok(),
            _ => None,
        }
    })
}

fn input_bool(node: &lifetime_proto::GraphNode, key: &str) -> bool {
    node.properties.iter().find_map(|property| {
        if property.key != key { return None; }
        match property.value.as_ref()? {
            lifetime_proto::scalar_property::Value::Boolean(value) => Some(*value),
            lifetime_proto::scalar_property::Value::Text(value) => Some(value == "true"),
            _ => None,
        }
    }).unwrap_or(false)
}

fn resolve_decl(node: &str, refs: &HashMap<String, String>,
               children: &HashMap<String, Vec<String>>,
               seen: &mut HashSet<String>) -> Option<String> {
    if !seen.insert(node.to_owned()) { return None; }
    if let Some(declaration) = refs.get(node) { return Some(declaration.clone()); }
    children.get(node).into_iter().flatten()
        .find_map(|child| resolve_decl(child, refs, children, seen))
}

fn frame<'a>(input: &'a [u8], offset: &mut usize) -> Result<&'a [u8], String> {
    if input.len().saturating_sub(*offset) < FRAME_HEADER {
        return Err("truncated graph sidecar frame header".to_owned());
    }
    let length = u32::from_be_bytes(input[*offset..*offset + FRAME_HEADER].try_into().unwrap()) as usize;
    *offset += FRAME_HEADER;
    if length > input.len().saturating_sub(*offset) {
        return Err("truncated graph sidecar frame".to_owned());
    }
    let payload = &input[*offset..*offset + length];
    *offset += length;
    Ok(payload)
}

fn stream_frame<R: Read>(reader: &mut R) -> Result<Option<Vec<u8>>, String> {
    let mut header = [0u8; FRAME_HEADER];
    match reader.read_exact(&mut header) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(format!("cannot read graph sidecar frame header: {error}")),
    }
    let length = u32::from_be_bytes(header) as usize;
    let mut payload = vec![0u8; length];
    reader.read_exact(&mut payload)
        .map_err(|error| format!("truncated graph sidecar frame: {error}"))?;
    Ok(Some(payload))
}

fn owner(node: &graph_proto::NodeRecord) -> Option<String> {
    scalar(node, "owner_function_id").or_else(|| scalar(node, "function_id"))
}

fn function_kind(kind: &str) -> bool {
    matches!(kind, "function" | "method" | "constructor" | "FunctionDecl"
        | "CXXMethodDecl" | "CXXConstructorDecl" | "CXXDestructorDecl"
        | "FunctionDef" | "AsyncFunctionDef" | "FunctionDeclaration"
        | "ArrowFunction" | "MethodDeclaration" | "MethodDefinition"
        | "Constructor")
}

fn call_kind(kind: &str) -> bool {
    matches!(kind, "CallExpr" | "CXXMemberCallExpr" | "CXXOperatorCallExpr"
        | "call" | "Call" | "CallExpression" | "construct" | "NewExpression"
        | "allocation" | "release" | "realloc")
}

fn translation_call_kind(kind: &str) -> bool {
    matches!(kind, "CallExpr" | "CXXMemberCallExpr" | "CXXOperatorCallExpr"
        | "call" | "Call" | "CallExpression" | "construct" | "NewExpression")
}

fn translation_return_kind(kind: &str) -> bool {
    matches!(kind, "ReturnStmt" | "Return" | "ReturnStatement" | "return")
}

/// Convert the complete framed substrate to the existing native preparation
/// contract. This is deliberately one conversion inside Rust; Python never
/// creates FunctionInput/FunctionCall records for this path.
pub(crate) fn sidecar_to_request(
    input: &[u8],
) -> Result<lifetime_proto::PrepareRequest, String> {
    sidecar_to_request_with_selection(input, None, true)
}

/// Temporal solving has already grouped each node into its owning function,
/// so owner properties would be redundant in its per-node records.  Keep them
/// for the semantic emitter, which still reads them when publishing events.
pub(crate) fn sidecar_to_temporal_request(
    input: &[u8],
) -> Result<lifetime_proto::PrepareRequest, String> {
    sidecar_to_request_with_selection(input, None, false)
}

pub(crate) fn sidecar_to_request_selected(
    input: &[u8], selected_ids: &HashSet<String>,
) -> Result<lifetime_proto::PrepareRequest, String> {
    sidecar_to_request_with_selection(input, Some(selected_ids), true)
}

fn sidecar_to_request_with_selection(
    input: &[u8], selected_ids: Option<&HashSet<String>>, retain_owner: bool,
) -> Result<lifetime_proto::PrepareRequest, String> {
    let mut functions: BTreeMap<String, lifetime_proto::FunctionInput> = BTreeMap::new();
    let mut call_nodes: Vec<(String, String)> = Vec::new();
    let (owners, function_names, call_ids, edges_by_source, initializer_targets) = scan_lifetime_metadata(
        input, selected_ids, |item| {
            let item_id = item.id.clone();
            let syntax = scalar(&item, "syntax_kind").unwrap_or_else(|| item.kind.clone());
            let function = if function_kind(&syntax) {
                Some(item.id.clone())
            } else {
                owner(&item)
            };
            let Some(function) = function else { return };
            if selected_ids.is_some_and(|selected| !selected.contains(&function)) { return; }
            let entry = functions.entry(function.clone()).or_insert_with(||
                lifetime_proto::FunctionInput { id: function.clone(), ..Default::default() });
            if matches!(syntax.as_str(), "ParmVarDecl" | "parameter" | "arg") {
                entry.parameters.push(item.id.clone());
            }
            entry.nodes.push(node(&item, retain_owner));
            if call_kind(&syntax) {
                call_nodes.push((function, item_id));
            }
        },
    )?;
    let parents: HashMap<String, String> = edges_by_source.values().flatten()
        .filter(|item| item.kind == "AST_CHILD" && call_ids.contains(&item.target))
        .map(|item| (item.target.clone(), item.source.clone()))
        .collect();
    // Calls are part of the graph contract, not a Python-side projection.  The
    // frontend has already persisted the canonical lifecycle classification;
    // Rust only links arguments and assignment destinations using AST edges.
    let node_lookup: HashMap<&str, &lifetime_proto::GraphNode> = functions.values()
        .flat_map(|input| input.nodes.iter().map(|item| (item.id.as_str(), item)))
        .collect();
    let mut built_calls = Vec::with_capacity(call_nodes.len());
    for (function, item_id) in call_nodes {
        let Some(item) = node_lookup.get(item_id.as_str()).copied() else { continue };
        let mut call = lifetime_proto::FunctionCall {
            node: item.id.clone(),
            callee: input_text(&item, "primary_target_id")
                .and_then(|target| function_names.get(target).cloned())
                .or_else(|| input_text(&item, "callee").map(str::to_owned))
                .or_else(|| input_text(&item, "callee_name").map(str::to_owned))
                .or_else(|| input_text(&item, "release_method").map(str::to_owned))
                .unwrap_or_else(|| item.label.clone()),
            assigned: String::new(),
            receiver: input_text(&item, "receiver").unwrap_or_default().to_owned(),
            line: input_integer(&item, "start_line").unwrap_or_default(),
            has_line: input_integer(&item, "start_line").is_some(),
            is_alloc: input_bool(&item, "is_alloc")
                || input_text(&item, "syntax_kind") == Some("allocation"),
            is_release: input_bool(&item, "is_release")
                || input_text(&item, "syntax_kind") == Some("release"),
            is_realloc: input_bool(&item, "is_realloc")
                || input_text(&item, "syntax_kind") == Some("realloc"),
            is_source: false,
            is_aggregate_copy: input_bool(&item, "is_aggregate_copy"),
            arguments: Vec::new(),
            assigned_root: String::new(),
            assigned_selectors: Vec::new(),
            assigned_name: String::new(),
        };
        if let Some(assigned) = input_text(&item, "target_id")
            .or_else(|| input_text(&item, "value_id")) {
            call.assigned = assigned.to_owned();
        }
        let parent = parents.get(&item.id).and_then(|id| node_lookup.get(id.as_str()).copied());
        if let Some(parent) = parent {
            let parent_kind = input_text(parent, "syntax_kind").unwrap_or(parent.kind.as_str());
            if parent_kind == "BinaryOperator" && input_text(parent, "operator") == Some("=") {
                if let Some(left) = edges_by_source.get(&parent.id).into_iter().flatten().find(|edge| {
                        edge.kind == "AST_CHILD"
                            && edge.role == "LEFT_OPERAND"
                    }) {
                    call.assigned = left.target.clone();
                }
            }
        }
        if call.assigned.is_empty() {
            if let Some(initializer) = edges_by_source.get(&item.id).into_iter().flatten().find(|edge| {
                edge.kind == "VALUE_FLOWS_TO"
                        && initializer_targets.get(&item.id)
                            .is_some_and(|targets| targets.contains(&edge.target))
                }) {
                call.assigned = initializer.target.clone();
            }
        }
        let mut arguments = edges_by_source.get(&item.id).into_iter().flatten().filter_map(|edge| {
            if edge.kind != "AST_CHILD"
                || edge.role != "ARGUMENT" { return None; }
            Some(lifetime_proto::FunctionArgument {
                position: edge.position as u32,
                node: edge.target.clone(),
                root: String::new(),
                selectors: Vec::new(),
                expression: String::new(),
                root_name: String::new(),
            })
        }).collect::<Vec<_>>();
        arguments.sort_by_key(|argument| argument.position);
        call.arguments = arguments;
        built_calls.push((function, call));
    }
    drop(node_lookup);
    for (function, call) in built_calls {
        if let Some(entry) = functions.get_mut(&function) {
            entry.calls.push(call);
        }
    }
    // The scan already stores final protobuf edges, so consuming the index
    // transfers them directly into their owning function without cloning a
    // second graph-sized edge representation.
    for (_, edges) in edges_by_source {
        for item in edges {
            let source_owner = owners.get(&item.source);
            let target_owner = owners.get(&item.target);
            let Some(function) = source_owner.or(target_owner) else { continue };
            let Some(entry) = functions.get_mut(function) else { continue };
            entry.edges.push(item);
        }
    }
    // Build the first native interprocedural summary lattice.  These effects
    // are deliberately expressed in formal-parameter positions, which is the
    // same contract consumed by the lifetime preparer.  A small fixed-point is
    // enough here because the summary domain is finite (callee, position,
    // selectors); recursive SCCs converge by set union.
    let function_names_by_id = function_names;
    let names_by_input_id: HashMap<String, String> = functions.keys().filter_map(|id| {
        function_names_by_id.get(id).map(|name| (id.clone(), name.clone()))
    }).collect();
    let mut summary_effects: HashMap<String, Vec<(u32, Vec<String>)>> = HashMap::new();
    for (id, input) in &functions {
        let Some(name) = names_by_input_id.get(id) else { continue };
        // Most functions do not directly release/reallocate a parameter.  Do
        // not build three temporary AST indexes for those functions; their
        // summary is known to be empty until a callee summary can flow into
        // them in the fixed point below.
        if !input.calls.iter().any(|call| call.is_release || call.is_realloc) {
            summary_effects.insert(name.clone(), Vec::new());
            continue;
        }
        let refs: HashMap<String, String> = input.edges.iter()
            .filter(|edge| edge.kind == "REFERS_TO")
            .map(|edge| (edge.source.clone(), edge.target.clone()))
            .collect();
        let mut children: HashMap<String, Vec<String>> = HashMap::new();
        for edge in input.edges.iter().filter(|edge| edge.kind == "AST_CHILD") {
            children.entry(edge.source.clone()).or_default().push(edge.target.clone());
        }
        let parameter_positions: HashMap<String, u32> = input.parameters.iter()
            .enumerate().map(|(position, node)| (node.clone(), position as u32)).collect();
        let mut effects: Vec<(u32, Vec<String>)> = Vec::new();
        for call in &input.calls {
            if !call.is_release && !call.is_realloc { continue; }
            for argument in &call.arguments {
                let Some(declaration) = resolve_decl(&argument.node, &refs, &children,
                    &mut HashSet::new()) else { continue };
                let Some(position) = parameter_positions.get(&declaration) else { continue };
                if !effects.iter().any(|(existing, selectors)| *existing == *position && selectors.is_empty()) {
                    effects.push((*position, Vec::new()));
                }
            }
        }
        summary_effects.insert(name.clone(), effects);
    }
    for _ in 0..32 {
        let mut changed = false;
        for input in functions.values() {
            let Some(name) = names_by_input_id.get(&input.id) else { continue };
            // Avoid reconstructing per-function AST indexes unless at least
            // one call currently has a non-empty callee summary to propagate.
            if !input.calls.iter().any(|call| {
                summary_effects.get(&call.callee).is_some_and(|effects| !effects.is_empty())
            }) { continue; }
            let refs: HashMap<String, String> = input.edges.iter()
                .filter(|edge| edge.kind == "REFERS_TO")
                .map(|edge| (edge.source.clone(), edge.target.clone()))
                .collect();
            let mut children: HashMap<String, Vec<String>> = HashMap::new();
            for edge in input.edges.iter().filter(|edge| edge.kind == "AST_CHILD") {
                children.entry(edge.source.clone()).or_default().push(edge.target.clone());
            }
            let parameter_positions: HashMap<String, u32> = input.parameters.iter()
                .enumerate().map(|(position, node)| (node.clone(), position as u32)).collect();
            let mut additions = Vec::new();
            for call in &input.calls {
                let Some(callee_effects) = summary_effects.get(&call.callee) else { continue };
                for (callee_position, selectors) in callee_effects {
                    let Some(argument) = call.arguments.iter()
                        .find(|argument| argument.position == *callee_position) else { continue };
                    let Some(declaration) = resolve_decl(&argument.node, &refs, &children,
                        &mut HashSet::new()) else { continue };
                    let Some(position) = parameter_positions.get(&declaration) else { continue };
                    additions.push((*position, selectors.clone()));
                }
            }
            let target = summary_effects.get_mut(name).expect("summary entry exists");
            for addition in additions {
                if !target.iter().any(|existing| *existing == addition) {
                    target.push(addition);
                    changed = true;
                }
            }
        }
        if !changed { break; }
    }
    for input in functions.values_mut() {
        for call in &input.calls {
            let Some(effects) = summary_effects.get(&call.callee) else { continue };
            if effects.is_empty() { continue; }
            let summary_index = input.summaries.iter()
                .position(|summary| summary.callee == call.callee);
            let summary_index = summary_index.unwrap_or_else(|| {
                input.summaries.push(lifetime_proto::FunctionSummary {
                    callee: call.callee.clone(), alternatives: Vec::new(),
                });
                input.summaries.len() - 1
            });
            let summary = &mut input.summaries[summary_index];
            let mut alternative = lifetime_proto::FunctionSummaryAlternative { effects: Vec::new() };
            for (position, selectors) in effects {
                alternative.effects.push(lifetime_proto::FunctionSummaryEffect {
                    kind: lifetime_proto::operation::Kind::Free as i32,
                    position: *position,
                    selectors: selectors.clone(),
                    is_return: false,
                });
            }
            summary.alternatives.push(alternative);
        }
    }
    for entry in functions.values_mut() {
        let offsets: HashMap<String, i64> = entry.nodes.iter().filter_map(|node| {
            if node.id.is_empty() { return None; }
            input_integer(node, "start_offset")
                .map(|offset| (node.id.clone(), offset))
        }).collect();
        entry.parameters.sort_by_key(|id| offsets.get(id).copied().unwrap_or(i64::MAX));
        entry.parameters.dedup();
        entry.nodes.sort_by(|left, right| left.id.cmp(&right.id));
        entry.edges.sort_by(|left, right| {
            (&left.kind, &left.source, &left.target, left.position)
                .cmp(&(&right.kind, &right.source, &right.target, right.position))
        });
    }
    Ok(lifetime_proto::PrepareRequest { functions: functions.into_values().collect() })
}

#[derive(Clone)]
struct CompactNode {
    id: String,
    kind: String,
    label: String,
    properties: HashMap<String, String>,
}

fn compact_path_name(nodes: &HashMap<String, CompactNode>, root: &str) -> String {
    let root = root.strip_prefix("decl:").unwrap_or(root);
    nodes.get(root)
        .map(|node| if node.label.is_empty() { root.to_owned() } else { node.label.clone() })
        .unwrap_or_else(|| root.to_owned())
}

#[derive(Clone)]
struct CompactEdge {
    kind: String,
    source: String,
    target: String,
    role: String,
    reason: String,
    position: Option<u32>,
}

fn compact_node(record: graph_proto::NodeRecord) -> CompactNode {
    let properties = record.properties.into_iter().filter_map(|field| {
        if !matches!(field.key.as_str(),
            "syntax_kind" | "owner_function_id" | "function_id" | "start_line" |
            "start_offset" | "primary_target_id" | "callee" | "receiver" |
            "is_alloc" | "is_release" | "is_realloc" | "is_aggregate_copy" |
            "type" | "operator" | "storage_class" | "file") {
            return None;
        }
        let value = field.value?.kind?;
        let value = match value {
            graph_proto::value::Kind::Text(value) => value,
            graph_proto::value::Kind::Integer(value) => value.to_string(),
            graph_proto::value::Kind::Real(value) => value.to_string(),
            graph_proto::value::Kind::Boolean(value) => value.to_string(),
            _ => return None,
        };
        Some((field.key, value))
    }).collect();
    CompactNode { id: record.id, kind: record.kind, label: record.label, properties }
}

fn compact_edge(record: graph_proto::EdgeRecord) -> CompactEdge {
    let role = record.properties.iter().find_map(|field| {
        if field.key == "role" { scalar_edge_value(field) } else { None }
    }).unwrap_or_default();
    let position: Option<u32> = record.properties.iter().find_map(|field| {
        if field.key != "position" { return None; }
        scalar_edge_value(field)?.parse::<u32>().ok()
    });
    let reason = record.properties.iter().find_map(|field| {
        if field.key == "reason" { scalar_edge_value(field) } else { None }
    }).unwrap_or_default();
    CompactEdge { kind: record.kind, source: record.source, target: record.target,
                  role, reason, position }
}

fn input_edge(record: graph_proto::EdgeRecord) -> lifetime_proto::GraphEdge {
    let role = record.properties.iter().find_map(|field| {
        if field.key == "role" { scalar_edge_value(field) } else { None }
    }).unwrap_or_default();
    let position: Option<i64> = record.properties.iter().find_map(|field| {
        if field.key != "position" { return None; }
        scalar_edge_value(field)?.parse::<i64>().ok()
    });
    lifetime_proto::GraphEdge {
        kind: record.kind,
        source: record.source,
        target: record.target,
        role,
        position: position.unwrap_or_default() as i64,
        has_position: position.is_some(),
    }
}

fn scan_lifetime_metadata(
    input: &[u8],
    selected_ids: Option<&HashSet<String>>,
    mut on_node: impl FnMut(graph_proto::NodeRecord),
) -> Result<(
    HashMap<String, String>,
    HashMap<String, String>,
    HashSet<String>,
    HashMap<String, Vec<lifetime_proto::GraphEdge>>,
    HashMap<String, HashSet<String>>,
), String> {
    let mut offset = 0;
    let header = frame(input, &mut offset)?;
    let _: graph_proto::Document = graph_proto::Document::decode(header)
        .map_err(|error| format!("invalid graph sidecar header: {error}"))?;
    let mut reader = Cursor::new(&input[offset..]);
    scan_lifetime_metadata_reader(&mut reader, selected_ids, &mut on_node)
}

fn scan_lifetime_metadata_reader<R: Read>(
    reader: &mut R,
    selected_ids: Option<&HashSet<String>>,
    on_node: &mut impl FnMut(graph_proto::NodeRecord),
) -> Result<(
    HashMap<String, String>,
    HashMap<String, String>,
    HashSet<String>,
    HashMap<String, Vec<lifetime_proto::GraphEdge>>,
    HashMap<String, HashSet<String>>,
), String> {
    let mut owners = HashMap::new();
    let mut function_names = HashMap::new();
    let mut call_ids = HashSet::new();
    let mut edges_by_source: HashMap<String, Vec<lifetime_proto::GraphEdge>> = HashMap::new();
    let mut initializer_targets: HashMap<String, HashSet<String>> = HashMap::new();
    while let Some(payload) = stream_frame(reader)? {
        if payload.is_empty() { continue; }
        match payload[0] {
            b'N' => {
                let item = graph_proto::NodeRecord::decode(&payload[1..])
                    .map_err(|error| format!("invalid graph node frame: {error}"))?;
                if let Some(function) = owner(&item) {
                    owners.insert(item.id.clone(), function);
                }
                let syntax = scalar(&item, "syntax_kind").unwrap_or_else(|| item.kind.clone());
                if function_kind(&syntax) {
                    function_names.insert(item.id.clone(), item.label.clone());
                }
                if call_kind(&syntax) {
                    call_ids.insert(item.id.clone());
                }
                on_node(item);
            }
            b'E' => {
                let item = graph_proto::EdgeRecord::decode(&payload[1..])
                    .map_err(|error| format!("invalid graph edge frame: {error}"))?;
                if !retain_lifetime_edge(item.kind.as_str()) { continue; }
                if let Some(selected) = selected_ids {
                    let source_selected = owners.get(&item.source)
                        .is_some_and(|owner| selected.contains(owner));
                    let target_selected = owners.get(&item.target)
                        .is_some_and(|owner| selected.contains(owner));
                    if !source_selected && !target_selected { continue; }
                }
                let reason = item.properties.iter().find_map(|field| {
                    if field.key == "reason" { scalar_edge_value(field) } else { None }
                });
                if item.kind == "VALUE_FLOWS_TO" && reason.as_deref() == Some("initializer") {
                    initializer_targets.entry(item.source.clone()).or_default()
                        .insert(item.target.clone());
                }
                let source = item.source.clone();
                edges_by_source.entry(source).or_default().push(input_edge(item));
            }
            _ => return Err("unknown graph sidecar record prefix".to_owned()),
        }
    }
    Ok((owners, function_names, call_ids, edges_by_source, initializer_targets))
}

fn compact_property<'a>(node: &'a CompactNode, key: &str) -> Option<&'a str> {
    node.properties.get(key).map(String::as_str)
}

fn compact_kind(node: &CompactNode) -> &str {
    compact_property(node, "syntax_kind").unwrap_or(node.kind.as_str())
}

fn record_kind(node: &graph_proto::NodeRecord) -> &str {
    for field in &node.properties {
        if field.key != "syntax_kind" { continue; }
        if let Some(graph_proto::value::Kind::Text(value)) =
            field.value.as_ref().and_then(|value| value.kind.as_ref()) {
            return value.as_str();
        }
    }
    node.kind.as_str()
}

fn compact_peel(nodes: &HashMap<String, CompactNode>, children: &HashMap<String, Vec<String>>, mut id: String) -> String {
    for _ in 0..12 {
        if matches!(nodes.get(&id).map(|node| compact_kind(node)).unwrap_or(""),
            "ImplicitCastExpr" | "CStyleCastExpr" | "ParenExpr" | "CXXConstCastExpr" |
            "CXXStaticCastExpr" | "CXXReinterpretCastExpr" | "CXXFunctionalCastExpr") {
            if let Some(child) = children.get(&id).and_then(|items| items.first()) {
                id = child.clone();
                continue;
            }
        }
        break;
    }
    id
}

fn compact_path(nodes: &HashMap<String, CompactNode>, children: &HashMap<String, Vec<String>>,
               refers: &HashMap<String, String>, id: &str, depth: usize) -> Option<lifetime_proto::Path> {
    if depth > 40 { return None; }
    let id = compact_peel(nodes, children, id.to_owned());
    let node = nodes.get(&id)?;
    match compact_kind(node) {
        "DeclRefExpr" => compact_path(nodes, children, refers, refers.get(&id)?, depth + 1),
        "ParmVarDecl" | "VarDecl" => Some(lifetime_proto::Path { root: format!("decl:{id}"), selectors: Vec::new() }),
        "MemberExpr" => {
            let child = children.get(&id)?.first()?;
            let mut base = compact_path(nodes, children, refers, child, depth + 1)?;
            let label = node.label.as_str();
            let (index, width, arrow) = if let Some(index) = label.rfind("->") {
                (index, 2, true)
            } else if let Some(index) = label.rfind('.') {
                (index, 1, false)
            } else { return Some(base); };
            let field = label[index + width..].split(['[', '(', ' ']).next().unwrap_or("");
            if field.is_empty() { return Some(base); }
            let mut selectors = Vec::with_capacity(base.selectors.len() + 2);
            if arrow { selectors.push("*".to_owned()); }
            selectors.push(field.to_owned());
            selectors.extend(base.selectors);
            base.selectors = selectors;
            Some(base)
        }
        "ArraySubscriptExpr" => {
            let child = children.get(&id)?.first()?;
            let mut base = compact_path(nodes, children, refers, child, depth + 1)?;
            base.selectors.extend(["<?>".to_owned(), "*".to_owned()]);
            Some(base)
        }
        "UnaryOperator" => {
            let child = children.get(&id)?.first()?;
            let mut base = compact_path(nodes, children, refers, child, depth + 1)?;
            match compact_property(node, "operator").unwrap_or("") {
                "*" => base.selectors.push("*".to_owned()),
                "&" => base.selectors.push("&".to_owned()),
                _ => {}
            }
            Some(base)
        }
        _ => None,
    }
}

fn compact_owner(node: &CompactNode) -> Option<String> {
    compact_property(node, "owner_function_id")
        .or_else(|| compact_property(node, "function_id"))
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn scan_compact_records<FN, FE>(input: &[u8], on_node: FN, on_edge: FE) -> Result<(), String>
where
    FN: FnMut(graph_proto::NodeRecord),
    FE: FnMut(CompactEdge),
{
    let mut offset = 0;
    let header = frame(input, &mut offset)?;
    let _: graph_proto::Document = graph_proto::Document::decode(header)
        .map_err(|error| format!("invalid graph sidecar header: {error}"))?;
    scan_compact_records_at(input, offset, on_node, on_edge)
}

fn scan_compact_records_at<FN, FE>(input: &[u8], mut offset: usize,
                                   mut on_node: FN, mut on_edge: FE) -> Result<(), String>
where
    FN: FnMut(graph_proto::NodeRecord),
    FE: FnMut(CompactEdge),
{
    while offset < input.len() {
        let payload = frame(input, &mut offset)?;
        if payload.is_empty() { continue; }
        match payload[0] {
            b'N' => on_node(graph_proto::NodeRecord::decode(&payload[1..])
                .map_err(|error| format!("invalid graph node frame: {error}"))?),
            b'E' => {
                let record = graph_proto::EdgeRecord::decode(&payload[1..])
                    .map_err(|error| format!("invalid graph edge frame: {error}"))?;
                if matches!(record.kind.as_str(), "AST_CHILD" | "REFERS_TO" | "VALUE_FLOWS_TO") {
                    on_edge(compact_edge(record));
                }
            }
            _ => return Err("unknown graph sidecar record prefix".to_owned()),
        }
    }
    Ok(())
}

// The substrate writer emits one contiguous node section followed by one
// contiguous edge section.  Find that boundary without decoding protobufs so
// later edge-only passes do not repeatedly walk the million-node prefix.
fn compact_edge_offset(input: &[u8]) -> Result<usize, String> {
    let mut offset = 0;
    let header = frame(input, &mut offset)?;
    let _: graph_proto::Document = graph_proto::Document::decode(header)
        .map_err(|error| format!("invalid graph sidecar header: {error}"))?;
    while offset < input.len() {
        let record_offset = offset;
        let payload = frame(input, &mut offset)?;
        if payload.first() == Some(&b'E') { return Ok(record_offset); }
    }
    Ok(input.len())
}

pub(crate) fn sidecar_to_translation(input: &[u8]) -> Result<Vec<u8>, String> {
    // Keep only the records needed to seed relevance.  The previous version
    // retained every compact node before filtering edges, which defeated the
    // purpose of the compact ABI on million-node graphs.
    let mut seed_nodes = HashMap::new();
    scan_compact_records(input, |record| {
        if function_kind(record_kind(&record))
            || translation_call_kind(record_kind(&record))
            || translation_return_kind(record_kind(&record))
            || record_kind(&record) == "ParmVarDecl" {
            let node = compact_node(record);
            seed_nodes.insert(node.id.clone(), node);
        }
    }, |_| {})?;
    let edge_offset = compact_edge_offset(input)?;
    let call_ids: HashSet<String> = seed_nodes.values().filter(|node| translation_call_kind(compact_kind(node)))
        .map(|node| node.id.clone()).collect();
    let return_ids: HashSet<String> = seed_nodes.values().filter(|node| translation_return_kind(compact_kind(node)))
        .map(|node| node.id.clone()).collect();
    let mut relevant = call_ids.union(&return_ids).cloned().collect::<HashSet<_>>();
    for _ in 0..2 {
        scan_compact_records_at(input, edge_offset, |_| {}, |edge| {
            match edge.kind.as_str() {
                "AST_CHILD" => {
                    if call_ids.contains(&edge.source) || return_ids.contains(&edge.source)
                        || relevant.contains(&edge.source) || call_ids.contains(&edge.target) {
                        relevant.insert(edge.source);
                        relevant.insert(edge.target);
                    }
                }
                "REFERS_TO" if relevant.contains(&edge.source) => {
                    relevant.insert(edge.target);
                }
                "VALUE_FLOWS_TO" if call_ids.contains(&edge.source) => {
                    relevant.insert(edge.target);
                }
                _ => {}
            }
        })?;
    }
    let mut nodes = seed_nodes;
    let mut edges = Vec::new();
    // Re-read only the node section to add relevant intermediates; the edge
    // section is scanned independently from its known boundary below.
    scan_compact_records(input, |record| {
        if relevant.contains(&record.id) {
            let node = compact_node(record);
            nodes.insert(node.id.clone(), node);
        }
    }, |_| {})?;
    scan_compact_records_at(input, edge_offset, |_| {}, |edge| {
        let keep = match edge.kind.as_str() {
            "AST_CHILD" => relevant.contains(&edge.source) || relevant.contains(&edge.target),
            "REFERS_TO" => relevant.contains(&edge.source),
            "VALUE_FLOWS_TO" => call_ids.contains(&edge.source),
            _ => false,
        };
        if keep { edges.push(edge); }
    })?;
    let mut children: HashMap<String, Vec<String>> = HashMap::new();
    let mut parents = HashMap::new();
    let mut refers = HashMap::new();
    let mut assignment_left = HashMap::new();
    let mut initializer_targets = HashMap::new();
    let mut argument_edges: HashMap<String, Vec<usize>> = HashMap::new();
    for (edge_index, edge) in edges.iter().enumerate() {
        match edge.kind.as_str() {
            "AST_CHILD" => {
                children.entry(edge.source.clone()).or_default().push(edge.target.clone());
                parents.entry(edge.target.clone()).or_insert_with(|| edge.source.clone());
                if edge.role == "LEFT_OPERAND" {
                    assignment_left.insert(edge.source.clone(), edge.target.clone());
                } else if edge.role == "ARGUMENT" {
                    argument_edges.entry(edge.source.clone()).or_default().push(edge_index);
                }
            }
            "REFERS_TO" => { refers.insert(edge.source.clone(), edge.target.clone()); }
            "VALUE_FLOWS_TO" if edge.reason == "initializer" => {
                initializer_targets.insert(edge.source.clone(), edge.target.clone());
            }
            _ => {}
        }
    }
    let function_names: HashMap<String, String> = nodes.values().filter_map(|node| {
        if function_kind(compact_kind(node)) {
            Some((node.id.clone(), node.label.clone()))
        } else { None }
    }).collect();
    let mut functions: BTreeMap<String, lifetime_proto::TranslationFunction> = BTreeMap::new();
    let mut nodes_by_owner: HashMap<String, Vec<String>> = HashMap::new();
    for node in nodes.values() {
        // A declaration-only function owns its declaration node.  This mirrors
        // the language-neutral Python projection and is required for headers
        // whose bodies are intentionally absent from the substrate.
        let owner = compact_owner(node).or_else(|| {
            function_kind(compact_kind(node)).then_some(node.id.clone())
        });
        let Some(owner) = owner else { continue };
        nodes_by_owner.entry(owner.clone()).or_default().push(node.id.clone());
        let entry = functions.entry(owner.clone()).or_insert_with(||
            lifetime_proto::TranslationFunction { id: owner, ..Default::default() });
        if compact_kind(node) == "ParmVarDecl" { entry.parameters.push(node.id.clone()); }
        if matches!(compact_kind(node), "VarDecl" | "ParmVarDecl" | "variable" | "parameter") {
            entry.roots.push(lifetime_proto::RootMetadata {
                id: node.id.clone(),
                label: node.label.clone(),
                owner: compact_owner(node).unwrap_or_default(),
                r#type: compact_property(node, "type").unwrap_or("").to_owned(),
            });
        }
    }
    for entry in functions.values_mut() {
        if let Some(function) = nodes.get(&entry.id) {
            entry.name = function.label.clone();
            entry.file = compact_property(function, "file").unwrap_or("").to_owned();
            if let Some(line) = compact_property(function, "start_line")
                .and_then(|value| value.parse::<i64>().ok())
            {
                entry.start_line = line;
                entry.has_start_line = true;
            }
            entry.externally_visible = compact_property(function, "storage_class") != Some("static");
        }
    }
    for entry in functions.values_mut() {
        entry.parameters.sort_by_key(|id| nodes.get(id).and_then(|node| compact_property(node, "start_offset"))
            .and_then(|value| value.parse::<i64>().ok()).unwrap_or(i64::MAX));
        entry.parameter_names = entry.parameters.iter().map(|id| compact_path_name(&nodes, id)).collect();
    }
    for node in nodes.values() {
        if !translation_call_kind(compact_kind(node)) { continue; }
        let Some(owner) = compact_owner(node) else { continue };
        let Some(entry) = functions.get_mut(&owner) else { continue };
        let callee = compact_property(node, "primary_target_id")
            .and_then(|id| function_names.get(id).cloned())
            .or_else(|| compact_property(node, "callee").map(str::to_owned))
            .unwrap_or_else(|| node.label.clone());
        let mut call = lifetime_proto::FunctionCall {
            node: node.id.clone(), callee, assigned: String::new(),
            receiver: compact_property(node, "receiver").unwrap_or("").to_owned(),
            line: compact_property(node, "start_line").and_then(|value| value.parse::<i64>().ok()).unwrap_or_default(),
            has_line: compact_property(node, "start_line").is_some(),
            is_alloc: compact_property(node, "is_alloc") == Some("true"),
            is_release: compact_property(node, "is_release") == Some("true"),
            is_realloc: compact_property(node, "is_realloc") == Some("true"),
            is_source: false,
            is_aggregate_copy: compact_property(node, "is_aggregate_copy") == Some("true"),
            arguments: Vec::new(), assigned_root: String::new(), assigned_selectors: Vec::new(),
            assigned_name: String::new(),
        };
        if let Some(parent) = parents.get(&node.id).and_then(|id| nodes.get(id)) {
            if compact_kind(parent) == "BinaryOperator" && compact_property(parent, "operator") == Some("=") {
                call.assigned = assignment_left.get(&parent.id).cloned().unwrap_or_default();
            }
        }
        if call.assigned.is_empty() {
            call.assigned = initializer_targets.get(&node.id).cloned().unwrap_or_default();
        }
        if let Some(path) = compact_path(&nodes, &children, &refers, &call.assigned, 0) {
            call.assigned_name = compact_path_name(&nodes, &path.root);
            call.assigned_root = path.root; call.assigned_selectors = path.selectors;
        }
        let mut arguments = argument_edges.get(&node.id).into_iter().flatten()
            .filter_map(|edge_index| edges.get(*edge_index)).map(|edge| {
                let path = compact_path(&nodes, &children, &refers, &edge.target, 0);
                let root_name = path.as_ref().map(|path| compact_path_name(&nodes, &path.root)).unwrap_or_default();
                lifetime_proto::FunctionArgument {
                    position: edge.position.unwrap_or_default(), node: edge.target.clone(),
                    root: path.as_ref().map(|path| path.root.clone()).unwrap_or_default(),
                    selectors: path.map(|path| path.selectors).unwrap_or_default(),
                    expression: nodes.get(&edge.target).map(|node| node.label.clone()).unwrap_or_default(),
                    root_name,
                }
            }).collect::<Vec<_>>();
        arguments.sort_by_key(|argument| argument.position);
        call.arguments = arguments;
        entry.calls.push(call);
    }
    for entry in functions.values_mut() {
        for node_id in nodes_by_owner.get(&entry.id).into_iter().flatten() {
            if !translation_return_kind(compact_kind(nodes.get(node_id).unwrap())) { continue; }
            let line = nodes.get(node_id).and_then(|node| compact_property(node, "start_line"))
                .and_then(|value| value.parse::<i64>().ok());
            let Some(child) = children.get(node_id).and_then(|items| items.first()) else { continue };
            // Return expressions may be wrapped in an implicit cast or
            // parenthesized node.  Classify the peeled child exactly as the
            // Python projection does before deciding between call and value.
            let peeled = compact_peel(&nodes, &children, child.clone());
            if call_ids.contains(&peeled) {
                let callee = nodes.get(&peeled)
                    .and_then(|node| compact_property(node, "primary_target_id"))
                    .and_then(|id| function_names.get(id).cloned())
                    .or_else(|| nodes.get(&peeled).and_then(|node| compact_property(node, "callee")).map(str::to_owned))
                    .unwrap_or_else(|| nodes.get(&peeled).map(|node| node.label.clone()).unwrap_or_default());
                entry.returns.push(lifetime_proto::FunctionReturn { kind: "call".to_owned(), callee, root: String::new(), selectors: Vec::new(), line: line.unwrap_or_default(), has_line: line.is_some(), root_name: String::new() });
            } else if let Some(path) = compact_path(&nodes, &children, &refers, child, 0) {
                let root_name = compact_path_name(&nodes, &path.root);
                entry.returns.push(lifetime_proto::FunctionReturn { kind: "var".to_owned(), callee: String::new(), root: path.root, selectors: path.selectors, line: line.unwrap_or_default(), has_line: line.is_some(), root_name });
            }
        }
    }
    let result = lifetime_proto::TranslationResult { functions: functions.into_values().collect() };
    let mut output = Vec::new();
    result.encode(&mut output).map_err(|error| error.to_string())?;
    Ok(output)
}
