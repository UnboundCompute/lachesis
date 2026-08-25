//! Native reader for the Pass-1 framed substrate.
//!
//! The Python process writes this file while it still owns the frontend build.
//! Pass 2 does not receive Python dictionaries: Rust reads the framed protobuf
//! records directly and constructs the function inputs in native memory.

use std::collections::{BTreeMap, HashMap, HashSet};

use prost::Message;

use crate::{graph_proto, lifetime_proto};

const FRAME_HEADER: usize = 4;

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

fn scalar_properties(node: &graph_proto::NodeRecord) -> Vec<lifetime_proto::ScalarProperty> {
    node.properties.iter().filter_map(|field| {
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

fn node(node: &graph_proto::NodeRecord) -> lifetime_proto::GraphNode {
    lifetime_proto::GraphNode {
        id: node.id.clone(),
        kind: node.kind.clone(),
        label: node.label.clone(),
        properties: scalar_properties(node),
    }
}

fn edge(edge: &graph_proto::EdgeRecord) -> lifetime_proto::GraphEdge {
    let role = edge.properties.iter().find_map(|field| {
        if field.key == "role" { scalar_edge_value(field) } else { None }
    }).unwrap_or_default();
    let position = edge.properties.iter().find_map(|field| {
        if field.key != "position" { return None; }
        scalar_edge_value(field)?.parse().ok()
    });
    lifetime_proto::GraphEdge {
        kind: edge.kind.clone(),
        source: edge.source.clone(),
        target: edge.target.clone(),
        role,
        position: position.unwrap_or_default(),
        has_position: position.is_some(),
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

fn edge_scalar(edge: &graph_proto::EdgeRecord, key: &str) -> Option<String> {
    edge.properties.iter().find_map(|field| {
        if field.key == key { scalar_edge_value(field) } else { None }
    })
}

fn input_scalar(node: &lifetime_proto::GraphNode, key: &str) -> Option<String> {
    node.properties.iter().find_map(|property| {
        if property.key != key { return None; }
        property.value.as_ref().map(|value| match value {
            lifetime_proto::scalar_property::Value::Text(value) => value.clone(),
            lifetime_proto::scalar_property::Value::Integer(value) => value.to_string(),
            lifetime_proto::scalar_property::Value::Boolean(value) => value.to_string(),
        })
    })
}

fn resolve_decl(node: &str, refs: &HashMap<String, String>,
               children: &HashMap<String, Vec<String>>,
               seen: &mut std::collections::HashSet<String>) -> Option<String> {
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

fn owner(node: &graph_proto::NodeRecord) -> Option<String> {
    scalar(node, "owner_function_id").or_else(|| scalar(node, "function_id"))
}

/// Convert the complete framed substrate to the existing native preparation
/// contract. This is deliberately one conversion inside Rust; Python never
/// creates FunctionInput/FunctionCall records for this path.
pub(crate) fn sidecar_to_request(
    input: &[u8],
) -> Result<lifetime_proto::PrepareRequest, String> {
    let mut offset = 0;
    let header = frame(input, &mut offset)?;
    let _: graph_proto::Document = graph_proto::Document::decode(header)
        .map_err(|error| format!("invalid graph sidecar header: {error}"))?;

    let mut nodes = Vec::new();
    let mut edges = Vec::new();
    while offset < input.len() {
        let payload = frame(input, &mut offset)?;
        if payload.is_empty() { continue; }
        match payload[0] {
            b'N' => nodes.push(graph_proto::NodeRecord::decode(&payload[1..])
                .map_err(|error| format!("invalid graph node frame: {error}"))?),
            b'E' => edges.push(graph_proto::EdgeRecord::decode(&payload[1..])
                .map_err(|error| format!("invalid graph edge frame: {error}"))?),
            _ => return Err("unknown graph sidecar record prefix".to_owned()),
        }
    }

    let owners: HashMap<String, String> = nodes.iter().filter_map(|item| {
        owner(item).map(|function| (item.id.clone(), function))
    }).collect();
    let function_names: HashMap<String, String> = nodes.iter().filter_map(|item| {
        let syntax = scalar(item, "syntax_kind").unwrap_or_else(|| item.kind.clone());
        if matches!(syntax.as_str(), "function" | "method" | "constructor"
            | "FunctionDecl" | "CXXMethodDecl" | "CXXConstructorDecl" | "CXXDestructorDecl") {
            Some((item.id.clone(), item.label.clone()))
        } else {
            None
        }
    }).collect();
    let node_by_id: HashMap<String, &graph_proto::NodeRecord> = nodes.iter()
        .map(|item| (item.id.clone(), item)).collect();
    let mut parents = HashMap::new();
    let mut edges_by_source: HashMap<String, Vec<usize>> = HashMap::new();
    for (edge_index, item) in edges.iter().enumerate() {
        edges_by_source.entry(item.source.clone()).or_default().push(edge_index);
        if item.kind == "AST_CHILD" {
            parents.entry(item.target.clone()).or_insert_with(|| item.source.clone());
        }
    }
    let mut functions: BTreeMap<String, lifetime_proto::FunctionInput> = BTreeMap::new();
    for item in &nodes {
        let Some(function) = owner(item) else { continue };
        let entry = functions.entry(function.clone()).or_insert_with(||
            lifetime_proto::FunctionInput { id: function, ..Default::default() });
        let syntax = scalar(item, "syntax_kind").unwrap_or_else(|| item.kind.clone());
        if syntax == "ParmVarDecl" { entry.parameters.push(item.id.clone()); }
        entry.nodes.push(node(item));
    }
    for item in &edges {
        let source_owner = owners.get(&item.source);
        let target_owner = owners.get(&item.target);
        let Some(function) = source_owner.or(target_owner) else { continue };
        let Some(entry) = functions.get_mut(function) else { continue };
        entry.edges.push(edge(item));
    }
    // Calls are part of the graph contract, not a Python-side projection.  The
    // frontend has already persisted the canonical lifecycle classification;
    // Rust only links arguments and assignment destinations using AST edges.
    for item in &nodes {
        let syntax = scalar(item, "syntax_kind").unwrap_or_else(|| item.kind.clone());
        if syntax != "CallExpr" && syntax != "CXXMemberCallExpr" && syntax != "CXXOperatorCallExpr" {
            continue;
        }
        let Some(function) = owner(item) else { continue };
        let Some(entry) = functions.get_mut(&function) else { continue };
        let mut call = lifetime_proto::FunctionCall {
            node: item.id.clone(),
            callee: scalar(item, "primary_target_id")
                .and_then(|target| function_names.get(&target).cloned())
                .or_else(|| scalar(item, "callee"))
                .unwrap_or_else(|| item.label.clone()),
            assigned: String::new(),
            receiver: scalar(item, "receiver").unwrap_or_default(),
            line: scalar(item, "start_line").and_then(|value| value.parse().ok()).unwrap_or_default(),
            has_line: scalar(item, "start_line").is_some(),
            is_alloc: scalar(item, "is_alloc").as_deref() == Some("true"),
            is_release: scalar(item, "is_release").as_deref() == Some("true"),
            is_realloc: scalar(item, "is_realloc").as_deref() == Some("true"),
            is_source: false,
            is_aggregate_copy: scalar(item, "is_aggregate_copy").as_deref() == Some("true"),
            arguments: Vec::new(),
            assigned_root: String::new(),
            assigned_selectors: Vec::new(),
        };
        let parent = parents.get(&item.id).and_then(|id| node_by_id.get(id));
        if let Some(parent) = parent {
            let parent_kind = scalar(parent, "syntax_kind").unwrap_or_else(|| parent.kind.clone());
            if parent_kind == "BinaryOperator" && scalar(parent, "operator").as_deref() == Some("=") {
                if let Some(left) = edges_by_source.get(&parent.id).into_iter().flatten()
                    .map(|index| &edges[*index]).find(|edge| {
                        edge.kind == "AST_CHILD"
                            && edge_scalar(edge, "role").as_deref() == Some("LEFT_OPERAND")
                    }) {
                    call.assigned = left.target.clone();
                }
            }
        }
        if call.assigned.is_empty() {
            if let Some(initializer) = edges_by_source.get(&item.id).into_iter().flatten()
                .map(|index| &edges[*index]).find(|edge| {
                    edge.kind == "VALUE_FLOWS_TO"
                        && edge_scalar(edge, "reason").as_deref() == Some("initializer")
                }) {
                call.assigned = initializer.target.clone();
            }
        }
        let mut arguments = edges_by_source.get(&item.id).into_iter().flatten().filter_map(|index| {
            let edge = &edges[*index];
            if edge.kind != "AST_CHILD"
                || edge_scalar(edge, "role").as_deref() != Some("ARGUMENT") { return None; }
            Some(lifetime_proto::FunctionArgument {
                position: edge_scalar(edge, "position").and_then(|value| value.parse().ok()).unwrap_or_default(),
                node: edge.target.clone(),
                root: String::new(),
                selectors: Vec::new(),
                expression: String::new(),
            })
        }).collect::<Vec<_>>();
        arguments.sort_by_key(|argument| argument.position);
        call.arguments = arguments;
        entry.calls.push(call);
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
                    &mut std::collections::HashSet::new()) else { continue };
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
                        &mut std::collections::HashSet::new()) else { continue };
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
            input_scalar(node, "start_offset").and_then(|value| value.parse().ok())
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

#[derive(Clone)]
struct CompactEdge {
    kind: String,
    source: String,
    target: String,
    role: String,
    position: Option<u32>,
}

fn compact_node(record: graph_proto::NodeRecord) -> CompactNode {
    let properties = record.properties.into_iter().filter_map(|field| {
        if !matches!(field.key.as_str(),
            "syntax_kind" | "owner_function_id" | "function_id" | "start_line" |
            "start_offset" | "primary_target_id" | "callee" | "receiver" |
            "is_alloc" | "is_release" | "is_realloc" | "is_aggregate_copy" |
            "type" | "operator" | "storage_class") {
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
    let position = record.properties.iter().find_map(|field| {
        if field.key != "position" { return None; }
        scalar_edge_value(field)?.parse().ok()
    });
    CompactEdge { kind: record.kind, source: record.source, target: record.target,
                  role, position }
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
        if matches!(record_kind(&record),
            "CallExpr" | "CXXMemberCallExpr" | "CXXOperatorCallExpr" |
            "ReturnStmt" | "function" | "method" | "constructor" |
            "FunctionDecl" | "CXXMethodDecl" | "CXXConstructorDecl" |
            "CXXDestructorDecl" | "ParmVarDecl") {
            let node = compact_node(record);
            seed_nodes.insert(node.id.clone(), node);
        }
    }, |_| {})?;
    let edge_offset = compact_edge_offset(input)?;
    let call_ids: HashSet<String> = seed_nodes.values().filter(|node| matches!(compact_kind(node),
        "CallExpr" | "CXXMemberCallExpr" | "CXXOperatorCallExpr")).map(|node| node.id.clone()).collect();
    let return_ids: HashSet<String> = seed_nodes.values().filter(|node| compact_kind(node) == "ReturnStmt")
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
    let mut initializers = HashMap::new();
    for edge in &edges {
        match edge.kind.as_str() {
            "AST_CHILD" => {
                children.entry(edge.source.clone()).or_default().push(edge.target.clone());
                parents.entry(edge.target.clone()).or_insert_with(|| edge.source.clone());
            }
            "REFERS_TO" => { refers.insert(edge.source.clone(), edge.target.clone()); }
            "VALUE_FLOWS_TO" => { initializers.insert(edge.target.clone(), edge.source.clone()); }
            _ => {}
        }
    }
    let function_names: HashMap<String, String> = nodes.values().filter_map(|node| {
        if matches!(compact_kind(node), "function" | "method" | "constructor" | "FunctionDecl" |
            "CXXMethodDecl" | "CXXConstructorDecl" | "CXXDestructorDecl") {
            Some((node.id.clone(), node.label.clone()))
        } else { None }
    }).collect();
    let mut functions: BTreeMap<String, lifetime_proto::TranslationFunction> = BTreeMap::new();
    for node in nodes.values() {
        let Some(owner) = compact_owner(node) else { continue };
        let entry = functions.entry(owner.clone()).or_insert_with(||
            lifetime_proto::TranslationFunction { id: owner, ..Default::default() });
        if compact_kind(node) == "ParmVarDecl" { entry.parameters.push(node.id.clone()); }
    }
    for entry in functions.values_mut() {
        entry.parameters.sort_by_key(|id| nodes.get(id).and_then(|node| compact_property(node, "start_offset"))
            .and_then(|value| value.parse::<i64>().ok()).unwrap_or(i64::MAX));
    }
    for node in nodes.values() {
        if !matches!(compact_kind(node), "CallExpr" | "CXXMemberCallExpr" | "CXXOperatorCallExpr") { continue; }
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
        };
        if let Some(parent) = parents.get(&node.id).and_then(|id| nodes.get(id)) {
            if compact_kind(parent) == "BinaryOperator" && compact_property(parent, "operator") == Some("=") {
                if let Some(left) = edges.iter().find(|edge| edge.source == parent.id && edge.kind == "AST_CHILD" && edge.role == "LEFT_OPERAND") {
                    call.assigned = left.target.clone();
                }
            }
        }
        if call.assigned.is_empty() {
            if let Some(initializer) = edges.iter().find(|edge| edge.kind == "VALUE_FLOWS_TO" && edge.source == node.id && edge.role == "initializer") {
                call.assigned = initializer.target.clone();
            }
        }
        if let Some(path) = compact_path(&nodes, &children, &refers, &call.assigned, 0) {
            call.assigned_root = path.root; call.assigned_selectors = path.selectors;
        }
        let mut arguments = edges.iter().filter(|edge| edge.kind == "AST_CHILD" && edge.source == node.id && edge.role == "ARGUMENT")
            .map(|edge| lifetime_proto::FunctionArgument {
                position: edge.position.unwrap_or_default(), node: edge.target.clone(),
                root: compact_path(&nodes, &children, &refers, &edge.target, 0).map(|path| path.root).unwrap_or_default(),
                selectors: compact_path(&nodes, &children, &refers, &edge.target, 0).map(|path| path.selectors).unwrap_or_default(),
                expression: nodes.get(&edge.target).map(|node| node.label.clone()).unwrap_or_default(),
            }).collect::<Vec<_>>();
        arguments.sort_by_key(|argument| argument.position);
        call.arguments = arguments;
        entry.calls.push(call);
    }
    for entry in functions.values_mut() {
        let function_nodes: HashSet<String> = nodes.values().filter_map(|node| {
            (compact_owner(node).as_deref() == Some(entry.id.as_str())).then_some(node.id.clone())
        }).collect();
        for node_id in function_nodes {
            if compact_kind(nodes.get(&node_id).unwrap()) != "ReturnStmt" { continue; }
            let line = nodes.get(&node_id).and_then(|node| compact_property(node, "start_line"))
                .and_then(|value| value.parse::<i64>().ok());
            let Some(child) = children.get(&node_id).and_then(|items| items.first()) else { continue };
            if call_ids.contains(child) {
                let callee = nodes.get(child)
                    .and_then(|node| compact_property(node, "primary_target_id"))
                    .and_then(|id| function_names.get(id).cloned())
                    .or_else(|| nodes.get(child).and_then(|node| compact_property(node, "callee")).map(str::to_owned))
                    .unwrap_or_else(|| nodes.get(child).map(|node| node.label.clone()).unwrap_or_default());
                entry.returns.push(lifetime_proto::FunctionReturn { kind: "call".to_owned(), callee, root: String::new(), selectors: Vec::new(), line: line.unwrap_or_default(), has_line: line.is_some() });
            } else if let Some(path) = compact_path(&nodes, &children, &refers, child, 0) {
                entry.returns.push(lifetime_proto::FunctionReturn { kind: "var".to_owned(), callee: String::new(), root: path.root, selectors: path.selectors, line: line.unwrap_or_default(), has_line: line.is_some() });
            }
        }
    }
    let result = lifetime_proto::TranslationResult { functions: functions.into_values().collect() };
    let mut output = Vec::new();
    result.encode(&mut output).map_err(|error| error.to_string())?;
    Ok(output)
}
