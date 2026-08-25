//! Native reader for the Pass-1 framed substrate.
//!
//! The Python process writes this file while it still owns the frontend build.
//! Pass 2 does not receive Python dictionaries: Rust reads the framed protobuf
//! records directly and constructs the function inputs in native memory.

use std::collections::{BTreeMap, HashMap};

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
    for item in &edges {
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
                if let Some(left) = edges.iter().find(|edge| {
                    edge.source == parent.id && edge.kind == "AST_CHILD"
                        && edge_scalar(edge, "role").as_deref() == Some("LEFT_OPERAND")
                }) {
                    call.assigned = left.target.clone();
                }
            }
        }
        if call.assigned.is_empty() {
            if let Some(initializer) = edges.iter().find(|edge| {
                edge.kind == "VALUE_FLOWS_TO" && edge.source == item.id
                    && edge_scalar(edge, "reason").as_deref() == Some("initializer")
            }) {
                call.assigned = initializer.target.clone();
            }
        }
        let mut arguments = edges.iter().filter_map(|edge| {
            if edge.kind != "AST_CHILD" || edge.source != item.id
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
