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
pub(crate) fn sidecar_to_request(input: &[u8]) -> Result<Vec<u8>, String> {
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
    for entry in functions.values_mut() {
        entry.parameters.sort();
        entry.parameters.dedup();
        entry.nodes.sort_by(|left, right| left.id.cmp(&right.id));
        entry.edges.sort_by(|left, right| {
            (&left.kind, &left.source, &left.target, left.position)
                .cmp(&(&right.kind, &right.source, &right.target, right.position))
        });
    }
    let request = lifetime_proto::PrepareRequest { functions: functions.into_values().collect() };
    let mut output = Vec::new();
    request.encode(&mut output).map_err(|error| error.to_string())?;
    Ok(output)
}
