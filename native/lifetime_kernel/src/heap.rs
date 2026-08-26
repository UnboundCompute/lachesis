//! Native allocation identity and points-to propagation.
//!
//! Object/value handles are interned graph symbols.  The worklist is monotone:
//! an identity edge is revisited only when its source points-to set grows.

use hashbrown::HashSet;
use rustc_hash::{FxHashMap, FxHashSet};
use crate::graph_proto;
use crate::pass2::{self, Delta, Graph};

const IDENTITY_REASONS: [&str; 15] = [
    "allocation", "initializer", "assignment", "write", "read", "read-value",
    "argument-value", "context-argument", "context-call-result", "return",
    "call-result", "branch-reaching-definition", "phi-input", "call-argument",
    "value-preserving-expression",
];

fn text<'a>(graph: &'a Graph, node: &'a pass2::Node, key: &str) -> Option<&'a str> { graph.node_property_text(node, key) }
fn edge_text<'a>(graph: &'a Graph, edge: &'a pass2::Edge, key: &str) -> Option<&'a str> { graph.edge_property_text(edge, key) }
fn list_field(key: &str, values: &[String]) -> graph_proto::Field { graph_proto::Field { key: key.to_owned(), value: Some(graph_proto::Value { kind: Some(graph_proto::value::Kind::List(graph_proto::ListValue { values: values.iter().map(|value| graph_proto::Value { kind: Some(graph_proto::value::Kind::Text(value.clone())) }).collect() })) }) } }
fn fact(evidence: &[String], confidence: &str) -> Vec<graph_proto::Field> { vec![pass2::text_field("fact_origin", "core-inference"), pass2::text_field("confidence", confidence), list_field("evidence_ids", evidence)] }
fn node(id: String, kind: &str, label: String, properties: Vec<graph_proto::Field>) -> graph_proto::NodeRecord { graph_proto::NodeRecord { id, kind: kind.to_owned(), label, properties, tier: String::new() } }
fn edge(kind: &str, source: &str, target: &str, properties: Vec<graph_proto::Field>) -> graph_proto::EdgeRecord { graph_proto::EdgeRecord { kind: kind.to_owned(), source: source.to_owned(), target: target.to_owned(), properties, source_tier: String::new(), relationship_class: String::new() } }
fn add_points(points: &mut FxHashMap<u32, FxHashSet<u32>>, value: u32, objects: &FxHashSet<u32>) -> bool {
    let entry = points.entry(value).or_default(); let before = entry.len(); entry.extend(objects); entry.len() != before
}

pub(crate) fn enrich(graph: &mut Graph) -> Delta {
    let mut points: FxHashMap<u32, FxHashSet<u32>> = FxHashMap::default();
    let mut object_owner: FxHashMap<u32, Option<u32>> = FxHashMap::default();
    let mut object_properties: FxHashMap<u32, Vec<graph_proto::Field>> = FxHashMap::default();
    let mut parameter_objects: FxHashMap<u32, u32> = FxHashMap::default();
    let mut identity_targets: FxHashMap<u32, Vec<u32>> = FxHashMap::default();
    let mut context_return_sources: FxHashMap<u32, Vec<u32>> = FxHashMap::default();
    let mut parameter_defs: FxHashMap<u32, Vec<u32>> = FxHashMap::default();
    let mut nodes = Vec::new(); let mut edges = Vec::new();
    let mut emitted_nodes = HashSet::new(); let mut emitted_edges = HashSet::new();

    let mut add_node = |id: String, kind: &str, label: String, properties: Vec<graph_proto::Field>| {
        if emitted_nodes.insert(id.clone()) { nodes.push(node(id, kind, label, properties)); }
    };
    let mut add_edge = |kind: &str, source: String, target: String, properties: Vec<graph_proto::Field>| {
        if source == target || source.is_empty() || target.is_empty() { return; }
        if emitted_edges.insert((kind.to_owned(), source.clone(), target.clone())) { edges.push(edge(kind, &source, &target, properties)); }
    };

    for item in &graph.edges {
        match graph.edge_kind(item) {
            "DEFINES" => {
                if graph.node_by_id.get(&item.source).is_some_and(|index| graph.kind(graph.nodes[*index].kind) == "parameter") { parameter_defs.entry(item.source).or_default().push(item.target); }
            }
            "ALIASES" | "ALIASES_VALUE" | "READS_FROM" | "PHI_INPUT" => { identity_targets.entry(item.source).or_default().push(item.target); }
            "VALUE_FLOWS_TO" => if edge_text(graph, item, "reason") == Some("context-return") { context_return_sources.entry(item.target).or_default().push(item.source); } else if IDENTITY_REASONS.contains(&edge_text(graph, item, "reason").unwrap_or("")) { identity_targets.entry(item.source).or_default().push(item.target); }
            _ => {}
        }
    }
    for definition in graph.nodes.iter().filter(|node| graph.kind(node.kind) == "definition") {
        if let Some(target) = text(graph, definition, "target_id").and_then(|id| graph.symbol(id)) { identity_targets.entry(definition.id).or_default().push(target); }
    }
    let allocation_indices: Vec<usize> = graph.nodes.iter().enumerate().filter(|(_, node)| graph.kind(node.kind) == "allocation").map(|(index, _)| index).collect();
    for allocation_index in allocation_indices {
        let allocation = &graph.nodes[allocation_index];
        let allocation_text = graph.id(allocation.id).to_owned();
        let object_text = pass2::stable_id("core", "heap-identity", "heap-object", &[&allocation_text]);
        let object = graph.symbols.intern(object_text.clone());
        let owner = text(graph, allocation, "owner_function_id").and_then(|id| graph.symbol(id));
        object_owner.insert(object, owner);
        let evidence = vec![allocation_text.clone()]; let mut properties = fact(&evidence, "exact"); properties.extend([pass2::text_field("allocation_id", &allocation_text), pass2::text_field("allocation_kind", text(graph, allocation, "allocation_kind").unwrap_or("allocation"))]);
        if let Some(value) = text(graph, allocation, "owner_function_id") { properties.push(pass2::text_field("owner_function_id", value)); }
        if let Some(value) = text(graph, allocation, "allocated_type") { properties.push(pass2::text_field("allocated_type", value)); }
        object_properties.insert(object, properties.clone());
        add_node(object_text.clone(), "heap-object", format!("object:{}", allocation.label), properties);
        points.entry(allocation.id).or_default().insert(object);
        add_edge("POINTS_TO", allocation_text, object_text, fact(&evidence, "high"));
    }
    let parameter_indices: Vec<usize> = graph.nodes.iter().enumerate().filter(|(_, node)| graph.kind(node.kind) == "parameter").map(|(index, _)| index).collect();
    for parameter_index in parameter_indices {
        let parameter = &graph.nodes[parameter_index];
        if text(graph, parameter, "value_category") == Some("primitive") || parameter_defs.get(&parameter.id).is_none_or(Vec::is_empty) { continue; }
        let parameter_text = graph.id(parameter.id).to_owned();
        let object_text = pass2::stable_id("core", "heap-identity", "heap-object", &["parameter", &parameter_text]);
        let object = graph.symbols.intern(object_text.clone()); parameter_objects.insert(parameter.id, object);
        object_owner.insert(object, text(graph, parameter, "owner_function_id").and_then(|id| graph.symbol(id)));
        let mut evidence = vec![parameter_text.clone()]; evidence.extend(parameter_defs[&parameter.id].iter().map(|id| graph.id(*id).to_owned()));
        let mut properties = fact(&evidence, "conservative"); properties.extend([pass2::text_field("allocation_kind", "parameter"), pass2::text_field("parameter_id", &parameter_text)]); if let Some(value) = text(graph, parameter, "owner_function_id") { properties.push(pass2::text_field("owner_function_id", value)); } if let Some(value) = text(graph, parameter, "type") { properties.push(pass2::text_field("allocated_type", value)); }
        object_properties.insert(object, properties.clone()); add_node(object_text.clone(), "heap-object", format!("parameter-object:{}", parameter.label), properties);
        points.entry(parameter.id).or_default().insert(object); add_edge("POINTS_TO", parameter_text, object_text.clone(), fact(&evidence, "conservative"));
        for definition in &parameter_defs[&parameter.id] { points.entry(*definition).or_default().insert(object); add_edge("POINTS_TO", graph.id(*definition).to_owned(), object_text.clone(), fact(&evidence, "conservative")); }
    }

    // Worklist propagation over all value-preserving identity edges.
    let mut queue: std::collections::VecDeque<u32> = points.keys().copied().collect(); let mut queued: FxHashSet<u32> = queue.iter().copied().collect();
    while let Some(source) = queue.pop_front() {
        queued.remove(&source); let source_objects = points.get(&source).cloned().unwrap_or_default();
        for target in identity_targets.get(&source).into_iter().flatten() {
            let target_set = points.entry(*target).or_default(); let before = target_set.len(); target_set.extend(&source_objects);
            if target_set.len() != before && queued.insert(*target) { queue.push_back(*target); }
        }
    }

    // Keep context-specific parameter objects separate, then instantiate
    // callee-local allocation templates at context returns.
    let mut substitutions: FxHashMap<String, FxHashMap<u32, FxHashSet<u32>>> = FxHashMap::default();
    for binding in graph.nodes.iter().filter(|node| graph.kind(node.kind) == "context-parameter") {
        let Some(context) = text(graph, binding, "context_id") else { continue }; let Some(argument) = text(graph, binding, "argument_id").and_then(|id| graph.symbol(id)) else { continue }; let Some(parameter) = text(graph, binding, "parameter_id").and_then(|id| graph.symbol(id)) else { continue };
        let Some(abstract_object) = parameter_objects.get(&parameter).copied() else { continue }; let caller_objects = points.get(&argument).cloned().unwrap_or_default(); add_points(&mut points, binding.id, &caller_objects); substitutions.entry(context.to_owned()).or_default().insert(abstract_object, caller_objects);
    }
    let returned_indices: Vec<usize> = graph.nodes.iter().enumerate().filter(|(_, node)| graph.kind(node.kind) == "context-return").map(|(index, _)| index).collect();
    for returned_index in returned_indices {
        let returned = &graph.nodes[returned_index];
        let returned_id = returned.id;
        let Some(context) = text(graph, returned, "context_id").map(str::to_owned) else { continue }; let callee = text(graph, returned, "callee_function_id").and_then(|id| graph.symbol(id)); let mut returned_objects = FxHashSet::default();
        for source in context_return_sources.get(&returned_id).into_iter().flatten() { for object in points.get(source).into_iter().flatten() {
            if let Some(replacement) = substitutions.get(&context).and_then(|map| map.get(object)) { returned_objects.extend(replacement); continue; }
            if callee.is_some() && object_owner.get(object).copied().flatten() == callee {
                let object_text = pass2::stable_id("core", "heap-identity", "heap-object", &["context", &context, graph.id(*object)]); let instance = graph.symbols.intern(object_text.clone());
                let mut properties = fact(&[graph.id(returned_id).to_owned(), context.clone(), graph.id(*object).to_owned()], "exact"); properties.push(pass2::text_field("context_id", &context)); properties.push(pass2::text_field("allocation_template_id", graph.id(*object))); object_owner.insert(instance, Some(callee.unwrap())); object_properties.insert(instance, properties.clone()); add_node(object_text.clone(), "heap-object", format!("context-object:{}", graph.id(*object)), properties); add_edge("CONTEXT_ALLOCATES", context.clone(), object_text, fact(&[graph.id(returned_id).to_owned(), context.clone(), graph.id(*object).to_owned()], "exact")); returned_objects.insert(instance);
            } else { returned_objects.insert(*object); }
        }}
        add_points(&mut points, returned.id, &returned_objects);
    }
    let mut queue: std::collections::VecDeque<u32> = points.keys().copied().collect(); let mut queued: FxHashSet<u32> = queue.iter().copied().collect();
    while let Some(source) = queue.pop_front() { queued.remove(&source); let source_objects = points.get(&source).cloned().unwrap_or_default(); for target in identity_targets.get(&source).into_iter().flatten() { let set = points.entry(*target).or_default(); let before = set.len(); set.extend(&source_objects); if set.len() != before && queued.insert(*target) { queue.push_back(*target); } } }
    let _ = object_properties;
    Delta { nodes, edges }
}
