//! Native allocation identity and points-to propagation.
//!
//! Object/value handles are interned graph symbols.  The worklist is monotone:
//! an identity edge is revisited only when its source points-to set grows.

use hashbrown::HashSet;
use rustc_hash::{FxHashMap, FxHashSet};
use roaring::RoaringBitmap;
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
type PointSet = RoaringBitmap;

fn add_points(points: &mut FxHashMap<u32, PointSet>, value: u32, objects: &PointSet) -> bool {
    let entry = points.entry(value).or_default(); let before = entry.len(); entry.extend(objects.iter()); entry.len() != before
}
fn add_point_iter<I: IntoIterator<Item = u32>>(
    points: &mut FxHashMap<u32, PointSet>, value: u32, objects: I,
) -> bool {
    let entry = points.entry(value).or_default(); let before = entry.len();
    entry.extend(objects); entry.len() != before
}
/// Propagate individual newly discovered object memberships instead of cloning
/// an entire points-to set for every worklist item.  The old set-at-a-time loop
/// copied large sets repeatedly on the full graph and made heap enrichment look
/// non-terminating even though the lattice is finite.
fn propagate_identity(
    points: &mut FxHashMap<u32, PointSet>,
    identity_targets: &FxHashMap<u32, Vec<u32>>,
) {
    let mut queue: std::collections::VecDeque<(u32, u32)> = points.iter()
        .flat_map(|(value, objects)| objects.iter().map(|object| (*value, object)))
        .collect();
    while let Some((source, object)) = queue.pop_front() {
        for target in identity_targets.get(&source).into_iter().flatten() {
            if points.entry(*target).or_default().insert(object) {
                queue.push_back((*target, object));
            }
        }
    }
}
fn propagate_identity_seed(
    points: &mut FxHashMap<u32, PointSet>,
    identity_targets: &FxHashMap<u32, Vec<u32>>,
    seeds: impl IntoIterator<Item = u32>,
) -> FxHashSet<u32> {
    let mut queue: std::collections::VecDeque<u32> = seeds.into_iter().collect();
    let mut queued: FxHashSet<u32> = queue.iter().copied().collect();
    let mut changed = FxHashSet::default();
    while let Some(source) = queue.pop_front() {
        queued.remove(&source);
        let objects = points.get(&source).cloned().unwrap_or_default();
        for target in identity_targets.get(&source).into_iter().flatten() {
            let entry = points.entry(*target).or_default(); let before = entry.len();
            entry.extend(objects.iter());
            if entry.len() != before {
                changed.insert(*target);
                if queued.insert(*target) { queue.push_back(*target); }
            }
        }
    }
    changed
}
fn value_text(value: &graph_proto::Value) -> Option<&str> { match value.kind.as_ref()? { graph_proto::value::Kind::Text(value) => Some(value), _ => None } }
fn object_field<'a>(value: &'a graph_proto::Value, key: &str) -> Option<&'a graph_proto::Value> {
    match value.kind.as_ref()? { graph_proto::value::Kind::Object(object) => object.fields.iter().find_map(|field| (field.key == key).then(|| field.value.as_ref()).flatten()), _ => None }
}
fn property_segments(graph: &Graph, node: &pass2::Node) -> Vec<String> {
    if let Some(value) = graph.node_property(node, "path_segments") {
        if let Some(list) = value.kind.as_ref().and_then(|kind| match kind { graph_proto::value::Kind::List(list) => Some(list), _ => None }) {
            let result: Vec<String> = list.values.iter().map(|segment| {
                if object_field(segment, "dynamic").and_then(|value| match value.kind.as_ref()? { graph_proto::value::Kind::Boolean(value) => Some(*value), _ => None }).unwrap_or(false) { "[*]".to_owned() } else { object_field(segment, "key").and_then(value_text).unwrap_or("?").to_owned() }
            }).collect();
            if !result.is_empty() { return result; }
        }
    }
    graph.node_property_text(node, "path").map(|value| vec![value.to_owned()]).unwrap_or_default()
}
fn emit_node(nodes: &mut Vec<graph_proto::NodeRecord>, emitted: &mut HashSet<String>, id: String, kind: &str, label: String, properties: Vec<graph_proto::Field>) {
    if emitted.insert(id.clone()) { nodes.push(node(id, kind, label, properties)); }
}
fn emit_edge(edges: &mut Vec<graph_proto::EdgeRecord>, emitted: &mut HashSet<(String, String, String)>, kind: &str, source: String, target: String, properties: Vec<graph_proto::Field>) {
    if source != target && !source.is_empty() && !target.is_empty() && emitted.insert((kind.to_owned(), source.clone(), target.clone())) { edges.push(edge(kind, &source, &target, properties)); }
}
fn ensure_location(
    graph: &mut Graph, locations: &mut FxHashMap<(u32, String), u32>, location_values: &mut FxHashMap<u32, FxHashSet<u32>>,
    nodes: &mut Vec<graph_proto::NodeRecord>, edges: &mut Vec<graph_proto::EdgeRecord>, emitted_nodes: &mut HashSet<String>, emitted_edges: &mut HashSet<(String, String, String)>, object: u32, segments: &[String], evidence: &[String],
) -> u32 {
    let key = (object, segments.join("\0"));
    if let Some(location) = locations.get(&key) { return *location; }
    let object_text = graph.id(object).to_owned(); let path_text = segments.join(".");
    let location_text = pass2::stable_id("core", "heap-identity", "heap-location", &[&object_text, &path_text]);
    let location = graph.symbols.intern(location_text.clone());
    let mut properties = fact(evidence, "high"); properties.extend([pass2::text_field("object_id", &object_text), list_field("path_segments", segments), pass2::text_field("path", &path_text)]);
    emit_node(nodes, emitted_nodes, location_text.clone(), "heap-location", format!("{}.{}", object_text, path_text), properties);
    emit_edge(edges, emitted_edges, "POINTS_TO", object_text, location_text, [fact(evidence, "high"), vec![pass2::text_field("relationship", "property")]].concat());
    locations.insert(key, location); location_values.entry(location).or_default(); location
}
fn target_locations(
    graph: &mut Graph, locations: &mut FxHashMap<(u32, String), u32>, location_values: &mut FxHashMap<u32, FxHashSet<u32>>,
    nodes: &mut Vec<graph_proto::NodeRecord>, edges: &mut Vec<graph_proto::EdgeRecord>, emitted_nodes: &mut HashSet<String>, emitted_edges: &mut HashSet<(String, String, String)>, object: u32, segments: &[String], evidence: &[String],
) -> Vec<u32> {
    let mut current = vec![object];
    for segment in segments.iter().take(segments.len().saturating_sub(1)) {
        let mut next = Vec::new();
        for current_object in current {
            let location = ensure_location(graph, locations, location_values, nodes, edges, emitted_nodes, emitted_edges, current_object, &[segment.clone()], evidence);
            if location_values.get(&location).is_none_or(FxHashSet::is_empty) {
                let current_text = graph.id(current_object).to_owned(); let location_text = graph.id(location).to_owned();
                let child_text = pass2::stable_id("core", "heap-identity", "heap-object", &["property", &current_text, segment]);
                let child = graph.symbols.intern(child_text.clone()); let child_fact = fact(&[evidence, &[location_text.clone()][..]].concat(), "conservative");
                emit_node(nodes, emitted_nodes, child_text.clone(), "heap-object", format!("property-object:{segment}"), child_fact.clone());
                location_values.entry(location).or_default().insert(child);
                emit_edge(edges, emitted_edges, "POINTS_TO", location_text, child_text, child_fact);
            }
            next.extend(location_values.get(&location).into_iter().flatten().copied());
        }
        current = next;
    }
    current.into_iter().map(|object| ensure_location(graph, locations, location_values, nodes, edges, emitted_nodes, emitted_edges, object, &segments[segments.len() - 1..], evidence)).collect()
}

pub(crate) fn enrich(graph: &mut Graph) -> Delta {
    let timing_enabled = std::env::var_os("LACHESIS_NATIVE_PASS2_TIMINGS").is_some();
    let started = std::time::Instant::now();
    let report = |name: &str, points: &FxHashMap<u32, PointSet>| {
        if timing_enabled {
            let memberships = points.values().map(RoaringBitmap::len).sum::<u64>();
            eprintln!("[lachesis native pass2] heap {name}: {:.3}s ({} values, {} memberships)",
                started.elapsed().as_secs_f64(), points.len(), memberships);
        }
    };
    let mut points: FxHashMap<u32, PointSet> = FxHashMap::default();
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
    propagate_identity(&mut points, &identity_targets);
    report("initial propagation", &points);

    // Keep context-specific parameter objects separate, then instantiate
    // callee-local allocation templates at context returns.
    let mut substitutions: FxHashMap<String, FxHashMap<u32, PointSet>> = FxHashMap::default();
    for binding in graph.nodes.iter().filter(|node| graph.kind(node.kind) == "context-parameter") {
        let Some(context) = text(graph, binding, "context_id") else { continue }; let Some(argument) = text(graph, binding, "argument_id").and_then(|id| graph.symbol(id)) else { continue }; let Some(parameter) = text(graph, binding, "parameter_id").and_then(|id| graph.symbol(id)) else { continue };
        let Some(abstract_object) = parameter_objects.get(&parameter).copied() else { continue }; let caller_objects = points.get(&argument).cloned().unwrap_or_default(); add_points(&mut points, binding.id, &caller_objects); substitutions.entry(context.to_owned()).or_default().insert(abstract_object, caller_objects);
    }
    let returned_indices: Vec<usize> = graph.nodes.iter().enumerate().filter(|(_, node)| graph.kind(node.kind) == "context-return").map(|(index, _)| index).collect();
    for returned_index in returned_indices {
        let returned = &graph.nodes[returned_index];
        let returned_id = returned.id;
        let Some(context) = text(graph, returned, "context_id").map(str::to_owned) else { continue }; let callee = text(graph, returned, "callee_function_id").and_then(|id| graph.symbol(id)); let mut returned_objects = PointSet::new();
        for source in context_return_sources.get(&returned_id).into_iter().flatten() { if let Some(source_objects) = points.get(source) { for object in source_objects.iter() {
            if let Some(replacement) = substitutions.get(&context).and_then(|map| map.get(&object)) { returned_objects.extend(replacement.iter()); continue; }
            if callee.is_some() && object_owner.get(&object).copied().flatten() == callee {
                let object_text = pass2::stable_id("core", "heap-identity", "heap-object", &["context", &context, graph.id(object)]); let instance = graph.symbols.intern(object_text.clone());
                let mut properties = fact(&[graph.id(returned_id).to_owned(), context.clone(), graph.id(object).to_owned()], "exact"); properties.push(pass2::text_field("context_id", &context)); properties.push(pass2::text_field("allocation_template_id", graph.id(object))); object_owner.insert(instance, Some(callee.unwrap())); object_properties.insert(instance, properties.clone()); add_node(object_text.clone(), "heap-object", format!("context-object:{}", graph.id(object)), properties); add_edge("CONTEXT_ALLOCATES", context.clone(), object_text, fact(&[graph.id(returned_id).to_owned(), context.clone(), graph.id(object).to_owned()], "exact")); returned_objects.insert(instance);
            } else { returned_objects.insert(object); }
        }} }
        add_points(&mut points, returned.id, &returned_objects);
    }
    propagate_identity(&mut points, &identity_targets);
    report("context propagation", &points);
    drop(add_node);
    drop(add_edge);

    let path_specs: Vec<(u32, u32, Vec<String>)> = graph.nodes.iter().filter(|node| graph.kind(node.kind) == "property-path").filter_map(|path| Some((path.id, text(graph, path, "base_value_id").and_then(|id| graph.symbol(id))?, property_segments(graph, path)))).filter(|(_, _, segments)| !segments.is_empty()).collect();
    let mut writes_by_path: FxHashMap<u32, Vec<(u32, Option<u32>)>> = FxHashMap::default();
    let mut reads_by_path: FxHashMap<u32, Vec<u32>> = FxHashMap::default();
    for item in &graph.nodes {
        match graph.kind(item.kind) {
            "write" => if let Some(path) = text(graph, item, "target_id").and_then(|id| graph.symbol(id)) { writes_by_path.entry(path).or_default().push((item.id, text(graph, item, "value_id").and_then(|id| graph.symbol(id)))); },
            "read" => if let Some(path) = text(graph, item, "target_id").and_then(|id| graph.symbol(id)) { reads_by_path.entry(path).or_default().push(item.id); },
            _ => {}
        }
    }
    let mut locations: FxHashMap<(u32, String), u32> = FxHashMap::default();
    let mut location_values: FxHashMap<u32, FxHashSet<u32>> = FxHashMap::default();
    let mut locations_by_path: FxHashMap<u32, Vec<u32>> = FxHashMap::default();
    let mut paths_by_dependency: FxHashMap<u32, Vec<usize>> = FxHashMap::default();
    for (index, (path, base, _)) in path_specs.iter().enumerate() {
        paths_by_dependency.entry(*base).or_default().push(index);
        for (_, value) in writes_by_path.get(path).into_iter().flatten() {
            if let Some(value) = value { paths_by_dependency.entry(*value).or_default().push(index); }
        }
    }
    let mut pending: std::collections::VecDeque<usize> = (0..path_specs.len()).collect();
    let mut queued: FxHashSet<usize> = (0..path_specs.len()).collect();
    let mut readers: FxHashMap<u32, FxHashSet<u32>> = FxHashMap::default();
    while let Some(path_index) = pending.pop_front() {
        queued.remove(&path_index);
        let (path, base, segments) = &path_specs[path_index];
        let objects: Vec<u32> = points.get(base).map(|set| set.iter().collect()).unwrap_or_default();
        for object in objects {
            let evidence = vec![graph.id(*path).to_owned(), graph.id(*base).to_owned(), graph.id(object).to_owned()];
            let targets = target_locations(graph, &mut locations, &mut location_values, &mut nodes, &mut edges, &mut emitted_nodes, &mut emitted_edges, object, segments, &evidence);
            let path_locations = locations_by_path.entry(*path).or_default();
            for location in targets { if !path_locations.contains(&location) { path_locations.push(location); } }
        }
        let mut changed_values = FxHashSet::default();
        for location in locations_by_path.get(path).into_iter().flatten().copied() {
            for (_write, value) in writes_by_path.get(path).into_iter().flatten() {
                let Some(value_id) = value else { continue };
                let values = points.get(value_id).cloned().unwrap_or_default();
                let slot = location_values.entry(location).or_default(); let before = slot.len(); slot.extend(values.iter());
                if slot.len() != before {
                    for read in readers.get(&location).into_iter().flatten().copied() {
                        let read_values = location_values.get(&location).cloned().unwrap_or_default();
                        if add_point_iter(&mut points, read, read_values.into_iter()) { changed_values.insert(read); }
                    }
                }
            }
            for read in reads_by_path.get(path).into_iter().flatten().copied() {
                readers.entry(location).or_default().insert(read);
                let values = location_values.get(&location).cloned().unwrap_or_default();
                if add_point_iter(&mut points, read, values.into_iter()) { changed_values.insert(read); }
            }
        }
        changed_values.extend(propagate_identity_seed(&mut points, &identity_targets, changed_values.clone()));
        for value in changed_values {
            for dependency in paths_by_dependency.get(&value).into_iter().flatten().copied() {
                if queued.insert(dependency) { pending.push_back(dependency); }
            }
        }
    }
    report("property worklist", &points);
    // Emit the final read/write facts once, after the monotone state has converged.
    for (path, base, segments) in &path_specs {
        let objects: Vec<u32> = points.get(base).map(|set| set.iter().collect()).unwrap_or_default();
        for object in objects {
            let evidence = vec![graph.id(*path).to_owned(), graph.id(*base).to_owned(), graph.id(object).to_owned()];
            let targets = target_locations(graph, &mut locations, &mut location_values, &mut nodes, &mut edges, &mut emitted_nodes, &mut emitted_edges, object, segments, &evidence);
            for location in targets {
                for (write, _) in writes_by_path.get(path).into_iter().flatten() {
                    let write_text = graph.id(*write).to_owned(); let path_text = graph.id(*path).to_owned(); let location_text = graph.id(location).to_owned(); emit_edge(&mut edges, &mut emitted_edges, "WRITES_HEAP", write_text.clone(), location_text.clone(), fact(&[write_text, path_text, location_text], "high"));
                }
                for read in reads_by_path.get(path).into_iter().flatten() {
                    let read_text = graph.id(*read).to_owned(); let path_text = graph.id(*path).to_owned(); let location_text = graph.id(location).to_owned(); emit_edge(&mut edges, &mut emitted_edges, "READS_HEAP", location_text.clone(), read_text.clone(), fact(&[read_text, path_text, location_text], "high"));
                }
            }
        }
    }
    for (value, objects) in points {
        let value_text = graph.id(value).to_owned();
        for object in objects { let object_text = graph.id(object).to_owned(); emit_edge(&mut edges, &mut emitted_edges, "POINTS_TO", value_text.clone(), object_text.clone(), fact(&[value_text.clone(), object_text], "high")); }
    }
    let _ = object_properties;
    Delta { nodes, edges }
}
