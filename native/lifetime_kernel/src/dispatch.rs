//! Native dynamic-dispatch expansion over interned graph handles.

use hashbrown::HashSet;
use rustc_hash::FxHashMap;

use crate::graph_proto;
use crate::pass2::{self, Delta, Graph};

const CALLABLE_KINDS: [&str; 3] = ["function", "method", "constructor"];
const IDENTITY_REASONS: [&str; 10] = [
    "initializer", "assignment", "write", "read", "read-value", "argument-value",
    "call-result", "context-call-result", "branch-reaching-definition", "phi-input",
];

fn value_text(value: &graph_proto::Value) -> Option<&str> {
    match value.kind.as_ref()? {
        graph_proto::value::Kind::Text(value) => Some(value),
        _ => None,
    }
}

fn edge_property<'a>(edge: &'a pass2::Edge, key: &str) -> Option<&'a graph_proto::Value> {
    edge.properties.iter().find_map(|field| {
        (field.key == key).then(|| field.value.as_ref()).flatten()
    })
}

fn edge_text<'a>(edge: &'a pass2::Edge, key: &str) -> Option<&'a str> {
    edge_property(edge, key).and_then(value_text)
}

fn last_name(value: &str) -> String {
    let mut result = value.split("?.").last().unwrap_or(value);
    if let Some((_, suffix)) = result.rsplit_once('.') { result = suffix; }
    if let Some((_, suffix)) = result.rsplit_once('[') { result = suffix; }
    if let Some((prefix, _)) = result.split_once('(') { result = prefix; }
    result.trim_matches(['\'', '"', '`', ']', ' ']).to_owned()
}

fn fact(evidence: &[String], confidence: &str, reason: Option<&str>) -> Vec<graph_proto::Field> {
    let mut fields = vec![
        pass2::text_field("fact_origin", "core-inference"),
        pass2::text_field("confidence", confidence),
        pass2::text_field("evidence_ids", evidence.join("\x1f")),
    ];
    if let Some(reason) = reason { fields.push(pass2::text_field("reason", reason)); }
    fields
}

fn output_edge(kind: &str, source: &str, target: &str, properties: Vec<graph_proto::Field>)
    -> graph_proto::EdgeRecord
{
    graph_proto::EdgeRecord {
        kind: kind.to_owned(), source: source.to_owned(), target: target.to_owned(),
        properties, source_tier: String::new(), relationship_class: String::new(),
    }
}

pub(crate) fn enrich(graph: &Graph) -> Delta {
    let mut implementations: FxHashMap<u32, HashSet<u32>> = FxHashMap::default();
    let mut callable_targets: FxHashMap<u32, HashSet<u32>> = FxHashMap::default();
    let mut identity_out: FxHashMap<u32, Vec<u32>> = FxHashMap::default();
    let mut references: FxHashMap<u32, HashSet<u32>> = FxHashMap::default();
    let mut read_by_evidence: FxHashMap<u32, Vec<u32>> = FxHashMap::default();
    let mut ast_children: FxHashMap<u32, Vec<u32>> = FxHashMap::default();
    let mut bindings_by_parameter: FxHashMap<u32, Vec<u32>> = FxHashMap::default();
    let mut callbacks_by_argument: FxHashMap<u32, HashSet<u32>> = FxHashMap::default();
    let mut identity_edges = Vec::new();

    for (index, node) in graph.nodes.iter().enumerate() {
        if CALLABLE_KINDS.contains(&graph.kind(node.kind)) {
            callable_targets.entry(node.id).or_default().insert(node.id);
        }
        let _ = index;
    }
    for item in &graph.edges {
        let kind = graph.edge_kind(item);
        match kind.as_str() {
            "OVERRIDES" | "IMPLEMENTS_MEMBER" | "IMPLEMENTED_BY" => {
                if CALLABLE_KINDS.iter().any(|kind| graph.node_index(graph.id(item.source))
                    .is_some_and(|index| graph.node_kind(index) == *kind)) &&
                    CALLABLE_KINDS.iter().any(|kind| graph.node_index(graph.id(item.target))
                    .is_some_and(|index| graph.node_kind(index) == *kind)) {
                    if kind == "IMPLEMENTED_BY" {
                        implementations.entry(item.source).or_default().insert(item.target);
                    } else {
                        implementations.entry(item.target).or_default().insert(item.source);
                    }
                }
            }
            "FUNCTION_VALUE" => { callable_targets.entry(item.target).or_default().insert(item.source); }
            "ALIASES" | "ALIASES_VALUE" | "READS_FROM" | "PHI_INPUT" => {
                identity_edges.push((item.source, item.target));
            }
            "VALUE_FLOWS_TO" if IDENTITY_REASONS.contains(&edge_text(item, "reason").unwrap_or("\0")) => {
                identity_edges.push((item.source, item.target));
            }
            "DEFINES" => { identity_edges.push((item.target, item.source)); }
            "AST_CHILD" => { ast_children.entry(item.source).or_default().push(item.target); }
            "REFERS_TO" => { references.entry(item.source).or_default().insert(item.target); }
            "READ_EVIDENCED_BY" => { read_by_evidence.entry(item.target).or_default().push(item.source); }
            "ARGUMENT_BINDS_PARAMETER" => { bindings_by_parameter.entry(item.target).or_default().push(item.source); }
            "PASSES_CALLBACK" => { callbacks_by_argument.entry(item.source).or_default().insert(item.target); }
            _ => {}
        }
    }
    for (source, target) in identity_edges {
        identity_out.entry(source).or_default().push(target);
    }

    let mut pending: Vec<u32> = callable_targets.keys().copied().collect();
    let mut queued: HashSet<u32> = pending.iter().copied().collect();
    while let Some(source) = pending.pop() {
        queued.remove(&source);
        let targets = callable_targets.get(&source).cloned().unwrap_or_default();
        for target in identity_out.get(&source).into_iter().flatten() {
            let values = callable_targets.entry(*target).or_default();
            let before = values.len();
            values.extend(targets.iter().copied());
            if values.len() != before && queued.insert(*target) { pending.push(*target); }
        }
    }
    let mut changed = true;
    while changed {
        changed = false;
        let snapshot = implementations.clone();
        for values in implementations.values_mut() {
            let before = values.len();
            let current: Vec<u32> = values.iter().copied().collect();
            for item in current { values.extend(snapshot.get(&item).into_iter().flatten().copied()); }
            changed |= values.len() != before;
        }
    }

    let mut emitted: HashSet<(u32, u32)> = HashSet::new();
    let mut edges = Vec::new();
    for node in &graph.nodes {
        if !["call", "construct"].contains(&graph.kind(node.kind)) { continue; }
        let call_id = node.id;
        for edge_index in graph.outgoing.get(graph.node_by_id.get(&call_id).copied().unwrap_or(usize::MAX)).into_iter().flatten() {
            let existing = &graph.edges[*edge_index];
            if !["INVOKES", "MAY_INVOKE"].contains(&graph.edge_kind(existing).as_str()) { continue; }
            for implementation in implementations.get(&existing.target).into_iter().flatten() {
                if emitted.insert((call_id, *implementation)) {
                    let source = graph.id(call_id).to_owned(); let target = graph.id(*implementation).to_owned();
                    edges.push(output_edge("MAY_INVOKE", &source, &target,
                        fact(&[source.clone(), graph.id(existing.target).to_owned(), target.clone()], "high",
                             Some("override-or-interface-implementation"))));
                }
            }
        }
        let receiver = graph.node_property_text(node, "receiver_value_id").and_then(|id| graph.symbol(id));
        for target in receiver.and_then(|id| callable_targets.get(&id)).into_iter().flatten() {
            if emitted.insert((call_id, *target)) {
                let source = graph.id(call_id).to_owned(); let target_name = graph.id(*target).to_owned();
                edges.push(output_edge("MAY_INVOKE", &source, &target_name,
                    fact(&[source.clone(), target_name.clone()], "high", Some("callable-receiver"))));
            }
        }
        let children = ast_children.get(&call_id).cloned().unwrap_or_default();
        for child in children {
            for target in callable_targets.get(&child).into_iter().flatten() {
                if emitted.insert((call_id, *target)) {
                    let source = graph.id(call_id).to_owned(); let target_name = graph.id(*target).to_owned();
                    edges.push(output_edge("MAY_INVOKE", &source, &target_name,
                        fact(&[source.clone(), graph.id(child).to_owned(), target_name.clone()], "high",
                             Some("function-valued-reference"))));
                }
            }
            if let Some(arguments) = bindings_by_parameter.get(&child) {
                for argument in arguments {
                    let mut targets = callbacks_by_argument.get(argument).cloned().unwrap_or_default();
                    targets.extend(callable_targets.get(argument).into_iter().flatten().copied());
                    for target in targets {
                        if emitted.insert((call_id, target)) {
                            let source = graph.id(call_id).to_owned(); let target_name = graph.id(target).to_owned();
                            edges.push(output_edge("MAY_INVOKE", &source, &target_name,
                                fact(&[source.clone(), graph.id(child).to_owned(), graph.id(*argument).to_owned(), target_name.clone()], "high",
                                     Some("contextual-callback-binding"))));
                        }
                    }
                }
            }
        }
    }
    let _ = (references, read_by_evidence, last_name);
    Delta { nodes: Vec::new(), edges }
}
