//! Native source-to-sink propagation over the Pass-2 graph.

use std::collections::VecDeque;
use hashbrown::{HashMap, HashSet};
use rustc_hash::FxHashMap;

use crate::graph_proto;
use crate::pass2::{self, Delta, Graph};

const FLOW_KINDS: [&str; 17] = [
    "DEFINES", "VALUE_FLOWS_TO", "READS_FROM", "PROPERTY_READ", "ALIASES",
    "ALIASES_VALUE", "PHI_INPUT", "BRANCH_READS_FROM", "BRANCH_PREVIOUS",
    "POINTS_TO", "WRITES_HEAP", "READS_HEAP", "DYNAMIC_INPUT", "REACHING_DEF",
    "CALL_PASSTHROUGH", "SINK_ARGUMENT", "TAINT_INPUT",
];
const MAX_STATES_PER_SOURCE: usize = 300_000;

#[derive(Clone)]
struct RoleRecord {
    node: String,
    value: u32,
    confidence: String,
    subtype: String,
    label: String,
}

#[derive(Clone, Eq, Hash, PartialEq)]
struct State {
    value: u32,
    contexts: Vec<String>,
}

fn value_text(value: &graph_proto::Value) -> Option<&str> {
    match value.kind.as_ref()? {
        graph_proto::value::Kind::Text(value) => Some(value),
        _ => None,
    }
}

fn object_field<'a>(value: &'a graph_proto::Value, key: &str) -> Option<&'a graph_proto::Value> {
    match value.kind.as_ref()? {
        graph_proto::value::Kind::Object(object) => object.fields.iter().find_map(|field| {
            (field.key == key).then(|| field.value.as_ref()).flatten()
        }),
        _ => None,
    }
}

fn roles(graph: &pass2::Node, role_name: &str) -> Vec<(String, String)> {
    let Some(value) = graph.properties.iter().find(|field| field.key == "roles")
        .and_then(|field| field.value.as_ref()) else { return Vec::new(); };
    let graph_proto::value::Kind::List(list) = value.kind.as_ref().unwrap() else { return Vec::new(); };
    list.values.iter().filter_map(|role| {
        let role_value = object_field(role, "role").and_then(value_text)?;
        if !role_value.eq_ignore_ascii_case(role_name) { return None; }
        let subtype = object_field(role, "subtype").and_then(value_text)
            .unwrap_or("untrusted").to_owned();
        let confidence = object_field(role, "confidence").and_then(value_text)
            .unwrap_or("high").to_owned();
        Some((subtype, confidence))
    }).collect()
}

fn list_field(key: &str, values: &[String]) -> graph_proto::Field {
    graph_proto::Field {
        key: key.to_owned(),
        value: Some(graph_proto::Value {
            kind: Some(graph_proto::value::Kind::List(graph_proto::ListValue {
                values: values.iter().map(|value| graph_proto::Value {
                    kind: Some(graph_proto::value::Kind::Text(value.clone())),
                }).collect(),
            })),
        }),
    }
}

fn fact(evidence: &[String], confidence: &str) -> Vec<graph_proto::Field> {
    vec![pass2::text_field("fact_origin", "core-inference"),
         pass2::text_field("confidence", confidence), list_field("evidence_ids", evidence)]
}

fn edge(kind: &str, source: &str, target: &str, properties: Vec<graph_proto::Field>)
    -> graph_proto::EdgeRecord
{
    graph_proto::EdgeRecord {
        kind: kind.to_owned(), source: source.to_owned(), target: target.to_owned(),
        properties, source_tier: String::new(), relationship_class: String::new(),
    }
}

pub(crate) fn enrich(graph: &Graph) -> Delta {
    let mut adjacency: FxHashMap<u32, Vec<(u32, String, Option<String>, Option<String>)>> = FxHashMap::default();
    let mut evidence: FxHashMap<(u32, u32), Vec<String>> = FxHashMap::default();
    for item in &graph.edges {
        let kind = graph.edge_kind(item);
        if !FLOW_KINDS.contains(&kind.as_str()) { continue; }
        let transition = kind.clone();
        let reason = graph.edge_property_text(item, "reason").map(str::to_owned);
        let context_id = graph.edge_property_text(item, "context_id").map(str::to_owned);
        adjacency.entry(item.source).or_default().push((item.target, transition, reason, context_id));
        evidence.entry((item.source, item.target)).or_insert_with(|| vec![
            graph.id(item.source).to_owned(), graph.id(item.target).to_owned(),
        ]);
    }

    let mut arguments_by_call: FxHashMap<u32, Vec<u32>> = FxHashMap::default();
    for node in &graph.nodes {
        if graph.kind(node.kind) != "argument" { continue; }
        let Some(callsite) = graph.node_property_text(node, "callsite_id")
            .and_then(|value| graph.symbol(value)) else { continue; };
        arguments_by_call.entry(callsite).or_default().push(node.id);
    }
    let mut call_result: FxHashMap<u32, u32> = FxHashMap::default();
    for node in &graph.nodes {
        if !["call", "construct"].contains(&graph.kind(node.kind)) { continue; }
        if let Some(result) = graph.node_property_text(node, "value_id")
            .and_then(|value| graph.symbol(value)) {
            call_result.insert(node.id, result);
        }
    }
    for (call, arguments) in &arguments_by_call {
        let Some(result) = call_result.get(call) else { continue; };
        for argument in arguments {
            adjacency.entry(*argument).or_default()
                .push((*result, "CALL_PASSTHROUGH".to_owned(), None, None));
            evidence.entry((*argument, *result)).or_insert_with(|| vec![
                graph.id(*argument).to_owned(), graph.id(*call).to_owned(), graph.id(*result).to_owned(),
            ]);
        }
    }
    for node in &graph.nodes {
        if !["call", "construct"].contains(&graph.kind(node.kind)) { continue; }
        let Some(receiver) = graph.node_property_text(node, "receiver_value_id")
            .and_then(|value| graph.symbol(value)) else { continue; };
        let Some(result) = call_result.get(&node.id) else { continue; };
        adjacency.entry(receiver).or_default()
            .push((*result, "CALL_PASSTHROUGH".to_owned(), None, None));
        evidence.entry((receiver, *result)).or_insert_with(|| vec![
            graph.id(receiver).to_owned(), graph.id(node.id).to_owned(), graph.id(*result).to_owned(),
        ]);
    }

    let mut source_records = Vec::new();
    let mut sink_records = Vec::new();
    let mut nodes = Vec::new();
    let mut output_edges = Vec::new();
    for node in &graph.nodes {
        let kind = graph.kind(node.kind);
        if kind == "source" || kind == "sink" {
            let Some(value) = graph.node_property_text(node, "value_id")
                .and_then(|value| graph.symbol(value)) else { continue; };
            let confidence = graph.node_property_text(node, "confidence").unwrap_or("high").to_owned();
            let subtype = graph.node_property_text(node, if kind == "source" { "source_kind" } else { "sink_kind" })
                .unwrap_or(if kind == "source" { "untrusted" } else { "sensitive-operation" }).to_owned();
            let record = RoleRecord { node: graph.id(node.id).to_owned(), value, confidence, subtype, label: node.label.clone() };
            if kind == "source" { source_records.push(record); } else { sink_records.push(record); }
        }
        for (subtype, confidence) in roles(node, "source") {
            let source_id = pass2::stable_id("core", "taint-propagation", "source", &[graph.id(node.id), &subtype]);
            let value = node.id;
            let label = format!("source:{}", node.label);
            let mut properties = fact(&[graph.id(node.id).to_owned()], &confidence);
            properties.push(pass2::text_field("value_id", graph.id(value)));
            properties.push(pass2::text_field("source_kind", subtype.clone()));
            nodes.push(graph_proto::NodeRecord { id: source_id.clone(), kind: "source".to_owned(),
                label: label.clone(), properties, tier: String::new() });
            output_edges.push(edge("TAINT_SOURCE", &source_id, graph.id(value),
                fact(&[graph.id(value).to_owned()], &confidence)));
            source_records.push(RoleRecord { node: source_id, value,
                confidence: confidence.clone(), subtype: subtype.clone(), label: label.clone() });
        }
        for (subtype, confidence) in roles(node, "sink") {
            let sink_id = pass2::stable_id("core", "taint-propagation", "sink", &[graph.id(node.id), &subtype]);
            let label = format!("sink:{}", node.label);
            let mut properties = fact(&[graph.id(node.id).to_owned()], &confidence);
            properties.push(pass2::text_field("value_id", graph.id(node.id)));
            properties.push(pass2::text_field("sink_kind", subtype.clone()));
            nodes.push(graph_proto::NodeRecord { id: sink_id.clone(), kind: "sink".to_owned(),
                label: label.clone(), properties, tier: String::new() });
            output_edges.push(edge("TAINT_SINK", &sink_id, graph.id(node.id),
                fact(&[graph.id(node.id).to_owned()], &confidence)));
            sink_records.push(RoleRecord { node: sink_id, value: node.id,
                confidence, subtype, label });
        }
    }

    let mut emitted = HashSet::new();
    for source in source_records {
        let initial = State { value: source.value, contexts: Vec::new() };
        let mut queue = VecDeque::from([initial.clone()]);
        let mut seen: HashSet<State> = HashSet::new();
        seen.insert(initial.clone());
        let mut predecessor: HashMap<State, State> = HashMap::new();
        let sink_by_value: FxHashMap<u32, &RoleRecord> = sink_records.iter()
            .map(|record| (record.value, record)).collect();
        let mut reaches = Vec::new();
        while let Some(state) = queue.pop_front() {
            if seen.len() > MAX_STATES_PER_SOURCE { break; }
            if state != initial && sink_by_value.contains_key(&state.value) {
                reaches.push(state.clone());
            }
            for (target, transition, reason, context_id) in adjacency.get(&state.value).into_iter().flatten() {
                let mut contexts = state.contexts.clone();
                if reason.as_deref() == Some("context-parameter") {
                    let Some(context) = context_id.as_ref() else { continue; };
                    if contexts.len() >= 12 { continue; }
                    contexts.push(context.clone());
                } else if reason.as_deref() == Some("context-return") {
                    let Some(context) = context_id.as_ref() else { continue; };
                    if contexts.last() != Some(context) { continue; }
                    contexts.pop();
                }
                let next = State { value: *target, contexts };
                if seen.insert(next.clone()) {
                    predecessor.insert(next.clone(), state.clone());
                    queue.push_back(next);
                }
                let key = (state.value, *target);
                if emitted.insert(key) {
                    let source_name = graph.id(state.value).to_owned();
                    let target_name = graph.id(*target).to_owned();
                    let fallback = vec![source_name.clone(), target_name.clone()];
                    output_edges.push(edge("TAINT_FLOWS_TO", &source_name, &target_name,
                        fact(evidence.get(&key).unwrap_or(&fallback), "high")));
                }
            }
        }
        for sink_state in reaches {
            let Some(sink) = sink_by_value.get(&sink_state.value) else { continue; };
            let mut witness = vec![sink_state.value];
            let mut cursor = sink_state;
            while cursor != initial {
                let Some(previous) = predecessor.get(&cursor) else { break; };
                witness.push(previous.value); cursor = previous.clone();
            }
            witness.reverse();
            let source_name = graph.id(source.value).to_owned();
            let sink_name = sink.node.clone();
            let reach_id = pass2::stable_id("core", "taint-propagation", "taint-reach", &[&source_name, &sink_name]);
            let witness_ids: Vec<String> = witness.iter().map(|value| graph.id(*value).to_owned()).collect();
            let mut properties = fact(&witness_ids, &source.confidence);
            properties.push(pass2::text_field("source_id", &source.node));
            properties.push(pass2::text_field("sink_id", &sink.node));
            properties.push(list_field("witness_ids", &witness_ids));
            nodes.push(graph_proto::NodeRecord { id: reach_id.clone(), kind: "taint-reach".to_owned(),
                label: format!("{} → {}", source.label, sink.label), properties, tier: String::new() });
            let reach_fact = fact(&witness_ids, &source.confidence);
            output_edges.push(edge("TAINT_REACHES", &source.node, &reach_id, reach_fact.clone()));
            output_edges.push(edge("TAINT_REACHES", &reach_id, &sink_name, reach_fact));
        }
    }
    Delta { nodes, edges: output_edges }
}
