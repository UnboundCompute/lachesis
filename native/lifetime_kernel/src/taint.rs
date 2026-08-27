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

fn catalog_language(function: &str) -> Option<&'static str> {
    if function.contains(":cpython-ast:") { Some("python") }
    else if function.contains(":typescript-compiler-api:") { Some("typescript") }
    else if function.contains(":clang-c:") || function.contains(":clang-c-native:") {
        Some("c")
    } else if function.contains(":javascript:") { Some("javascript") } else { None }
}

fn model_matches(model: &crate::atropos_proto::Model, language: Option<&str>, callee: &str) -> bool {
    if !model.language.is_empty() && language != Some(model.language.as_str())
        && !(language == Some("typescript") && model.language == "javascript") { return false; }
    if model.package.is_empty() || model.package == "builtins" {
        model.method == callee || callee.rsplit('.').next() == Some(model.method.as_str())
    } else { callee == format!("{}.{}", model.package, model.method) }
}

fn endpoint_values(endpoint: &str, call: &pass2::Node,
                   arguments: &HashMap<u32, Vec<(u32, u32)>>,
                   call_results: &HashMap<u32, Vec<u32>>, graph: &Graph) -> Vec<u32> {
    if endpoint == "ReturnValue" {
        if let Some(value) = graph.node_property_text(call, "value_id")
            .and_then(|value| graph.symbol(value)) {
            return vec![value];
        }
        // A call node is the language-neutral result identity when the
        // frontend does not materialize a dedicated value_id.  The existing
        // call->initializer flow carries it into a local declaration, while
        // the return-to-callsite rule carries it across a resolved wrapper.
        let mut values = vec![call.id];
        if let Some(results) = call_results.get(&call.id) {
            values.extend(results.iter().copied());
        }
        values.sort_unstable();
        values.dedup();
        return values;
    }
    if endpoint == "Receiver" {
        return graph.node_property_text(call, "receiver_value_id").and_then(|value| graph.symbol(value))
            .into_iter().collect();
    }
    let position = endpoint.strip_prefix("Argument[").and_then(|value| value.strip_suffix(']'));
    let Some(position) = position else { return Vec::new() };
    if position == "*" {
        return arguments.get(&call.id).into_iter().flatten().map(|(_, node)| *node).collect();
    }
    let Ok(position) = position.parse::<u32>() else { return Vec::new() };
    arguments.get(&call.id).into_iter().flatten()
        .filter_map(|(index, node)| (*index == position).then_some(*node)).collect()
}

fn referenced_variables(graph: &Graph, start: u32) -> Vec<u32> {
    let mut queue = VecDeque::from([start]);
    let mut seen = HashSet::new();
    seen.insert(start);
    let mut variables = Vec::new();
    while let Some(current) = queue.pop_front() {
        let Some(index) = graph.node_by_id.get(&current).copied() else { continue };
        for edge_index in &graph.outgoing[index] {
            let edge = &graph.edges[*edge_index];
            match graph.edge_kind(edge) {
                "AST_CHILD" => {
                    if seen.insert(edge.target) { queue.push_back(edge.target); }
                }
                "REFERS_TO" if graph.node_by_id.get(&edge.target).is_some_and(|target|
                    graph.node_kind(*target) == "variable") => variables.push(edge.target),
                _ => {}
            }
        }
    }
    variables.sort_unstable();
    variables.dedup();
    variables
}

/// Apply declarative Atropos source/sink rows to compiler call/argument facts.
/// The catalog is a binary protobuf by this point; no authored JSON is read.
pub(crate) fn catalog_delta(graph: &Graph, catalog: &crate::atropos_proto::Request) -> Delta {
    let mut arguments: HashMap<u32, Vec<(u32, u32)>> = HashMap::new();
    for node in &graph.nodes {
        if graph.kind(node.kind) != "argument" { continue; }
        let Some(callsite) = graph.node_property_text(node, "callsite_id")
            .and_then(|value| graph.symbol(value)) else { continue };
        let position = graph.node_property_i64(node, "position")
            .and_then(|value| u32::try_from(value).ok()).unwrap_or(0);
        arguments.entry(callsite).or_default().push((position, node.id));
    }
    // The compact Pass-1 projection represents the same call arguments as
    // HAS_ARGUMENT edges.  Prefer/merge that lossless edge form so catalog
    // models remain independent of whether a frontend materializes explicit
    // argument nodes.
    for edge in &graph.edges {
        if graph.edge_kind(edge) != "HAS_ARGUMENT" { continue; }
        let Some(position) = graph.edge_property_i64(edge, "position")
            .and_then(|value| u32::try_from(value).ok()) else { continue };
        arguments.entry(edge.source).or_default().push((position, edge.target));
    }
    for values in arguments.values_mut() {
        values.sort_unstable();
        values.dedup();
    }
    let mut call_results: HashMap<u32, Vec<u32>> = HashMap::new();
    for edge in &graph.edges {
        if graph.edge_kind(edge) != "VALUE_FLOWS_TO"
            || graph.edge_property_text(edge, "reason") != Some("initializer") {
            continue;
        }
        if graph.node_by_id.contains_key(&edge.source) {
            call_results.entry(edge.source).or_default().push(edge.target);
        }
    }
    for values in call_results.values_mut() {
        values.sort_unstable();
        values.dedup();
    }
    let mut nodes = Vec::new();
    let mut edges = Vec::new();
    for call in &graph.nodes {
        if !matches!(graph.kind(call.kind), "call" | "construct") { continue; }
        let Some(callee) = graph.node_property_text(call, "callee")
            .or_else(|| graph.node_property_text(call, "method_name"))
            .or_else(|| graph.node_property_text(call, "callee_name")) else { continue };
        let language = graph.node_owner(call).map(|owner| graph.id(owner)).and_then(catalog_language);
        for model in &catalog.models {
            if !model_matches(model, language, callee) { continue; }
            if model.role == "summary" {
                let mut endpoints = model.access_path.split("->").map(str::trim);
                let Some(from_endpoint) = endpoints.next() else { continue };
                let Some(to_endpoint) = endpoints.next() else { continue };
                let from_values = endpoint_values(from_endpoint, call, &arguments, &call_results, graph);
                let to_values = endpoint_values(to_endpoint, call, &arguments, &call_results, graph);
                let model_id = if model.id.is_empty() { model.method.as_str() } else { model.id.as_str() };
                for from in from_values {
                    for to in &to_values {
                        let mut properties = fact(&[graph.id(from).to_owned(), graph.id(*to).to_owned()], "high");
                        properties.push(pass2::text_field("summary_kind",
                            if model.kind.is_empty() { "flow" } else { model.kind.as_str() }));
                        properties.push(pass2::text_field("catalog_model_id", model_id));
                        edges.push(edge("VALUE_FLOWS_TO", graph.id(from), graph.id(*to), properties));
                    }
                }
                continue;
            }
            if !matches!(model.role.as_str(), "source" | "sink") { continue; }
            let values = endpoint_values(model.access_path.trim(), call, &arguments, &call_results, graph);
            let role = model.role.as_str();
            let model_id = if model.id.is_empty() { model.method.as_str() } else { model.id.as_str() };
            let kind = if role == "source" { "source" } else { "sink" };
            let semantic_kind = if model.kind.is_empty() { model_id } else { model.kind.as_str() };
            for value in values {
                let id = pass2::stable_id("catalog", role, "endpoint",
                    &[graph.id(call.id), model_id, model.access_path.as_str(), graph.id(value)]);
                let mut properties = fact(&[graph.id(call.id).to_owned()], "high");
                properties.push(pass2::text_field("value_id", graph.id(value)));
                properties.push(pass2::text_field(if role == "source" { "source_kind" } else { "sink_kind" }, semantic_kind));
                properties.push(pass2::text_field("catalog_model_id", model_id));
                nodes.push(graph_proto::NodeRecord { id: id.clone(), kind: kind.to_owned(),
                    label: format!("{}:{}", role, callee), properties, tier: String::new() });
                edges.push(edge(if role == "source" { "TAINT_SOURCE" } else { "TAINT_SINK" },
                    &id, graph.id(value), fact(&[graph.id(value).to_owned()], "high")));
            }
        }
    }
    Delta { nodes, edges }
}

pub(crate) fn enrich(graph: &Graph) -> Delta {
    let mut adjacency: FxHashMap<u32, Vec<(u32, String, Option<String>, Option<String>)>> = FxHashMap::default();
    let mut evidence: FxHashMap<(u32, u32), Vec<String>> = FxHashMap::default();
    for item in &graph.edges {
        let kind = graph.edge_kind(item);
        if !FLOW_KINDS.contains(&kind) { continue; }
        let transition = kind.to_owned();
        let reason = graph.edge_property_text(item, "reason").map(str::to_owned);
        let context_id = graph.edge_property_text(item, "context_id").map(str::to_owned);
        adjacency.entry(item.source).or_default().push((item.target, transition, reason, context_id));
        evidence.entry((item.source, item.target)).or_insert_with(|| vec![
            graph.id(item.source).to_owned(), graph.id(item.target).to_owned(),
        ]);
    }

    // Port the old C return-value overlay generically.  A resolved function
    // return and a resolved callsite share the function endpoint; the value
    // returned by the callee therefore reaches the caller's call node.  This
    // is a structural fact and applies equally to every frontend that emits
    // these neutral edge kinds.
    let mut returns_by_function: FxHashMap<u32, Vec<u32>> = FxHashMap::default();
    let mut calls_by_function: FxHashMap<u32, Vec<u32>> = FxHashMap::default();
    for item in &graph.edges {
        match graph.edge_kind(item) {
            "RETURNS_VALUE" => returns_by_function.entry(item.target).or_default().push(item.source),
            "INVOKES" => calls_by_function.entry(item.target).or_default().push(item.source),
            _ => {}
        }
    }
    for (function, returned_values) in returns_by_function {
        let Some(calls) = calls_by_function.get(&function) else { continue };
        for returned in returned_values {
            for call in calls {
                adjacency.entry(returned).or_default()
                    .push((*call, "VALUE_FLOWS_TO".to_owned(),
                           Some("c-return-to-callsite".to_owned()), None));
                evidence.entry((returned, *call)).or_insert_with(|| vec![
                    graph.id(returned).to_owned(), graph.id(*call).to_owned(),
                ]);
            }
        }
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

    // Port the old out-parameter writeback overlay.  Only values that the
    // Atropos catalog actually marked as source arguments are reversed.  The
    // endpoint can be an AST wrapper, so resolve its descendant reference to
    // the variable structurally rather than relying on a function/API name.
    for source in &source_records {
        for variable in referenced_variables(graph, source.value) {
            adjacency.entry(source.value).or_default()
                .push((variable, "VALUE_FLOWS_TO".to_owned(),
                       Some("c-out-param-writeback".to_owned()), None));
            evidence.entry((source.value, variable)).or_insert_with(|| vec![
                graph.id(source.value).to_owned(), graph.id(variable).to_owned(),
            ]);
        }
    }
    // The same structural aliases are needed on the sink side when a call
    // argument is an AST wrapper around a reference.  This keeps the source
    // variable connected to the exact catalog sink endpoint.
    for sink in &sink_records {
        for variable in referenced_variables(graph, sink.value) {
            adjacency.entry(variable).or_default()
                .push((sink.value, "VALUE_FLOWS_TO".to_owned(),
                       Some("referenced-variable".to_owned()), None));
            evidence.entry((variable, sink.value)).or_insert_with(|| vec![
                graph.id(variable).to_owned(), graph.id(sink.value).to_owned(),
            ]);
        }
    }

    // A context-specific transition is a distinct fact even when its endpoints
    // match another flow.  Collapsing on only (source, target) loses call-stack
    // evidence and changes the query-visible graph.
    let mut emitted: HashSet<(u32, u32, Option<String>)> = HashSet::new();
    for source in source_records {
        let initial = State { value: source.value, contexts: Vec::new() };
        let mut queue = VecDeque::from([initial.clone()]);
        let mut seen: HashSet<State> = HashSet::new();
        seen.insert(initial.clone());
        let mut predecessor: HashMap<State, State> = HashMap::new();
        let sink_by_value: FxHashMap<u32, &RoleRecord> = sink_records.iter()
            .map(|record| (record.value, record)).collect();
        let mut reaches: FxHashMap<u32, State> = FxHashMap::default();
        while let Some(state) = queue.pop_front() {
            if seen.len() > MAX_STATES_PER_SOURCE { break; }
            if state != initial && sink_by_value.contains_key(&state.value) {
                reaches.entry(state.value).or_insert_with(|| state.clone());
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
                let key = (state.value, *target, context_id.clone());
                if emitted.insert(key) {
                    let source_name = graph.id(state.value).to_owned();
                    let target_name = graph.id(*target).to_owned();
                    let fallback = vec![source_name.clone(), target_name.clone()];
                    let mut properties = fact(evidence.get(&(state.value, *target)).unwrap_or(&fallback), "high");
                    properties.push(pass2::text_field("transition", transition));
                    if let Some(context) = context_id {
                        properties.push(pass2::text_field("context_id", context));
                    }
                    output_edges.push(edge("TAINT_FLOWS_TO", &source_name, &target_name, properties));
                }
            }
        }
        for sink_state in reaches.into_values() {
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
