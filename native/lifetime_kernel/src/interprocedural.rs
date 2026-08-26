//! Native context-specific argument/parameter/return bindings.

use hashbrown::{HashMap, HashSet};
use crate::graph_proto;
use crate::pass2::{self, Delta, Graph};

fn text<'a>(node: &'a pass2::Node, key: &str) -> Option<&'a str> {
    node.properties.iter().find_map(|field| {
        if field.key != key { return None; }
        match field.value.as_ref()?.kind.as_ref()? {
            graph_proto::value::Kind::Text(value) => Some(value.as_str()), _ => None,
        }
    })
}
fn integer(node: &pass2::Node, key: &str) -> Option<i64> {
    node.properties.iter().find_map(|field| {
        if field.key != key { return None; }
        match field.value.as_ref()?.kind.as_ref()? {
            graph_proto::value::Kind::Integer(value) => Some(*value), _ => None,
        }
    })
}
fn edge_text<'a>(edge: &'a pass2::Edge, key: &str) -> Option<&'a str> {
    edge.properties.iter().find_map(|field| {
        if field.key != key { return None; }
        match field.value.as_ref()?.kind.as_ref()? {
            graph_proto::value::Kind::Text(value) => Some(value.as_str()), _ => None,
        }
    })
}
fn edge_integer(edge: &pass2::Edge, key: &str) -> Option<i64> {
    edge.properties.iter().find_map(|field| {
        if field.key != key { return None; }
        match field.value.as_ref()?.kind.as_ref()? {
            graph_proto::value::Kind::Integer(value) => Some(*value), _ => None,
        }
    })
}
fn list_field(key: &str, values: &[String]) -> graph_proto::Field {
    graph_proto::Field { key: key.to_owned(), value: Some(graph_proto::Value { kind: Some(
        graph_proto::value::Kind::List(graph_proto::ListValue { values: values.iter().map(|v| graph_proto::Value {
            kind: Some(graph_proto::value::Kind::Text(v.clone())) }).collect() })
    ) }) }
}
fn fact(evidence: &[String], confidence: &str) -> Vec<graph_proto::Field> {
    vec![pass2::text_field("fact_origin", "core-inference"), pass2::text_field("confidence", confidence), list_field("evidence_ids", evidence)]
}
fn node(id: String, kind: &str, label: String, properties: Vec<graph_proto::Field>) -> graph_proto::NodeRecord {
    graph_proto::NodeRecord { id, kind: kind.to_owned(), label, properties, tier: String::new() }
}
fn edge(kind: &str, source: &str, target: &str, properties: Vec<graph_proto::Field>) -> graph_proto::EdgeRecord {
    graph_proto::EdgeRecord { kind: kind.to_owned(), source: source.to_owned(), target: target.to_owned(), properties, source_tier: String::new(), relationship_class: String::new() }
}

pub(crate) fn enrich(graph: &Graph) -> Delta {
    let mut arguments_by_call: HashMap<u32, Vec<u32>> = HashMap::new();
    let mut parameter_defs: HashMap<u32, Vec<u32>> = HashMap::new();
    let mut returns_by_function: HashMap<u32, Vec<u32>> = HashMap::new();
    let mut bindings_by_call: HashMap<u32, Vec<usize>> = HashMap::new();
    for node in &graph.nodes {
        if graph.kind(node.kind) == "argument" {
            if let Some(call) = text(node, "callsite_id").and_then(|id| graph.symbol(id)) { arguments_by_call.entry(call).or_default().push(node.id); }
        }
    }
    for (edge_index, item) in graph.edges.iter().enumerate() {
        match graph.edge_kind(item).as_str() {
            "RETURNS_VALUE" => { returns_by_function.entry(item.target).or_default().push(item.source); }
            "ARGUMENT_BINDS_PARAMETER" => {
                if let Some(argument) = graph.node_by_id.get(&item.source).map(|index| &graph.nodes[*index]) {
                    if let Some(call) = text(argument, "callsite_id").and_then(|id| graph.symbol(id)) {
                        bindings_by_call.entry(call).or_default().push(edge_index);
                    }
                }
            }
            "DEFINES" => {
                let target = graph.node_by_id.get(&item.target).map(|index| &graph.nodes[*index]);
                if target.is_some_and(|node| text(node, "origin") == Some("parameter")) { parameter_defs.entry(item.source).or_default().push(item.target); }
            }
            _ => {}
        }
    }
    let mut nodes = Vec::new(); let mut edges = Vec::new(); let mut emitted = HashSet::new();
    for call in &graph.nodes {
        if !matches!(graph.kind(call.kind), "call" | "construct") { continue; }
        let targets: Vec<u32> = graph.outgoing[graph.node_by_id[&call.id]].iter().filter_map(|edge_index| {
            let item = &graph.edges[*edge_index];
            (matches!(graph.edge_kind(item).as_str(), "INVOKES" | "MAY_INVOKE") && graph.node_by_id.contains_key(&item.target)).then_some(item.target)
        }).collect::<HashSet<_>>().into_iter().collect();
        let contextual_targets = if targets.is_empty() { vec![None] } else { targets.into_iter().map(Some).collect() };
        let call_id = graph.id(call.id).to_owned();
        for target in contextual_targets {
            let target_id = target.map(|id| graph.id(id).to_owned());
            let context_id = pass2::stable_id("core", "interprocedural-contexts", "call-context", &[&call_id, target_id.as_deref().unwrap_or("unresolved")]);
            if !emitted.insert(context_id.clone()) { continue; }
            let confidence = if target_id.is_some() { "exact" } else { "unresolved" };
            let mut evidence = vec![call_id.clone()]; if let Some(id) = &target_id { evidence.push(id.clone()); }
            let context_fact = fact(&evidence, confidence);
            let label = format!("context:{}", call.label);
            nodes.push(node(context_id.clone(), "call-context", label, [context_fact.clone(), vec![pass2::text_field("callsite_id", &call_id)], target_id.as_ref().map(|id| vec![pass2::text_field("callee_function_id", id)]).unwrap_or_default()].concat()));
            edges.push(edge("HAS_CALL_CONTEXT", &call_id, &context_id, context_fact.clone()));
            if let Some(target_id) = &target_id { edges.push(edge("CONTEXT_CALLS", &context_id, target_id, context_fact.clone())); }
            for edge_index in bindings_by_call.get(&call.id).into_iter().flatten() {
                let binding = &graph.edges[*edge_index];
                let parameter_id = binding.target;
                let Some(parameter) = graph.node_by_id.get(&parameter_id).map(|index| &graph.nodes[*index]) else { continue };
                if let Some(target) = target { if text(parameter, "owner_function_id").and_then(|id| graph.symbol(id)) != Some(target) { continue; } }
                let argument_id = binding.source;
                let argument_text = graph.id(argument_id).to_owned(); let parameter_text = graph.id(parameter_id).to_owned();
                let binding_id = pass2::stable_id("core", "interprocedural-contexts", "context-parameter", &[&context_id, &argument_text, &parameter_text]);
                let binding_evidence = vec![call_id.clone(), argument_text.clone(), parameter_text.clone()];
                let binding_fact = fact(&binding_evidence, "exact");
                let mut properties = [binding_fact.clone(), vec![pass2::text_field("context_id", &context_id), pass2::text_field("callsite_id", &call_id), pass2::text_field("argument_id", &argument_text), pass2::text_field("parameter_id", &parameter_text)]].concat();
                if let Some(position) = edge_integer(binding, "position") { properties.push(pass2::integer_field("position", position)); }
                nodes.push(node(binding_id.clone(), "context-parameter", format!("{} → {}", call.label, parameter.label), properties));
                edges.push(edge("BINDS_PARAMETER", &argument_text, &binding_id, binding_fact.clone()));
                edges.push(edge("CONTEXTUALIZES", &binding_id, &parameter_text, binding_fact.clone()));
                edges.push(edge("VALUE_FLOWS_TO", &argument_text, &binding_id, [binding_fact.clone(), vec![pass2::text_field("reason", "context-argument")]].concat()));
                for definition in parameter_defs.get(&parameter_id).into_iter().flatten() {
                    let definition_text = graph.id(*definition).to_owned();
                    edges.push(edge("VALUE_FLOWS_TO", &binding_id, &definition_text, [binding_fact.clone(), vec![pass2::text_field("reason", "context-parameter"), pass2::text_field("context_id", &context_id)]].concat()));
                }
            }
            let Some(call_value) = text(call, "value_id").and_then(|id| graph.symbol(id)) else { continue };
            let call_value_text = graph.id(call_value).to_owned();
            let return_id = pass2::stable_id("core", "interprocedural-contexts", "context-return", &[&context_id, &call_value_text]);
            let mut return_evidence = vec![call_id.clone(), call_value_text.clone()];
            return_evidence.extend(target.and_then(|id| returns_by_function.get(&id)).into_iter().flatten().map(|id| graph.id(*id).to_owned()));
            let return_fact = fact(&return_evidence, confidence);
            nodes.push(node(return_id.clone(), "context-return", format!("return:{}", call.label), [return_fact.clone(), vec![pass2::text_field("context_id", &context_id), pass2::text_field("callsite_id", &call_id), pass2::text_field("call_value_id", &call_value_text)]].concat()));
            edges.push(edge("CONTEXT_RETURNS", &context_id, &return_id, return_fact.clone()));
            if let Some(target) = target { for source in returns_by_function.get(&target).into_iter().flatten() { let source_text = graph.id(*source).to_owned(); edges.push(edge("VALUE_FLOWS_TO", &source_text, &return_id, [return_fact.clone(), vec![pass2::text_field("reason", "context-return"), pass2::text_field("context_id", &context_id)]].concat())); } }
            edges.push(edge("VALUE_FLOWS_TO", &return_id, &call_value_text, [return_fact, vec![pass2::text_field("reason", "context-call-result"), pass2::text_field("context_id", &context_id)]].concat()));
        }
    }
    Delta { nodes, edges }
}
