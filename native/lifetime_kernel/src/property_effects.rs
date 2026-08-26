//! Native instantiation of parameter-property mutation summaries.

use hashbrown::{HashMap, HashSet};
use crate::graph_proto;
use crate::pass2::{self, Delta, Graph};

fn value_text(value: &graph_proto::Value) -> Option<&str> { match value.kind.as_ref()? { graph_proto::value::Kind::Text(value) => Some(value), _ => None } }
fn text<'a>(graph: &'a Graph, node: &'a pass2::Node, key: &str) -> Option<&'a str> { graph.node_property_text(node, key) }
fn integer(graph: &Graph, node: &pass2::Node, key: &str) -> Option<i64> { graph.node_property_i64(node, key) }
fn edge_integer(edge: &pass2::Edge, key: &str) -> Option<i64> { edge.properties.iter().find_map(|field| { if field.key != key { return None; } match field.value.as_ref()?.kind.as_ref()? { graph_proto::value::Kind::Integer(value) => Some(*value), _ => None } }) }
fn list_text(graph: &Graph, node: &pass2::Node, key: &str) -> Vec<String> {
    graph.node_property(node, key).and_then(|value| match value.kind.as_ref()? { graph_proto::value::Kind::List(list) => Some(list.values.iter().filter_map(value_text).map(str::to_owned).collect()), _ => None }).unwrap_or_default()
}
fn list_field(key: &str, values: &[String]) -> graph_proto::Field { graph_proto::Field { key: key.to_owned(), value: Some(graph_proto::Value { kind: Some(graph_proto::value::Kind::List(graph_proto::ListValue { values: values.iter().map(|value| graph_proto::Value { kind: Some(graph_proto::value::Kind::Text(value.clone())) }).collect() })) }) } }
fn fact(evidence: &[String]) -> Vec<graph_proto::Field> { vec![pass2::text_field("fact_origin", "core-inference"), pass2::text_field("confidence", "high"), list_field("evidence_ids", evidence)] }
fn node(id: String, kind: &str, label: String, properties: Vec<graph_proto::Field>) -> graph_proto::NodeRecord { graph_proto::NodeRecord { id, kind: kind.to_owned(), label, properties, tier: String::new() } }
fn edge(kind: &str, source: &str, target: &str, properties: Vec<graph_proto::Field>) -> graph_proto::EdgeRecord { graph_proto::EdgeRecord { kind: kind.to_owned(), source: source.to_owned(), target: target.to_owned(), properties, source_tier: String::new(), relationship_class: String::new() } }

pub(crate) fn enrich(graph: &Graph) -> Delta {
    let effects: Vec<&pass2::Edge> = graph.edges.iter().filter(|item| graph.edge_kind(item) == "WRITES_PARAMETER_PROPERTY").collect();
    if effects.is_empty() { return Delta { nodes: vec![], edges: vec![] }; }
    let mut nodes = Vec::new(); let mut edges = Vec::new(); let mut emitted_locations = HashSet::new(); let mut locations: HashMap<(u32, u32), (String, u32)> = HashMap::new();
    for effect in effects {
        let Some(receiver_position) = edge_integer(effect, "receiver_position").and_then(|value| usize::try_from(value).ok()) else { continue };
        let Some(value_position) = edge_integer(effect, "value_position").and_then(|value| usize::try_from(value).ok()) else { continue };
        let Some(effect_source) = graph.node_by_id.get(&effect.source).map(|index| &graph.nodes[*index]) else { continue };
        let property_id = effect.target;
        for call in graph.nodes.iter().filter(|node| matches!(graph.kind(node.kind), "call" | "construct")) {
            if text(graph, call, "primary_target_id").and_then(|id| graph.symbol(id)) != Some(effect.source) { continue; }
            let values = list_text(graph, call, "argument_value_ids"); if receiver_position >= values.len() || value_position >= values.len() { continue; }
            let Some(receiver_id) = graph.symbol(&values[receiver_position]) else { continue }; let Some(value_id) = graph.symbol(&values[value_position]) else { continue };
            let call_text = graph.id(call.id).to_owned(); let receiver_text = graph.id(receiver_id).to_owned(); let value_text = graph.id(value_id).to_owned(); let property_text = graph.id(property_id).to_owned(); let effect_text = graph.id(effect.source).to_owned();
            let location_id = pass2::stable_id("core", "parameter-property-effects", "heap-location", &[&call_text, &receiver_text, &property_text]);
            let location_fact = fact(&[call_text.clone(), property_text.clone(), receiver_text.clone()]);
            if emitted_locations.insert(location_id.clone()) {
                let label = format!("{}.{}", graph.nodes[graph.node_by_id[&receiver_id]].label, graph.node_by_id.get(&property_id).map(|index| &graph.nodes[*index].label).unwrap_or(&property_text));
                nodes.push(node(location_id.clone(), "heap-location", label, [location_fact.clone(), vec![pass2::text_field("receiver_value_id", &receiver_text), pass2::text_field("property_id", &property_text), pass2::text_field("callsite_id", &call_text), pass2::bool_field("context_sensitive", true)]].concat()));
            }
            locations.insert((receiver_id, property_id), (location_id.clone(), value_id));
            let write_fact = fact(&[call_text.clone(), effect_text.clone(), property_text.clone(), receiver_text.clone(), value_text.clone()]);
            edges.push(edge("APPLIES_EFFECT", &call_text, &location_id, [write_fact.clone(), vec![pass2::text_field("summary_function_id", &effect_text)]].concat()));
            edges.push(edge("POINTS_TO", &receiver_text, &location_id, [write_fact.clone(), vec![pass2::text_field("callsite_id", &call_text)]].concat()));
            edges.push(edge("WRITES_HEAP", &value_text, &location_id, [write_fact, vec![pass2::text_field("callsite_id", &call_text)]].concat()));
            let _ = effect_source;
        }
    }
    for call in graph.nodes.iter().filter(|node| graph.kind(node.kind) == "call") {
        let Some(receiver) = text(graph, call, "receiver_value_id").and_then(|id| graph.symbol(id)) else { continue };
        let Some(property) = text(graph, call, "receiver_member_id").and_then(|id| graph.symbol(id)) else { continue };
        let Some((location, target)) = locations.get(&(receiver, property)) else { continue };
        if !graph.node_by_id.contains_key(target) { continue; }
        let call_text = graph.id(call.id).to_owned(); let location_text = location.clone(); let target_text = graph.id(*target).to_owned(); let evidence = vec![call_text.clone(), location_text.clone(), target_text.clone()]; let f = fact(&evidence);
        edges.push(edge("READS_HEAP", &location_text, &call_text, f.clone())); edges.push(edge("MAY_INVOKE", &call_text, &target_text, [f, vec![pass2::text_field("resolution", "interprocedural-property-effect"), pass2::text_field("heap_location_id", &location_text)]].concat()));
    }
    Delta { nodes, edges }
}
