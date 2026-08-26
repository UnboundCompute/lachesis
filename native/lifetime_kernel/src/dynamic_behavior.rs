//! Native dynamic-runtime boundary overlay.
//!
//! This is intentionally additive: unresolved calls get a behavior node and
//! every behavior gets a boundary plus input edges.  All graph lookups use the
//! interned Pass-2 graph; strings are materialized only in the protobuf delta.

use hashbrown::{HashMap, HashSet};

use crate::graph_proto;
use crate::pass2::{self, Delta, Graph};

fn value_text(value: &graph_proto::Value) -> Option<&str> {
    match value.kind.as_ref()? {
        graph_proto::value::Kind::Text(value) => Some(value),
        _ => None,
    }
}

fn node_property<'a>(node: &'a pass2::Node, key: &str) -> Option<&'a graph_proto::Value> {
    node.properties.iter().find_map(|field| {
        (field.key == key).then(|| field.value.as_ref()).flatten()
    })
}

fn text_property<'a>(node: &'a pass2::Node, key: &str) -> Option<&'a str> {
    node_property(node, key).and_then(value_text)
}

fn fact(evidence: &[String], confidence: &str) -> Vec<graph_proto::Field> {
    vec![
        pass2::text_field("fact_origin", "core-inference"),
        pass2::text_field("confidence", confidence),
        graph_proto::Field {
            key: "evidence_ids".to_owned(),
            value: Some(graph_proto::Value {
                kind: Some(graph_proto::value::Kind::List(graph_proto::ListValue {
                    values: evidence.iter().map(|id| graph_proto::Value {
                        kind: Some(graph_proto::value::Kind::Text(id.clone())),
                    }).collect(),
                })),
            }),
        },
    ]
}

fn node(id: String, kind: &str, label: String, properties: Vec<graph_proto::Field>)
    -> graph_proto::NodeRecord
{
    graph_proto::NodeRecord {
        id, kind: kind.to_owned(), label, properties, tier: String::new(),
    }
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
    let mut explicit_by_site: HashMap<u32, Vec<usize>> = HashMap::new();
    let mut arguments_by_call: HashMap<u32, Vec<u32>> = HashMap::new();
    let mut behavior_indices = Vec::new();

    for (index, item) in graph.nodes.iter().enumerate() {
        let kind = graph.kind(item.kind);
        if kind == "dynamic-behavior" {
            behavior_indices.push(index);
            if let Some(site) = text_property(item, "site_id").and_then(|id| graph.symbol(id)) {
                explicit_by_site.entry(site).or_default().push(index);
            }
        } else if kind == "argument" {
            if let Some(call) = text_property(item, "callsite_id").and_then(|id| graph.symbol(id)) {
                arguments_by_call.entry(call).or_default().push(item.id);
            }
        }
    }

    let mut nodes = Vec::new();
    let mut edges = Vec::new();
    let mut generated_by_site: HashMap<u32, String> = HashMap::new();

    for item in &graph.nodes {
        if !matches!(graph.kind(item.kind), "call" | "construct") { continue; }
        let call_index = match graph.node_by_id.get(&item.id).copied() { Some(v) => v, None => continue };
        let resolved = graph.outgoing[call_index].iter().any(|edge_index| {
            matches!(graph.edge_kind(&graph.edges[*edge_index]), "INVOKES" | "MAY_INVOKE")
        });
        if resolved || explicit_by_site.contains_key(&item.id) { continue; }

        let call_id = graph.id(item.id).to_owned();
        let behavior_id = pass2::stable_id("core", "dynamic-behavior", "dynamic-behavior", &["unresolved-call", &call_id]);
        let properties = vec![
            pass2::text_field("fact_origin", "core-inference"),
            pass2::text_field("confidence", "unresolved"),
            graph_proto::Field { key: "evidence_ids".to_owned(), value: Some(graph_proto::Value {
                kind: Some(graph_proto::value::Kind::List(graph_proto::ListValue {
                    values: vec![graph_proto::Value { kind: Some(graph_proto::value::Kind::Text(call_id.clone())) }],
                })),
            }) },
            pass2::text_field("behavior_kind", "unresolved-call"),
            pass2::text_field("site_id", &call_id),
            pass2::text_field("resolution", text_property(item, "resolution").unwrap_or("unresolved")),
        ];
        nodes.push(node(behavior_id.clone(), "dynamic-behavior", "unresolved-call".to_owned(), properties));
        edges.push(edge("DYNAMIC_BEHAVIOR_AT", &behavior_id, &call_id, fact(&[call_id.clone()], "unresolved")));
        explicit_by_site.entry(item.id).or_default().push(usize::MAX);
        generated_by_site.insert(item.id, behavior_id);
    }

    // Process original behaviors. Generated behaviors are processed inline so
    // they do not require mutating the graph or rebuilding its indexes.
    for index in behavior_indices {
        let (behavior_text, site_id, behavior_kind, confidence, key_value, target) = if index == usize::MAX {
            unreachable!("generated behavior records are processed below")
        } else {
            let item = &graph.nodes[index];
            let site = text_property(item, "site_id").and_then(|id| graph.symbol(id))
                .or_else(|| graph.outgoing[graph.node_by_id[&item.id]].iter().find_map(|edge_index| {
                    let e = &graph.edges[*edge_index];
                    (graph.edge_kind(e) == "DYNAMIC_BEHAVIOR_AT").then_some(e.target)
                }));
            (graph.id(item.id).to_owned(), site, text_property(item, "behavior_kind").unwrap_or(graph.id(item.kind)),
             text_property(item, "confidence").unwrap_or("unresolved"),
             text_property(item, "key_value_id"), text_property(item, "target_id"))
        };
        let site_text = site_id.map(|id| graph.id(id).to_owned());
        let mut evidence = vec![behavior_text.clone()];
        if let Some(site) = &site_text { evidence.push(site.clone()); }
        let boundary_id = pass2::stable_id("core", "dynamic-behavior", "boundary", &[&behavior_text]);
        let boundary_fact = fact(&evidence, confidence);
        nodes.push(node(boundary_id.clone(), "boundary", format!("dynamic:{behavior_kind}"), vec![
            pass2::text_field("fact_origin", "core-inference"),
            pass2::text_field("confidence", confidence),
            pass2::text_field("boundary_kind", "dynamic-runtime"),
            pass2::text_field("behavior_id", &behavior_text),
            site_text.as_ref().map(|value| pass2::text_field("site_id", value)).unwrap_or_else(|| pass2::text_field("site_id", "")),
        ]));
        edges.push(edge("EVIDENCED_BY", &boundary_id, &behavior_text, boundary_fact.clone()));

        let mut inputs = arguments_by_call.get(&site_id.unwrap_or(0)).cloned().unwrap_or_default();
        for value in [key_value, target].into_iter().flatten() {
            if let Some(symbol) = graph.symbol(value) { inputs.push(symbol); }
        }
        let mut seen = HashSet::new();
        for input in inputs {
            if seen.insert(input) {
                edges.push(edge("DYNAMIC_INPUT", graph.id(input), &behavior_text,
                    [boundary_fact.clone(), vec![pass2::text_field("boundary_id", &boundary_id)]].concat()));
            }
        }
    }

    for (site_id, behavior_text) in generated_by_site {
        let site_text = graph.id(site_id).to_owned();
        let evidence = vec![behavior_text.clone(), site_text.clone()];
        let boundary_id = pass2::stable_id("core", "dynamic-behavior", "boundary", &[&behavior_text]);
        let boundary_fact = fact(&evidence, "unresolved");
        nodes.push(node(boundary_id.clone(), "boundary", "dynamic:unresolved-call".to_owned(), vec![
            pass2::text_field("fact_origin", "core-inference"),
            pass2::text_field("confidence", "unresolved"),
            pass2::text_field("boundary_kind", "dynamic-runtime"),
            pass2::text_field("behavior_id", &behavior_text),
            pass2::text_field("site_id", &site_text),
        ]));
        edges.push(edge("EVIDENCED_BY", &boundary_id, &behavior_text, boundary_fact.clone()));
        let mut seen = HashSet::new();
        for input in arguments_by_call.get(&site_id).cloned().unwrap_or_default() {
            if seen.insert(input) {
                edges.push(edge("DYNAMIC_INPUT", graph.id(input), &behavior_text,
                    [boundary_fact.clone(), vec![pass2::text_field("boundary_id", &boundary_id)]].concat()));
            }
        }
    }
    Delta { nodes, edges }
}
