//! Native module singleton/state and import-cycle inference.

use hashbrown::{HashMap, HashSet};
use crate::graph_proto;
use crate::pass2::{self, Delta, Graph};

fn text<'a>(graph: &'a Graph, node: &'a pass2::Node, key: &str) -> Option<&'a str> { graph.node_property_text(node, key) }
fn integer(graph: &Graph, node: &pass2::Node, key: &str) -> Option<i64> { graph.node_property_i64(node, key) }
fn bool_value(graph: &Graph, node: &pass2::Node, key: &str) -> Option<bool> { graph.node_property_bool(node, key) }
fn fact(evidence: &[String], confidence: &str) -> Vec<graph_proto::Field> {
    let values = evidence.iter().map(|value| graph_proto::Value { kind: Some(graph_proto::value::Kind::Text(value.clone())) }).collect();
    vec![pass2::text_field("fact_origin", "core-inference"), pass2::text_field("confidence", confidence), graph_proto::Field { key: "evidence_ids".to_owned(), value: Some(graph_proto::Value { kind: Some(graph_proto::value::Kind::List(graph_proto::ListValue { values })) }) }]
}
fn node(id: String, kind: &str, label: String, properties: Vec<graph_proto::Field>) -> graph_proto::NodeRecord { graph_proto::NodeRecord { id, kind: kind.to_owned(), label, properties, tier: String::new() } }
fn edge(kind: &str, source: &str, target: &str, properties: Vec<graph_proto::Field>) -> graph_proto::EdgeRecord { graph_proto::EdgeRecord { kind: kind.to_owned(), source: source.to_owned(), target: target.to_owned(), properties, source_tier: String::new(), relationship_class: String::new() } }

fn strongly_connected(graph: &HashMap<u32, Vec<u32>>) -> Vec<Vec<u32>> {
    fn visit(node: u32, graph: &HashMap<u32, Vec<u32>>, seen: &mut HashSet<u32>, order: &mut Vec<u32>) {
        if !seen.insert(node) { return; }
        for target in graph.get(&node).into_iter().flatten() { visit(*target, graph, seen, order); }
        order.push(node);
    }
    let mut reverse: HashMap<u32, Vec<u32>> = HashMap::new();
    for (source, targets) in graph { for target in targets { reverse.entry(*target).or_default().push(*source); } }
    let mut seen = HashSet::new(); let mut order = Vec::new();
    for node in graph.keys() { visit(*node, graph, &mut seen, &mut order); }
    fn collect(node: u32, graph: &HashMap<u32, Vec<u32>>, seen: &mut HashSet<u32>, component: &mut Vec<u32>) {
        if !seen.insert(node) { return; }
        component.push(node);
        for target in graph.get(&node).into_iter().flatten() { collect(*target, graph, seen, component); }
    }
    seen.clear(); let mut components = Vec::new();
    while let Some(node) = order.pop() {
        if seen.contains(&node) { continue; }
        let mut component = Vec::new(); collect(node, &reverse, &mut seen, &mut component);
        if component.len() > 1 || graph.get(&node).is_some_and(|targets| targets.contains(&node)) { component.sort_unstable(); components.push(component); }
    }
    components
}

pub(crate) fn enrich(graph: &Graph) -> Delta {
    let mut file_by_value = HashMap::new();
    let mut exports = HashSet::new();
    let mut definitions: HashMap<u32, Vec<u32>> = HashMap::new();
    let mut writes: HashMap<u32, Vec<u32>> = HashMap::new();
    let mut values_by_source: HashMap<u32, Vec<u32>> = HashMap::new();
    let mut dependencies: HashMap<u32, Vec<u32>> = HashMap::new();
    for node in &graph.nodes { if graph.kind(node.kind) == "file" { dependencies.entry(node.id).or_default(); } }
    for item in &graph.edges {
        match graph.edge_kind(item) {
            "DECLARES_VALUE" => if graph.node_by_id.get(&item.source).is_some_and(|index| graph.kind(graph.nodes[*index].kind) == "file") { file_by_value.insert(item.target, item.source); },
            "EXPORTS" => { exports.insert(item.target); }
            "DEFINES" => { definitions.entry(item.source).or_default().push(item.target); }
            "WRITES_TO" => { writes.entry(item.target).or_default().push(item.source); }
            "VALUE_FLOWS_TO" => { values_by_source.entry(item.source).or_default().push(item.target); }
            "DEPENDS_ON" | "RUNTIME_DEPENDS_ON" | "RE_EXPORTS" => if dependencies.contains_key(&item.source) && dependencies.contains_key(&item.target) { dependencies.entry(item.source).or_default().push(item.target); },
            _ => {}
        }
    }
    let mut sources_by_variable: HashMap<u32, Vec<u32>> = HashMap::new();
    for source in graph.nodes.iter().filter(|node| matches!(graph.kind(node.kind), "allocation" | "call-value")) {
        if graph.kind(source.kind) == "call-value" && text(graph, source, "value_category") == Some("primitive") { continue; }
        let mut frontier = vec![source.id]; let mut seen: HashSet<u32> = HashSet::from_iter([source.id]);
        for _ in 0..3 {
            let mut next = Vec::new();
            for current in frontier {
                for target in values_by_source.get(&current).into_iter().flatten() {
                    if !seen.insert(*target) { continue; }
                    let is_variable = graph.node_by_id.get(target).is_some_and(|index| graph.kind(graph.nodes[*index].kind) == "variable");
                    if is_variable && file_by_value.contains_key(target) { sources_by_variable.entry(*target).or_default().push(source.id); } else { next.push(*target); }
                }
            }
            frontier = next;
        }
    }
    let mut nodes = Vec::new(); let mut edges = Vec::new();
    for variable in graph.nodes.iter().filter(|node| graph.kind(node.kind) == "variable") {
        let Some(file_id) = file_by_value.get(&variable.id).copied() else { continue };
        let mut source_ids = sources_by_variable.get(&variable.id).cloned().unwrap_or_default(); source_ids.sort_unstable(); source_ids.dedup();
        let exported = exports.contains(&variable.id);
        for source_id in source_ids {
            let source = &graph.nodes[graph.node_by_id[&source_id]]; let source_text = graph.id(source_id).to_owned(); let variable_text = graph.id(variable.id).to_owned(); let file_text = graph.id(file_id).to_owned();
            let singleton_id = pass2::stable_id("core", "module-initialization", "singleton", &[&variable_text, &source_text]);
            let evidence = vec![file_text.clone(), variable_text.clone(), source_text.clone()];
            let mut properties = fact(&evidence, "high"); properties.extend([pass2::text_field("file_id", &file_text), pass2::text_field("symbol_id", &variable_text), pass2::text_field("value_source_id", &source_text), pass2::text_field("singleton_kind", if graph.kind(source.kind) == "call-value" { "factory" } else { text(graph, source, "allocation_kind").unwrap_or("allocation") })]);
            if let Some(value) = text(graph, source, "allocated_type").or_else(|| text(graph, source, "type")) { properties.push(pass2::text_field("allocated_type", value)); }
            if exported { properties.push(pass2::bool_field("exported", true)); }
            nodes.push(node(singleton_id.clone(), "singleton", variable.label.clone(), properties));
            let f = fact(&evidence, "high"); edges.push(edge("HAS_SINGLETON", &file_text, &singleton_id, f.clone())); edges.push(edge("SINGLETON_OF", &singleton_id, &variable_text, f));
        }
        let later = definitions.get(&variable.id).into_iter().flatten().filter(|id| graph.node_by_id.get(id).and_then(|index| integer(graph, &graph.nodes[*index], "version")) .unwrap_or(0) > 0).count() > 0;
        let non_initializer = writes.get(&variable.id).into_iter().flatten().any(|id| graph.node_by_id.get(id).and_then(|index| text(graph, &graph.nodes[*index], "write_kind")) != Some("initializer"));
        let mutable_source = sources_by_variable.get(&variable.id).into_iter().flatten().any(|id| graph.node_by_id.get(id).is_some_and(|index| matches!(text(graph, &graph.nodes[*index], "allocation_kind"), Some("object" | "array" | "class-instance"))));
        let binding = text(graph, variable, "symbol_kind");
        let state_kind = if matches!(binding, Some("let" | "var")) { Some("reassignable") } else if later || non_initializer { Some("mutated") } else if mutable_source { Some("mutable-allocation") } else { None };
        let Some(state_kind) = state_kind else { continue };
        let mut evidence = vec![graph.id(file_id).to_owned(), graph.id(variable.id).to_owned()]; evidence.extend(definitions.get(&variable.id).into_iter().flatten().map(|id| graph.id(*id).to_owned())); evidence.extend(writes.get(&variable.id).into_iter().flatten().map(|id| graph.id(*id).to_owned()));
        let state_id = pass2::stable_id("core", "module-initialization", "module-state", &[graph.id(variable.id)]); let state_fact = fact(&evidence, "high");
        let mut properties = state_fact.clone(); properties.extend([pass2::text_field("file_id", graph.id(file_id)), pass2::text_field("symbol_id", graph.id(variable.id)), pass2::text_field("state_kind", state_kind)]); if let Some(binding) = binding { properties.push(pass2::text_field("binding_kind", binding)); } if exported { properties.push(pass2::bool_field("exported", true)); }
        nodes.push(node(state_id.clone(), "module-state", variable.label.clone(), properties)); edges.push(edge("HAS_MODULE_STATE", graph.id(file_id), &state_id, state_fact.clone())); edges.push(edge("STATE_OF", &state_id, graph.id(variable.id), state_fact));
    }
    for component in strongly_connected(&dependencies) {
        let member_ids: Vec<String> = component.iter().map(|id| graph.id(*id).to_owned()).collect(); let cycle_id = pass2::stable_id("core", "module-initialization", "import-cycle", &member_ids.iter().map(String::as_str).collect::<Vec<_>>()); let mut properties = fact(&member_ids, "exact"); properties.push(list_field("member_file_ids", &member_ids)); properties.push(pass2::integer_field("size", member_ids.len() as i64)); nodes.push(node(cycle_id.clone(), "import-cycle", format!("import cycle ({} modules)", member_ids.len()), properties.clone())); for member in member_ids { edges.push(edge("PARTICIPATES_IN_IMPORT_CYCLE", &member, &cycle_id, properties.clone())); }
    }
    Delta { nodes, edges }
}

fn list_field(key: &str, values: &[String]) -> graph_proto::Field {
    graph_proto::Field { key: key.to_owned(), value: Some(graph_proto::Value { kind: Some(graph_proto::value::Kind::List(graph_proto::ListValue { values: values.iter().map(|value| graph_proto::Value { kind: Some(graph_proto::value::Kind::Text(value.clone())) }).collect() })) }) }
}
