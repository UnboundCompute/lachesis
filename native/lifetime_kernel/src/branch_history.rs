//! Native branch-sensitive reaching definitions.
//!
//! The analysis mirrors the Python overlay's two solves: a raw reaching
//! definition pass identifies merge points, then a second pass includes the
//! generated phi definitions.  IDs stay interned until the protobuf boundary.

use hashbrown::HashSet;
use rustc_hash::{FxHashMap, FxHashSet};

use crate::graph_proto;
use crate::pass2::{self, Delta, Graph};

const CFG_KINDS: [&str; 5] = ["cfg-entry", "cfg-block", "cfg-condition", "cfg-merge", "cfg-exit"];
const CFG_EDGES: [&str; 9] = ["CFG_NEXT", "TRUE_BRANCH", "FALSE_BRANCH", "LOOP_BACK", "SWITCH_CASE", "EXCEPTION_BRANCH", "RUNS_FINALLY", "MERGES_AT", "EXECUTES_BEFORE"];

fn text<'a>(graph: &'a Graph, node: &'a pass2::Node, key: &str) -> Option<&'a str> {
    graph.node_property_text(node, key)
}
fn integer(graph: &Graph, node: &pass2::Node, key: &str) -> Option<i64> {
    graph.node_property_i64(node, key)
}
fn edge_text<'a>(graph: &'a Graph, edge: &'a pass2::Edge, key: &str) -> Option<&'a str> {
    graph.edge_property_text(edge, key)
}
fn list_field(key: &str, values: &[String]) -> graph_proto::Field {
    graph_proto::Field { key: key.to_owned(), value: Some(graph_proto::Value { kind: Some(
        graph_proto::value::Kind::List(graph_proto::ListValue { values: values.iter().map(|value| graph_proto::Value {
            kind: Some(graph_proto::value::Kind::Text(value.clone())) }).collect() })
    ) }) }
}
fn fact(evidence: &[String]) -> Vec<graph_proto::Field> {
    vec![pass2::text_field("fact_origin", "core-inference"), pass2::text_field("confidence", "high"), list_field("evidence_ids", evidence)]
}
fn node(id: String, kind: &str, label: String, properties: Vec<graph_proto::Field>) -> graph_proto::NodeRecord {
    graph_proto::NodeRecord { id, kind: kind.to_owned(), label, properties, tier: String::new() }
}
fn edge(kind: &str, source: &str, target: &str, mut properties: Vec<graph_proto::Field>) -> graph_proto::EdgeRecord {
    properties.shrink_to_fit();
    graph_proto::EdgeRecord { kind: kind.to_owned(), source: source.to_owned(), target: target.to_owned(), properties, source_tier: String::new(), relationship_class: String::new() }
}

fn merge_maps<'a>(maps: impl IntoIterator<Item = &'a FxHashMap<u32, FxHashSet<u32>>>) -> FxHashMap<u32, FxHashSet<u32>> {
    let mut result = FxHashMap::default();
    for map in maps {
        for (target, versions) in map {
            result.entry(*target).or_insert_with(FxHashSet::default).extend(versions);
        }
    }
    result
}

fn transfer(
    node: u32,
    incoming: &FxHashMap<u32, FxHashSet<u32>>,
    phis: &FxHashMap<u32, Vec<(u32, u32)>>,
    definitions: &FxHashMap<u32, Vec<(u32, u32)>>,
) -> FxHashMap<u32, FxHashSet<u32>> {
    let mut result = incoming.clone();
    for (target, phi) in phis.get(&node).into_iter().flatten() {
        result.insert(*target, FxHashSet::from_iter([*phi]));
    }
    for (target, definition) in definitions.get(&node).into_iter().flatten() {
        result.insert(*target, FxHashSet::from_iter([*definition]));
    }
    result
}

fn solve(
    entry: u32,
    owned: &FxHashSet<u32>,
    predecessors: &FxHashMap<u32, Vec<u32>>,
    successors: &FxHashMap<u32, Vec<u32>>,
    seed: &FxHashMap<u32, FxHashSet<u32>>,
    phis: &FxHashMap<u32, Vec<(u32, u32)>>,
    definitions: &FxHashMap<u32, Vec<(u32, u32)>>,
) -> (FxHashMap<u32, FxHashMap<u32, FxHashSet<u32>>>, FxHashMap<u32, FxHashMap<u32, FxHashSet<u32>>>) {
    let empty = FxHashMap::default();
    let mut incoming: FxHashMap<u32, FxHashMap<u32, FxHashSet<u32>>> = owned.iter().map(|id| (*id, empty.clone())).collect();
    let mut outgoing = incoming.clone();
    let mut queue = std::collections::VecDeque::from([entry]);
    let mut queued = FxHashSet::from_iter([entry]);
    while let Some(node) = queue.pop_front() {
        queued.remove(&node);
        let merged = merge_maps(predecessors.get(&node).into_iter().flatten().map(|pred| &outgoing[pred]).chain(std::iter::once(seed)));
        let new_out = transfer(node, &merged, phis, definitions);
        if incoming[&node] == merged && outgoing[&node] == new_out { continue; }
        incoming.insert(node, merged);
        outgoing.insert(node, new_out);
        for successor in successors.get(&node).into_iter().flatten() {
            if queued.insert(*successor) { queue.push_back(*successor); }
        }
    }
    (incoming, outgoing)
}

fn containing(
    graph: &Graph, ast_parent: &FxHashMap<u32, u32>,
    evidence_body: &FxHashMap<u32, u32>,
    intervals_by_function: &FxHashMap<u32, Vec<(i64, i64, u32)>>,
    event: u32, owner: u32,
) -> Option<u32> {
    let mut current = evidence_body.get(&event).copied();
    while let Some(item) = current {
        let index = graph.node_by_id.get(&item).copied()?;
        let node = &graph.nodes[index];
        if graph.kind(node.kind) == "statement"
            && graph.node_property_text(node, "owner_function_id")
                .and_then(|id| graph.symbol(id)) == Some(owner) { return Some(item); }
        current = ast_parent.get(&item).copied();
    }
    let index = graph.node_by_id.get(&event).copied()?;
    let node = &graph.nodes[index];
    let start = graph.node_property_i64(node, "start_offset")?;
    let end = graph.node_property_i64(node, "end_offset").unwrap_or(start);
    intervals_by_function.get(&owner).and_then(|items| items.iter()
        .filter(|(left, right, _)| *left <= start && *right >= end)
        .min_by_key(|(left, right, id)| (right - left, *left, *id))
        .map(|(_, _, id)| *id))
}

pub(crate) fn enrich(graph: &mut Graph) -> Delta {
    let mut ast_parent = FxHashMap::default();
    let mut evidence_body = FxHashMap::default();
    let mut cfg_nodes_by_function: FxHashMap<u32, FxHashSet<u32>> = FxHashMap::default();
    let mut entries_by_function: FxHashMap<u32, Vec<u32>> = FxHashMap::default();
    let mut node_function = FxHashMap::default();
    let mut cfg_edges_by_function: FxHashMap<u32, Vec<(u32, u32)>> = FxHashMap::default();
    let mut statements_by_function: FxHashMap<u32, Vec<usize>> = FxHashMap::default();
    let mut definitions_by_function: FxHashMap<u32, Vec<usize>> = FxHashMap::default();
    let mut reads_by_function: FxHashMap<u32, Vec<usize>> = FxHashMap::default();

    for (index, item) in graph.nodes.iter().enumerate() {
        let kind = graph.kind(item.kind);
        if kind == "statement" {
            if let Some(owner) = text(graph, item, "owner_function_id").and_then(|id| graph.symbol(id)) { statements_by_function.entry(owner).or_default().push(index); }
        } else if kind == "definition" {
            if let Some(owner) = text(graph, item, "owner_function_id").and_then(|id| graph.symbol(id)) { definitions_by_function.entry(owner).or_default().push(index); }
        } else if kind == "read" {
            if let Some(owner) = text(graph, item, "owner_function_id").and_then(|id| graph.symbol(id)) { reads_by_function.entry(owner).or_default().push(index); }
        }
        if CFG_KINDS.contains(&kind) {
            if let Some(owner) = text(graph, item, "function_id").and_then(|id| graph.symbol(id)) {
                cfg_nodes_by_function.entry(owner).or_default().insert(item.id);
                node_function.insert(item.id, owner);
                if kind == "cfg-entry" { entries_by_function.entry(owner).or_default().push(item.id); }
            }
        }
    }
    for item in &graph.edges {
        match graph.edge_kind(item) {
            "AST_CHILD" => { ast_parent.insert(item.target, item.source); }
            "READ_EVIDENCED_BY" | "EVIDENCED_BY" => { evidence_body.entry(item.source).or_insert(item.target); }
            kind if CFG_EDGES.contains(&kind) => {
                if let (Some(owner), Some(target_owner)) = (node_function.get(&item.source), node_function.get(&item.target)) {
                    if owner == target_owner { cfg_edges_by_function.entry(*owner).or_default().push((item.source, item.target)); }
                }
            }
            _ => {}
        }
    }

    let mut intervals_by_function: FxHashMap<u32, Vec<(i64, i64, u32)>> = FxHashMap::default();
    for (owner, statements) in &statements_by_function {
        let mut intervals = statements.iter().filter_map(|index| {
            let item = &graph.nodes[*index];
            Some((integer(graph, item, "start_offset")?, integer(graph, item, "end_offset")?, item.id))
        }).filter(|(left, right, _)| left <= right).collect::<Vec<_>>();
        intervals.sort_unstable_by_key(|item| (item.0, item.1, item.2));
        intervals_by_function.insert(*owner, intervals);
    }
    let mut nodes = Vec::new();
    let mut edges = Vec::new();
    let mut emitted = HashSet::new();
    let mut add_edge = |kind: &str, source: String, target: String, evidence: Vec<String>, extra: Vec<graph_proto::Field>| {
        if source.is_empty() || target.is_empty() || source == target { return; }
        if emitted.insert((kind.to_owned(), source.clone(), target.clone())) {
            edges.push(edge(kind, &source, &target, [fact(&evidence), extra].concat()));
        }
    };

    let function_indices: Vec<usize> = graph.nodes.iter().enumerate()
        .filter(|(_, node)| matches!(graph.kind(node.kind), "function" | "method" | "constructor"))
        .map(|(index, _)| index).collect();
    for function_index in function_indices {
        let function_id = graph.nodes[function_index].id;
        let Some(entry) = entries_by_function.get(&function_id).and_then(|entries| entries.first()).copied() else { continue };
        let mut owned = cfg_nodes_by_function.get(&function_id).cloned().unwrap_or_default();
        for statement in statements_by_function.get(&function_id).into_iter().flatten() { owned.insert(graph.nodes[*statement].id); }
        let mut predecessors: FxHashMap<u32, Vec<u32>> = FxHashMap::default();
        let mut successors: FxHashMap<u32, Vec<u32>> = FxHashMap::default();
        for (source, target) in cfg_edges_by_function.get(&function_id).into_iter().flatten() { predecessors.entry(*target).or_default().push(*source); successors.entry(*source).or_default().push(*target); }
        let mut defs_by_statement: FxHashMap<u32, Vec<(u32, u32)>> = FxHashMap::default();
        let mut seed = FxHashMap::default();
        for definition_index in definitions_by_function.get(&function_id).into_iter().flatten() {
            let definition = &graph.nodes[*definition_index];
            let Some(target) = text(graph, definition, "target_id").and_then(|id| graph.symbol(id)) else { continue };
            if let Some(statement) = containing(graph, &ast_parent, &evidence_body, &intervals_by_function, definition.id, function_id) { defs_by_statement.entry(statement).or_default().push((target, definition.id)); }
            else if text(graph, definition, "origin") == Some("parameter") { seed.entry(target).or_insert_with(FxHashSet::default).insert(definition.id); }
        }
        for definitions in defs_by_statement.values_mut() { definitions.sort_unstable_by_key(|(_, definition)| (graph.node_by_id.get(definition).and_then(|index| integer(graph, &graph.nodes[*index], "start_offset")).unwrap_or(i64::MAX), *definition)); }
        let empty_phis = FxHashMap::default();
        let (_raw_incoming, raw_outgoing) = solve(entry, &owned, &predecessors, &successors, &seed, &empty_phis, &defs_by_statement);
        let mut phis: FxHashMap<u32, Vec<(u32, u32)>> = FxHashMap::default();
        for node_id in &owned {
            let preds = predecessors.get(node_id).cloned().unwrap_or_default();
            if preds.len() < 2 { continue; }
            let mut targets = FxHashSet::default();
            for predecessor in &preds { targets.extend(raw_outgoing[predecessor].keys()); }
            for target in targets {
                let predecessor_versions: Vec<FxHashSet<u32>> = preds.iter().map(|pred| raw_outgoing[pred].get(&target).cloned().unwrap_or_default()).collect();
                let versions = predecessor_versions.iter().flat_map(|set| set.iter().copied()).collect::<FxHashSet<_>>();
                let distinct = predecessor_versions.iter().enumerate().filter(|(index, current)| {
                    !predecessor_versions[..*index].iter().any(|previous| previous == *current)
                }).count();
                if versions.len() < 2 || distinct < 2 { continue; }
                let function_text = graph.id(function_id).to_owned(); let node_text = graph.id(*node_id).to_owned(); let target_text = graph.id(target).to_owned();
                let phi_id = pass2::stable_id("core", "branch-history", "phi", &[&function_text, &node_text, &target_text]);
                let mut evidence = vec![node_text.clone(), target_text.clone()]; evidence.extend(versions.iter().map(|id| graph.id(*id).to_owned()));
                let target_label = graph.node_by_id.get(&target).map(|index| graph.nodes[*index].label.clone()).unwrap_or_else(|| target_text.clone());
                nodes.push(node(phi_id.clone(), "phi", format!("phi:{target_label}"), [fact(&evidence), vec![pass2::text_field("function_id", &function_text), pass2::text_field("cfg_node_id", &node_text), pass2::text_field("target_id", &target_text), list_field("incoming_definition_ids", &evidence[2..])]].concat()));
                let phi_symbol = graph.symbols.intern(phi_id.clone());
                phis.entry(*node_id).or_default().push((target, phi_symbol));
                add_edge("PHI_FOR_SYMBOL", target_text.clone(), phi_id.clone(), evidence.clone(), vec![]);
                add_edge("PHI_AT", phi_id.clone(), node_text.clone(), evidence.clone(), vec![]);
                for version in versions { let version_text = graph.id(version).to_owned(); add_edge("PHI_INPUT", version_text.clone(), phi_id.clone(), evidence.clone(), vec![]); add_edge("VALUE_FLOWS_TO", version_text, phi_id.clone(), evidence.clone(), vec![pass2::text_field("reason", "phi-input")]); }
            }
        }
        let (incoming, _) = solve(entry, &owned, &predecessors, &successors, &seed, &phis, &defs_by_statement);
        for read_index in reads_by_function.get(&function_id).into_iter().flatten() {
            let read = &graph.nodes[*read_index];
            let Some(statement) = containing(graph, &ast_parent, &evidence_body, &intervals_by_function, read.id, function_id) else { continue };
            let Some(target) = text(graph, read, "target_id").and_then(|id| graph.symbol(id)) else { continue };
            let mut environment = incoming.get(&statement).cloned().unwrap_or_default();
            for (phi_target, phi) in phis.get(&statement).into_iter().flatten() { environment.insert(*phi_target, FxHashSet::from_iter([*phi])); }
            for definition in environment.get(&target).into_iter().flatten() {
                let definition_text = graph.id(*definition).to_owned(); let read_text = graph.id(read.id).to_owned(); let statement_text = graph.id(statement).to_owned(); let evidence = vec![definition_text.clone(), read_text.clone(), statement_text.clone()];
                add_edge("BRANCH_READS_FROM", definition_text.clone(), read_text.clone(), evidence.clone(), vec![pass2::text_field("statement_id", &statement_text)]);
                add_edge("VALUE_FLOWS_TO", definition_text, read_text, evidence, vec![pass2::text_field("reason", "branch-reaching-definition")]);
            }
        }
        for definition_index in definitions_by_function.get(&function_id).into_iter().flatten() {
            let definition = &graph.nodes[*definition_index];
            let Some(statement) = containing(graph, &ast_parent, &evidence_body, &intervals_by_function, definition.id, function_id) else { continue };
            let Some(target) = text(graph, definition, "target_id").and_then(|id| graph.symbol(id)) else { continue };
            let prior = incoming.get(&statement).and_then(|map| map.get(&target)).cloned().unwrap_or_default();
            for previous in prior { let previous_text = graph.id(previous).to_owned(); let definition_text = graph.id(definition.id).to_owned(); let statement_text = graph.id(statement).to_owned(); add_edge("BRANCH_PREVIOUS", previous_text, definition_text.clone(), vec![graph.id(previous).to_owned(), definition_text, statement_text.clone()], vec![pass2::text_field("statement_id", &statement_text)]); }
        }
    }
    Delta { nodes, edges }
}
