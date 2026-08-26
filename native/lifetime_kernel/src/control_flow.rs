//! Native control-flow overlay over the complete Pass-2 graph.
//!
//! The overlay emits the same additive CFG vocabulary as the Python producer.
//! It deliberately works on interned graph handles and appends protobuf records
//! only at the boundary, so later native overlays can consume the same adjacency.

use hashbrown::HashSet;
use rustc_hash::FxHashMap;
use crate::graph_proto;
use crate::pass2::{self, Delta, Graph};

const LOOP_KINDS: [&str; 4] = ["for", "for-each", "while", "do-while"];
const TERMINAL_KINDS: [&str; 2] = ["return", "throw"];
const BRANCHING_KINDS: [&str; 8] = [
    "if", "switch", "for", "for-each", "while", "do-while", "try", "catch",
];
const CONTAINER_KINDS: [&str; 7] = [
    "try", "if", "switch", "for", "for-each", "while", "do-while",
];

fn contains(items: &[&str], value: &str) -> bool { items.iter().any(|item| *item == value) }

fn value_text(value: &graph_proto::Value) -> Option<&str> {
    match value.kind.as_ref()? {
        graph_proto::value::Kind::Text(value) => Some(value),
        _ => None,
    }
}

fn edge_prop<'a>(edge: &'a pass2::Edge, key: &str) -> Option<&'a graph_proto::Value> {
    edge.properties.iter().find_map(|field| {
        (field.key == key).then(|| field.value.as_ref()).flatten()
    })
}

fn edge_role(edge: &pass2::Edge) -> Option<&str> {
    edge_prop(edge, "role").and_then(value_text)
}

fn text_list_field(key: &str, values: &[String]) -> graph_proto::Field {
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
    let mut unique = Vec::with_capacity(evidence.len());
    let mut seen = HashSet::new();
    for item in evidence {
        if seen.insert(item) { unique.push(item.clone()); }
    }
    vec![
        pass2::text_field("fact_origin", "core-inference"),
        pass2::text_field("confidence", confidence),
        text_list_field("evidence_ids", &unique),
    ]
}

fn node(id: String, kind: String, label: String, properties: Vec<graph_proto::Field>)
    -> graph_proto::NodeRecord
{
    graph_proto::NodeRecord { id, kind, label, properties, tier: String::new() }
}

fn edge(kind: &str, source: &str, target: &str, properties: Vec<graph_proto::Field>)
    -> graph_proto::EdgeRecord
{
    graph_proto::EdgeRecord {
        kind: kind.to_owned(), source: source.to_owned(), target: target.to_owned(),
        properties, source_tier: String::new(), relationship_class: String::new(),
    }
}

fn position(graph: &Graph, node: &pass2::Node) -> (i64, i64) {
    (
        graph.node_property_i64(node, "start_offset").unwrap_or(i64::MAX),
        graph.node_property_i64(node, "end_offset").unwrap_or(i64::MAX),
    )
}

fn node_control_kind<'a>(graph: &'a Graph, node: &'a pass2::Node) -> &'a str {
    graph.node_property_text(node, "control_kind").unwrap_or("")
}

fn owned_by(graph: &Graph, node: &pass2::Node) -> Option<u32> {
    graph.node_property_text(node, "owner_function_id")
        .or_else(|| graph.node_property_text(node, "function_id"))
        .and_then(|value| graph.symbol(value))
}

pub(crate) fn enrich(graph: &Graph) -> Delta {
    let mut nodes = Vec::new();
    let mut edges = Vec::new();
    let mut emitted: HashSet<(String, String, String)> = HashSet::new();
    let mut ast_children: FxHashMap<u32, Vec<(u32, Vec<graph_proto::Field>)>> = FxHashMap::default();
    let mut ast_parent: FxHashMap<u32, u32> = FxHashMap::default();
    let mut sequential: FxHashMap<u32, Vec<u32>> = FxHashMap::default();
    let mut contained: FxHashMap<u32, Vec<u32>> = FxHashMap::default();
    let mut direct_control: FxHashMap<u32, Vec<(String, u32, Vec<graph_proto::Field>)>> = FxHashMap::default();

    for item in &graph.edges {
        let kind = graph.edge_kind(item);
        let Some(source) = graph.symbols.find(graph.id(item.source)) else { continue };
        let Some(target) = graph.symbols.find(graph.id(item.target)) else { continue };
        match kind {
            "AST_CHILD" => {
                ast_children.entry(source).or_default().push((target, item.properties.clone()));
                ast_parent.insert(target, source);
            }
            "EXECUTES_BEFORE" => sequential.entry(source).or_default().push(target),
            "CONTAINS_BODY" => contained.entry(source).or_default().push(target),
            value if contains(&[
                "CONDITION", "TRUE_BRANCH", "FALSE_BRANCH", "LOOP_TRUE", "LOOP_BACK",
                "SWITCH_CASE", "EXCEPTION_BRANCH", "TRY_BODY", "RUNS_FINALLY",
                "BREAKS_TO", "CONTINUES_TO", "ITERATES", "SHORT_CIRCUIT_LEFT",
                "SHORT_CIRCUIT_RIGHT",
            ], value) => direct_control.entry(source).or_default().push((
                value.to_owned(), target, item.properties.clone(),
            )),
            _ => {}
        }
    }

    let mut children_cache: FxHashMap<(u32, u32), Vec<u32>> = FxHashMap::default();
    let mut successor_cache: FxHashMap<(u32, u32), Vec<u32>> = FxHashMap::default();
    let mut branch_end_cache: FxHashMap<(u32, u32), u32> = FxHashMap::default();

    let statement_children = |graph: &Graph, node_id: u32, owner: u32,
                               ast_children: &FxHashMap<u32, Vec<(u32, Vec<graph_proto::Field>)>>|
     -> Vec<u32> {
        let in_block = graph.node_by_id.get(&node_id).is_some_and(|index|
            graph.node_property_text(&graph.nodes[*index], "control_kind") == Some("block"));
        let mut result: Vec<u32> = ast_children.get(&node_id).into_iter().flatten()
            .filter_map(|(child, _)| {
                let child_node = graph.node_by_id.get(child).map(|index| &graph.nodes[*index])?;
                let child_owner = owned_by(graph, child_node);
                let child_kind = graph.node_kind(*graph.node_by_id.get(child)?);
                (child_owner == Some(owner) &&
                    (child_kind == "statement" ||
                     (in_block && (child_kind == "call" || child_kind == "expression"))))
                    .then_some(*child)
            }).collect();
        result.sort_by_key(|child| graph.node_by_id.get(child)
            .map(|index| position(graph, &graph.nodes[*index])).unwrap_or((i64::MAX, i64::MAX)));
        result.dedup();
        result
    };

    let branch_end = |graph: &Graph, mut node_id: u32, owner: u32,
                      ast_children: &FxHashMap<u32, Vec<(u32, Vec<graph_proto::Field>)>>,
                      cache: &mut FxHashMap<(u32, u32), u32>| {
        let original = node_id;
        let mut seen = HashSet::new();
        while seen.insert(node_id) {
            let children = statement_children(graph, node_id, owner, ast_children);
            let Some(last) = children.last() else { break; };
            node_id = *last;
        }
        cache.insert((original, owner), node_id);
        node_id
    };

    let add_edge = |edges: &mut Vec<graph_proto::EdgeRecord>, emitted: &mut HashSet<(String,String,String)>,
                    kind: &str, source: &str, target: &str, evidence: &[String], properties: Vec<graph_proto::Field>| {
        if source.is_empty() || target.is_empty() || source == target { return; }
        let key = (kind.to_owned(), source.to_owned(), target.to_owned());
        if !emitted.insert(key) { return; }
        let mut fields = fact(evidence, "high");
        fields.extend(properties);
        edges.push(edge(kind, source, target, fields));
    };

    let function_indices: Vec<usize> = graph.nodes.iter().enumerate()
        .filter(|(_, node)| contains(&["function", "method", "constructor"], graph.kind(node.kind)))
        .map(|(index, _)| index).collect();
    let mut statements_by_function: FxHashMap<u32, Vec<u32>> = FxHashMap::default();
    for item in &graph.nodes {
        if graph.kind(item.kind) != "statement" { continue; }
        if let Some(owner) = owned_by(graph, item) { statements_by_function.entry(owner).or_default().push(item.id); }
    }

    for function_index in function_indices {
        let function = &graph.nodes[function_index];
        let function_id = function.id;
        let function_name = graph.id(function.id).to_owned();
        let entry_id = pass2::stable_id("core", "control-flow", "cfg-entry", &[&function_name]);
        let exit_id = pass2::stable_id("core", "control-flow", "cfg-exit", &[&function_name]);
        let function_label = function.label.clone();
        let mut entry_properties = fact(&[function_name.clone()], "exact");
        entry_properties.push(pass2::text_field("function_id", function_name.clone()));
        nodes.push(node(entry_id.clone(), "cfg-entry".to_owned(),
            format!("entry:{function_label}"), entry_properties));
        let mut exit_properties = fact(&[function_name.clone()], "exact");
        exit_properties.push(pass2::text_field("function_id", function_name.clone()));
        nodes.push(node(exit_id.clone(), "cfg-exit".to_owned(),
            format!("exit:{function_label}"), exit_properties));

        let mut owned_statements = statements_by_function.get(&function_id).cloned().unwrap_or_default();
        owned_statements.sort_by_key(|id| graph.node_by_id.get(id)
            .map(|index| position(graph, &graph.nodes[*index])).unwrap_or((i64::MAX, i64::MAX)));
        let top_level: Vec<u32> = contained.get(&function_id).into_iter().flatten()
            .filter(|id| graph.node_by_id.get(id).is_some_and(|index| {
                graph.node_kind(*index) == "statement" && owned_by(graph, &graph.nodes[*index]) == Some(function_id)
            })).copied().collect();
        let mut top_level = top_level;
        top_level.sort_by_key(|id| graph.node_by_id.get(id)
            .map(|index| position(graph, &graph.nodes[*index])).unwrap_or((i64::MAX, i64::MAX)));
        if let Some(first) = top_level.first() {
            let first_id = graph.id(*first).to_owned();
            add_edge(&mut edges, &mut emitted, "CFG_NEXT", &entry_id, &first_id,
                &[function_name.clone(), first_id.clone()], Vec::new());
        } else {
            add_edge(&mut edges, &mut emitted, "CFG_NEXT", &entry_id, &exit_id,
                &[function_name.clone()], Vec::new());
        }

        // Blocks contribute their direct statement sequence.  Exact sequence
        // edges from the frontend are added below as well; the accumulator's
        // triple deduplication makes the two sources equivalent.
        for statement_id in &owned_statements {
            let children = statement_children(graph, *statement_id, function_id, &ast_children);
            if let Some(first) = children.first() {
                let source = graph.id(*statement_id).to_owned();
                let target = graph.id(*first).to_owned();
                add_edge(&mut edges, &mut emitted, "CFG_NEXT", &source, &target,
                    &[source.clone(), target.clone()], Vec::new());
                for pair in children.windows(2) {
                    let left_kind = graph.node_by_id.get(&pair[0])
                        .map(|index| node_control_kind(graph, &graph.nodes[*index])).unwrap_or("");
                    if contains(&TERMINAL_KINDS, left_kind) || contains(&CONTAINER_KINDS, left_kind) {
                        continue;
                    }
                    let left = graph.id(pair[0]).to_owned();
                    let right = graph.id(pair[1]).to_owned();
                    add_edge(&mut edges, &mut emitted, "CFG_NEXT", &left, &right,
                        &[left.clone(), right.clone()], Vec::new());
                }
            }
        }

        let mut merge_by_container: FxHashMap<u32, String> = FxHashMap::default();
        let mut condition_by_container: FxHashMap<u32, String> = FxHashMap::default();
        for statement_id in &owned_statements {
            let Some(index) = graph.node_by_id.get(statement_id).copied() else { continue };
            let statement = &graph.nodes[index];
            let control_kind = node_control_kind(graph, statement);
            if !contains(&BRANCHING_KINDS, control_kind) { continue; }
            let condition_target = direct_control.get(statement_id).into_iter().flatten()
                .find(|(kind, _, _)| kind == "CONDITION").map(|(_, target, _)| *target)
                .or_else(|| ast_children.get(statement_id).into_iter().flatten()
                    .find(|(_, props)| props.iter().any(|field| field.key == "role" &&
                        field.value.as_ref().and_then(value_text) == Some("CONDITION")))
                    .map(|(target, _)| *target))
                .unwrap_or(*statement_id);
            let statement_name = graph.id(*statement_id).to_owned();
            let condition_name = graph.id(condition_target).to_owned();
            let condition_id = pass2::stable_id("core", "control-flow", "cfg-condition",
                &[&function_name, &statement_name, &condition_name]);
            let merge_id = pass2::stable_id("core", "control-flow", "cfg-merge",
                &[&function_name, &statement_name]);
            let evidence = vec![statement_name.clone(), condition_name.clone()];
            nodes.push(node(condition_id.clone(), "cfg-condition".to_owned(),
                format!("condition:{}", statement.label), {
                    let mut fields = fact(&evidence, "high");
                    fields.push(pass2::text_field("function_id", function_name.clone()));
                    fields.push(pass2::text_field("body_id", condition_name.clone()));
                    fields.push(pass2::text_field("control_kind", control_kind)); fields
                }));
            nodes.push(node(merge_id.clone(), "cfg-merge".to_owned(),
                format!("merge:{}", statement.label), {
                    let mut fields = fact(&evidence, "high");
                    fields.push(pass2::text_field("function_id", function_name.clone()));
                    fields.push(pass2::text_field("container_id", statement_name.clone())); fields
                }));
            condition_by_container.insert(*statement_id, condition_id.clone());
            merge_by_container.insert(*statement_id, merge_id.clone());
            add_edge(&mut edges, &mut emitted, "CFG_NEXT", &statement_name, &condition_id,
                &evidence, Vec::new());
            let mut branches: Vec<(String, u32, Vec<graph_proto::Field>)> = direct_control
                .get(&condition_target).into_iter().flatten()
                .filter(|(kind, _, _)| contains(&["TRUE_BRANCH", "FALSE_BRANCH", "LOOP_TRUE", "SWITCH_CASE", "ITERATES"], kind))
                .cloned().collect();
            if branches.is_empty() {
                branches = ast_children.get(statement_id).into_iter().flatten()
                    .filter_map(|(target, props)| {
                        let role = props.iter().find(|field| field.key == "role")
                            .and_then(|field| field.value.as_ref()).and_then(value_text)?;
                        contains(&["TRUE_BRANCH", "FALSE_BRANCH", "LOOP_BODY"], role)
                            .then(|| (if role == "LOOP_BODY" { "LOOP_TRUE" } else { role }.to_owned(), *target, props.clone()))
                    }).collect();
            }
            let mut has_false = false;
            for (kind, target, properties) in branches {
                let cfg_kind = if contains(&["TRUE_BRANCH", "LOOP_TRUE", "ITERATES"], &kind) { "TRUE_BRANCH" } else { kind.as_str() };
                if cfg_kind == "FALSE_BRANCH" { has_false = true; }
                let target_name = graph.id(target).to_owned();
                add_edge(&mut edges, &mut emitted, cfg_kind, &condition_id, &target_name,
                    &[evidence[0].clone(), evidence[1].clone(), target_name.clone()], properties);
                let end = branch_end(graph, target, function_id, &ast_children, &mut branch_end_cache);
                let end_kind = graph.node_by_id.get(&end).map(|index| node_control_kind(graph, &graph.nodes[*index])).unwrap_or("");
                if contains(&LOOP_KINDS, control_kind) && cfg_kind == "TRUE_BRANCH" &&
                    !contains(&TERMINAL_KINDS, end_kind) && !contains(&["break", "continue"], end_kind) {
                    let end_name = graph.id(end).to_owned();
                    add_edge(&mut edges, &mut emitted, "LOOP_BACK", &end_name, &condition_id,
                        &[end_name.clone(), condition_name.clone()], Vec::new());
                } else if !contains(&TERMINAL_KINDS, end_kind) && !contains(&["break", "continue"], end_kind) {
                    let end_name = graph.id(end).to_owned();
                    add_edge(&mut edges, &mut emitted, "MERGES_AT", &end_name, &merge_id,
                        &[end_name.clone(), statement_name.clone()], Vec::new());
                }
            }
            if contains(&["if", "for", "for-each", "while", "do-while"], control_kind) && !has_false {
                add_edge(&mut edges, &mut emitted, "FALSE_BRANCH", &condition_id, &merge_id,
                    &evidence, Vec::new());
            }
            let successor = sequential.get(statement_id).and_then(|items| items.first()).copied();
            let successor_name = successor.map(|id| graph.id(id).to_owned()).unwrap_or(exit_id.clone());
            add_edge(&mut edges, &mut emitted, "CFG_NEXT", &merge_id, &successor_name,
                &[statement_name, successor_name.clone()], Vec::new());
        }

        for statement_id in &owned_statements {
            let Some(index) = graph.node_by_id.get(statement_id).copied() else { continue };
            let statement = &graph.nodes[index];
            let kind = node_control_kind(graph, statement);
            let source = graph.id(*statement_id).to_owned();
            if contains(&TERMINAL_KINDS, kind) {
                add_edge(&mut edges, &mut emitted, "CFG_NEXT", &source, &exit_id,
                    &[source.clone(), exit_id.clone()], Vec::new());
            } else if !contains(&CONTAINER_KINDS, kind) {
                if let Some(target) = sequential.get(statement_id).and_then(|items| items.first()) {
                    let target_name = graph.id(*target).to_owned();
                    add_edge(&mut edges, &mut emitted, "CFG_NEXT", &source, &target_name,
                        &[source.clone(), target_name.clone()], Vec::new());
                }
            }
        }
        let _ = (&mut children_cache, &mut successor_cache);
    }
    Delta { nodes, edges }
}
