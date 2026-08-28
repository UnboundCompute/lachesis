//! Structural reaching-definition facts for the native Pass-2 graph.
//!
//! The compiler substrate already records the facts needed for the C
//! reaching-definition overlay: AST ownership, declaration references,
//! assignment/initializer value flow, and source offsets.  Keep this producer
//! independent of API names so the same representation is also useful to
//! frontends that expose the same neutral edges.

use hashbrown::{HashMap, HashSet};

use crate::graph_proto;
use crate::pass2::{self, Delta, Graph};

#[derive(Clone, Eq, Hash, PartialEq)]
struct AccessPath(Vec<u32>);

#[derive(Clone, Copy)]
struct Definition {
    node: u32,
    owner: Option<u32>,
    offset: i64,
}

fn edge_text<'a>(graph: &'a Graph, edge: &'a pass2::Edge, key: &str) -> Option<&'a str> {
    graph.edge_property_text(edge, key)
}

fn reference_targets(graph: &Graph) -> HashMap<u32, u32> {
    let mut refs = HashMap::new();
    for edge in &graph.edges {
        if graph.edge_kind(edge) == "REFERS_TO" {
            refs.insert(edge.source, edge.target);
        }
    }
    refs
}

fn ast_children(graph: &Graph) -> Vec<Vec<u32>> {
    let mut children = vec![Vec::new(); graph.nodes.len()];
    for edge in &graph.edges {
        if graph.edge_kind(edge) != "AST_CHILD" { continue; }
        let Some(source) = graph.node_by_id.get(&edge.source).copied() else { continue; };
        children[source].push(edge.target);
    }
    children
}

fn access_path(
    graph: &Graph, node: u32, refs: &HashMap<u32, u32>, children: &[Vec<u32>],
    seen: &mut HashSet<u32>,
) -> Option<AccessPath> {
    if !seen.insert(node) { return None; }
    if let Some(target) = refs.get(&node).copied() {
        return Some(AccessPath(vec![target]));
    }
    let index = graph.node_by_id.get(&node).copied()?;
    // A declaration/parameter is itself the access-path root.  Initializer
    // flows target this node directly rather than a DeclRefExpr child.
    if matches!(graph.node_kind(index), "variable" | "parameter" | "property" | "value") {
        return Some(AccessPath(vec![node]));
    }
    for child in &children[index] {
        if let Some(path) = access_path(graph, *child, refs, children, seen) {
            return Some(path);
        }
    }
    None
}

fn path_for(
    graph: &Graph, node: u32, refs: &HashMap<u32, u32>, children: &[Vec<u32>],
) -> Option<AccessPath> {
    access_path(graph, node, refs, children, &mut HashSet::new())
}

fn owner(graph: &Graph, node: u32) -> Option<u32> {
    graph.node_by_id.get(&node).and_then(|index| graph.node_owner(&graph.nodes[*index]))
}

fn position(graph: &Graph, node: u32) -> i64 {
    graph.node_by_id.get(&node)
        .and_then(|index| graph.node_meta.get(*index))
        .map(|meta| meta.start_offset)
        .unwrap_or(i64::MAX)
}

fn record(source: u32, target: u32, graph: &Graph) -> graph_proto::EdgeRecord {
    graph_proto::EdgeRecord {
        kind: "REACHING_DEF".to_owned(),
        source: graph.id(source).to_owned(),
        target: graph.id(target).to_owned(),
        properties: vec![
            pass2::text_field("fact_origin", "core-inference"),
            pass2::text_field("confidence", "high"),
            pass2::text_field("inference", "reaching-definition"),
        ],
        source_tier: String::new(),
        relationship_class: "REACHING_DEF".to_owned(),
    }
}

/// Emit definition-to-use edges for exact declaration access paths.
///
/// Definitions are collected from assignment and initializer edges.  Uses are
/// the targets of compiler-produced `read` flows.  Only definitions in the
/// same owner and before the use are considered; multiple earlier definitions
/// are retained, which is the conservative may-reaching result at joins.
pub(crate) fn enrich(graph: &Graph) -> Delta {
    let refs = reference_targets(graph);
    let children = ast_children(graph);
    let mut definitions: HashMap<(Option<u32>, AccessPath), Vec<Definition>> = HashMap::new();
    let mut uses: Vec<(u32, Option<u32>, AccessPath)> = Vec::new();

    for edge in &graph.edges {
        if graph.edge_kind(edge) != "VALUE_FLOWS_TO" { continue; }
        let reason = edge_text(graph, edge, "reason");
        match reason {
            Some("assignment") | Some("initializer") => {
                let Some(path) = path_for(graph, edge.target, &refs, &children) else { continue; };
                let node = edge.target;
                let def = Definition { node, owner: owner(graph, node), offset: position(graph, node) };
                definitions.entry((def.owner, path)).or_default().push(def);
            }
            Some("read") => {
                let Some(path) = path_for(graph, edge.target, &refs, &children) else { continue; };
                uses.push((edge.target, owner(graph, edge.target), path));
            }
            _ => {}
        }
    }

    for entries in definitions.values_mut() {
        entries.sort_by_key(|definition| (definition.offset, definition.node));
        entries.dedup_by_key(|definition| definition.node);
    }
    let mut emitted = HashSet::new();
    let mut edges = Vec::new();
    for (use_node, use_owner, path) in uses {
        let Some(candidates) = definitions.get(&(use_owner, path)) else { continue; };
        let use_offset = position(graph, use_node);
        for definition in candidates {
            if definition.node == use_node || definition.offset > use_offset { continue; }
            if emitted.insert((definition.node, use_node)) {
                edges.push(record(definition.node, use_node, graph));
            }
        }
    }
    Delta { nodes: Vec::new(), edges }
}
