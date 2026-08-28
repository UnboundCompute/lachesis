//! Binary Claus skeleton construction for Pass 3.
//!
//! Claus receives source-rooted regions and re-serializes the native semantic
//! graph into a compact, ordered skeleton.  The skeleton retains event order,
//! control markers, guards, and graph edges; no source text or JSON is needed.

use std::collections::{BTreeSet, HashMap, VecDeque};

use crate::lifetime_proto;

fn lifecycle_family(event: &str, language: &str) -> String {
    let c = language == "c" || language == "cpp";
    match event {
        "ALLOC_ATTEMPT" | "ORIGIN" => if c { "memory.alloc" } else { "lifecycle.acquire" },
        "RELEASE" | "memory.free" => if c { "memory.free" } else { "lifecycle.release" },
        "READ_STORAGE" | "WRITE_STORAGE" | "memory.deref" => {
            if c { "memory.deref" } else { "lifecycle.use" }
        }
        "ESCAPE" => "lifecycle.escape",
        "REALLOC_FAILED" | "LOST_FROM_SLOT" => "lifecycle.invalidate",
        "DERIVE" => "lifecycle.derive",
        "RETURN_VALUE" => "lifecycle.return",
        "BRANCH" | "MERGE" | "LOOP" => "control",
        other => return format!("lifecycle.{}", other.to_ascii_lowercase()),
    }.to_owned()
}

fn function_map(
    result: &lifetime_proto::NativeSemanticResult,
) -> HashMap<&str, &lifetime_proto::NativeSemanticFunction> {
    result.functions.iter().map(|function| (function.id.as_str(), function)).collect()
}

type FunctionIndex<'a> = HashMap<&'a str, &'a lifetime_proto::NativeSemanticFunction>;
type NodeIndex<'a> = HashMap<&'a str, &'a lifetime_proto::NativeSemanticNode>;
type EdgeIndex<'a> = HashMap<&'a str, Vec<&'a lifetime_proto::NativeSemanticEdge>>;

fn node_allowed(node: &lifetime_proto::NativeSemanticNode, allowed: &BTreeSet<&str>) -> bool {
    node.function.is_empty() || allowed.contains(node.function.as_str())
}

fn semantic_indexes<'a>(
    result: &'a lifetime_proto::NativeSemanticResult,
) -> (FunctionIndex<'a>, NodeIndex<'a>, EdgeIndex<'a>) {
    let functions = function_map(result);
    let mut nodes = HashMap::new();
    let mut adjacency = HashMap::new();
    for function in &result.functions {
        for node in &function.nodes { nodes.insert(node.id.as_str(), node); }
        for edge in &function.edges {
            adjacency.entry(edge.source.as_str()).or_insert_with(Vec::new).push(edge);
        }
    }
    for edge in &result.seams {
        adjacency.entry(edge.source.as_str()).or_insert_with(Vec::new).push(edge);
    }
    for edges in adjacency.values_mut() {
        edges.sort_by(|left, right| (&left.kind, &left.seam_kind, &left.target, &left.return_to)
            .cmp(&(&right.kind, &right.seam_kind, &right.target, &right.return_to)));
    }
    (functions, nodes, adjacency)
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct WalkState {
    node: String,
    stack: Vec<String>,
}

/// Render the same source-rooted composition boundary as the old Claus path.
///
/// The old renderer did not print every function in a call cone.  It followed
/// a concrete summary flow, opening a callee at a call seam and closing it at
/// the matching return continuation.  The native semantic sidecar carries
/// those seams explicitly, so keep that discipline here instead of treating a
/// region's function list as a linear order.  The walk is intentionally
/// bounded by the finite `(node, call-stack)` state space; revisiting a state
/// is a loop back-edge, not a second copy of the function.
fn walk_region(
    result: &lifetime_proto::NativeSemanticResult,
    region: &lifetime_proto::NativeSourceRegion,
    context: &str,
    functions: &FunctionIndex<'_>,
    nodes: &NodeIndex<'_>,
    adjacency: &EdgeIndex<'_>,
) -> (Vec<lifetime_proto::NativeSkeletonToken>, Vec<lifetime_proto::NativeSemanticEdge>, bool) {
    let allowed: BTreeSet<&str> = region.functions.iter().map(String::as_str).collect();

    let mut starts = Vec::new();
    if context != "__entry__" {
        for id in &region.source_nodes {
            if id != context { continue; }
            if nodes.contains_key(id.as_str()) {
                starts.push(id.clone());
            } else if let Some(node) = nodes.values().find(|node| node.anchor == *id
                && node_allowed(node, &allowed)) {
                starts.push(node.id.clone());
            }
        }
    } else {
        // A structural root has no catalogued launch site.  Start at its
        // compiler entry exactly as the old scheduler's __entry__ context did.
        starts.extend(region.source_nodes.iter()
            .filter(|id| nodes.contains_key(id.as_str()))
            .cloned());
    }
    if starts.is_empty() && context == "__entry__" {
        if let Some(function) = functions.get(region.source_function.as_str()) {
            if !function.entry.is_empty() && nodes.get(function.entry.as_str())
                .is_some_and(|node| node_allowed(node, &allowed)) {
                starts.push(function.entry.clone());
            } else if let Some(node) = function.nodes.iter()
                .find(|node| node_allowed(node, &allowed)) {
                starts.push(node.id.clone());
            }
        }
    }
    if starts.is_empty() { return (Vec::new(), Vec::new(), false); }

    let mut queue = VecDeque::new();
    let mut seen = BTreeSet::new();
    for start in starts {
        queue.push_back(WalkState { node: start, stack: Vec::new() });
    }
    let mut tokens = Vec::new();
    let mut edges_used = Vec::new();
    let mut complete = true;
    while let Some(state) = queue.pop_front() {
        if !seen.insert(state.clone()) { continue; }
        let Some(node) = nodes.get(state.node.as_str())
            .filter(|node| node_allowed(node, &allowed))
        else { complete = false; continue; };
        let depth = state.stack.len() as u32;
        let language = functions.get(node.function.as_str())
            .map(|function| function.language.as_str())
            .or_else(|| functions.get(region.source_function.as_str())
                .map(|function| function.language.as_str()))
            .unwrap_or_default();
        let guards = adjacency.get(state.node.as_str()).into_iter().flatten()
            .flat_map(|edge| edge.guards.iter().cloned())
            .collect::<Vec<_>>();
        // Keep anchors in the skeleton even when they carry no lifecycle
        // event.  The old semantic graph retained those anchors to preserve
        // branch/loop structure; dropping them forces a later matcher to
        // reconnect edges heuristically and can create paths that do not
        // exist.  ``family=control`` is an internal binary marker, not a
        // catalogued vulnerability family.
        tokens.push(lifetime_proto::NativeSkeletonToken {
                kind: if node.event_kind.is_empty() ||
                    matches!(node.event_kind.as_str(), "BRANCH" | "MERGE" | "LOOP") {
                    "control".into()
                } else { "event".into() },
                function: node.function.clone(), node: node.id.clone(),
                family: if node.event_kind.is_empty() { "control".into() }
                    else { lifecycle_family(&node.event_kind, language) },
                object_root: node.object_root.clone(), object_selectors: node.object_selectors.clone(),
                line: node.line, has_line: node.has_line, depth,
                guarded: !guards.is_empty(), guards,
                source_reachable: node.source_reachable,
                source_witness_nodes: node.source_witness_nodes.clone(),
                ..Default::default()
            });
        for edge in adjacency.get(state.node.as_str()).into_iter().flatten() {
            let target_allowed = nodes.get(edge.target.as_str())
                .is_some_and(|target| node_allowed(target, &allowed));
            let seam_allowed = edge.seam_kind.is_empty()
                || allowed.contains(edge.callee.as_str())
                || (allowed.contains(node.function.as_str()) && target_allowed);
            if !seam_allowed { continue; }
            if !edge.target.is_empty() && !target_allowed {
                complete = false;
                continue;
            }
            edges_used.push((*edge).clone());
            let mut next_stack = state.stack.clone();
            if edge.seam_kind == "call" {
                let callee = edge.callee.as_str();
                if !callee.is_empty() && allowed.contains(callee) {
                    tokens.push(lifetime_proto::NativeSkeletonToken {
                        kind: "enter".into(), function: callee.to_owned(),
                        node: edge.target.clone(), depth: depth + 1, ..Default::default()
                    });
                    if !edge.return_to.is_empty() { next_stack.push(edge.return_to.clone()); }
                }
            } else if edge.seam_kind == "return" {
                if let Some(expected) = next_stack.pop() {
                    if !edge.target.is_empty() && expected != edge.target {
                        complete = false;
                        continue;
                    }
                    tokens.push(lifetime_proto::NativeSkeletonToken {
                        kind: "exit".into(), function: node.function.clone(),
                        node: node.id.clone(), depth, ..Default::default()
                    });
                } else {
                    complete = false;
                    continue;
                }
            }
            queue.push_back(WalkState { node: edge.target.clone(), stack: next_stack });
        }
    }
    (tokens, edges_used, complete && !seen.is_empty())
}

/// Build one cached skeleton per source/context region.
pub(crate) fn build(
    result: &lifetime_proto::NativeSemanticResult,
) -> Vec<lifetime_proto::NativeFlowSkeleton> {
    let mut output = Vec::new();
    for function in &result.functions {
        let Some(compact) = crate::compact_event_function(function.clone()) else { continue; };
        let language = compact.language.as_str();
        let mut tokens = Vec::with_capacity(compact.nodes.len() + 2);
        tokens.push(lifetime_proto::NativeSkeletonToken {
            kind: "enter".into(), function: compact.id.clone(), depth: 0, ..Default::default()
        });
        for node in &compact.nodes {
            let guards = compact.edges.iter()
                .filter(|edge| edge.source == node.id)
                .flat_map(|edge| edge.guards.iter().cloned())
                .collect::<Vec<_>>();
            tokens.push(lifetime_proto::NativeSkeletonToken {
                kind: if node.event_kind.is_empty() { "control".into() } else { "event".into() },
                function: compact.id.clone(), node: node.id.clone(),
                family: if node.event_kind.is_empty() { "control".into() }
                    else { lifecycle_family(&node.event_kind, language) },
                object_root: node.object_root.clone(), object_selectors: node.object_selectors.clone(),
                line: node.line, has_line: node.has_line, depth: 1,
                guarded: !guards.is_empty(), guards,
                source_reachable: node.source_reachable,
                source_witness_nodes: node.source_witness_nodes.clone(),
                ..Default::default()
            });
        }
        tokens.push(lifetime_proto::NativeSkeletonToken {
            kind: "exit".into(), function: compact.id.clone(), depth: 0, ..Default::default()
        });
        output.push(lifetime_proto::NativeFlowSkeleton {
            kind: "typestate".into(), entry: compact.id.clone(),
            source_function: compact.id, context: "__entry__".into(), complete: true,
            tokens, edges: compact.edges,
            is_source: !function.source_launch_nodes.is_empty(),
        });
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emits_ordered_source_rooted_lifecycle_skeleton() {
        let function = lifetime_proto::NativeSemanticFunction {
            id: "f".into(), language: "c".into(),
            nodes: vec![
                lifetime_proto::NativeSemanticNode { id: "a".into(), event_kind: "ORIGIN".into(), ..Default::default() },
                lifetime_proto::NativeSemanticNode { id: "b".into(), event_kind: "RELEASE".into(), ..Default::default() },
            ],
            edges: vec![lifetime_proto::NativeSemanticEdge {
                source: "a".into(), target: "b".into(), ..Default::default()
            }],
            ..Default::default()
        };
        let result = lifetime_proto::NativeSemanticResult {
            functions: vec![function],
            regions: vec![lifetime_proto::NativeSourceRegion {
                source_function: "f".into(), functions: vec!["f".into()],
                contexts: vec!["__entry__".into()], ..Default::default()
            }],
            ..Default::default()
        };
        let skeletons = build(&result);
        assert_eq!(skeletons.len(), 1);
        assert_eq!(skeletons[0].tokens[1].family, "memory.alloc");
        assert_eq!(skeletons[0].tokens[2].family, "memory.free");
        assert!(skeletons[0].edges.len() >= 1);
    }

    #[test]
    fn emits_compact_function_local_typestate_skeletons() {
        let source = lifetime_proto::NativeSemanticFunction {
            id: "source".into(), entry: "s0".into(),
            nodes: vec![
                lifetime_proto::NativeSemanticNode { id: "s0".into(), function: "source".into(), ..Default::default() },
                lifetime_proto::NativeSemanticNode { id: "s1".into(), function: "source".into(), event_kind: "memory.deref".into(), ..Default::default() },
                lifetime_proto::NativeSemanticNode { id: "s2".into(), function: "source".into(), ..Default::default() },
            ],
            edges: vec![
                lifetime_proto::NativeSemanticEdge { source: "s0".into(), target: "s1".into(), ..Default::default() },
                lifetime_proto::NativeSemanticEdge { source: "s1".into(), target: "s2".into(), ..Default::default() },
            ], ..Default::default()
        };
        let callee = lifetime_proto::NativeSemanticFunction {
            id: "callee".into(), entry: "c0".into(),
            nodes: vec![
                lifetime_proto::NativeSemanticNode { id: "c0".into(), function: "callee".into(), event_kind: "ORIGIN".into(), ..Default::default() },
                lifetime_proto::NativeSemanticNode { id: "c1".into(), function: "callee".into(), event_kind: "memory.free".into(), ..Default::default() },
            ],
            edges: vec![lifetime_proto::NativeSemanticEdge {
                source: "c0".into(), target: "c1".into(), ..Default::default()
            }], ..Default::default()
        };
        let result = lifetime_proto::NativeSemanticResult {
            functions: vec![source, callee],
            seams: vec![
                lifetime_proto::NativeSemanticEdge {
                    source: "s1".into(), target: "c0".into(), kind: "call".into(),
                    seam_kind: "call".into(), callee: "callee".into(), return_to: "s2".into(), ..Default::default()
                },
                lifetime_proto::NativeSemanticEdge {
                    source: "c1".into(), target: "s2".into(), kind: "return".into(),
                    seam_kind: "return".into(), callee: "callee".into(), return_to: "s2".into(), ..Default::default()
                },
            ],
            regions: vec![lifetime_proto::NativeSourceRegion {
                source_function: "source".into(), source_nodes: vec!["s0".into()],
                functions: vec!["source".into(), "callee".into()], contexts: vec!["s0".into()], ..Default::default()
            }], ..Default::default()
        };
        let skeletons = build(&result);
        assert_eq!(skeletons.len(), 2);
        let kinds: Vec<_> = skeletons[0].tokens.iter().map(|token| token.kind.as_str()).collect();
        assert!(kinds.windows(2).any(|pair| pair == ["enter", "event"]));
        assert_eq!(skeletons[0].kind, "typestate");
        assert_eq!(skeletons[0].context, "__entry__");
        assert!(skeletons.iter().any(|skeleton| skeleton.entry == "callee"));
        assert!(skeletons[0].complete);
    }
}
