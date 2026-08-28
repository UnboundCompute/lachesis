//! Binary Claus skeleton construction for Pass 3.
//!
//! Claus receives source-rooted regions and re-serializes the native semantic
//! graph into a compact, ordered skeleton.  The skeleton retains event order,
//! control markers, guards, and graph edges; no source text or JSON is needed.

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};

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
    (functions, nodes, adjacency)
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct WalkState {
    node: String,
    stack: Vec<String>,
    // Active function identities mirror the old Claus recursion guard.  A
    // return address alone is insufficient: mutually recursive calls can
    // keep producing distinct return-node stacks indefinitely.
    active_functions: Vec<String>,
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
        // ``__entry__`` is also used for a source-resolved component. Start
        // from every launch anchor in that component; this is one cached walk,
        // not one replay per source callsite.
        for id in &region.source_nodes {
            if starts.iter().any(|start| start == id) { continue; }
            if nodes.contains_key(id.as_str()) {
                starts.push(id.clone());
            } else if let Some(node) = nodes.values().find(|node| node.anchor == *id
                && node_allowed(node, &allowed)) {
                starts.push(node.id.clone());
            }
        }
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

    let mut stack = Vec::new();
    let mut seen = BTreeSet::new();
    for start in starts.into_iter().rev() {
        let active_functions = nodes.get(start.as_str())
            .map(|node| vec![node.function.clone()])
            .unwrap_or_default();
        stack.push(WalkState { node: start, stack: Vec::new(), active_functions });
    }
    let mut tokens = Vec::new();
    let mut edges_used = Vec::new();
    let mut complete = true;
    while let Some(state) = stack.pop() {
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
                generation: node.generation.clone(),
                stack_local: node.stack_local, is_null: node.is_null,
                access: node.access.clone(), value_root: node.value_root.clone(),
                value_selectors: node.value_selectors.clone(),
                ..Default::default()
            });
        let outgoing = adjacency.get(state.node.as_str()).into_iter().flatten()
            .copied().collect::<Vec<_>>();
        // Claus is a nested flow renderer: a call seam is entered before the
        // caller's continuation, and a return seam is handled before leaving
        // the callee.  Preserve the sidecar order within each class while
        // placing seams ahead of ordinary continuation edges.
        let mut ordered = Vec::with_capacity(outgoing.len());
        ordered.extend(outgoing.iter().copied().filter(|edge| !edge.seam_kind.is_empty()));
        ordered.extend(outgoing.iter().copied().filter(|edge| edge.seam_kind.is_empty()));
        for edge in ordered.iter().rev() {
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
            let mut next_active_functions = state.active_functions.clone();
            if edge.seam_kind == "call" {
                let callee = edge.callee.as_str();
                if !callee.is_empty() && allowed.contains(callee) {
                    if state.active_functions.iter().any(|function| function == callee) {
                        // Match the old `_expand_reach` chain guard: retain
                        // the discovered recursive edge for diagnostics, but
                        // do not recurse into an unbounded call stack.
                        complete = false;
                        continue;
                    }
                    tokens.push(lifetime_proto::NativeSkeletonToken {
                        kind: "enter".into(), function: callee.to_owned(),
                        node: edge.target.clone(), depth: depth + 1, ..Default::default()
                    });
                    if !edge.return_to.is_empty() { next_stack.push(edge.return_to.clone()); }
                    next_active_functions.push(callee.to_owned());
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
                    next_active_functions.pop();
                } else {
                    complete = false;
                    continue;
                }
            }
            stack.push(WalkState {
                node: edge.target.clone(), stack: next_stack, active_functions: next_active_functions,
            });
        }
    }
    (tokens, edges_used, complete && !seen.is_empty())
}

fn typestate_event(event: &str) -> bool {
    matches!(event,
        "ORIGIN" | "ALLOC_ATTEMPT" | "REALLOC_ATTEMPT" | "REALLOC_FAILED" |
        "memory.free" | "RELEASE" | "memory.deref" | "READ_STORAGE" |
        "WRITE_STORAGE" | "ESCAPE" | "INVALIDATE" | "DERIVE" |
        "RETURN_VALUE" | "UNINITIALIZED")
}

/// Render the old engine's per-function/object typestate streams from the
/// compiler-owned event nodes. Object identity is the native root plus
/// generation, never a display name.
fn build_typestate(
    result: &lifetime_proto::NativeSemanticResult,
) -> Vec<lifetime_proto::NativeFlowSkeleton> {
    let mut streams = BTreeSet::new();
    for function in &result.functions {
        for node in &function.nodes {
            if typestate_event(&node.event_kind) && !node.object_root.is_empty() {
                streams.insert((function.id.clone(), node.object_root.clone(), node.generation.clone()));
            }
        }
    }
    let functions = function_map(result);
    let mut output = Vec::new();
    for (function_id, root, generation) in streams {
        let Some(function) = functions.get(function_id.as_str()) else { continue };
        let events: Vec<_> = function.nodes.iter().filter(|node|
            typestate_event(&node.event_kind)
                && node.object_root == root && node.generation == generation).collect();
        if events.is_empty() { continue; }
        let mut tokens = Vec::with_capacity(events.len() + 2);
        tokens.push(lifetime_proto::NativeSkeletonToken {
            kind: "enter".into(), function: function_id.clone(), depth: 0, ..Default::default()
        });
        for node in &events {
            let guards: Vec<_> = function.edges.iter().filter(|edge| edge.source == node.id)
                .flat_map(|edge| edge.guards.iter().cloned()).collect();
            tokens.push(lifetime_proto::NativeSkeletonToken {
                kind: "event".into(), function: function_id.clone(), node: node.id.clone(),
                family: lifecycle_family(&node.event_kind, &function.language),
                object_root: node.object_root.clone(), object_selectors: node.object_selectors.clone(),
                line: node.line, has_line: node.has_line, depth: 1,
                guarded: !guards.is_empty(), guards,
                source_reachable: node.source_reachable,
                source_witness_nodes: node.source_witness_nodes.clone(),
                generation: node.generation.clone(), stack_local: node.stack_local,
                is_null: node.is_null, access: node.access.clone(),
                value_root: node.value_root.clone(), value_selectors: node.value_selectors.clone(),
                ..Default::default()
            });
        }
        tokens.push(lifetime_proto::NativeSkeletonToken {
            kind: "exit".into(), function: function_id.clone(), depth: 0, ..Default::default()
        });
        let event_ids: HashSet<&str> = events.iter().map(|node| node.id.as_str()).collect();
        let mut successors: HashMap<&str, Vec<&str>> = HashMap::new();
        for edge in &function.edges {
            successors.entry(edge.source.as_str()).or_default().push(edge.target.as_str());
        }
        // Preserve CFG branch structure while keeping each object stream
        // compact: walk through control/value nodes until the next lifecycle
        // event, instead of inventing textual edges between branch arms.
        let mut event_edges = BTreeSet::new();
        for event in &events {
            let mut queue: VecDeque<&str> = successors.get(event.id.as_str())
                .into_iter().flatten().copied().collect();
            let mut seen = HashSet::new();
            while let Some(node) = queue.pop_front() {
                if !seen.insert(node) { continue; }
                if event_ids.contains(node) {
                    event_edges.insert((event.id.as_str(), node));
                    continue;
                }
                queue.extend(successors.get(node).into_iter().flatten().copied());
            }
        }
        // Synthetic/unit semantic results can omit CFG links. Retain a
        // deterministic local stream for those inputs only; compiler-produced
        // graphs always take the CFG-compressed path above.
        if event_edges.is_empty() {
            event_edges.extend(events.windows(2).map(|pair| (pair[0].id.as_str(), pair[1].id.as_str())));
        }
        let edges = event_edges.into_iter().map(|(source, target)| lifetime_proto::NativeSemanticEdge {
            source: source.to_owned(), target: target.to_owned(), kind: "typestate".into(), ..Default::default()
        }).collect();
        output.push(lifetime_proto::NativeFlowSkeleton {
            kind: "typestate".into(), entry: function_id.clone(), source_function: function_id,
            context: root, complete: true, tokens, edges,
            is_source: !function.source_launch_nodes.is_empty(),
        });
    }
    output
}

/// Build one cached skeleton per source/context region.
pub(crate) fn build(
    result: &lifetime_proto::NativeSemanticResult,
) -> Vec<lifetime_proto::NativeFlowSkeleton> {
    if !result.regions.is_empty() {
        let (functions, nodes, adjacency) = semantic_indexes(result);
        let mut output = Vec::new();
        for region in &result.regions {
            for context in if region.contexts.is_empty() {
                vec!["__entry__".to_owned()]
            } else {
                region.contexts.clone()
            } {
                // A region without a compiler/source launch is the generic
                // structural coverage fallback.  It must remain represented,
                // but walking its entire CFG would repeat the same expensive
                // path exploration once per disconnected function.  The
                // function-local typestate builder below retains all event
                // semantics; source-launched regions alone need Claus's full
                // nested walk.
                if region.source_nodes.is_empty() {
                    let entry = functions.get(region.source_function.as_str())
                        .and_then(|function| {
                            (!function.entry.is_empty()).then(|| function.entry.clone())
                                .or_else(|| function.nodes.first().map(|node| node.id.clone()))
                        });
                    if let Some(entry) = entry {
                        output.push(lifetime_proto::NativeFlowSkeleton {
                            kind: "source-rooted".into(),
                            entry: region.source_function.clone(),
                            source_function: region.source_function.clone(),
                            context,
                            complete: true,
                            tokens: vec![lifetime_proto::NativeSkeletonToken {
                                kind: "control".into(), function: region.source_function.clone(),
                                node: entry, ..Default::default()
                            }],
                            edges: Vec::new(),
                            is_source: false,
                        });
                    }
                    continue;
                }
                let (tokens, edges, complete) = walk_region(
                    region, &context, &functions, &nodes, &adjacency);
                if tokens.is_empty() { continue; }
                output.push(lifetime_proto::NativeFlowSkeleton {
                    kind: "source-rooted".into(),
                    entry: region.source_function.clone(),
                    source_function: region.source_function.clone(),
                    context,
                    complete,
                    tokens,
                    edges,
                    is_source: functions.get(region.source_function.as_str())
                        .is_some_and(|function| !function.source_launch_nodes.is_empty()),
                });
            }
        }
        output.extend(build_typestate(result));
        if !output.is_empty() { return output; }
    }

    // Older or synthetic semantic sidecars may not carry Claus regions.
    build_typestate(result)
    /*
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
    output */
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emits_ordered_source_rooted_lifecycle_skeleton() {
        let function = lifetime_proto::NativeSemanticFunction {
            id: "f".into(), language: "c".into(),
            nodes: vec![
                lifetime_proto::NativeSemanticNode { id: "a".into(), event_kind: "ORIGIN".into(), generation: "g1".into(), ..Default::default() },
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
                source_function: "f".into(), source_nodes: vec!["a".into()],
                functions: vec!["f".into()],
                contexts: vec!["__entry__".into()], ..Default::default()
            }],
            ..Default::default()
        };
        let skeletons = build(&result);
        assert_eq!(skeletons.len(), 1);
        assert_eq!(skeletons[0].tokens[0].family, "memory.alloc");
        assert_eq!(skeletons[0].tokens[1].family, "memory.free");
        assert_eq!(skeletons[0].tokens[0].generation, "g1");
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
        assert_eq!(skeletons.len(), 1);
        let kinds: Vec<_> = skeletons[0].tokens.iter().map(|token| token.kind.as_str()).collect();
        assert!(kinds.iter().any(|kind| *kind == "event"));
        assert_eq!(skeletons[0].kind, "source-rooted");
        assert_eq!(skeletons[0].context, "s0");
        assert!(skeletons[0].tokens.iter().any(|token| token.function == "callee"));
        assert!(skeletons[0].complete);
        let callee_enter = skeletons[0].tokens.iter()
            .position(|token| token.kind == "enter" && token.function == "callee").unwrap();
        let callee_exit = skeletons[0].tokens.iter()
            .position(|token| token.kind == "exit" && token.function == "callee").unwrap();
        let continuation = skeletons[0].tokens.iter()
            .position(|token| token.node == "s2").unwrap();
        assert!(callee_enter < callee_exit && callee_exit < continuation);
    }
}
