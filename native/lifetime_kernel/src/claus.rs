//! Source-rooted Pass-3 work selection.
//!
//! This is the first stage of the rebuilt Claus flow.  It selects a stable
//! source function, walks the compiler-resolved call graph, and emits the
//! function cone that the skeleton builder will consume.  The selection is
//! deliberately independent of vulnerability names: source identity comes
//! from the binary taint evidence and call identity comes from compiler seams.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

use crate::lifetime_proto;

fn node_functions(result: &lifetime_proto::NativeSemanticResult) -> HashMap<&str, &str> {
    result.functions.iter()
        .flat_map(|function| function.nodes.iter().map(move |node| {
            (node.id.as_str(), function.id.as_str())
        }))
        .collect()
}

fn call_graph(
    result: &lifetime_proto::NativeSemanticResult,
) -> (BTreeMap<String, BTreeSet<String>>, BTreeMap<String, BTreeSet<String>>) {
    let owners = node_functions(result);
    let mut callees: BTreeMap<String, BTreeSet<String>> = result.functions.iter()
        .map(|function| (function.id.clone(), BTreeSet::new()))
        .collect();
    let mut callers: BTreeMap<String, BTreeSet<String>> = callees.clone();
    for edge in &result.seams {
        if edge.seam_kind != "call" { continue; }
        let Some(caller) = owners.get(edge.source.as_str()).copied()
            .or_else(|| edge.bindings.first().map(|binding| binding.caller.as_str()))
        else { continue };
        let callee = if !edge.callee.is_empty() {
            edge.callee.as_str()
        } else if let Some(function) = owners.get(edge.target.as_str()) {
            function
        } else if let Some(binding) = edge.bindings.first() {
            binding.callee.as_str()
        } else {
            continue;
        };
        if !callees.contains_key(caller) || !callees.contains_key(callee) { continue; }
        callees.get_mut(caller).expect("caller exists").insert(callee.to_owned());
        callers.get_mut(callee).expect("callee exists").insert((*caller).to_owned());
    }
    (callees, callers)
}

fn forward(start: &str, callees: &BTreeMap<String, BTreeSet<String>>) -> BTreeSet<String> {
    let mut seen = BTreeSet::from([start.to_owned()]);
    let mut queue = VecDeque::from([start.to_owned()]);
    while let Some(function) = queue.pop_front() {
        for callee in callees.get(&function).into_iter().flatten() {
            if seen.insert(callee.clone()) { queue.push_back(callee.clone()); }
        }
    }
    seen
}

fn backward(start: &str, callers: &BTreeMap<String, BTreeSet<String>>) -> BTreeSet<String> {
    let mut seen = BTreeSet::from([start.to_owned()]);
    let mut queue = VecDeque::from([start.to_owned()]);
    while let Some(function) = queue.pop_front() {
        for caller in callers.get(&function).into_iter().flatten() {
            if seen.insert(caller.clone()) { queue.push_back(caller.clone()); }
        }
    }
    seen
}

/// Pick source-rooted Claus regions until every emitted function is covered.
///
/// A source witness identifies the function containing the source value.  If
/// no witness exists, callerless functions are structural roots, matching the
/// old Python scheduler's conservative fallback.  Each source cone is emitted
/// once, so downstream Claus/skeleton caches never repeat the same function
/// for the same source context.
pub(crate) fn pick_regions(
    result: &lifetime_proto::NativeSemanticResult,
) -> Vec<lifetime_proto::NativeSourceRegion> {
    let owners = node_functions(result);
    let (callees, callers) = call_graph(result);
    let mut source_nodes: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for function in &result.functions {
        // Source contexts come from compiler-resolved source call sites, just
        // like CoverageScheduler._source_contexts in the old engine.  A taint
        // witness is evidence attached to a reached value, not a new launch
        // context; treating every witness as one caused a full cone walk per
        // reached node on large graphs.
        if !function.source_launch_nodes.is_empty() {
            source_nodes.entry(function.id.clone()).or_default()
                .extend(function.source_launch_nodes.iter().cloned());
            continue;
        }
        for node in &function.nodes {
            if node.source_reachable != Some(true) { continue; }
            let source_function = node.source_witness_nodes.first()
                .and_then(|id| owners.get(id.as_str()).copied())
                .unwrap_or(function.id.as_str());
            let entry = source_nodes.entry(source_function.to_owned()).or_default();
            if node.source_witness_nodes.is_empty() {
                entry.insert(node.anchor.clone());
            } else {
                entry.extend(node.source_witness_nodes.iter().cloned());
            }
        }
    }
    for (function, incoming) in &callers {
        if incoming.is_empty() { source_nodes.entry(function.clone()).or_default(); }
    }
    if source_nodes.is_empty() {
        for function in &result.functions { source_nodes.entry(function.id.clone()).or_default(); }
    }

    // A source is materialized once.  If a disconnected component has no
    // source root, its callerless/root function is added as a structural root.
    let mut regions = Vec::new();
    let mut covered = BTreeSet::new();
    for (source, nodes) in &source_nodes {
        let cone = forward(source, &callees);
        // Keep the old scheduler's two-sided proof: a function belongs to a
        // source region only when it is both forward-reachable from that
        // source and backward-reachable to it.  This prevents a malformed
        // disconnected seam from crediting an unrelated function.
        let selected: Vec<String> = result.functions.iter()
            .map(|function| function.id.as_str())
            .filter(|function| cone.contains(*function)
                && backward(function, &callers).contains(source))
            .map(str::to_owned)
            .collect();
        if selected.is_empty() { continue; }
        covered.extend(selected.iter().cloned());
        let contexts = if nodes.is_empty() {
            vec!["__entry__".to_owned()]
        } else {
            nodes.iter().cloned().collect()
        };
        regions.push(lifetime_proto::NativeSourceRegion {
            source_function: source.clone(),
            source_nodes: nodes.iter().cloned().collect(),
            functions: selected,
            contexts,
        });
    }
    // Ensure the invariant is explicit even when a malformed/incomplete seam
    // graph leaves a function outside every source cone.
    for function in result.functions.iter().map(|item| item.id.as_str()).filter(|id| !covered.contains(*id)) {
        regions.push(lifetime_proto::NativeSourceRegion {
            source_function: function.to_owned(),
            source_nodes: Vec::new(),
            functions: vec![function.to_owned()],
            contexts: vec!["__entry__".to_owned()],
        });
    }
    regions.sort_by(|left, right| left.source_function.cmp(&right.source_function));
    regions
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(id: &str, function: &str, reachable: Option<bool>) -> lifetime_proto::NativeSemanticNode {
        lifetime_proto::NativeSemanticNode {
            id: id.to_owned(), function: function.to_owned(),
            source_reachable: reachable, ..Default::default()
        }
    }

    #[test]
    fn picks_source_function_and_forward_cone_once() {
        let result = lifetime_proto::NativeSemanticResult {
            functions: vec![
                lifetime_proto::NativeSemanticFunction {
                    id: "source".into(), nodes: vec![node("src", "source", Some(true))], ..Default::default()
                },
                lifetime_proto::NativeSemanticFunction {
                    id: "callee".into(), nodes: vec![node("sink", "callee", Some(false))], ..Default::default()
                },
            ],
            seams: vec![lifetime_proto::NativeSemanticEdge {
                source: "src".into(), target: "sink".into(), seam_kind: "call".into(), callee: "callee".into(), ..Default::default()
            }],
            ..Default::default()
        };
        let regions = pick_regions(&result);
        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].source_function, "source");
        assert_eq!(regions[0].functions, vec!["source", "callee"]);
    }

    #[test]
    fn disconnected_functions_are_not_dropped() {
        let result = lifetime_proto::NativeSemanticResult {
            functions: vec![
                lifetime_proto::NativeSemanticFunction { id: "a".into(), nodes: vec![node("a", "a", None)], ..Default::default() },
                lifetime_proto::NativeSemanticFunction { id: "b".into(), nodes: vec![node("b", "b", None)], ..Default::default() },
            ], ..Default::default()
        };
        let regions = pick_regions(&result);
        let functions: BTreeSet<_> = regions.iter().flat_map(|region| region.functions.iter()).collect();
        assert_eq!(functions, BTreeSet::from([&"a".to_owned(), &"b".to_owned()]));
    }

    #[test]
    fn taint_witnesses_do_not_become_duplicate_source_contexts() {
        let result = lifetime_proto::NativeSemanticResult {
            functions: vec![lifetime_proto::NativeSemanticFunction {
                id: "source".into(),
                source_launch_nodes: vec!["source-call".into()],
                nodes: (0..100).map(|index| node(&format!("w{index}"), "source", Some(true))).collect(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let regions = pick_regions(&result);
        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].contexts, vec!["source-call"]);
    }
}
