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

fn seed_order(functions: &[String]) -> Vec<String> {
    let mut order = functions.to_vec();
    let mut state = 0x9e37_79b9_u64;
    for index in (1..order.len()).rev() {
        state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut value = state;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^= value >> 31;
        order.swap(index, (value as usize) % (index + 1));
    }
    order
}

/// Match the old two-phase UDF traversal: callers to a fixpoint, then
/// callees to a fixpoint, with one shared visited set across all seeds.
fn traverse_component(
    start: &str,
    callees: &BTreeMap<String, BTreeSet<String>>,
    callers: &BTreeMap<String, BTreeSet<String>>,
    visited: &mut BTreeSet<String>,
) -> Vec<String> {
    let mut local = Vec::new();
    if !visited.insert(start.to_owned()) { return local; }
    local.push(start.to_owned());
    let mut queue: VecDeque<String> = callers.get(start).into_iter().flatten()
        .filter(|name| !visited.contains(*name)).cloned().collect();
    let mut queued: BTreeSet<String> = queue.iter().cloned().collect();
    while let Some(function) = queue.pop_front() {
        if !visited.insert(function.clone()) { continue; }
        local.push(function.clone());
        for caller in callers.get(&function).into_iter().flatten() {
            if !visited.contains(caller) && queued.insert(caller.clone()) {
                queue.push_back(caller.clone());
            }
        }
    }
    queue.clear();
    queued.clear();
    for function in &local {
        for callee in callees.get(function).into_iter().flatten() {
            if !visited.contains(callee) && queued.insert(callee.clone()) {
                queue.push_back(callee.clone());
            }
        }
    }
    while let Some(function) = queue.pop_front() {
        if !visited.insert(function.clone()) { continue; }
        local.push(function.clone());
        for callee in callees.get(&function).into_iter().flatten() {
            if !visited.contains(callee) && queued.insert(callee.clone()) {
                queue.push_back(callee.clone());
            }
        }
    }
    local
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
    let (callees, callers) = call_graph(result);
    let mut names: Vec<String> = result.functions.iter().map(|function| function.id.clone()).collect();
    names.sort();
    let order = seed_order(&names);
    let mut regions = Vec::new();
    let mut visited = BTreeSet::new();
    for source in order {
        if visited.contains(&source) { continue; }
        let selected = traverse_component(&source, &callees, &callers, &mut visited);
        if selected.is_empty() { continue; }
        // The random UDF seed is a coverage starting point, not necessarily
        // the source UDF.  Resolve the source in caller-first traversal order;
        // this mirrors the old flow's "walk to the source, then launch Claus"
        // behavior while remaining language/catalog neutral.
        let source_function = selected.iter().find(|name|
            result.functions.iter().find(|function| function.id.as_str() == name.as_str())
                .is_some_and(|function| !function.source_launch_nodes.is_empty()))
            .cloned().unwrap_or_else(|| source.clone());
        let source_nodes: Vec<String> = result.functions.iter()
            .find(|function| function.id == source_function)
            .into_iter()
            .flat_map(|function| function.source_launch_nodes.iter().cloned())
            .collect::<BTreeSet<_>>().into_iter().collect();
        // A component is one cached Claus walk. Keep all launch anchors on
        // that walk instead of replaying the same function cone once per
        // source callsite; the old renderer composed one function flow and
        // retained the launch sites as evidence on its tokens.
        let contexts = vec!["__entry__".to_owned()];
        regions.push(lifetime_proto::NativeSourceRegion {
            source_function: source_function,
            source_nodes,
            functions: selected,
            contexts,
        });
    }
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
                    id: "callee".into(), source_launch_nodes: vec!["source-call".into()],
                    nodes: vec![node("sink", "callee", Some(false))], ..Default::default()
                },
            ],
            seams: vec![lifetime_proto::NativeSemanticEdge {
                source: "src".into(), target: "sink".into(), seam_kind: "call".into(), callee: "callee".into(), ..Default::default()
            }],
            ..Default::default()
        };
        let regions = pick_regions(&result);
        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].source_function, "callee");
        assert_eq!(regions[0].contexts, vec!["__entry__"]);
        assert_eq!(regions[0].functions.iter().collect::<BTreeSet<_>>(),
                   BTreeSet::from([&"source".to_owned(), &"callee".to_owned()]));
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
        assert_eq!(regions[0].contexts, vec!["__entry__"]);
    }
}
