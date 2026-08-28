//! Source-rooted Pass-3 work selection.
//!
//! This is the first stage of the rebuilt Claus flow.  It selects a stable
//! source function, walks the compiler-resolved call graph, and emits the
//! function cone that the skeleton builder will consume.  The selection is
//! deliberately independent of vulnerability names: source identity comes
//! from the binary taint evidence and call identity comes from compiler seams.

use std::collections::{BTreeSet, HashMap, VecDeque};

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
) -> (HashMap<String, Vec<String>>, HashMap<String, Vec<String>>) {
    let owners = node_functions(result);
    let mut callees: HashMap<String, Vec<String>> = result.functions.iter()
        .map(|function| (function.id.clone(), Vec::new()))
        .collect();
    let mut callers = callees.clone();
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
        let callees_for_caller = callees.get_mut(caller).expect("caller exists");
        if !callees_for_caller.iter().any(|item| item == callee) {
            callees_for_caller.push(callee.to_owned());
        }
        let callers_for_callee = callers.get_mut(callee).expect("callee exists");
        if !callers_for_callee.iter().any(|item| item.as_str() == caller) {
            callers_for_callee.push((*caller).to_owned());
        }
    }
    for targets in callees.values_mut() { targets.sort(); }
    for targets in callers.values_mut() { targets.sort(); }
    (callees, callers)
}

fn callerless_root(
    start: &str,
    callers: &HashMap<String, Vec<String>>,
) -> String {
    let mut queue = VecDeque::from([start.to_owned()]);
    let mut seen = BTreeSet::new();
    let mut roots = BTreeSet::new();
    while let Some(function) = queue.pop_front() {
        if !seen.insert(function.clone()) { continue; }
        let parents = callers.get(&function).map(Vec::as_slice).unwrap_or_default();
        if parents.is_empty() {
            roots.insert(function);
        } else {
            queue.extend(parents.iter().cloned());
        }
    }
    // A recursive component may have no callerless member. Use its stable
    // smallest member as the structural root so coverage still terminates.
    roots.into_iter().next().or_else(|| seen.into_iter().next())
        .unwrap_or_else(|| start.to_owned())
}

fn downward_cone(start: &str, callees: &HashMap<String, Vec<String>>) -> Vec<String> {
    let mut queue = VecDeque::from([start.to_owned()]);
    let mut seen = BTreeSet::new();
    let mut ordered = Vec::new();
    while let Some(function) = queue.pop_front() {
        if !seen.insert(function.clone()) { continue; }
        ordered.push(function.clone());
        queue.extend(callees.get(&function).into_iter().flatten().cloned());
    }
    ordered
}

struct PythonRandom {
    state: [u32; 624],
    index: usize,
}

impl PythonRandom {
    fn seed_zero() -> Self {
        let mut state = [0u32; 624];
        state[0] = 19650218;
        for index in 1..624 {
            state[index] = 1812433253u32
                .wrapping_mul(state[index - 1] ^ (state[index - 1] >> 30))
                .wrapping_add(index as u32);
        }
        let mut index = 1usize;
        let mut key_index = 0usize;
        for _ in 0..624 {
            state[index] = (state[index]
                ^ (state[index - 1] ^ (state[index - 1] >> 30))
                    .wrapping_mul(1664525))
                .wrapping_add(key_index as u32);
            index += 1;
            key_index += 1;
            if index >= 624 { state[0] = state[623]; index = 1; }
            if key_index >= 1 { key_index = 0; }
        }
        for _ in 0..623 {
            state[index] = (state[index]
                ^ (state[index - 1] ^ (state[index - 1] >> 30))
                    .wrapping_mul(1566083941))
                .wrapping_sub(index as u32);
            index += 1;
            if index >= 624 { state[0] = state[623]; index = 1; }
        }
        state[0] = 0x8000_0000;
        Self { state, index: 624 }
    }

    fn twist(&mut self) {
        let old = self.state;
        for index in 0..624 {
            let value = (old[index] & 0x8000_0000)
                | (old[(index + 1) % 624] & 0x7fff_ffff);
            self.state[index] = old[(index + 397) % 624]
                ^ (value >> 1)
                ^ if value & 1 != 0 { 0x9908_b0df } else { 0 };
        }
        self.index = 0;
    }

    fn next_u32(&mut self) -> u32 {
        if self.index >= 624 { self.twist(); }
        let mut value = self.state[self.index];
        self.index += 1;
        value ^= value >> 11;
        value ^= (value << 7) & 0x9d2c_5680;
        value ^= (value << 15) & 0xefc6_0000;
        value ^ (value >> 18)
    }

    fn randbelow(&mut self, bound: usize) -> usize {
        let bits = usize::BITS - bound.leading_zeros();
        loop {
            let value = (self.next_u32() >> (32 - bits)) as usize;
            if value < bound { return value; }
        }
    }
}

fn seed_order(items: &[String]) -> Vec<String> {
    let mut order = items.to_vec();
    let mut random = PythonRandom::seed_zero();
    for index in (1..order.len()).rev() {
        order.swap(index, random.randbelow(index + 1));
    }
    order
}

fn region_seed_node(
    root: &str,
    functions_by_id: &HashMap<&str, &lifetime_proto::NativeSemanticFunction>,
) -> String {
    functions_by_id.get(root)
        .and_then(|function| function.nodes.first().map(|node| node.id.clone()))
        .unwrap_or_else(|| root.to_owned())
}

/// Faithful port of the reference source discovery.  Launch roots are the
/// catalogued source functions unioned with callerless functions; each root
/// owns the compiler-resolved callee cone reachable below it.  A launch that
/// is itself reachable from another launch is absorbed into that ancestor's
/// region -- its launch anchors are still emitted as walk starts, so no
/// source-originated flow is lost -- while pure cyclic components with neither
/// a callerless nor a catalogued member fall back to their stable-smallest
/// member so coverage still terminates over every function.  The seeded
/// shuffle over roots keeps binary sidecars reproducible while avoiding
/// source-order bias in which root owns a shared downstream cone.
pub(crate) fn pick_regions(
    result: &lifetime_proto::NativeSemanticResult,
) -> Vec<lifetime_proto::NativeSourceRegion> {
    let (callees, callers) = call_graph(result);
    let functions_by_id: HashMap<&str, &lifetime_proto::NativeSemanticFunction> =
        result.functions.iter().map(|function| (function.id.as_str(), function)).collect();

    // Launch anchors per function: catalogued source call nodes when present,
    // otherwise the structural entry of a callerless function.
    let mut launch_nodes: HashMap<String, Vec<String>> = HashMap::new();
    for function in &result.functions {
        if !function.source_launch_nodes.is_empty() {
            launch_nodes.insert(function.id.clone(), function.source_launch_nodes.clone());
        } else if callers.get(&function.id).map_or(true, |parents| parents.is_empty()) {
            let anchor = if !function.entry.is_empty() {
                Some(function.entry.clone())
            } else {
                function.nodes.first().map(|node| node.id.clone())
            };
            launch_nodes.insert(function.id.clone(), anchor.into_iter().collect());
        }
    }

    // A launch reachable from another launch's cone is not a distinct root; it
    // is covered under that ancestor (its anchors still seed the walk there).
    // One combined downward frontier seeded a single hop below every launch
    // marks every function dominated by some launch in O(edges); a launch that
    // lands in it is absorbed.  (A launch reachable only from its own cycle is
    // re-rooted by the coverage fallback below, so no function is dropped.)
    let mut dominated: BTreeSet<String> = BTreeSet::new();
    let mut frontier: VecDeque<String> = VecDeque::new();
    for launch in launch_nodes.keys() {
        for callee in callees.get(launch).into_iter().flatten() {
            if dominated.insert(callee.clone()) { frontier.push_back(callee.clone()); }
        }
    }
    while let Some(function) = frontier.pop_front() {
        for callee in callees.get(&function).into_iter().flatten() {
            if dominated.insert(callee.clone()) { frontier.push_back(callee.clone()); }
        }
    }
    let absorbed = dominated;

    let mut regions = Vec::new();
    let mut covered: BTreeSet<String> = BTreeSet::new();
    let mut emitted_roots: BTreeSet<String> = BTreeSet::new();

    let mut root_order: Vec<String> = launch_nodes.keys()
        .filter(|launch| !absorbed.contains(*launch))
        .cloned().collect();
    root_order.sort();
    for root in seed_order(&root_order) {
        if !emitted_roots.insert(root.clone()) { continue; }
        let cone = downward_cone(&root, &callees);
        let mut source_nodes: BTreeSet<String> = BTreeSet::new();
        for function_id in &cone {
            if let Some(anchors) = launch_nodes.get(function_id) {
                source_nodes.extend(anchors.iter().cloned());
            }
        }
        covered.extend(cone.iter().cloned());
        regions.push(lifetime_proto::NativeSourceRegion {
            source_function: root.clone(),
            source_nodes: source_nodes.into_iter().collect(),
            functions: cone,
            contexts: vec!["__entry__".to_owned()],
            seed_node: region_seed_node(&root, &functions_by_id),
        });
    }

    // Coverage fallback: cyclic components with no callerless or catalogued
    // launch. Root them at their stable-smallest member so every emitted node
    // still lands in exactly one region.
    let mut fallback_order: Vec<String> = result.functions.iter()
        .filter(|function| !function.nodes.is_empty())
        .map(|function| function.id.clone()).collect();
    fallback_order.sort();
    for seed in seed_order(&fallback_order) {
        if covered.contains(&seed) { continue; }
        let root = callerless_root(&seed, &callers);
        if !emitted_roots.insert(root.clone()) { continue; }
        let cone = downward_cone(&root, &callees);
        let source_nodes: Vec<String> = functions_by_id.get(root.as_str())
            .and_then(|function| (!function.entry.is_empty()).then(|| function.entry.clone())
                .or_else(|| function.nodes.first().map(|node| node.id.clone())))
            .into_iter().collect();
        covered.extend(cone.iter().cloned());
        regions.push(lifetime_proto::NativeSourceRegion {
            source_function: root.clone(),
            source_nodes,
            functions: cone,
            contexts: vec!["__entry__".to_owned()],
            seed_node: region_seed_node(&root, &functions_by_id),
        });
    }

    // Preserve compiler functions whose compact semantic projection has no
    // nodes. They cannot produce a skeleton today, but recording the region
    // keeps the all-function coverage contract explicit in the sidecar.
    for function in &result.functions {
        if !function.nodes.is_empty()
            || covered.contains(&function.id)
            || emitted_roots.contains(&function.id) { continue; }
        regions.push(lifetime_proto::NativeSourceRegion {
            source_function: function.id.clone(), functions: vec![function.id.clone()],
            seed_node: function.id.clone(), contexts: vec!["__entry__".to_owned()],
            ..Default::default()
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
                    id: "source".into(), source_launch_nodes: vec!["src-source".into()],
                    nodes: vec![node("src", "source", Some(true))], ..Default::default()
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
        assert_eq!(regions[0].source_function, "source");
        assert!(["src", "sink"].contains(&regions[0].seed_node.as_str()));
        assert_eq!(regions[0].contexts, vec!["__entry__"]);
        assert_eq!(regions[0].source_nodes.iter().collect::<BTreeSet<_>>(),
                   BTreeSet::from([&"src-source".to_owned(), &"source-call".to_owned()]));
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

    #[test]
    fn seed_order_matches_python_random_seed_zero() {
        let items = ["a", "b", "c", "d", "e"].into_iter().map(str::to_owned).collect::<Vec<_>>();
        assert_eq!(seed_order(&items), ["c", "b", "a", "e", "d"]);
    }
}
