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
    (callees, callers)
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

/// Match the old two-phase UDF traversal: callers to a fixpoint, then
/// callees to a fixpoint, with one shared visited set across all seeds.
fn traverse_component(
    start: &str,
    callees: &HashMap<String, Vec<String>>,
    callers: &HashMap<String, Vec<String>>,
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

/// Pick source-rooted Claus regions until every emitted UDF is covered.  The
/// old scheduler shuffles the sorted function records, not compiler node IDs,
/// then runs the two-phase caller/callee traversal from the selected UDF.
/// Keeping the same scheduling granularity is important: node-level shuffling
/// changes component seeds and therefore changes the Claus flow order.
///
/// A source witness identifies the function containing the source value.  If
/// no witness exists, every function still remains a structural root, matching
/// the old Python scheduler's conservative fallback.  Each source cone is
/// emitted once, so downstream Claus/skeleton caches never repeat the same
/// function for the same source context.
pub(crate) fn pick_regions(
    result: &lifetime_proto::NativeSemanticResult,
) -> Vec<lifetime_proto::NativeSourceRegion> {
    let (callees, callers) = call_graph(result);
    let mut function_order: Vec<String> = result.functions.iter()
        .map(|function| function.id.clone()).collect();
    function_order.sort();
    function_order.dedup();
    let shuffled = seed_order(&function_order);
    let mut regions = Vec::new();
    let mut visited = BTreeSet::new();
    for seed_function in shuffled {
        if visited.contains(&seed_function) { continue; }
        let selected = traverse_component(&seed_function, &callees, &callers, &mut visited);
        if selected.is_empty() { continue; }
        // The random UDF seed is a coverage starting point, not necessarily
        // the source UDF.  Resolve the source in caller-first traversal order;
        // this mirrors the old flow's "walk to the source, then launch Claus"
        // behavior while remaining language/catalog neutral.
        let source_function = selected.iter().find(|name|
            result.functions.iter().find(|function| function.id.as_str() == name.as_str())
                .is_some_and(|function| !function.source_launch_nodes.is_empty()))
            .cloned().unwrap_or_else(|| seed_function.clone());
        let mut source_nodes = Vec::new();
        for function_id in &selected {
            let Some(function) = result.functions.iter().find(|function| &function.id == function_id)
            else { continue };
            for launch in &function.source_launch_nodes {
                if !source_nodes.iter().any(|item| item == launch) {
                    source_nodes.push(launch.clone());
                }
            }
        }
        let seed_node = result.functions.iter()
            .find(|function| function.id == seed_function)
            .and_then(|function| function.nodes.first())
            .map(|node| node.id.clone())
            .unwrap_or_else(|| seed_function.clone());
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
            seed_node,
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
        assert_eq!(regions[0].source_function, "callee");
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
