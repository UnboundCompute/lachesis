//! Native Pass-3 matcher for the compact semantic sidecar.
//!
//! This module deliberately works on the protobuf sidecar, not on Python graph
//! objects.  Lifecycle identities are interned once per function: worklist
//! states carry `u32` handles rather than cloning root/selector/generation
//! strings on every CFG transfer.

use std::collections::VecDeque;
use rayon::prelude::*;
use rustc_hash::{FxHashMap as HashMap, FxHashSet as HashSet};

use crate::lifetime_proto;

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct ObjectKey {
    root: String,
    selectors: Vec<String>,
    generation: String,
}

impl ObjectKey {
    fn from_node(node: &lifetime_proto::NativeSemanticNode) -> Option<Self> {
        if node.object_root.is_empty() { return None; }
        Some(Self {
            root: node.object_root.clone(),
            selectors: node.object_selectors.clone(),
            generation: if node.generation.is_empty() {
                "g0".to_owned()
            } else {
                node.generation.clone()
            },
        })
    }

}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct StateKey {
    node: usize,
    bindings: Vec<(u32, u32)>,
    released: MarkSet,
    origins: MarkSet,
    nulls: MarkSet,
    uninitialized: MarkSet,
    pointer_arithmetic: MarkSet,
    escaped: MarkSet,
    realloc_lost: MarkSet,
}

/// Dense local object-id set used by the matcher worklist. Object handles are
/// assigned per function, so a bitset avoids sorting/deduplicating/cloning
/// vectors of u32 on every CFG transfer while retaining deterministic hashing.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct MarkSet(Vec<u64>);

impl MarkSet {
    fn empty(object_count: usize) -> Self {
        Self(vec![0; object_count.div_ceil(64)])
    }

    #[inline]
    fn contains(&self, value: u32) -> bool {
        let word = (value / 64) as usize;
        word < self.0.len() && self.0[word] & (1u64 << (value % 64)) != 0
    }

    #[inline]
    fn insert(&mut self, value: u32) {
        let word = (value / 64) as usize;
        if let Some(bits) = self.0.get_mut(word) {
            *bits |= 1u64 << (value % 64);
        }
    }

    #[inline]
    fn remove(&mut self, value: u32) {
        let word = (value / 64) as usize;
        if let Some(bits) = self.0.get_mut(word) {
            *bits &= !(1u64 << (value % 64));
        }
    }

    fn iter(&self) -> impl Iterator<Item = u32> + '_ {
        self.0.iter().enumerate().flat_map(|(word, bits)| {
            let mut bits = *bits;
            std::iter::from_fn(move || {
                if bits == 0 { return None; }
                let bit = bits.trailing_zeros();
                bits &= bits - 1;
                Some((word as u32) * 64 + bit)
            })
        })
    }
}

fn canonical(mut value: u32, bindings: &[(u32, u32)]) -> u32 {
    // Bindings are normalized by source before every transfer.  A binary
    // search avoids allocating a temporary cycle set on every event.  The
    // bound still makes malformed cyclic alias data terminate safely.
    for _ in 0..=bindings.len() {
        let Some(index) = bindings.binary_search_by_key(&value, |(source, _)| *source).ok()
        else { break };
        let target = bindings[index].1;
        if target == value { break; }
        value = target;
    }
    value
}

fn add_finding(
    output: &mut HashMap<(String, String, String, i64), lifetime_proto::NativeTemporalFinding>,
    function: &str,
    pattern: &str,
    object: &ObjectKey,
    node: &lifetime_proto::NativeSemanticNode,
) {
    let line = if node.has_line { node.line } else { 0 };
    let key = (function.to_owned(), pattern.to_owned(), node.id.clone(), line);
    output.entry(key).or_insert_with(|| lifetime_proto::NativeTemporalFinding {
        function: function.to_owned(),
        pattern: pattern.to_owned(),
        path: Some(lifetime_proto::Path {
            root: object.root.clone(),
            selectors: object.selectors.clone(),
        }),
        line,
        has_line: node.has_line,
        node: node.id.clone(),
    });
}

fn match_function(
    function: &lifetime_proto::NativeSemanticFunction,
) -> lifetime_proto::NativeTemporalFunction {
    if function.nodes.is_empty() {
        return lifetime_proto::NativeTemporalFunction {
            id: function.id.clone(),
            findings: Vec::new(),
            transfers: 0,
            widenings: 0,
            capped: false,
        };
    }
    let mut by_id = HashMap::with_capacity_and_hasher(function.nodes.len(), Default::default());
    for (index, node) in function.nodes.iter().enumerate() {
        by_id.insert(node.id.as_str(), index);
    }
    let mut outgoing = vec![Vec::new(); function.nodes.len()];
    for edge in &function.edges {
        if let (Some(source), Some(target)) = (by_id.get(edge.source.as_str()), by_id.get(edge.target.as_str())) {
            outgoing[*source].push(*target);
        }
    }
    let entry = by_id.get(function.entry.as_str()).copied().unwrap_or(0);
    let exits: HashSet<usize> = function.exits.iter()
        .filter_map(|id| by_id.get(id.as_str()).copied())
        .collect();

    // Intern object identities once.  The old representation put five cloned
    // ObjectKey vectors into every worklist state; on branch-heavy functions
    // that made state hashing and transfer cloning dominate the actual event
    // checks.  Handles are local to this function and never cross the ABI.
    let mut object_ids: HashMap<ObjectKey, u32> =
        HashMap::with_capacity_and_hasher(function.nodes.len(), Default::default());
    let mut objects = Vec::with_capacity(function.nodes.len());
    let mut node_object_ids = vec![None; function.nodes.len()];
    let mut node_value_ids = vec![None; function.nodes.len()];
    for (index, node) in function.nodes.iter().enumerate() {
        let value_object = (!node.value_root.is_empty()).then(|| ObjectKey {
            root: node.value_root.clone(),
            selectors: node.value_selectors.clone(),
            generation: if node.generation.is_empty() { "g0".to_owned() }
                        else { node.generation.clone() },
        });
        for (slot, object) in [ObjectKey::from_node(node), value_object].into_iter().enumerate() {
            let Some(object) = object else { continue };
            let id = if let Some(id) = object_ids.get(&object) {
                *id
            } else {
                let id = objects.len() as u32;
                object_ids.insert(object.clone(), id);
                objects.push(object);
                id
            };
            if slot == 0 { node_object_ids[index] = Some(id); }
            else { node_value_ids[index] = Some(id); }
        }
    }

    let empty = MarkSet::empty(objects.len());
    let mut queue = VecDeque::from([(
        entry,
        Vec::<(u32, u32)>::new(), empty.clone(), empty.clone(), empty.clone(),
        empty.clone(), empty.clone(), empty.clone(), empty,
    )]);
    let mut seen = HashSet::with_capacity_and_hasher(function.nodes.len(), Default::default());
    let mut findings = HashMap::with_capacity_and_hasher(function.nodes.len(), Default::default());
    let mut transfers = 0u64;
    // A malformed or adversarial sidecar must not make a query process diverge.
    // This is a work bound for one function, not a wall-clock hard stop.
    const MAX_STATES: usize = 1_000_000;

    while let Some((index, mut bindings, mut released, mut origins, mut nulls,
                    mut uninitialized, mut pointer_arithmetic, mut escaped,
                    mut realloc_lost)) = queue.pop_front() {
        if transfers as usize >= MAX_STATES { break; }
        transfers += 1;
        bindings.sort_unstable();
        bindings.dedup();
        let state = StateKey {
            node: index, bindings: bindings.clone(), released: released.clone(), origins: origins.clone(),
            nulls: nulls.clone(), uninitialized: uninitialized.clone(),
            pointer_arithmetic: pointer_arithmetic.clone(), escaped: escaped.clone(),
            realloc_lost: realloc_lost.clone(),
        };
        if !seen.insert(state) { continue; }
        let node = &function.nodes[index];
        let raw_object_id = node_object_ids[index];
        let object_id = raw_object_id.map(|value| canonical(value, &bindings));
        let value_id = node_value_ids[index].map(|value| canonical(value, &bindings));
        match node.event_kind.as_str() {
            "DERIVE" => if let (Some(target), Some(value)) = (raw_object_id, value_id) {
                bindings.retain(|(source, _)| *source != target);
                bindings.push((target, value));
                if node.access == "aggregate-copy" {
                    add_finding(&mut findings, &function.id, "aggregate-copy-alias",
                                &objects[target as usize], node);
                }
            },
            "ORIGIN" => if let Some(object) = object_id {
                released.remove(object);
                nulls.remove(object);
                uninitialized.remove(object);
                escaped.remove(object);
                realloc_lost.remove(object);
                origins.insert(object);
            },
            "RELEASE" => if let Some(object) = object_id {
                // A release through a slot proven to contain null is a no-op.
                // Keep this check before adding the object to the released set;
                // otherwise a later valid release would be misclassified.
                if !nulls.contains(object) {
                    if released.contains(object) {
                        add_finding(&mut findings, &function.id, "double-free",
                                    &objects[object as usize], node);
                    }
                    released.insert(object);
                }
            },
            "INVALIDATE" => if let Some(object) = object_id {
                released.insert(object);
            },
            "REALLOC_FAILED" => if let Some(object) = object_id {
                realloc_lost.insert(object);
            },
            "ESCAPE" => if let Some(object) = object_id {
                escaped.insert(object);
            },
            "LOST_FROM_SLOT" => if let Some(object) = object_id {
                nulls.insert(object);
                realloc_lost.insert(object);
            },
            "READ_STORAGE" => if let Some(object) = object_id {
                if released.contains(object) {
                    add_finding(&mut findings, &function.id, "uaf.deref",
                                &objects[object as usize], node);
                }
                if nulls.contains(object) {
                    add_finding(&mut findings, &function.id, "null-deref",
                                &objects[object as usize], node);
                }
                if uninitialized.contains(object) {
                    add_finding(&mut findings, &function.id, "uninitialized-use",
                                &objects[object as usize], node);
                }
                if pointer_arithmetic.contains(object) {
                    add_finding(&mut findings, &function.id,
                                "pointer-arithmetic-before-validation",
                                &objects[object as usize], node);
                }
            },
            "WRITE_STORAGE" => if let Some(object) = object_id {
                if released.contains(object) {
                    add_finding(&mut findings, &function.id, "uaf.deref",
                                &objects[object as usize], node);
                }
                if nulls.contains(object) {
                    add_finding(&mut findings, &function.id, "null-deref",
                                &objects[object as usize], node);
                }
                if uninitialized.contains(object) {
                    add_finding(&mut findings, &function.id,
                                "uninitialized-use", &objects[object as usize], node);
                }
                if let Some(value) = value_id {
                    bindings.retain(|(source, _)| *source != object);
                    bindings.push((object, value));
                }
            },
            "PASS_VALUE" | "COMPARE_VALUE" | "RETURN_VALUE" => if let Some(object) = object_id {
                if released.contains(object) {
                    add_finding(&mut findings, &function.id, "use.dangling",
                                &objects[object as usize], node);
                }
                if uninitialized.contains(object) {
                    add_finding(&mut findings, &function.id, "uninitialized-use",
                                &objects[object as usize], node);
                }
                if node.event_kind == "RETURN_VALUE" && node.stack_local {
                    add_finding(&mut findings, &function.id, "use-after-return",
                                &objects[object as usize], node);
                }
            },
            "WRITE_STORAGE_NULL" => if let Some(object) = object_id {
                nulls.insert(object);
            },
            "UNINITIALIZED" => if let Some(object) = object_id {
                uninitialized.insert(object);
            },
            "POINTER_ARITHMETIC" => if let Some(object) = object_id {
                pointer_arithmetic.insert(object);
            },
            _ => {}
        }
        if exits.contains(&index) {
            for object in realloc_lost.iter() {
                if !released.contains(object)
                    && !escaped.contains(object)
                {
                    add_finding(&mut findings, &function.id,
                                "realloc-failure-leak", &objects[object as usize], node);
                }
            }
            for object in origins.iter() {
                if !released.contains(object)
                    && !escaped.contains(object)
                {
                    add_finding(&mut findings, &function.id, "leak",
                                &objects[object as usize], node);
                }
            }
        }
        for target in &outgoing[index] {
            queue.push_back((*target, bindings.clone(), released.clone(), origins.clone(), nulls.clone(),
                             uninitialized.clone(), pointer_arithmetic.clone(), escaped.clone(),
                             realloc_lost.clone()));
        }
    }

    let mut findings: Vec<_> = findings.into_values().collect();
    findings.sort_by(|left, right| {
        (&left.pattern, &left.node, left.line, left.has_line)
            .cmp(&(&right.pattern, &right.node, right.line, right.has_line))
    });
    lifetime_proto::NativeTemporalFunction {
        id: function.id.clone(),
        findings,
        transfers,
        widenings: 0,
        capped: transfers as usize >= MAX_STATES,
    }
}

pub(crate) fn match_result(
    result: lifetime_proto::NativeSemanticResult,
) -> lifetime_proto::NativeTemporalResult {
    // Function states are independent. Parallelize the common small-function
    // case, but keep large CFGs serialized so branch-heavy state sets do not
    // multiply peak RSS on large repositories.
    const LARGE_FUNCTION_NODES: usize = 2_000;
    let total = result.functions.len();
    let (large, small): (Vec<_>, Vec<_>) = result.functions.into_iter().enumerate()
        .partition(|(_, function)| function.nodes.len() > LARGE_FUNCTION_NODES);
    let worker_count = std::env::var("LACHESIS_PASS3_WORKERS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0);
    let matched_small: Vec<(usize, lifetime_proto::NativeTemporalFunction)> = match worker_count {
        Some(1) => small.into_iter().map(|(index, function)|
            (index, match_function(&function))).collect(),
        Some(count) => rayon::ThreadPoolBuilder::new()
            .num_threads(count)
            .build()
            .map(|pool| pool.install(|| small.par_iter()
                .map(|(index, function)| (*index, match_function(function))).collect()))
            .unwrap_or_else(|_| small.into_iter()
                .map(|(index, function)| (index, match_function(&function))).collect()),
        None => small.par_iter()
            .map(|(index, function)| (*index, match_function(function))).collect(),
    };
    let mut ordered: Vec<Option<lifetime_proto::NativeTemporalFunction>> =
        (0..total).map(|_| None).collect();
    for (index, matched) in matched_small {
        ordered[index] = Some(matched);
    }
    for (index, function) in large {
        ordered[index] = Some(match_function(&function));
    }
    lifetime_proto::NativeTemporalResult {
        functions: ordered.into_iter().flatten().collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(id: &str, event_kind: &str, line: i64) -> lifetime_proto::NativeSemanticNode {
        lifetime_proto::NativeSemanticNode {
            id: id.to_owned(), function: "f".to_owned(),
            event_kind: event_kind.to_owned(), object_root: "p".to_owned(),
            object_selectors: Vec::new(), generation: "g0".to_owned(),
            line, has_line: true, anchor: id.to_owned(), stack_local: false,
            is_null: false, access: String::new(), value_root: String::new(),
            value_selectors: Vec::new(),
        }
    }

    fn function(nodes: Vec<lifetime_proto::NativeSemanticNode>)
        -> lifetime_proto::NativeSemanticFunction
    {
        let ids: Vec<String> = nodes.iter().map(|item| item.id.clone()).collect();
        let edges = ids.windows(2).map(|pair| lifetime_proto::NativeSemanticEdge {
            source: pair[0].clone(), target: pair[1].clone(), kind: "normal".to_owned(),
        }).collect();
        lifetime_proto::NativeSemanticFunction {
            id: "f".to_owned(), entry: ids[0].clone(), exits: vec![ids[ids.len() - 1].clone()],
            nodes, edges, language: "c".to_owned(),
        }
    }

    #[test]
    fn finds_double_free_on_a_reachable_lifecycle_path() {
        let result = match_result(lifetime_proto::NativeSemanticResult {
            functions: vec![function(vec![node("o", "ORIGIN", 1),
                                             node("r1", "RELEASE", 2),
                                             node("r2", "RELEASE", 3)])],
            complete: true,
        });
        assert_eq!(result.functions[0].findings.len(), 1);
        assert_eq!(result.functions[0].findings[0].pattern, "double-free");
        assert_eq!(result.functions[0].findings[0].line, 3);
    }

    #[test]
    fn finds_use_after_free_on_a_reachable_lifecycle_path() {
        let result = match_result(lifetime_proto::NativeSemanticResult {
            functions: vec![function(vec![node("o", "ORIGIN", 1),
                                             node("r", "RELEASE", 2),
                                             node("u", "READ_STORAGE", 3)])],
            complete: true,
        });
        assert_eq!(result.functions[0].findings.len(), 1);
        assert_eq!(result.functions[0].findings[0].pattern, "uaf.deref");
        assert_eq!(result.functions[0].findings[0].line, 3);
    }

    #[test]
    fn invalidation_is_not_misreported_as_a_second_free() {
        let result = match_result(lifetime_proto::NativeSemanticResult {
            functions: vec![function(vec![node("o", "ORIGIN", 1),
                                             node("i", "INVALIDATE", 2),
                                             node("n", "ORIGIN", 3)])],
            complete: true,
        });
        assert!(result.functions[0].findings.iter().all(|finding| finding.pattern != "double-free"));
    }

    #[test]
    fn follows_a_derived_alias_after_release() {
        let mut derive = node("d", "DERIVE", 2);
        derive.object_root = "alias".to_owned();
        derive.value_root = "p".to_owned();
        let mut use_alias = node("u", "READ_STORAGE", 4);
        use_alias.object_root = "alias".to_owned();
        let result = match_result(lifetime_proto::NativeSemanticResult {
            functions: vec![function(vec![node("o", "ORIGIN", 1),
                                             derive,
                                             node("r", "RELEASE", 3),
                                             use_alias])],
            complete: true,
        });
        assert_eq!(result.functions[0].findings.len(), 1);
        assert_eq!(result.functions[0].findings[0].pattern, "uaf.deref");
        assert_eq!(result.functions[0].findings[0].line, 4);
    }

    #[test]
    fn null_release_does_not_create_a_double_free() {
        let result = match_result(lifetime_proto::NativeSemanticResult {
            functions: vec![function(vec![node("n", "WRITE_STORAGE_NULL", 1),
                                             node("r", "RELEASE", 2)])],
            complete: true,
        });
        assert!(result.functions[0].findings.is_empty());
    }

    #[test]
    fn records_aggregate_copy_aliases() {
        let mut derive = node("copy", "DERIVE", 7);
        derive.object_root = "destination".to_owned();
        derive.value_root = "source".to_owned();
        derive.access = "aggregate-copy".to_owned();
        let result = match_result(lifetime_proto::NativeSemanticResult {
            functions: vec![function(vec![derive])],
            complete: true,
        });
        assert_eq!(result.functions[0].findings.len(), 1);
        assert_eq!(result.functions[0].findings[0].pattern, "aggregate-copy-alias");
    }

    #[test]
    fn records_realloc_failure_leak_at_function_exit() {
        let result = match_result(lifetime_proto::NativeSemanticResult {
            functions: vec![function(vec![node("o", "ORIGIN", 1),
                                             node("f", "REALLOC_FAILED", 2),
                                             node("x", "", 3)])],
            complete: true,
        });
        assert!(result.functions[0].findings.iter()
            .any(|finding| finding.pattern == "realloc-failure-leak"));
    }

    #[test]
    fn escaped_object_is_not_reported_as_a_leak() {
        let result = match_result(lifetime_proto::NativeSemanticResult {
            functions: vec![function(vec![node("o", "ORIGIN", 1),
                                             node("e", "ESCAPE", 2)])],
            complete: true,
        });
        assert!(result.functions[0].findings.is_empty());
    }
}
