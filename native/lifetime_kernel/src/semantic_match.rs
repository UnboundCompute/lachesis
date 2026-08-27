//! Native Pass-3 matcher for the compact semantic sidecar.
//!
//! This module deliberately works on the protobuf sidecar, not on Python graph
//! objects.  It is the first native matcher slice: lifecycle event identities
//! and their intra-function control-flow reachability.  More expressive
//! catalog/sink facts remain separate until their facts are represented in the
//! binary semantic contract.

use std::collections::{HashMap, HashSet, VecDeque};

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

    fn into_path(self) -> lifetime_proto::Path {
        lifetime_proto::Path { root: self.root, selectors: self.selectors }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct StateKey {
    node: usize,
    released: Vec<ObjectKey>,
    origins: Vec<ObjectKey>,
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
    let mut by_id = HashMap::with_capacity(function.nodes.len());
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

    let mut queue = VecDeque::from([(entry, Vec::<ObjectKey>::new(), Vec::<ObjectKey>::new())]);
    let mut seen = HashSet::new();
    let mut findings = HashMap::new();
    let mut transfers = 0u64;
    // A malformed or adversarial sidecar must not make a query process diverge.
    // This is a work bound for one function, not a wall-clock hard stop.
    const MAX_STATES: usize = 1_000_000;

    while let Some((index, mut released, mut origins)) = queue.pop_front() {
        if transfers as usize >= MAX_STATES { break; }
        transfers += 1;
        released.sort();
        origins.sort();
        let state = StateKey { node: index, released: released.clone(), origins: origins.clone() };
        if !seen.insert(state) { continue; }
        let node = &function.nodes[index];
        let object = ObjectKey::from_node(node);
        match node.event_kind.as_str() {
            "ORIGIN" => if let Some(object) = object {
                released.retain(|item| item != &object);
                if !origins.contains(&object) { origins.push(object); }
            },
            "RELEASE" | "INVALIDATE" => if let Some(object) = object {
                if released.contains(&object) {
                    add_finding(&mut findings, &function.id, "double-free", &object, node);
                }
                released.push(object);
            },
            "READ_STORAGE" | "WRITE_STORAGE" => if let Some(object) = object {
                if released.contains(&object) {
                    add_finding(&mut findings, &function.id, "uaf.deref", &object, node);
                }
            },
            "PASS_VALUE" | "COMPARE_VALUE" | "RETURN_VALUE" => if let Some(object) = object {
                if released.contains(&object) {
                    add_finding(&mut findings, &function.id, "use.dangling", &object, node);
                }
            },
            _ => {}
        }
        if exits.contains(&index) {
            for object in &origins {
                if !released.contains(object) {
                    add_finding(&mut findings, &function.id, "leak", object, node);
                }
            }
        }
        for target in &outgoing[index] {
            queue.push_back((*target, released.clone(), origins.clone()));
        }
    }

    lifetime_proto::NativeTemporalFunction {
        id: function.id.clone(),
        findings: findings.into_values().collect(),
        transfers,
        widenings: 0,
        capped: transfers as usize >= MAX_STATES,
    }
}

pub(crate) fn match_result(
    result: lifetime_proto::NativeSemanticResult,
) -> lifetime_proto::NativeTemporalResult {
    lifetime_proto::NativeTemporalResult {
        functions: result.functions.iter().map(match_function).collect(),
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
            line, has_line: true, anchor: id.to_owned(),
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
            nodes, edges,
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
}
