//! Binary Claus skeleton construction for Pass 3.
//!
//! Claus receives source-rooted regions and re-serializes the native semantic
//! graph into a compact, ordered skeleton.  The skeleton retains event order,
//! control markers, guards, and graph edges; no source text or JSON is needed.

use std::collections::{BTreeMap, BTreeSet, HashMap};

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

fn tokens_for_function(
    function: &lifetime_proto::NativeSemanticFunction,
    depth: u32,
) -> (Vec<lifetime_proto::NativeSkeletonToken>, BTreeSet<String>) {
    let mut incoming: BTreeMap<&str, Vec<lifetime_proto::GuardProof>> = BTreeMap::new();
    for edge in &function.edges {
        if !edge.guards.is_empty() {
            incoming.entry(edge.target.as_str()).or_default().extend(edge.guards.clone());
        }
    }
    let mut tokens = Vec::new();
    let mut ids = BTreeSet::new();
    tokens.push(lifetime_proto::NativeSkeletonToken {
        kind: "enter".into(), function: function.id.clone(), depth, ..Default::default()
    });
    for node in &function.nodes {
        if node.event_kind.is_empty() { continue; }
        let guards = incoming.remove(node.id.as_str()).unwrap_or_default();
        let mut unique = BTreeSet::new();
        let guards: Vec<_> = guards.into_iter().filter(|guard| {
            unique.insert((guard.kind.clone(), guard.value.clone()))
        }).collect();
        ids.insert(node.id.clone());
        tokens.push(lifetime_proto::NativeSkeletonToken {
            kind: if matches!(node.event_kind.as_str(), "BRANCH" | "MERGE" | "LOOP") {
                "control".into()
            } else { "event".into() },
            function: function.id.clone(), node: node.id.clone(),
            family: lifecycle_family(&node.event_kind, &function.language),
            object_root: node.object_root.clone(), object_selectors: node.object_selectors.clone(),
            line: node.line, has_line: node.has_line, depth,
            guarded: !guards.is_empty(), guards,
            source_reachable: node.source_reachable,
            source_witness_nodes: node.source_witness_nodes.clone(),
        });
    }
    tokens.push(lifetime_proto::NativeSkeletonToken {
        kind: "exit".into(), function: function.id.clone(), depth, ..Default::default()
    });
    (tokens, ids)
}

/// Build one cached skeleton per source/context region.
pub(crate) fn build(
    result: &lifetime_proto::NativeSemanticResult,
) -> Vec<lifetime_proto::NativeFlowSkeleton> {
    let functions = function_map(result);
    let mut output = Vec::new();
    for region in &result.regions {
        let contexts = if region.contexts.is_empty() {
            vec!["__entry__".to_owned()]
        } else { region.contexts.clone() };
        for context in contexts {
            let mut tokens = Vec::new();
            let mut included = BTreeSet::new();
            let mut complete = true;
            for (depth, id) in region.functions.iter().enumerate() {
                let Some(function) = functions.get(id.as_str()) else {
                    complete = false;
                    continue;
                };
                let (mut part, ids) = tokens_for_function(function, depth as u32);
                tokens.append(&mut part);
                included.extend(ids);
            }
            let edges = result.functions.iter()
                .filter(|function| region.functions.contains(&function.id))
                .flat_map(|function| function.edges.iter())
                .chain(result.seams.iter())
                .filter(|edge| included.contains(&edge.source) && included.contains(&edge.target))
                .cloned()
                .collect();
            output.push(lifetime_proto::NativeFlowSkeleton {
                kind: "source-rooted".into(),
                entry: region.source_function.clone(),
                source_function: region.source_function.clone(),
                context, complete, tokens, edges,
            });
        }
    }
    output.sort_by(|left, right| (&left.source_function, &left.context)
        .cmp(&(&right.source_function, &right.context)));
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
        assert_eq!(skeletons[0].edges.len(), 1);
    }
}
