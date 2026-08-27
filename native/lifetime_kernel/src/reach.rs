//! Binary source-to-sink skeletons built from native reach summaries.
//!
//! The old Pass-3 flow rendered one reach skeleton for each summary flow and
//! stitched `via` callee summaries through call sites.  This module keeps that
//! composition data-driven: sink families come from the compiled Atropos
//! catalog and function identity comes from compiler translation facts.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::{atropos_proto, lifetime_proto};

fn sink_parts(sink: &str) -> Option<(&str, u32)> {
    let (callee, position) = sink.rsplit_once(".a")?;
    Some((callee, position.parse().ok()?))
}

fn argument_root(argument: &lifetime_proto::FunctionArgument) -> String {
    let root = if !argument.root_name.is_empty() { &argument.root_name }
        else if !argument.root.is_empty() { &argument.root }
        else { &argument.expression };
    if root.is_empty() { String::new() }
    else { format!("{}{}", root.trim_start_matches("decl:"), argument.selectors.join("")) }
}

fn family_for(
    callee: &str,
    language: &str,
    position: u32,
    catalog: &atropos_proto::Request,
) -> String {
    catalog.models.iter()
        .filter(|model| model.role == "sink"
            && (model.language.is_empty() || model.language == language)
            && (model.package.is_empty() || model.package == "builtins"
                && model.method == callee
                || !model.package.is_empty()
                    && format!("{}.{}", model.package, model.method) == callee))
        .filter(|model| model.access_path.contains(&format!("Argument[{position}]"))
            || model.access_path.contains("Argument[*]"))
        .find_map(|model| (!model.kind.is_empty()).then(|| model.kind.clone()))
        .unwrap_or_default()
}

fn sink_token(
    flow: &lifetime_proto::NativeSinkFlow,
    language: &str,
    catalog: &atropos_proto::Request,
    depth: u32,
    guarded: bool,
    truncated: bool,
) -> lifetime_proto::NativeSkeletonToken {
    let (callee, argument) = sink_parts(&flow.sink).unwrap_or((flow.sink.as_str(), 0));
    lifetime_proto::NativeSkeletonToken {
        kind: "sink".into(), family: family_for(callee, language, argument, catalog),
        object_root: flow.root.clone(), value: flow.value.clone(), node: flow.node.clone(),
        line: flow.line, has_line: flow.has_line, depth,
        guarded, tainted: flow.provenance != "const",
        bound: if guarded { "bounded".into() } else { "unbounded".into() },
        callee: callee.into(), argument, has_argument: true, truncated,
        size_expression: flow.size_expression.clone(), destination: flow.destination.clone(),
        control: flow.control.clone(), guards: flow.guard_predicates.iter().map(|value|
            lifetime_proto::GuardProof { kind: "PREDICATE".into(), value: value.clone() }).collect(),
        guard_status: flow.guard_status.clone(),
        source_witness_nodes: flow.source_witness_nodes.clone(),
        ..Default::default()
    }
}

fn expand(
    function: &str,
    flow: &lifetime_proto::NativeSinkFlow,
    functions: &BTreeMap<String, &lifetime_proto::TranslationFunction>,
    summaries: &HashMap<String, &lifetime_proto::NativeSummaryFunction>,
    catalog: &atropos_proto::Request,
    depth: u32,
    guarded_acc: bool,
    chain: &BTreeSet<String>,
    tokens: &mut Vec<lifetime_proto::NativeSkeletonToken>,
) -> bool {
    let Some((sink_callee, sink_position)) = sink_parts(&flow.sink) else {
        tokens.push(sink_token(flow, "", catalog, depth, guarded_acc || flow.guarded, true));
        return false;
    };
    if flow.via == "direct" {
        let language = functions.get(function).map(|item| item.language.as_str()).unwrap_or("");
        tokens.push(sink_token(flow, language, catalog, depth, guarded_acc || flow.guarded, false));
        return true;
    }
    if !chain.contains(&flow.via) {
        if let (Some(caller), Some(callee)) = (functions.get(function), functions.get(&flow.via)) {
            let call = caller.calls.iter().find(|call| {
                call.callee == flow.via && call.arguments.iter().any(|argument|
                    argument_root(argument) == flow.root)
            }).or_else(|| caller.calls.iter().find(|call| call.callee == flow.via));
            if call.is_some() && callee.id == flow.via {
                if let Some(summary) = summaries.get(&flow.via) {
                    let actual_root = call.and_then(|call| call.arguments.iter()
                        .find(|argument| argument_root(argument) == flow.root))
                        .map(argument_root);
                    if let Some(subflow) = summary.sink_flows.iter().find(|candidate|
                        candidate.sink == flow.sink
                            && actual_root.as_deref().is_none_or(|root| candidate.root == root)
                    ) {
                        tokens.push(lifetime_proto::NativeSkeletonToken {
                            kind: "enter".into(), function: flow.via.clone(), depth: depth + 1,
                            ..Default::default()
                        });
                    let site_guarded = call.is_some_and(|call| !call.control.is_empty()
                        || !call.guard_predicates.is_empty());
                    let mut next_chain = chain.clone();
                    next_chain.insert(flow.via.clone());
                    let complete = expand(&flow.via, subflow, functions, summaries, catalog,
                                              depth + 1, guarded_acc || flow.guarded || site_guarded,
                                              &next_chain, tokens);
                        tokens.push(lifetime_proto::NativeSkeletonToken {
                            kind: "exit".into(), function: flow.via.clone(), depth: depth + 1,
                            ..Default::default()
                        });
                        return complete;
                    }
                }
            }
        }
    }
    let language = functions.get(function).map(|item| item.language.as_str()).unwrap_or("");
    let _ = (sink_callee, sink_position);
    tokens.push(sink_token(flow, language, catalog, depth, guarded_acc || flow.guarded, true));
    false
}

/// Build reach skeletons from the native summary fixed point.  Callerless
/// functions are the conservative source-root fallback used by the old
/// scheduler; disconnected functions are still retained when they contain a
/// summary flow.
pub(crate) fn build(
    translation: &lifetime_proto::TranslationResult,
    summaries: &lifetime_proto::NativeSummaryResult,
    catalog: &atropos_proto::Request,
) -> Vec<lifetime_proto::NativeFlowSkeleton> {
    let mut functions = BTreeMap::new();
    for function in &translation.functions {
        let key = if function.name.is_empty() { function.id.clone() } else { function.name.clone() };
        functions.entry(key).or_insert(function);
    }
    let summary_map: HashMap<String, &lifetime_proto::NativeSummaryFunction> = summaries.functions.iter()
        .map(|summary| (summary.name.clone(), summary)).collect();
    // The old engine emitted a skeleton for every function carrying a summary
    // flow.  Callerless/source roots are marked separately; they are not a
    // reason to discard callee-local skeletons, which are needed for coverage
    // and for callers whose chain cannot be stitched completely.
    let roots: Vec<String> = functions.keys()
        .filter(|name| summary_map.get(*name).is_some_and(|summary| !summary.sink_flows.is_empty()))
        .cloned().collect();
    let mut output = Vec::new();
    for root in roots {
        let Some(summary) = summary_map.get(&root) else { continue };
        let is_source = functions.get(&root).is_some_and(|function|
            function.calls.iter().any(|call| call.is_source));
        for flow in &summary.sink_flows {
            let mut tokens = vec![lifetime_proto::NativeSkeletonToken {
                kind: "enter".into(), function: root.clone(), depth: 0, ..Default::default()
            }];
            let complete = expand(&root, flow, &functions, &summary_map, catalog, 0,
                                  false, &BTreeSet::from([root.clone()]), &mut tokens);
            tokens.push(lifetime_proto::NativeSkeletonToken {
                kind: "exit".into(), function: root.clone(), depth: 0, ..Default::default()
            });
            output.push(lifetime_proto::NativeFlowSkeleton {
                kind: "reach".into(), entry: root.clone(), source_function: root.clone(),
                context: "__entry__".into(), complete, tokens, edges: Vec::new(), is_source,
            });
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sink_catalog() -> atropos_proto::Request {
        atropos_proto::Request {
            models: vec![atropos_proto::Model {
                language: "c".into(), method: "sink_call".into(), role: "sink".into(),
                access_path: "Argument[0]".into(), kind: "buffer-size".into(),
                ..Default::default()
            }], ..Default::default()
        }
    }

    #[test]
    fn emits_a_skeleton_for_each_flow_carrying_function_including_internal_functions() {
        let call = |node: &str, source: bool| lifetime_proto::FunctionCall {
            node: node.into(), callee: "sink_call".into(), is_source: source,
            arguments: vec![lifetime_proto::FunctionArgument {
                position: 0, root: "input".into(), root_name: "input".into(), ..Default::default()
            }], ..Default::default()
        };
        let translation = lifetime_proto::TranslationResult { functions: vec![
            lifetime_proto::TranslationFunction {
                id: "public-id".into(), name: "public_entry".into(), language: "c".into(),
                calls: vec![call("source-call", true)], ..Default::default()
            },
            lifetime_proto::TranslationFunction {
                id: "static-id".into(), name: "internal_helper".into(), language: "c".into(),
                calls: vec![call("sink-call", false)], ..Default::default()
            },
        ]};
        let summaries = crate::summary::summarize(translation.clone(), sink_catalog());
        let skeletons = build(&translation, &summaries, &sink_catalog());
        assert_eq!(skeletons.len(), 2);
        assert!(skeletons.iter().any(|item| item.entry == "public_entry" && item.is_source));
        assert!(skeletons.iter().any(|item| item.entry == "internal_helper" && !item.is_source));
        assert!(skeletons.iter().all(|item| item.tokens.iter().any(|token|
            token.kind == "sink" && (token.node == "source-call" || token.node == "sink-call"))));
    }
}
