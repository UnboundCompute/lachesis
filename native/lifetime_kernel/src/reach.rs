//! Binary source-to-sink skeletons built from native reach summaries.
//!
//! The old Pass-3 flow rendered one reach skeleton for each summary flow and
//! stitched `via` callee summaries through call sites.  This module keeps that
//! composition data-driven: sink families come from the compiled Atropos
//! catalog and function identity comes from compiler translation facts.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};

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
    let canonical = catalog.callee_aliases.iter()
        .find(|alias| alias.language == language && alias.surface == callee)
        .map(|alias| alias.canonical.as_str())
        .unwrap_or(callee);
    catalog.models.iter()
        .filter(|model| model.role == "sink"
            && (model.language.is_empty() || model.language == language)
            && ((model.package.is_empty() || model.package == "builtins")
                && model.method == canonical
                || !model.package.is_empty()
                    && model.package != "builtins"
                    && format!("{}.{}", model.package, model.method) == canonical))
        .filter(|model| model.access_path.contains(&format!("Argument[{position}]"))
            || model.access_path.contains("Argument[*]"))
        .find_map(|model| (!model.kind.is_empty()).then(|| model.kind.clone()))
        .unwrap_or_default()
}

fn direct_call<'a>(
    function: &'a lifetime_proto::TranslationFunction,
    callee: &str,
    root: &str,
) -> Option<&'a lifetime_proto::FunctionCall> {
    let mut fallback = None;
    for call in &function.calls {
        if call.callee != callee { continue; }
        if fallback.is_none() { fallback = Some(call); }
        if root.is_empty() || call.arguments.iter()
            .any(|argument| argument_root(argument) == root) {
            return Some(call);
        }
    }
    fallback
}

fn append_guard_tokens(
    call: &lifetime_proto::FunctionCall,
    function: &str,
    depth: u32,
    tokens: &mut Vec<lifetime_proto::NativeSkeletonToken>,
) {
    tokens.extend(call.guards.iter().map(|guard| lifetime_proto::NativeSkeletonToken {
        kind: "guard".into(), function: function.into(), depth,
        value: guard.var.clone(), control: vec![guard.canon.clone()],
        guards: vec![lifetime_proto::GuardProof {
            kind: "VALUE".into(), value: guard.canon.clone(),
        }],
        ..Default::default()
    }));
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
    let family = family_for(callee, language, argument, catalog);
    // The legacy renderer exposes a bound only for the relational evaluator.
    // Other sink families must not acquire synthetic bounded/unbounded state
    // merely because a call site happens to have a guard.
    let bound = (!truncated && catalog.pattern_catalog.as_ref()
        .and_then(|catalog| catalog.kind_evaluator.get(&family))
        .is_some_and(|recipe| recipe.split(',')
            .any(|evaluator| evaluator.trim() == "relational")))
        .then(|| if guarded { "bounded" } else { "unbounded" })
        .unwrap_or_default()
        .to_owned();
    lifetime_proto::NativeSkeletonToken {
        kind: "sink".into(), family,
        object_root: flow.root.clone(), value: flow.value.clone(), node: flow.node.clone(),
        line: flow.line, has_line: flow.has_line, depth,
        guarded, tainted: flow.provenance != "const",
        bound,
        callee: callee.into(), argument, has_argument: true, truncated,
        size_expression: flow.size_expression.clone(), destination: flow.destination.clone(),
        control: flow.control.clone(), guards: flow.guard_predicates.iter().map(|value|
            lifetime_proto::GuardProof { kind: "PREDICATE".into(), value: value.clone() }).collect(),
        guard_status: flow.guard_status.clone(),
        source_witness_nodes: flow.source_witness_nodes.clone(),
        source_reachable: (!flow.source_witness_nodes.is_empty()).then_some(true),
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
    // A "const" flow is a rootless (constant) argument to a sink: the call is a
    // real, complete observation for the presence evaluator, it simply carries
    // no taint. Emit it as a terminal sink just like a direct flow -- do not let
    // it fall through to the interprocedural branch (which would fail to resolve
    // callee "const" and mark the skeleton truncated/incomplete).
    if flow.via == "direct" || flow.via == "const" {
        let function_record = functions.get(function).copied();
        if let Some(call) = function_record.and_then(|item|
            direct_call(item, sink_callee, &flow.root)) {
            append_guard_tokens(call, function, depth, tokens);
        }
        let language = function_record.map(|item| item.language.as_str()).unwrap_or("");
        tokens.push(sink_token(flow, language, catalog, depth, guarded_acc || flow.guarded, false));
        return true;
    }
    if !chain.contains(&flow.via) {
        if let (Some(caller), Some(callee)) = (functions.get(function), functions.get(&flow.via)) {
            let call = caller.calls.iter().find(|call| {
                (call.callee == flow.via || call.callee == callee.name
                    || call.callee_function_id == callee.id)
                    && call.arguments.iter().any(|argument|
                    argument_root(argument) == flow.root)
            }).or_else(|| caller.calls.iter().find(|call|
                call.callee == flow.via || call.callee == callee.name
                    || call.callee_function_id == callee.id));
            if let Some(call) = call {
                append_guard_tokens(call, function, depth, tokens);
                if let Some(summary) = summaries.get(&flow.via) {
                    let formal_root = call.arguments.iter()
                        .find(|argument| argument_root(argument) == flow.root)
                        .and_then(|argument| callee.parameter_names
                            .get(argument.position as usize));
                    if let Some(subflow) = summary.sink_flows.iter().find(|candidate|
                        candidate.sink == flow.sink
                            && formal_root.is_none_or(|root| candidate.root == *root)
                    ) {
                        tokens.push(lifetime_proto::NativeSkeletonToken {
                            kind: "enter".into(), function: flow.via.clone(), depth,
                            ..Default::default()
                        });
                    let site_guarded = !call.guards.is_empty();
                    let mut next_chain = chain.clone();
                    next_chain.insert(flow.via.clone());
                    let complete = expand(&flow.via, subflow, functions, summaries, catalog,
                                              depth + 1, guarded_acc || flow.guarded || site_guarded,
                                              &next_chain, tokens);
                        tokens.push(lifetime_proto::NativeSkeletonToken {
                            kind: "exit".into(), function: flow.via.clone(), depth,
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
        let base = if function.name.is_empty() { function.id.clone() } else { function.name.clone() };
        // Keep the same deterministic collision scheme as summary::function_names.
        // Display names are not compiler identities: two internal functions in
        // different translation units may legitimately share one spelling.
        let key = if functions.contains_key(&base) {
            format!("{}@{}", base, function.id)
        } else {
            base
        };
        functions.entry(key).or_insert(function);
    }
    let summary_map: HashMap<String, &lifetime_proto::NativeSummaryFunction> = summaries.functions.iter()
        .map(|summary| (summary.name.clone(), summary)).collect();
    let function_by_id: HashMap<&str, &str> = functions.values()
        .map(|function| (function.id.as_str(), function.name.as_str()))
        .collect();
    // The legacy F record's `is_source` is a graph-topology property: it is
    // true for a function with no resolved callers.  A catalogued source call
    // is separate launch evidence and must not replace that definition. Keep
    // compiler-ID resolution first so same-spelled internal functions do not
    // steal one another's caller relation.
    let mut callers = BTreeSet::new();
    for function in functions.values() {
        for call in &function.calls {
            let target = if !call.callee_function_id.is_empty() {
                function_by_id.get(call.callee_function_id.as_str()).copied()
            } else {
                functions.contains_key(&call.callee).then_some(call.callee.as_str())
            };
            if let Some(target) = target {
                callers.insert(target.to_owned());
            }
        }
    }
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
        let is_source = !callers.contains(&root);
        for flow in &summary.sink_flows {
            let mut tokens = vec![lifetime_proto::NativeSkeletonToken {
                kind: "enter".into(), function: root.clone(), depth: 0, ..Default::default()
            }];
            let complete = expand(&root, flow, &functions, &summary_map, catalog, 1,
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

/// Build compact per-function sink graphs for catalog patterns that relate
/// two sink observations. Only proven CFG reachability between sink anchors
/// is retained; the semantic graph itself is not duplicated in the sidecar.
pub(crate) fn build_sink_graphs(
    semantic: &lifetime_proto::NativeSemanticResult,
    translation: &lifetime_proto::TranslationResult,
    summaries: &lifetime_proto::NativeSummaryResult,
    catalog: &atropos_proto::Request,
) -> Vec<lifetime_proto::NativeFlowSkeleton> {
    let by_id: HashMap<&str, &lifetime_proto::TranslationFunction> = translation.functions.iter()
        .map(|function| (function.id.as_str(), function)).collect();
    let mut by_name = HashMap::new();
    for function in &translation.functions {
        let base = if function.name.is_empty() { function.id.clone() } else { function.name.clone() };
        let key = if by_name.contains_key(&base) { format!("{}@{}", base, function.id) } else { base };
        by_name.insert(key, function);
    }
    let mut output = Vec::new();
    for summary in &summaries.functions {
        let Some(translation_function) = by_name.get(&summary.name).copied()
            .or_else(|| by_id.get(summary.name.as_str()).copied()) else { continue };
        let Some(function) = semantic.functions.iter()
            .find(|function| function.id == translation_function.id) else { continue };
        let direct: Vec<_> = summary.sink_flows.iter()
            .filter(|flow| flow.via == "direct").collect();
        if direct.len() < 2 { continue; }
        let mut adjacency: HashMap<&str, Vec<&str>> = HashMap::new();
        for edge in &function.edges {
            adjacency.entry(edge.source.as_str()).or_default().push(edge.target.as_str());
        }
        let mut tokens = Vec::new();
        let mut anchors = Vec::new();
        for (ordinal, flow) in direct.into_iter().enumerate() {
            let anchor = function.nodes.iter().find(|node| node.anchor == flow.node)
                .map(|node| node.id.clone());
            let Some(anchor) = anchor else { continue };
            let mut token = sink_token(flow, &function.language, catalog, 0,
                flow.guarded, false);
            token.node = format!("native:sink:{}:{}:{ordinal}", function.id, flow.node);
            token.function = function.id.clone();
            anchors.push(anchor);
            tokens.push(token);
        }
        if tokens.len() < 2 { continue; }
        let mut edges = Vec::new();
        for (source_index, source) in anchors.iter().enumerate() {
            if tokens[source_index].family != "alloc-size" { continue; }
            let mut queue = VecDeque::from([source.as_str()]);
            let mut seen = HashSet::from([source.as_str()]);
            while let Some(node) = queue.pop_front() {
                for target in adjacency.get(node).into_iter().flatten() {
                    if seen.insert(target) { queue.push_back(target); }
                }
            }
            for (target_index, target) in anchors.iter().enumerate() {
                if source_index != target_index && seen.contains(target.as_str()) {
                    edges.push(lifetime_proto::NativeSemanticEdge {
                        source: tokens[source_index].node.clone(),
                        target: tokens[target_index].node.clone(),
                        kind: "sink-reaches".into(), ..Default::default()
                    });
                }
            }
        }
        output.push(lifetime_proto::NativeFlowSkeleton {
            kind: "reach-graph".into(), entry: function.id.clone(),
            source_function: function.id.clone(), context: "__entry__".into(),
            complete: true, tokens, edges, is_source: false,
        });
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
            guards: source.then(|| lifetime_proto::GuardFact {
                var: "input".into(), canon: "input < capacity".into(),
            }).into_iter().collect(),
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
            lifetime_proto::TranslationFunction {
                id: "static-id-2".into(), name: "internal_helper".into(), language: "c".into(),
                calls: vec![call("sink-call-2", false)], ..Default::default()
            },
        ]};
        let summaries = crate::summary::summarize(&translation, &sink_catalog());
        let skeletons = build(&translation, &summaries, &sink_catalog());
        assert_eq!(skeletons.len(), 3);
        assert!(skeletons.iter().any(|item| item.entry == "public_entry" && item.is_source));
        assert!(skeletons.iter().any(|item| item.entry == "internal_helper" && item.is_source));
        assert!(skeletons.iter().any(|item| item.entry == "internal_helper@static-id-2"));
        let sink_nodes: BTreeSet<&str> = skeletons.iter().flat_map(|item| item.tokens.iter())
            .filter(|token| token.kind == "sink")
            .map(|token| token.node.as_str()).collect();
        assert!(sink_nodes.contains("source-call"));
        assert!(sink_nodes.contains("sink-call"));
        assert!(sink_nodes.contains("sink-call-2"));
        let public = skeletons.iter().find(|item| item.entry == "public_entry").unwrap();
        assert_eq!(public.tokens.iter().map(|token| token.kind.as_str()).collect::<Vec<_>>(),
            vec!["enter", "guard", "sink", "exit"]);
        assert_eq!(public.tokens[1].value, "input");
        assert_eq!(public.tokens[1].control, vec!["input < capacity"]);
        assert_eq!(public.tokens[1].depth, 1);
        for skeleton in &skeletons {
            assert_eq!(skeleton.tokens.first().map(|token| token.depth), Some(0));
            assert_eq!(skeleton.tokens.last().map(|token| token.depth), Some(0));
            assert!(skeleton.tokens.iter()
                .filter(|token| token.kind == "sink")
                .all(|token| token.depth == 1));
        }
    }

    #[test]
    fn empty_package_models_match_only_their_method() {
        let catalog = sink_catalog();
        assert_eq!(family_for("sink_call", "c", 0, &catalog), "buffer-size");
        assert!(family_for("other_call", "c", 0, &catalog).is_empty());
    }

    #[test]
    fn bound_is_reserved_for_relational_sink_families() {
        let mut catalog = sink_catalog();
        catalog.pattern_catalog.get_or_insert_with(Default::default).kind_evaluator.insert(
            "buffer-size".into(), "relational".into());
        let flow = lifetime_proto::NativeSinkFlow {
            sink: "sink_call.a0".into(), provenance: "source".into(), ..Default::default()
        };
        assert_eq!(sink_token(&flow, "c", &catalog, 0, false, false).bound, "unbounded");
        assert!(sink_token(&flow, "c", &catalog, 0, false, true).bound.is_empty());
        catalog.pattern_catalog.get_or_insert_with(Default::default).kind_evaluator.insert(
            "buffer-size".into(), "relational,missing-guard".into());
        assert_eq!(sink_token(&flow, "c", &catalog, 0, true, false).bound, "bounded");
        catalog.pattern_catalog.get_or_insert_with(Default::default).kind_evaluator.insert(
            "buffer-size".into(), "presence".into());
        assert!(sink_token(&flow, "c", &catalog, 0, true, false).bound.is_empty());
    }
}
