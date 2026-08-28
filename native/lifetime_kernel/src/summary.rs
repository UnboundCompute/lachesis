//! Native interprocedural reach summaries.
//!
//! The reach-only summary domain is finite: a function, sink call and argument
//! position plus the parameter that carries the value.  Keep the fixed point
//! over compact protobuf facts so the Python F dictionaries never exist for
//! this phase.

use std::collections::{BTreeMap, BTreeSet};
use hashbrown::HashMap;

use crate::lifetime_proto;

fn expression_root(value: &str) -> String {
    let mut value = value.trim();
    while let Some(rest) = value.strip_prefix(['*', '&']) { value = rest.trim_start(); }
    let end = value.char_indices().find_map(|(index, ch)|
        (!(ch == '_' || ch.is_ascii_alphanumeric())).then_some(index))
        .unwrap_or(value.len());
    let root = &value[..end];
    if root.is_empty() || root.chars().next().is_some_and(|ch| ch.is_ascii_digit()) {
        String::new()
    } else { root.to_owned() }
}

fn argument_root(argument: &lifetime_proto::FunctionArgument) -> String {
    let root = if !argument.root_name.is_empty() { argument.root_name.clone() }
        else if !argument.root.is_empty() { argument.root.trim_start_matches("decl:").to_owned() }
        else { expression_root(&argument.expression) };
    if root.is_empty() { root } else { format!("{}{}", root, argument.selectors.join("")) }
}

fn sink_position(access_path: &str) -> Option<Option<u32>> {
    let value = access_path.strip_prefix("Argument[")?.strip_suffix(']')?;
    if value == "*" { Some(None) } else { Some(value.parse().ok()) }
}

#[derive(Clone, Default, Eq, PartialEq)]
struct Summary {
    flows: BTreeSet<(String, String, String, String)>, // sink, value, root, via
    params: BTreeSet<(String, String)>,                 // parameter, sink
}

fn model_sinks(request: &crate::atropos_proto::Request,
               languages: &BTreeSet<String>) -> HashMap<String, Vec<Option<u32>>> {
    let mut result: HashMap<String, BTreeSet<Option<u32>>> = HashMap::new();
    for model in &request.models {
        if model.role != "sink" { continue; }
        // An unknown or mixed-language substrate must not silently become C.
        // Empty `languages` means no language filter is safe to apply.
        if !model.language.is_empty()
            && !languages.is_empty()
            && !languages.contains(&model.language) { continue; }
        let Some(position) = sink_position(&model.access_path) else { continue };
        let name = if model.package.is_empty() || model.package == "builtins" {
            model.method.clone()
        } else { format!("{}.{}", model.package, model.method) };
        result.entry(name).or_default().insert(position);
    }
    for alias in &request.callee_aliases {
        if !alias.language.is_empty() && !languages.is_empty()
            && !languages.contains(&alias.language) { continue; }
        if let Some(positions) = result.get(&alias.canonical).cloned() {
            result.entry(alias.surface.clone()).or_default().extend(positions);
        }
    }
    result.into_iter().map(|(name, positions)| (name, positions.into_iter().collect())).collect()
}

fn function_names(items: &[lifetime_proto::TranslationFunction])
    -> (BTreeMap<String, lifetime_proto::TranslationFunction>, HashMap<String, String>, HashMap<String, String>) {
    let mut functions = BTreeMap::new();
    let mut by_base = HashMap::new();
    let mut by_id = HashMap::new();
    for item in items {
        let base = if item.name.is_empty() { item.id.clone() } else { item.name.clone() };
        if base.is_empty() { continue; }
        let name = if functions.contains_key(&base) { format!("{}@{}", base, item.id) } else { base.clone() };
        by_base.entry(base).or_insert_with(|| name.clone());
        by_id.insert(item.id.clone(), name.clone());
        functions.insert(name, item.clone());
    }
    (functions, by_base, by_id)
}

pub(crate) fn summarize(
    translation: lifetime_proto::TranslationResult,
    catalog: crate::atropos_proto::Request,
) -> lifetime_proto::NativeSummaryResult {
    summarize_with_evidence(translation, catalog, None)
}

pub(crate) fn summarize_with_evidence(
    translation: lifetime_proto::TranslationResult,
    catalog: crate::atropos_proto::Request,
    evidence: Option<&HashMap<String, Vec<String>>>,
) -> lifetime_proto::NativeSummaryResult {
    let (functions, by_base, by_id) = function_names(&translation.functions);
    let languages: BTreeSet<String> = translation.functions.iter()
        .filter_map(|function| (!function.language.is_empty()).then(|| function.language.clone()))
        .collect();
    let sinks = model_sinks(&catalog, &languages);
    let mut summaries: BTreeMap<String, Summary> = functions.keys()
        .map(|name| (name.clone(), Summary::default())).collect();

    // Monotone union fixed point. The number of call edges is small relative
    // to the graph substrate, and this avoids allocating SCC metadata twice.
    let mut complete = false;
    let mut iterations = 0u32;
    for _ in 0..64 {
        iterations += 1;
        let before = summaries.clone();
        for (name, function) in &functions {
            let parameters: BTreeSet<&str> = function.parameter_names.iter()
                .map(String::as_str).collect();
            let mut additions = Summary::default();
            for call in &function.calls {
                if let Some(positions) = sinks.get(&call.callee) {
                    for position in positions {
                        let selected: Vec<&lifetime_proto::FunctionArgument> = match position {
                            Some(position) => call.arguments.iter()
                                .filter(|argument| argument.position == *position).collect(),
                            None => call.arguments.iter().collect(),
                        };
                        for argument in selected {
                            let root = argument_root(argument);
                            if root.is_empty() { continue; }
                            let sink = format!("{}.a{}", call.callee, argument.position);
                            additions.flows.insert((sink.clone(), root.clone(), root.clone(), "direct".into()));
                            if parameters.contains(root.as_str()) {
                                additions.params.insert((root.clone(), sink));
                            }
                        }
                    }
                }
                let callee_name = (!call.callee_function_id.is_empty())
                    .then(|| by_id.get(&call.callee_function_id))
                    .flatten()
                    .or_else(|| by_base.get(&call.callee));
                let Some(callee_name) = callee_name else { continue };
                let Some(callee) = functions.get(callee_name) else { continue };
                let Some(callee_summary) = summaries.get(callee_name) else { continue };
                for (position, formal) in callee.parameter_names.iter().enumerate() {
                    let Some(argument) = call.arguments.iter()
                        .find(|argument| argument.position as usize == position) else { continue };
                    let root = argument_root(argument);
                    if root.is_empty() { continue; }
                    for (sink, _value, callee_root, _via) in &callee_summary.flows {
                        if callee_root != formal { continue; }
                        additions.flows.insert((sink.clone(), root.clone(), root.clone(), callee_name.clone()));
                        if parameters.contains(root.as_str()) {
                            additions.params.insert((root.clone(), sink.clone()));
                        }
                    }
                }
                let _ = callee;
            }
            let target = summaries.get_mut(name).expect("summary entry");
            target.flows.extend(additions.flows);
            target.params.extend(additions.params);
        }
        if summaries == before { complete = true; break; }
    }

    let functions = summaries.into_iter().map(|(name, summary)| {
        let item = functions.get(&name).expect("function summary input");
        let mut sink_flows = summary.flows.into_iter().map(|(sink, value, root, via)| {
            let (callee, position) = sink.rsplit_once(".a")
                .and_then(|(callee, position)| position.parse::<u32>().ok()
                    .map(|position| (callee, position)))
                .unwrap_or((sink.as_str(), 0));
            let call = item.calls.iter().find(|call| call.callee == callee
                && call.arguments.iter().any(|argument|
                    argument.position == position && argument_root(argument) == root));
            let witness = evidence.and_then(|items| items.get(&root)).cloned().unwrap_or_default();
            lifetime_proto::NativeSinkFlow {
                sink, value, root, provenance: if witness.is_empty() { "local".into() } else { "source".into() },
                guarded: call.is_some_and(|call| !call.guards.is_empty()),
                site_guarded: call.is_some_and(|call| !call.guards.is_empty()), via,
                node: call.map(|call| call.node.clone()).unwrap_or_default(),
                line: call.map(|call| call.line).unwrap_or_default(),
                has_line: call.is_some_and(|call| call.has_line),
                size_expression: call.map(|call| call.size_expression.clone()).unwrap_or_default(),
                destination: call.map(|call| call.destination.clone()).unwrap_or_default(),
                control: call.map(|call| call.control.clone()).unwrap_or_default(),
                guard_status: call.map(|call| call.guard_status.clone()).unwrap_or_default(),
                guard_predicates: call.map(|call| call.guard_predicates.clone()).unwrap_or_default(),
                source_witness_nodes: witness,
                ..Default::default()
            }
        }).collect::<Vec<_>>();
        sink_flows.sort_by(|left, right| (&left.sink, &left.root, &left.value, &left.via)
            .cmp(&(&right.sink, &right.root, &right.value, &right.via)));
        let mut sink_params = summary.params.into_iter().map(|(parameter, sink)|
            lifetime_proto::NativeSinkParam { parameter, sink, guards: Vec::new(), guarded: false })
            .collect::<Vec<_>>();
        sink_params.sort_by(|left, right| (&left.parameter, &left.sink).cmp(&(&right.parameter, &right.sink)));
        lifetime_proto::NativeSummaryFunction {
            name, parameters: item.parameter_names.clone(), sink_flows, sink_params,
        }
    }).collect();
    lifetime_proto::NativeSummaryResult { functions, complete, iterations }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_same_named_internal_callee_by_compiler_id() {
        let sink = |node: &str, root: &str| lifetime_proto::FunctionCall {
            node: node.into(), callee: "sink_call".into(),
            arguments: vec![lifetime_proto::FunctionArgument {
                position: 0, root: root.into(), root_name: root.into(), ..Default::default()
            }], ..Default::default()
        };
        let forward = lifetime_proto::FunctionCall {
            node: "forward-call".into(), callee: "helper".into(),
            callee_function_id: "helper-2".into(),
            arguments: vec![lifetime_proto::FunctionArgument {
                position: 0, root: "input".into(), root_name: "input".into(), ..Default::default()
            }], ..Default::default()
        };
        let translation = lifetime_proto::TranslationResult { functions: vec![
            lifetime_proto::TranslationFunction {
                id: "caller".into(), name: "caller".into(), parameter_names: vec!["input".into()],
                calls: vec![forward], ..Default::default()
            },
            lifetime_proto::TranslationFunction {
                id: "helper-1".into(), name: "helper".into(), parameter_names: vec!["p".into()],
                calls: vec![sink("sink-1", "p")], ..Default::default()
            },
            lifetime_proto::TranslationFunction {
                id: "helper-2".into(), name: "helper".into(), parameter_names: vec!["p".into()],
                calls: vec![sink("sink-2", "p")], ..Default::default()
            },
        ]};
        let catalog = crate::atropos_proto::Request { models: vec![crate::atropos_proto::Model {
            method: "sink_call".into(), role: "sink".into(), access_path: "Argument[0]".into(),
            ..Default::default()
        }], ..Default::default() };
        let result = summarize(translation, catalog);
        let caller = result.functions.iter().find(|item| item.name == "caller").unwrap();
        assert!(caller.sink_flows.iter().any(|flow| flow.via == "helper@helper-2"));
    }
}
