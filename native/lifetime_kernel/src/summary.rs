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

fn sink_position(access_path: &str) -> Option<u32> {
    access_path.strip_prefix("Argument[")?.strip_suffix(']')?.parse().ok()
}

#[derive(Clone, Default, Eq, PartialEq)]
struct Summary {
    flows: BTreeSet<(String, String, String, String)>, // sink, value, root, via
    params: BTreeSet<(String, String)>,                 // parameter, sink
}

fn model_sinks(request: &crate::atropos_proto::Request) -> HashMap<String, Vec<u32>> {
    let mut result: HashMap<String, BTreeSet<u32>> = HashMap::new();
    for model in &request.models {
        if model.role != "sink" { continue; }
        let Some(position) = sink_position(&model.access_path) else { continue };
        let name = if model.package.is_empty() || model.package == "builtins" {
            model.method.clone()
        } else { format!("{}.{}", model.package, model.method) };
        result.entry(name).or_default().insert(position);
    }
    result.into_iter().map(|(name, positions)| (name, positions.into_iter().collect())).collect()
}

fn function_names(items: &[lifetime_proto::TranslationFunction])
    -> (BTreeMap<String, lifetime_proto::TranslationFunction>, HashMap<String, String>) {
    let mut functions = BTreeMap::new();
    let mut by_base = HashMap::new();
    for item in items {
        let base = if item.name.is_empty() { item.id.clone() } else { item.name.clone() };
        if base.is_empty() { continue; }
        let name = if functions.contains_key(&base) { format!("{}@{}", base, item.id) } else { base.clone() };
        by_base.entry(base).or_insert_with(|| name.clone());
        functions.insert(name, item.clone());
    }
    (functions, by_base)
}

pub(crate) fn summarize(
    translation: lifetime_proto::TranslationResult,
    catalog: crate::atropos_proto::Request,
) -> lifetime_proto::NativeSummaryResult {
    let (functions, by_base) = function_names(&translation.functions);
    let sinks = model_sinks(&catalog);
    let mut summaries: BTreeMap<String, Summary> = functions.keys()
        .map(|name| (name.clone(), Summary::default())).collect();

    // Monotone union fixed point. The number of call edges is small relative
    // to the graph substrate, and this avoids allocating SCC metadata twice.
    for _ in 0..64 {
        let before = summaries.clone();
        for (name, function) in &functions {
            let parameters: BTreeSet<&str> = function.parameter_names.iter()
                .map(String::as_str).collect();
            let mut additions = Summary::default();
            for call in &function.calls {
                if let Some(positions) = sinks.get(&call.callee) {
                    for position in positions {
                        let Some(argument) = call.arguments.iter()
                            .find(|argument| argument.position == *position) else { continue };
                        let root = argument_root(argument);
                        if root.is_empty() { continue; }
                        let sink = format!("{}.a{}", call.callee, position);
                        additions.flows.insert((sink.clone(), root.clone(), root.clone(), "direct".into()));
                        if parameters.contains(root.as_str()) {
                            additions.params.insert((root.clone(), sink));
                        }
                    }
                }
                let Some(callee_name) = by_base.get(&call.callee) else { continue };
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
        if summaries == before { break; }
    }

    let functions = summaries.into_iter().map(|(name, summary)| {
        let item = functions.get(&name).expect("function summary input");
        let mut sink_flows = summary.flows.into_iter().map(|(sink, value, root, via)|
            lifetime_proto::NativeSinkFlow {
                sink, value, root, provenance: "local".into(), guards: Vec::new(),
                guarded: false, site_guarded: false, via,
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
    lifetime_proto::NativeSummaryResult { functions }
}
