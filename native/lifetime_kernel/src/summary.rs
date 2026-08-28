//! Native interprocedural reach summaries.
//!
//! The reach-only summary domain is finite: a function, sink call and argument
//! position plus the parameter that carries the value.  Keep the fixed point
//! over compact protobuf facts so the Python F dictionaries never exist for
//! this phase.

use std::collections::{BTreeMap, BTreeSet, HashSet};
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

/// Intra-graph call successors: for each function, the distinct internal callees
/// (resolved by compiler id, else by base name) that are themselves in the
/// translation unit.  Edge `F -> G` means "F calls G", the dependency the
/// bottom-up summary schedule inverts.  Resolution matches `contribute` exactly
/// so the schedule edges align with the flows they gate.
fn call_successors(
    functions: &BTreeMap<String, lifetime_proto::TranslationFunction>,
    by_id: &HashMap<String, String>,
    by_base: &HashMap<String, String>,
) -> BTreeMap<String, Vec<String>> {
    functions.iter().map(|(name, function)| {
        let mut callees: Vec<String> = Vec::new();
        let mut seen: BTreeSet<String> = BTreeSet::new();
        for call in &function.calls {
            let resolved = (!call.callee_function_id.is_empty())
                .then(|| by_id.get(&call.callee_function_id))
                .flatten()
                .or_else(|| by_base.get(&call.callee));
            if let Some(callee) = resolved {
                if functions.contains_key(callee) && seen.insert(callee.clone()) {
                    callees.push(callee.clone());
                }
            }
        }
        (name.clone(), callees)
    }).collect()
}

/// One function's summary contribution given the current callee summaries: its
/// direct sink arguments plus the interprocedural flows threaded through every
/// resolved callee.  Pure in `summaries`, so the caller controls the schedule.
fn contribute(
    function: &lifetime_proto::TranslationFunction,
    functions: &BTreeMap<String, lifetime_proto::TranslationFunction>,
    sinks: &HashMap<String, Vec<Option<u32>>>,
    by_id: &HashMap<String, String>,
    by_base: &HashMap<String, String>,
    summaries: &BTreeMap<String, Summary>,
) -> Summary {
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
                    let sink = format!("{}.a{}", call.callee, argument.position);
                    if root.is_empty() {
                        // Constant / rootless argument (a literal, a computed
                        // expression with no single root). It carries no taint,
                        // but the sink call itself is still an observation the
                        // presence evaluator must see -- e.g. a fixed-format
                        // string passed to a format sink. Tag it "const" so
                        // reach/relational (which key on taint) skip it while
                        // presence keeps it: reach.rs sets tainted=false for
                        // provenance=="const".
                        additions.flows.insert((sink, String::new(), String::new(), "const".into()));
                        continue;
                    }
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
    }
    additions
}

/// Iterative Tarjan SCC (recursion in the target codebase must not blow our
/// stack).  Returns components in reverse-topological (callees-first) order, so
/// a component whose callees are all already emitted is produced before its
/// callers -- exactly the bottom-up summary schedule.
fn tarjan_scc(nodes: &[String], succ: &BTreeMap<String, Vec<String>>) -> Vec<Vec<String>> {
    let empty: Vec<String> = Vec::new();
    let mut index: HashMap<&str, u32> = HashMap::new();
    let mut low: HashMap<&str, u32> = HashMap::new();
    let mut on_stack: HashSet<&str> = HashSet::new();
    let mut stack: Vec<&str> = Vec::new();
    let mut components: Vec<Vec<String>> = Vec::new();
    let mut counter: u32 = 0;

    for root in nodes {
        let root = root.as_str();
        if index.contains_key(root) { continue; }
        let mut work: Vec<(&str, usize)> = vec![(root, 0)];
        while let Some(&(node, resume)) = work.last() {
            if resume == 0 {
                index.insert(node, counter);
                low.insert(node, counter);
                counter += 1;
                stack.push(node);
                on_stack.insert(node);
            }
            let successors = succ.get(node).unwrap_or(&empty);
            let mut descended = false;
            let mut cursor = resume;
            while cursor < successors.len() {
                let next = successors[cursor].as_str();
                if !index.contains_key(next) {
                    *work.last_mut().expect("work frame") = (node, cursor + 1);
                    work.push((next, 0));
                    descended = true;
                    break;
                } else if on_stack.contains(next) {
                    let reached = *index.get(next).expect("index of stacked node");
                    let current = low.get_mut(node).expect("low of active node");
                    if reached < *current { *current = reached; }
                }
                cursor += 1;
            }
            if descended { continue; }
            if low.get(node) == index.get(node) {
                let mut component = Vec::new();
                loop {
                    let member = stack.pop().expect("scc stack");
                    on_stack.remove(member);
                    component.push(member.to_owned());
                    if member == node { break; }
                }
                components.push(component);
            }
            work.pop();
            if let Some(&(parent, _)) = work.last() {
                let child_low = *low.get(node).expect("low of finished node");
                let parent_low = low.get_mut(parent).expect("low of parent");
                if child_low < *parent_low { *parent_low = child_low; }
            }
        }
    }
    components
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

    // Bottom-up interprocedural schedule (reference `order.py`): summaries
    // compose callees-before-callers, so an acyclic function is solved in a
    // single pass over already-final callee summaries, and recursion is confined
    // to a per-component fixpoint.  Unlike a globally capped sweep this converges
    // regardless of call-chain depth -- a monotone union over a strongly
    // connected component of size m stabilises in at most m + 1 member passes.
    let succ = call_successors(&functions, &by_id, &by_base);
    let names: Vec<String> = functions.keys().cloned().collect();
    let mut complete = true;
    let mut iterations = 0u32;
    for component in tarjan_scc(&names, &succ) {
        let cyclic = component.len() > 1
            || succ.get(&component[0]).is_some_and(|callees| callees.contains(&component[0]));
        if !cyclic {
            let name = &component[0];
            let function = functions.get(name).expect("component function");
            let additions = contribute(function, &functions, &sinks, &by_id, &by_base, &summaries);
            let target = summaries.get_mut(name).expect("summary entry");
            target.flows.extend(additions.flows);
            target.params.extend(additions.params);
            iterations += 1;
            continue;
        }
        // Recursive component: iterate its members (monotone union, Gauss-Seidel)
        // until the summaries stop growing.  The bound is provably sufficient;
        // exceeding it can only mean a non-monotone defect, so mark the analysis
        // incomplete rather than loop unbounded.
        let mut members = component;
        members.sort();
        let mut converged = false;
        for _ in 0..members.len().saturating_add(4) {
            iterations += 1;
            let mut changed = false;
            for name in &members {
                let function = functions.get(name).expect("component function");
                let additions = contribute(function, &functions, &sinks, &by_id, &by_base, &summaries);
                let target = summaries.get_mut(name).expect("summary entry");
                let before = (target.flows.len(), target.params.len());
                target.flows.extend(additions.flows);
                target.params.extend(additions.params);
                if (target.flows.len(), target.params.len()) != before { changed = true; }
            }
            if !changed { converged = true; break; }
        }
        if !converged { complete = false; }
    }

    let functions = summaries.into_iter().map(|(name, summary)| {
        let item = functions.get(&name).expect("function summary input");
        let mut sink_flows = summary.flows.into_iter().map(|(sink, value, root, via)| {
            let (callee, position) = sink.rsplit_once(".a")
                .and_then(|(callee, position)| position.parse::<u32>().ok()
                    .map(|position| (callee, position)))
                .unwrap_or((sink.as_str(), 0));
            let call = item.calls.iter().find(|call| call.callee == callee
                && call.arguments.iter().any(|argument| argument.position == position
                    && (root.is_empty() || argument_root(argument) == root)));
            let witness = evidence.and_then(|items| items.get(&root)).cloned().unwrap_or_default();
            let provenance = if via == "const" { "const".into() }
                else if witness.is_empty() { "local".into() } else { "source".into() };
            lifetime_proto::NativeSinkFlow {
                sink, value, root, provenance,
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

    fn sink_catalog() -> crate::atropos_proto::Request {
        crate::atropos_proto::Request { models: vec![crate::atropos_proto::Model {
            method: "sink_call".into(), role: "sink".into(), access_path: "Argument[0]".into(),
            ..Default::default()
        }], ..Default::default() }
    }

    fn param_arg() -> Vec<lifetime_proto::FunctionArgument> {
        vec![lifetime_proto::FunctionArgument {
            position: 0, root: "p".into(), root_name: "p".into(), ..Default::default() }]
    }

    #[test]
    fn deep_call_chain_converges_beyond_the_old_iteration_cap() {
        // f0 -> f1 -> ... -> f79, each forwarding its parameter; the deepest
        // function passes it to a sink.  A globally capped sweep stops before the
        // flow reaches f0 and would mark the analysis incomplete; the bottom-up
        // schedule solves the whole chain and stays complete.
        const DEPTH: usize = 80;
        let functions = (0..DEPTH).map(|i| {
            let call = if i + 1 < DEPTH {
                lifetime_proto::FunctionCall {
                    node: format!("call-{}", i), callee: format!("f{}", i + 1),
                    callee_function_id: format!("id-f{}", i + 1),
                    arguments: param_arg(), ..Default::default() }
            } else {
                lifetime_proto::FunctionCall {
                    node: format!("sink-{}", i), callee: "sink_call".into(),
                    arguments: param_arg(), ..Default::default() }
            };
            lifetime_proto::TranslationFunction {
                id: format!("id-f{}", i), name: format!("f{}", i),
                parameter_names: vec!["p".into()], calls: vec![call], ..Default::default() }
        }).collect();
        let translation = lifetime_proto::TranslationResult { functions };
        let result = summarize(translation, sink_catalog());
        assert!(result.complete, "deep acyclic chain must converge");
        let top = result.functions.iter().find(|item| item.name == "f0").unwrap();
        assert!(top.sink_flows.iter().any(|flow| flow.sink == "sink_call.a0"),
            "deepest sink flow must reach the callerless source f0");
    }

    #[test]
    fn recursive_component_reaches_fixpoint() {
        // a <-> b (mutual recursion); b also calls a sink on its parameter.
        // The cyclic component is solved by the per-component fixpoint and both
        // members carry the sink flow.
        let a = lifetime_proto::TranslationFunction {
            id: "a".into(), name: "a".into(), parameter_names: vec!["p".into()],
            calls: vec![lifetime_proto::FunctionCall {
                node: "a-call-b".into(), callee: "b".into(), callee_function_id: "b".into(),
                arguments: param_arg(), ..Default::default() }], ..Default::default() };
        let b = lifetime_proto::TranslationFunction {
            id: "b".into(), name: "b".into(), parameter_names: vec!["p".into()],
            calls: vec![
                lifetime_proto::FunctionCall {
                    node: "b-call-a".into(), callee: "a".into(), callee_function_id: "a".into(),
                    arguments: param_arg(), ..Default::default() },
                lifetime_proto::FunctionCall {
                    node: "b-sink".into(), callee: "sink_call".into(),
                    arguments: param_arg(), ..Default::default() },
            ], ..Default::default() };
        let translation = lifetime_proto::TranslationResult { functions: vec![a, b] };
        let result = summarize(translation, sink_catalog());
        assert!(result.complete, "recursive component must reach a fixpoint");
        for name in ["a", "b"] {
            let function = result.functions.iter().find(|item| item.name == name).unwrap();
            assert!(function.sink_flows.iter().any(|flow| flow.sink == "sink_call.a0"),
                "{} should carry the recursive sink flow", name);
        }
    }
}
