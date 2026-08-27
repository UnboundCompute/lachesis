//! Native source discovery and coverage planning over compact translation facts.
//!
//! This is intentionally independent of Kùzu.  Pass 1 has already emitted the
//! call/parameter facts needed by these two deterministic graph algorithms.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use hashbrown::{HashMap, HashSet};

use crate::lifetime_proto;

const SEP: &str = "\u{1f}";

fn key2(a: &str, b: &str) -> String { format!("{a}{SEP}{b}") }
fn key3(a: &str, b: &str, c: &str) -> String { format!("{a}{SEP}{b}{SEP}{c}") }

fn expression_root(expression: &str) -> String {
    let mut value = expression.trim();
    while let Some(rest) = value.strip_prefix(['*', '&']) { value = rest.trim_start(); }
    let end = value.char_indices().find_map(|(index, ch)|
        (!((ch == '_') || ch.is_ascii_alphanumeric())).then_some(index)).unwrap_or(value.len());
    let root = &value[..end];
    if root.is_empty() || root.chars().next().is_some_and(|ch| ch.is_ascii_digit()) { String::new() } else { root.to_owned() }
}

fn argument_root(argument: &lifetime_proto::FunctionArgument) -> String {
    let base = if !argument.root_name.is_empty() { argument.root_name.clone() }
        else if !argument.root.is_empty() { argument.root.trim_start_matches("decl:").to_owned() }
        else { expression_root(&argument.expression) };
    if base.is_empty() { return base; }
    format!("{}{}", base, argument.selectors.join(""))
}

fn assigned_root(call: &lifetime_proto::FunctionCall) -> String {
    if !call.assigned_name.is_empty() {
        format!("{}{}", call.assigned_name, call.assigned_selectors.join(""))
    } else {
        // Python's F projection falls back to the assignment expression node
        // when the frontend cannot publish a declaration/root label.
        call.assigned.clone()
    }
}

pub(crate) fn plan(request: lifetime_proto::NativePlanRequest) -> lifetime_proto::NativePlanResult {
    let raw_functions = request.translation.unwrap_or_default().functions;
    let mut seen_names: HashSet<String> = HashSet::new();
    let functions: BTreeMap<String, lifetime_proto::TranslationFunction> = raw_functions
        .into_iter().filter_map(|item| {
            let base = if item.name.is_empty() { item.id.clone() } else { item.name.clone() };
            if base.is_empty() { return None; }
            let name = if seen_names.insert(base.clone()) { base } else { format!("{}@{}", base, item.id) };
            Some((name, item))
        }).collect();
    // Calls carry the source-level callee spelling.  Resolve it only when the
    // spelling is unambiguous, matching the legacy Python projection: an
    // overloaded/duplicate display name is not silently connected to an
    // arbitrary translation-unit owner.
    let mut by_source_name: HashMap<String, String> = HashMap::new();
    for (name, item) in &functions {
        let base = if item.name.is_empty() { item.id.clone() } else { item.name.clone() };
        by_source_name.entry(base).or_insert_with(|| name.clone());
    }
    let source_catalog: HashMap<String, String> = request.sources.into_iter()
        .map(|entry| (entry.name, if entry.kind.is_empty() { "external-input".into() } else { entry.kind }))
        .collect();

    let mut callees: HashMap<String, BTreeSet<String>> = HashMap::new();
    let mut callers: HashMap<String, BTreeSet<String>> = HashMap::new();
    let mut sites: HashMap<String, Vec<lifetime_proto::NativeSourceSite>> = HashMap::new();
    let mut bindings = Vec::new();
    let mut influenced: HashMap<String, BTreeSet<String>> = functions.keys()
        .map(|name| (name.clone(), BTreeSet::new())).collect();

    for (name, item) in &functions {
        for call in &item.calls {
            let callee = call.callee.clone();
            if callee.is_empty() { continue; }
            let internal_callee = by_source_name.get(&callee).cloned();
            if let Some(internal_callee) = internal_callee.as_ref() {
                callees.entry(name.clone()).or_default().insert(internal_callee.clone());
                callers.entry(internal_callee.clone()).or_default().insert(name.clone());
                let mut formal_to_actual = Vec::new();
                for arg in &call.arguments {
                    let actual = argument_root(arg);
                    if !actual.is_empty() && (arg.position as usize) < functions[internal_callee].parameter_names.len() {
                        formal_to_actual.push(key2(&functions[internal_callee].parameter_names[arg.position as usize], &actual));
                    }
                }
                bindings.push(lifetime_proto::NativeSeamBinding {
                    caller: name.clone(), callee: internal_callee.clone(), call_node: call.node.clone(),
                    formal_to_actual, return_to: assigned_root(call),
                });
            }
            let Some(kind) = source_catalog.get(&callee) else { continue };
            let mut roots = BTreeSet::new();
            let assigned = assigned_root(call);
            if !assigned.is_empty() { roots.insert(assigned); }
            let mut arguments = Vec::new();
            for arg in &call.arguments {
                let root = argument_root(arg);
                if !root.is_empty() {
                    roots.insert(root);
                    arguments.push(arg.position.to_string());
                }
            }
            influenced.entry(name.clone()).or_default().extend(roots.iter().cloned());
            sites.entry(name.clone()).or_default().push(lifetime_proto::NativeSourceSite {
                function: name.clone(), node: call.node.clone(), callee: callee.clone(),
                line: call.line, has_line: call.has_line, arguments,
                influenced_roots: roots.into_iter().collect(), kind: kind.clone(),
            });
        }
        callees.entry(name.clone()).or_default();
        callers.entry(name.clone()).or_default();
    }
    // CoverageScheduler additionally follows function-valued callback
    // arguments. Keep that normalization in a separate graph: source
    // discovery's legacy reachability intentionally uses only direct calls.
    let mut coverage_callees = callees.clone();
    let mut coverage_callers = callers.clone();
    for (caller, item) in &functions {
        for call in &item.calls {
            let Some(callee) = by_source_name.get(&call.callee) else { continue };
            let Some(callee_item) = functions.get(callee) else { continue };
            for argument in &call.arguments {
                let actual = argument_root(argument);
                let actual = if actual.is_empty() { argument.expression.clone() } else { actual };
                let actual = actual.trim_start_matches(['&', '*']).to_owned();
                if (argument.position as usize) < callee_item.parameter_names.len()
                    && functions.contains_key(&actual) && actual != *callee {
                    coverage_callees.entry(caller.clone()).or_default().insert(actual.clone());
                    coverage_callers.entry(actual).or_default().insert(caller.clone());
                }
            }
        }
    }
    // Source launches are catalogued callsites; callerless functions are the
    // deterministic structural fallback used by the Python implementation.
    let mut launches: BTreeMap<String, (String, Vec<String>)> = BTreeMap::new();
    for name in functions.keys() {
        if sites.get(name).is_some_and(|value| !value.is_empty()) {
            launches.insert(name.clone(), ("catalog".into(), sites[name].iter().filter_map(|s| (!s.node.is_empty()).then_some(s.node.clone())).collect()));
        } else if callers[name].is_empty() {
            launches.insert(name.clone(), (if functions[name].externally_visible { "export" } else { "structural" }.into(), vec!["__entry__".into()]));
        }
    }

    let mut reachable = BTreeSet::new();
    let mut provenance: HashMap<String, BTreeSet<String>> = HashMap::new();
    let mut queue = VecDeque::new();
    for (name, (kind, _)) in &launches {
        reachable.insert(name.clone());
        provenance.entry(name.clone()).or_default().insert(kind.clone());
        queue.push_back(name.clone());
    }
    while let Some(name) = queue.pop_front() {
        for callee in &callees[&name] {
            let before = provenance.get(callee).cloned().unwrap_or_default();
            let inherited = provenance.get(&name).cloned().unwrap_or_default();
            provenance.entry(callee.clone()).or_default().extend(inherited);
            if reachable.insert(callee.clone()) || provenance[callee] != before { queue.push_back(callee.clone()); }
        }
    }

    // A recursive component can have no callerless member and no catalogued
    // source/export root. It is still a real function region and must not be
    // silently omitted from coverage. Add one structural entry for each such
    // function after ordinary reachability has been exhausted; this is a
    // language-neutral fallback, not a source-name special case.
    let uncovered_roots: Vec<String> = functions.keys()
        .filter(|name| !reachable.contains(*name))
        .cloned().collect();
    for name in uncovered_roots {
        launches.entry(name.clone()).or_insert_with(||
            ("structural".into(), vec!["__entry__".into()]));
        reachable.insert(name.clone());
        provenance.entry(name.clone()).or_default().insert("structural".into());
        queue.push_back(name);
    }
    while let Some(name) = queue.pop_front() {
        for callee in &callees[&name] {
            let inherited = provenance.get(&name).cloned().unwrap_or_default();
            let before = provenance.get(callee).cloned().unwrap_or_default();
            provenance.entry(callee.clone()).or_default().extend(inherited);
            if provenance[callee] != before { queue.push_back(callee.clone()); }
        }
    }

    // Propagate source influence through formal/actual calls until stable.
    let mut changed = true;
    while changed {
        changed = false;
        for (caller, item) in &functions {
            for call in &item.calls {
                let Some(internal_callee) = by_source_name.get(&call.callee) else { continue };
                let Some(callee_item) = functions.get(internal_callee) else { continue };
                let caller_roots = influenced.get(caller).cloned().unwrap_or_default();
                for arg in &call.arguments {
                    let actual = argument_root(arg);
                    if caller_roots.contains(&actual) && (arg.position as usize) < callee_item.parameter_names.len() {
                        let formal = callee_item.parameter_names[arg.position as usize].clone();
                        if influenced.entry(internal_callee.clone()).or_default().insert(formal) { changed = true; }
                    }
                }
                let assigned = assigned_root(call);
                if !assigned.is_empty() && !influenced[internal_callee].is_empty()
                    && influenced.entry(caller.clone()).or_default().insert(assigned) { changed = true; }
            }
        }
    }

    let mut result_functions = Vec::new();
    for name in functions.keys() {
        let (launch_provenance, launch_nodes) = launches.get(name).cloned().unwrap_or_default();
        result_functions.push(lifetime_proto::NativePlanFunction {
            name: name.clone(),
            callees: callees[name].iter().cloned().collect(),
            callers: callers[name].iter().cloned().collect(),
            source_sites: sites.remove(name).unwrap_or_default(),
            launch_nodes, launch_provenance,
            provenance: provenance.remove(name).unwrap_or_default().into_iter().collect(),
            influenced_roots: influenced.remove(name).unwrap_or_default().into_iter().collect(),
            reachable: reachable.contains(name),
        });
    }

    let source_functions: BTreeSet<String> = result_functions.iter()
        .filter(|item| !item.source_sites.is_empty()
            || coverage_callers.get(&item.name).is_none_or(BTreeSet::is_empty)
            // A structurally-launched recursive component has no callerless
            // member after the ordinary call graph is closed. Its synthetic
            // entry is nevertheless a valid coverage source; excluding it
            // leaves the entire isolated SCC out of every region.
            || item.launch_provenance == "structural")
        .map(|item| item.name.clone()).collect();
    let mut forward: HashMap<String, BTreeSet<String>> = HashMap::new();
    for source in &source_functions {
        let mut seen = BTreeSet::from([source.clone()]);
        let mut work = vec![source.clone()];
        while let Some(current) = work.pop() {
            for next in &coverage_callees[&current] {
                if seen.insert(next.clone()) { work.push(next.clone()); }
            }
        }
        forward.insert(source.clone(), seen);
    }
    let mut regions = Vec::new();
    let all_names: BTreeSet<String> = functions.keys().cloned().collect();
    for target in functions.keys() {
        let mut backward: BTreeSet<String> = BTreeSet::from([target.clone()]);
        let mut work = vec![target.clone()];
        while let Some(current) = work.pop() {
            for caller in &coverage_callers[&current] {
                if backward.insert(caller.clone()) { work.push(caller.clone()); }
            }
        }
        let mut sources: Vec<String> = source_functions.intersection(&backward).cloned().collect();
        if sources.is_empty() { sources = backward.iter().filter(|name| callers[*name].is_empty()).cloned().collect(); }
        let mut region_functions = BTreeSet::new();
        let mut state_keys = Vec::new();
        let mut context_keys = Vec::new();
        for source in &sources {
            let selected: BTreeSet<String> = forward.get(source).into_iter().flat_map(|set| set.intersection(&backward)).cloned().collect();
            for function in &selected { region_functions.insert(function.clone()); state_keys.push(key2(function, source)); }
            let mut contexts: Vec<String> = result_functions.iter().find(|item| &item.name == source)
                .map(|item| item.source_sites.iter().map(|site| if site.node.is_empty() { format!("{}@{}", site.callee, site.line) } else { site.node.clone() }).collect())
                .unwrap_or_default();
            if contexts.is_empty() { contexts.push("__entry__".into()); }
            for context in contexts { for function in &selected { context_keys.push(key3(function, source, &context)); } }
        }
        regions.push(lifetime_proto::NativeCoverageRegion { target: target.clone(), sources, functions: region_functions.into_iter().collect(), state_keys, context_keys });
    }
    let covered: BTreeSet<String> = regions.iter().flat_map(|region| region.functions.iter().cloned()).collect();
    lifetime_proto::NativePlanResult {
        functions: result_functions, bindings, regions,
        covered_functions: covered.iter().cloned().collect(),
        uncovered_functions: all_names.difference(&covered).cloned().collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn structurally_launched_recursive_components_are_covered() {
        let recursive = lifetime_proto::TranslationFunction {
            id: "recursive-id".into(),
            name: "recursive".into(),
            calls: vec![lifetime_proto::FunctionCall { callee: "recursive".into(), ..Default::default() }],
            ..Default::default()
        };
        let result = plan(lifetime_proto::NativePlanRequest {
            translation: Some(lifetime_proto::TranslationResult { functions: vec![recursive] }),
            sources: Vec::new(),
        });
        assert_eq!(result.functions.len(), 1);
        assert_eq!(result.covered_functions, vec!["recursive"]);
        assert!(result.uncovered_functions.is_empty());
        assert_eq!(result.regions.len(), 1);
        assert_eq!(result.regions[0].functions, vec!["recursive"]);
    }
}
