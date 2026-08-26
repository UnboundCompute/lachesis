//! Native source discovery and coverage planning over compact translation facts.
//!
//! This is intentionally independent of Kùzu.  Pass 1 has already emitted the
//! call/parameter facts needed by these two deterministic graph algorithms.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

use crate::lifetime_proto;

const SEP: &str = "\u{1f}";

fn key2(a: &str, b: &str) -> String { format!("{a}{SEP}{b}") }
fn key3(a: &str, b: &str, c: &str) -> String { format!("{a}{SEP}{b}{SEP}{c}") }

pub(crate) fn plan(request: lifetime_proto::NativePlanRequest) -> lifetime_proto::NativePlanResult {
    let raw_functions = request.translation.unwrap_or_default().functions;
    let mut name_counts: HashMap<String, usize> = HashMap::new();
    for item in &raw_functions {
        let name = if item.name.is_empty() { &item.id } else { &item.name };
        if !name.is_empty() { *name_counts.entry(name.clone()).or_default() += 1; }
    }
    let functions: BTreeMap<String, lifetime_proto::TranslationFunction> = raw_functions
        .into_iter().filter_map(|item| {
            let base = if item.name.is_empty() { item.id.clone() } else { item.name.clone() };
            if base.is_empty() { return None; }
            let name = if name_counts[&base] == 1 { base } else { format!("{}@{}", base, item.id) };
            Some((name, item))
        }).collect();
    // Calls carry the source-level callee spelling.  Resolve it only when the
    // spelling is unambiguous, matching the legacy Python projection: an
    // overloaded/duplicate display name is not silently connected to an
    // arbitrary translation-unit owner.
    let mut by_source_name: HashMap<String, String> = HashMap::new();
    for (name, item) in &functions {
        let base = if item.name.is_empty() { item.id.clone() } else { item.name.clone() };
        if name_counts.get(&base) == Some(&1) { by_source_name.insert(base, name.clone()); }
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
                    let actual = if !arg.root_name.is_empty() { arg.root_name.clone() } else { arg.root.clone() };
                    if !actual.is_empty() && (arg.position as usize) < functions[internal_callee].parameter_names.len() {
                        formal_to_actual.push(key2(&functions[internal_callee].parameter_names[arg.position as usize], &actual));
                    }
                }
                bindings.push(lifetime_proto::NativeSeamBinding {
                    caller: name.clone(), callee: internal_callee.clone(), call_node: call.node.clone(),
                    formal_to_actual, return_to: call.assigned_name.clone(),
                });
            }
            let Some(kind) = source_catalog.get(&callee) else { continue };
            let mut roots = BTreeSet::new();
            if !call.assigned_name.is_empty() { roots.insert(call.assigned_name.clone()); }
            let mut arguments = Vec::new();
            for arg in &call.arguments {
                let root = if !arg.root_name.is_empty() { arg.root_name.clone() } else { arg.root.clone() };
                if !root.is_empty() { roots.insert(root); }
                arguments.push(arg.position.to_string());
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
                    let actual = if !arg.root_name.is_empty() { arg.root_name.clone() } else { arg.root.clone() };
                    if caller_roots.contains(&actual) && (arg.position as usize) < callee_item.parameter_names.len() {
                        let formal = callee_item.parameter_names[arg.position as usize].clone();
                        if influenced.entry(internal_callee.clone()).or_default().insert(formal) { changed = true; }
                    }
                }
                if !call.assigned_name.is_empty() && !influenced[internal_callee].is_empty()
                    && influenced.entry(caller.clone()).or_default().insert(call.assigned_name.clone()) { changed = true; }
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
        .filter(|item| !item.source_sites.is_empty() || item.callers.is_empty())
        .map(|item| item.name.clone()).collect();
    let mut forward: HashMap<String, BTreeSet<String>> = HashMap::new();
    for source in &source_functions {
        let mut seen = BTreeSet::from([source.clone()]);
        let mut work = vec![source.clone()];
        while let Some(current) = work.pop() {
            for next in &callees[&current] {
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
            for caller in &callers[&current] {
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
            let contexts: Vec<String> = result_functions.iter().find(|item| &item.name == source)
                .map(|item| item.source_sites.iter().map(|site| if site.node.is_empty() { format!("{}@{}", site.callee, site.line) } else { site.node.clone() }).collect())
                .unwrap_or_else(|| vec!["__entry__".into()]);
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
