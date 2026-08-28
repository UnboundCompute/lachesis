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

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct FindingKey {
    function: String,
    pattern: String,
    object: ObjectKey,
    node: String,
    line: i64,
    launch: String,
    returns: Vec<usize>,
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
    returns: Vec<usize>,
    bindings: Vec<(u32, u32)>,
    guards: Vec<(String, String)>,
    released: MarkSet,
    origins: MarkSet,
    nulls: MarkSet,
    nonnull: MarkSet,
    nullable: MarkSet,
    uninitialized: MarkSet,
    pointer_arithmetic: MarkSet,
    escaped: MarkSet,
    realloc_lost: MarkSet,
}

#[derive(Clone, Copy)]
struct TraceStep {
    node: usize,
    parent: Option<usize>,
}

fn trace_witness(
    traces: &[TraceStep], current: usize,
    nodes: &[lifetime_proto::NativeSemanticNode],
) -> Vec<String> {
    let mut output = Vec::new();
    let mut cursor = Some(current);
    while let Some(index) = cursor {
        let step = traces[index];
        output.push(nodes[step.node].id.clone());
        cursor = step.parent;
    }
    output.reverse();
    output
}

/// Canonical sparse object-id set used by the matcher worklist.  Stitched
/// graphs have a large global object universe, while each path usually marks
/// only a few objects.  Keeping sorted handles avoids cloning a dense bitset
/// sized to every object in every worklist state and retains deterministic
/// hashing/equality.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct MarkSet(Vec<u32>);

impl MarkSet {
    fn empty(_object_count: usize) -> Self {
        Self(Vec::new())
    }

    #[inline]
    fn contains(&self, value: u32) -> bool {
        self.0.binary_search(&value).is_ok()
    }

    #[inline]
    fn insert(&mut self, value: u32) {
        if let Err(index) = self.0.binary_search(&value) {
            self.0.insert(index, value);
        }
    }

    #[inline]
    fn remove(&mut self, value: u32) {
        if let Ok(index) = self.0.binary_search(&value) {
            self.0.remove(index);
        }
    }

    fn iter(&self) -> impl Iterator<Item = u32> + '_ {
        self.0.iter().copied()
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

fn value_constraint(value: &str) -> Option<(&str, &str, &str)> {
    for operator in ["<=", ">=", "==", "!=", "<", ">"] {
        if let Some(index) = value.find(operator) {
            return Some((&value[..index], operator, &value[index + operator.len()..]));
        }
    }
    None
}

fn contradictory_value(left: &str, right: &str) -> bool {
    let (Some((left_value, left_op, left_rhs)), Some((right_value, right_op, right_rhs))) =
        (value_constraint(left), value_constraint(right)) else { return false };
    if left_value != right_value { return false; }
    if left_op == "==" && right_op == "==" { return left_rhs != right_rhs; }
    if matches!((left_op, right_op), ("==", "!=") | ("!=", "==")) {
        return left_rhs == right_rhs;
    }
    matches!((left_op, right_op),
        ("<", ">=") | (">=", "<") | (">", "<=") | ("<=", ">"))
}

fn escaped_reaches(
    value: u32, escaped: &MarkSet, objects: &[ObjectKey], bindings: &[(u32, u32)],
) -> bool {
    let value = canonical(value, bindings);
    let object = &objects[value as usize];
    escaped.iter().map(|root| canonical(root, bindings)).any(|root| {
        let root = &objects[root as usize];
        root.root == object.root && root.generation == object.generation
            && object.selectors.starts_with(&root.selectors)
    })
}

fn has_surviving_alias(value: u32, bindings: &[(u32, u32)]) -> bool {
    let value = canonical(value, bindings);
    bindings.iter().any(|(alias, _)| *alias != value && canonical(*alias, bindings) == value)
}

fn object_label(object: &ObjectKey) -> String {
    format!("{}{}", object.root.strip_prefix("decl:").unwrap_or(&object.root),
            object.selectors.join(""))
}

fn selector_suffix<'a>(label: &'a str, prefix: &str) -> Option<&'a str> {
    let suffix = label.strip_prefix(prefix)?;
    if suffix.is_empty() || matches!(suffix.as_bytes()[0], b'-' | b'.' | b'[' | b'*' | b'&') {
        Some(suffix)
    } else {
        None
    }
}

fn add_finding(
    output: &mut HashMap<FindingKey, lifetime_proto::NativeTemporalFinding>,
    function: &str,
    pattern: &str,
    object: &ObjectKey,
    node: &lifetime_proto::NativeSemanticNode,
    witness_nodes: &[String],
    returns: &[usize],
    guards: &[lifetime_proto::GuardProof],
) {
    let owner = if node.function.is_empty() { function } else { node.function.as_str() };
    let line = if node.has_line { node.line } else { 0 };
    let key = FindingKey {
        function: owner.to_owned(), pattern: pattern.to_owned(), object: object.clone(),
        node: node.id.clone(), line,
        launch: witness_nodes.first().cloned().unwrap_or_default(),
        returns: returns.to_vec(),
    };
    output.entry(key).or_insert_with(|| lifetime_proto::NativeTemporalFinding {
        function: owner.to_owned(),
        pattern: pattern.to_owned(),
        path: Some(lifetime_proto::Path {
            root: object.root.clone(),
            selectors: object.selectors.clone(),
        }),
        line,
        has_line: node.has_line,
        node: node.id.clone(),
        // This is the exact matcher-state path, including call/return seams.
        // Source-taint provenance is retained separately below; substituting
        // it here would mislabel a value-flow proof as the temporal witness.
        witness_nodes: witness_nodes.to_vec(),
        witness_complete: !witness_nodes.is_empty(),
        source_witness_nodes: node.source_witness_nodes.clone(),
        source_reachable: node.source_reachable,
        // Temporal guards are path evidence, not proof that the lifetime
        // obligation was discharged. The old matcher therefore retained the
        // predicates while keeping `guarded=false` for emitted findings.
        guards: guards.to_vec(),
        guarded: false,
        family: String::new(), pattern_id: String::new(), evaluator: String::new(), tier: 0,
    });
}

fn cfg_witnesses(
    function: &lifetime_proto::NativeSemanticFunction,
    outgoing: &[Vec<usize>],
    entry: usize,
) -> Vec<Vec<String>> {
    // Compute one real CFG path per node after the compact event graph has
    // been built.  Keep only predecessor indices during the walk so the
    // common case does not retain a path vector in every worklist state.
    let mut predecessor = vec![None; function.nodes.len()];
    let mut queue = VecDeque::from([entry]);
    let mut visited = HashSet::with_capacity_and_hasher(function.nodes.len(), Default::default());
    visited.insert(entry);
    while let Some(source) = queue.pop_front() {
        for &target in &outgoing[source] {
            if visited.insert(target) {
                predecessor[target] = Some(source);
                queue.push_back(target);
            }
        }
    }
    (0..function.nodes.len()).map(|target| {
        let mut path = Vec::new();
        let mut current = Some(target);
        while let Some(index) = current {
            path.push(function.nodes[index].id.clone());
            current = predecessor[index];
        }
        path.reverse();
        // A node outside the entry-reachable CFG has no witness.  Do not
        // manufacture a partial path for it.
        if path.first().is_some_and(|id| id == &function.nodes[entry].id) {
            path
        } else {
            Vec::new()
        }
    }).collect()
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
    // Keep the metadata needed by seam traversal beside the adjacency entry.
    // Looking it up by scanning `function.edges` inside the state worklist made
    // stitched matching O(states * edges) on large functions/stitched graphs.
    let mut guarded_outgoing: Vec<Vec<(
        usize,
        Vec<lifetime_proto::GuardProof>,
        Vec<lifetime_proto::NativeSeamBinding>,
        String,
        String,
    )>> = vec![Vec::new(); function.nodes.len()];
    for edge in &function.edges {
        if let (Some(source), Some(target)) = (by_id.get(edge.source.as_str()), by_id.get(edge.target.as_str())) {
            outgoing[*source].push(*target);
            guarded_outgoing[*source].push((
                *target,
                edge.guards.clone(),
                edge.bindings.clone(),
                edge.seam_kind.clone(),
                edge.return_to.clone(),
            ));
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
    let object_labels: Vec<String> = objects.iter().map(object_label).collect();
    let mut objects_by_label: HashMap<&str, Vec<u32>> = HashMap::default();
    for (index, label) in object_labels.iter().enumerate() {
        objects_by_label.entry(label.as_str()).or_default().push(index as u32);
    }
    // Compile exact and field-prefix seam rebases once. The old matcher
    // composed the unmatched selector suffix (formal->field => actual->field);
    // doing that inside the worklist multiplied string scans by every state.
    let mut expanded_seam_bindings: HashMap<String, Vec<(u32, u32)>> = HashMap::default();
    for edge in &function.edges {
        for binding in &edge.bindings {
            for encoded in &binding.formal_to_actual {
                if expanded_seam_bindings.contains_key(encoded) { continue; }
                let Some((formal, actual)) = encoded.split_once('\u{1f}') else { continue };
                let formal = formal.strip_prefix("decl:").unwrap_or(formal);
                let actual = actual.strip_prefix("decl:").unwrap_or(actual);
                let mut pairs = Vec::new();
                for (source, label) in object_labels.iter().enumerate() {
                    let Some(suffix) = selector_suffix(label, formal) else { continue };
                    let target_label = format!("{actual}{suffix}");
                    let Some(targets) = objects_by_label.get(target_label.as_str()) else { continue };
                    let source_generation = &objects[source].generation;
                    if let Some(target) = targets.iter().copied().find(|target|
                        objects[*target as usize].generation == *source_generation)
                        .or_else(|| targets.iter().copied().find(|target|
                            objects[*target as usize].generation == "g0")) {
                        pairs.push((source as u32, target));
                    }
                }
                pairs.sort_unstable();
                pairs.dedup();
                expanded_seam_bindings.insert(encoded.clone(), pairs);
            }
        }
    }

    let empty = MarkSet::empty(objects.len());
    let mut queue = VecDeque::from([(
        entry, None::<usize>, Vec::<usize>::new(),
        Vec::<(u32, u32)>::new(), empty.clone(), empty.clone(), empty.clone(),
        empty.clone(), empty.clone(), empty.clone(), empty.clone(), empty.clone(), empty,
        Vec::<lifetime_proto::GuardProof>::new(),
    )]);
    let mut seen = HashSet::with_capacity_and_hasher(function.nodes.len(), Default::default());
    let mut findings = HashMap::with_capacity_and_hasher(function.nodes.len(), Default::default());
    let mut traces = Vec::new();
    let mut transfers = 0u64;
    let mut widenings = 0u64;
    // A malformed or adversarial sidecar must not make a query process diverge.
    // This is a work bound for one function, not a wall-clock hard stop.
    const MAX_STATES: usize = 1_000_000;

    while let Some((index, parent_trace, returns, mut bindings, mut released, mut origins, mut nulls,
                    mut nonnull, mut nullable, mut uninitialized, mut pointer_arithmetic, mut escaped,
                    mut realloc_lost, mut path_guards)) = queue.pop_front() {
        if transfers as usize >= MAX_STATES { break; }
        transfers += 1;
        bindings.sort_unstable();
        bindings.dedup();
        let state = StateKey {
            node: index, returns: returns.clone(), bindings: bindings.clone(),
            guards: path_guards.iter().map(|guard| (guard.kind.clone(), guard.value.clone())).collect(),
            released: released.clone(), origins: origins.clone(),
            nulls: nulls.clone(), nonnull: nonnull.clone(), nullable: nullable.clone(),
            uninitialized: uninitialized.clone(),
            pointer_arithmetic: pointer_arithmetic.clone(), escaped: escaped.clone(),
            realloc_lost: realloc_lost.clone(),
        };
        if !seen.insert(state) { continue; }
        let trace = traces.len();
        traces.push(TraceStep { node: index, parent: parent_trace });
        let node = &function.nodes[index];
        let witness_storage = trace_witness(&traces, trace, &function.nodes);
        let witness = witness_storage.as_slice();
        if node.event_kind == "LOOP" {
            // Predicates from one iteration are not stable facts for the
            // next. The old matcher clears them at its loop-widening boundary.
            path_guards.clear();
            widenings += 1;
        }
        let raw_object_id = node_object_ids[index];
        let object_id = raw_object_id.map(|value| canonical(value, &bindings));
        let value_id = node_value_ids[index].map(|value| canonical(value, &bindings));
        match node.event_kind.as_str() {
            "DERIVE" => if let (Some(target), Some(value)) = (raw_object_id, value_id) {
                bindings.retain(|(source, _)| *source != target);
                bindings.push((target, value));
                uninitialized.remove(target);
                if node.access == "aggregate-copy" {
                    add_finding(&mut findings, &function.id, "aggregate-copy-alias",
                                &objects[target as usize], node, witness, &returns, &path_guards);
                }
            },
            "ORIGIN" => if let Some(object) = object_id {
                released.remove(object);
                nulls.remove(raw_object_id.unwrap_or(object));
                if node.access == "return-may-null" {
                    nullable.insert(object);
                    nonnull.remove(object);
                } else {
                    nullable.remove(object);
                    nonnull.insert(object);
                }
                uninitialized.remove(object);
                escaped.remove(object);
                realloc_lost.remove(object);
                origins.insert(object);
            },
            "RELEASE" | "memory.free" => if let Some(object) = object_id {
                // A release through a slot proven to contain null is a no-op.
                // Keep this check before adding the object to the released set;
                // otherwise a later valid release would be misclassified.
                if !raw_object_id.is_some_and(|slot| nulls.contains(slot)) {
                    if released.contains(object) {
                        add_finding(&mut findings, &function.id, "double-free",
                                    &objects[object as usize], node, witness, &returns, &path_guards);
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
                nulls.insert(raw_object_id.unwrap_or(object));
                realloc_lost.insert(object);
            },
            "READ_STORAGE" | "memory.deref" => if let Some(object) = object_id {
                if released.contains(object) {
                    add_finding(&mut findings, &function.id, "uaf.deref",
                                &objects[object as usize], node, witness, &returns, &path_guards);
                }
                if raw_object_id.is_some_and(|slot| nulls.contains(slot)) {
                    add_finding(&mut findings, &function.id, "null-deref",
                                &objects[object as usize], node, witness, &returns, &path_guards);
                }
                if nullable.contains(object) && !nonnull.contains(object) {
                    add_finding(&mut findings, &function.id, "unchecked-return-deref",
                                &objects[object as usize], node, witness, &returns, &path_guards);
                }
                if uninitialized.contains(object) {
                    add_finding(&mut findings, &function.id, "uninitialized-use",
                                &objects[object as usize], node, witness, &returns, &path_guards);
                }
                if pointer_arithmetic.contains(object) {
                    add_finding(&mut findings, &function.id,
                                "pointer-arithmetic-before-validation",
                                &objects[object as usize], node, witness, &returns, &path_guards);
                }
            },
            "WRITE_STORAGE" => if let Some(object) = object_id {
                if released.contains(object) {
                    add_finding(&mut findings, &function.id, "uaf.deref",
                                &objects[object as usize], node, witness, &returns, &path_guards);
                }
                if raw_object_id.is_some_and(|slot| nulls.contains(slot)) {
                    add_finding(&mut findings, &function.id, "null-deref",
                                &objects[object as usize], node, witness, &returns, &path_guards);
                }
                if uninitialized.contains(object) {
                    add_finding(&mut findings, &function.id,
                                "uninitialized-use", &objects[object as usize], node, witness,
                                &returns, &path_guards);
                }
                if let Some(value) = value_id {
                    let slot = raw_object_id.unwrap_or(object);
                    bindings.retain(|(source, _)| *source != slot);
                    bindings.push((slot, value));
                    nulls.remove(slot);
                    uninitialized.remove(slot);
                }
            },
            "PASS_VALUE" | "COMPARE_VALUE" | "RETURN_VALUE" => if let Some(object) = object_id {
                if released.contains(object) {
                    add_finding(&mut findings, &function.id, "use.dangling",
                                &objects[object as usize], node, witness, &returns, &path_guards);
                }
                if uninitialized.contains(object) {
                    add_finding(&mut findings, &function.id, "uninitialized-use",
                                &objects[object as usize], node, witness, &returns, &path_guards);
                }
                if node.event_kind == "RETURN_VALUE" && node.stack_local {
                    add_finding(&mut findings, &function.id, "use-after-return",
                                &objects[object as usize], node, witness, &returns, &path_guards);
                }
                if node.event_kind == "RETURN_VALUE" {
                    escaped.insert(object);
                }
            },
            "WRITE_STORAGE_NULL" => if let Some(slot) = raw_object_id {
                // Null is a value in this storage slot. Aliases captured from
                // its former pointee remain valid independent identities.
                bindings.retain(|(source, _)| *source != slot);
                nulls.insert(slot);
                nonnull.remove(slot);
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
                    && !escaped_reaches(object, &escaped, &objects, &bindings)
                    && !has_surviving_alias(object, &bindings)
                {
                    add_finding(&mut findings, &function.id,
                                "mem.lifetime.realloc-failure-leak",
                                &objects[object as usize], node, witness, &returns, &path_guards);
                }
            }
            for object in origins.iter() {
                if !released.contains(object)
                    && !escaped_reaches(object, &escaped, &objects, &bindings)
                    && !has_surviving_alias(object, &bindings)
                {
                    add_finding(&mut findings, &function.id, "leak",
                                &objects[object as usize], node, witness, &returns, &path_guards);
                }
            }
        }
        for (target, guards, seam_bindings, seam_kind, return_to) in &guarded_outgoing[index] {
            let mut next_returns = returns.clone();
            if seam_kind == "call" {
                if !return_to.is_empty() {
                    let Some(continuation) = by_id.get(return_to.as_str()).copied() else {
                        continue;
                    };
                    next_returns.push(continuation);
                }
            } else if seam_kind == "return" {
                let Some(continuation) = next_returns.pop() else { continue };
                if continuation != *target { continue; }
            }
            let mut next_bindings = bindings.clone();
            for binding in seam_bindings {
                for encoded in &binding.formal_to_actual {
                    if let Some(pairs) = expanded_seam_bindings.get(encoded) {
                        next_bindings.extend(pairs.iter().copied());
                    }
                }
            }
            let mut returned_slot_binding = None;
            if seam_kind == "return" && !return_to.is_empty() {
                if let (Some(source), Some(target_object)) = (
                    node_object_ids[index],
                    object_labels.iter().position(|label|
                        label == return_to.strip_prefix("decl:").unwrap_or(return_to)),
                ) {
                    // A returned value is assigned in the caller. Keep
                    // canonicalization pointed from that caller-side
                    // destination to the callee-side returned object so
                    // released/escaped state follows the returned value.
                    next_bindings.push((target_object as u32, source));
                    returned_slot_binding = Some((target_object as u32, source));
                }
            }
            next_bindings.sort_unstable();
            next_bindings.dedup();
            let mut next_nulls = nulls.clone();
            let mut next_nonnull = nonnull.clone();
            let mut next_nullable = nullable.clone();
            let mut next_escaped = escaped.clone();
            if let Some((receiver, returned)) = returned_slot_binding {
                // Null/non-null are storage-slot facts and therefore flow
                // opposite to the receiver->returned identity binding.
                if next_nulls.contains(returned) { next_nulls.insert(receiver); }
                if next_nonnull.contains(returned) { next_nonnull.insert(receiver); }
                // RETURN_VALUE is an escape from the callee, but after the
                // seam the caller receiver owns that value. Keeping it in the
                // escaped set would suppress a genuine caller-side leak.
                next_escaped.remove(canonical(receiver, &next_bindings));
            }
            let mut next_guards = path_guards.clone();
            let mut contradiction = false;
            for guard in guards {
                if guard.kind == "VALUE" {
                    if next_guards.iter().any(|existing|
                        existing.kind == "VALUE" && contradictory_value(&existing.value, &guard.value)) {
                        contradiction = true;
                        break;
                    }
                    if !next_guards.iter().any(|item|
                        item.kind == guard.kind && item.value == guard.value) {
                        next_guards.push(guard.clone());
                    }
                    continue;
                }
                let Some((root, generation)) = guard.value.split_once('#') else { continue };
                let root = root.strip_prefix("decl:").unwrap_or(root);
                let Some(object) = objects.iter().position(|item|
                    item.root.strip_prefix("decl:").unwrap_or(&item.root) == root
                        && item.generation == generation).map(|id| id as u32)
                else { continue };
                let object = canonical(object, &next_bindings);
                match guard.kind.as_str() {
                    "ISNULL" => {
                        if next_nonnull.contains(object) { contradiction = true; break; }
                        next_nulls.insert(object);
                        next_nonnull.remove(object);
                        next_nullable.remove(object);
                    }
                    "NONNULL" => {
                        if next_nulls.contains(object) { contradiction = true; break; }
                        next_nonnull.insert(object);
                        next_nulls.remove(object);
                        next_nullable.remove(object);
                    }
                    _ => {}
                }
                if !next_guards.iter().any(|item|
                    item.kind == guard.kind && item.value == guard.value) {
                    next_guards.push(guard.clone());
                }
            }
            if !contradiction {
                queue.push_back((*target, Some(trace), next_returns, next_bindings, released.clone(), origins.clone(), next_nulls,
                                 next_nonnull, next_nullable, uninitialized.clone(), pointer_arithmetic.clone(),
                                 next_escaped, realloc_lost.clone(), next_guards));
            }
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
        widenings,
        capped: transfers as usize >= MAX_STATES,
    }
}

pub(crate) fn match_result(
    result: lifetime_proto::NativeSemanticResult,
) -> lifetime_proto::NativeTemporalResult {
    let had_skeletons = !result.skeletons.is_empty();
    let temporal_skeletons: Vec<_> = result.skeletons.iter()
        .filter(|skeleton| skeleton.kind != "reach")
        .cloned()
        .collect();
    if had_skeletons {
        return match_skeletons(temporal_skeletons);
    }
    if !result.seams.is_empty() {
        return match_stitched_result(result);
    }
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

/// Apply the executable Atropos pattern set after native state matching.
///
/// The transfer engine intentionally discovers generic semantic facts (for
/// example a release followed by a dereference).  Atropos owns which of those
/// facts are enabled for the installation.  Keeping that selection in the
/// compiled protobuf catalog prevents the Rust engine from growing a second,
/// product-specific pattern registry.
pub(crate) fn match_result_with_catalog(
    mut result: lifetime_proto::NativeSemanticResult,
    catalog: Option<&crate::atropos_proto::PatternCatalog>,
) -> lifetime_proto::NativeTemporalResult {
    let Some(catalog) = catalog else { return match_result(result); };
    // The Python matcher has two disjoint branches: reach skeletons are
    // evaluated as one sink fact, while typestate skeletons go through the
    // path-sensitive temporal automaton.  Passing both kinds to
    // `match_result` makes a reach sink look like a lifecycle event and can
    // produce duplicate or spurious temporal findings.
    let reach_skeletons: Vec<_> = result.skeletons.iter()
        .filter(|skeleton| skeleton.kind == "reach")
        .cloned().collect();
    let sink_graphs: Vec<_> = result.skeletons.iter()
        .filter(|skeleton| skeleton.kind == "reach-graph")
        .cloned().collect();
    result.skeletons.retain(|skeleton|
        skeleton.kind != "reach" && skeleton.kind != "reach-graph");
    let mut matched = match_result(result);
    matched.functions.extend(reach_skeletons.iter().enumerate()
        .filter_map(|(ordinal, skeleton)| match_reach_skeleton(skeleton, catalog, ordinal)));
    matched.functions.extend(sink_graphs.iter().enumerate()
        .filter_map(|(ordinal, skeleton)| match_sink_relations(skeleton, catalog, ordinal)));
    let enabled: HashSet<&str> = catalog.patterns.iter()
        .filter_map(|pattern| (!pattern.matcher_pattern.is_empty())
            .then_some(pattern.matcher_pattern.as_str()))
        .collect();
    if enabled.is_empty() { return matched; }
    for function in &mut matched.functions {
        function.findings.retain(|finding| enabled.contains(finding.pattern.as_str()));
        for finding in &mut function.findings {
            if let Some(pattern) = catalog.patterns.iter()
                .find(|pattern| pattern.matcher_pattern == finding.pattern) {
                finding.pattern_id = pattern.id.clone();
                finding.evaluator = pattern.evaluator.clone();
                finding.tier = pattern.tier;
            }
        }
    }
    matched
}

fn match_sink_relations(
    skeleton: &lifetime_proto::NativeFlowSkeleton,
    catalog: &crate::atropos_proto::PatternCatalog,
    ordinal: usize,
) -> Option<lifetime_proto::NativeTemporalFunction> {
    let pattern = catalog.patterns.iter().find(|pattern|
        pattern.evaluator == "relational"
            && pattern.requires.iter().any(|required| required == "memory.alloc")
            && pattern.requires.iter().any(|required| required == "memory.copy"))?;
    let tokens: HashMap<&str, &lifetime_proto::NativeSkeletonToken> = skeleton.tokens.iter()
        .map(|token| (token.node.as_str(), token)).collect();
    let mut findings = Vec::new();
    for edge in &skeleton.edges {
        let (Some(allocation), Some(copy)) =
            (tokens.get(edge.source.as_str()), tokens.get(edge.target.as_str())) else { continue };
        if allocation.family != "alloc-size"
            || !matches!(copy.family.as_str(), "buffer-write" | "buffer-size")
            || allocation.destination.is_empty()
            || allocation.destination != copy.destination
            || allocation.size_expression.is_empty()
            || copy.size_expression.is_empty()
            || allocation.size_expression == copy.size_expression {
            continue;
        }
        findings.push(lifetime_proto::NativeTemporalFinding {
            function: skeleton.source_function.clone(),
            pattern: pattern.matcher_pattern.clone(),
            path: Some(lifetime_proto::Path { root: copy.destination.clone(), selectors: Vec::new() }),
            line: copy.line, has_line: copy.has_line, node: copy.node.clone(),
            witness_nodes: vec![allocation.node.clone(), copy.node.clone()],
            witness_complete: true,
            source_witness_nodes: copy.source_witness_nodes.clone(),
            source_reachable: copy.source_reachable,
            guards: copy.guards.clone(), guarded: copy.guarded,
            family: copy.family.clone(), pattern_id: pattern.id.clone(),
            evaluator: pattern.evaluator.clone(), tier: pattern.tier,
        });
    }
    if findings.is_empty() { return None; }
    findings.sort_by(|left, right| (&left.node, left.line).cmp(&(&right.node, right.line)));
    findings.dedup_by(|left, right| left.node == right.node && left.path == right.path);
    Some(lifetime_proto::NativeTemporalFunction {
        id: format!("native:sink-graph:{ordinal}:{}", skeleton.entry),
        findings, transfers: skeleton.edges.len() as u64, widenings: 0,
        capped: !skeleton.complete,
    })
}

/// Evaluate the old Python reach substrate over a binary Claus skeleton.
/// Pattern IDs and sink families are entirely catalog-owned; these are only
/// the generic evaluator primitives from flow/patterns.py.
fn match_reach_skeleton(
    skeleton: &lifetime_proto::NativeFlowSkeleton,
    catalog: &crate::atropos_proto::PatternCatalog,
    ordinal: usize,
) -> Option<lifetime_proto::NativeTemporalFunction> {
    let mut findings = Vec::new();
    for token in &skeleton.tokens {
        if token.kind != "sink" || token.family.is_empty() { continue; }
        let recipe = catalog.kind_evaluator.get(&token.family)
            .map(String::as_str).unwrap_or_default();
        for pattern in &catalog.patterns {
            if pattern.matcher_pattern.is_empty() || pattern.evaluator.is_empty() { continue; }
            if pattern.matcher_families.is_empty()
                || !pattern.matcher_families.iter().any(|family| family == &token.family) {
                continue;
            }
            if !recipe.split(',').any(|name| name == pattern.evaluator) { continue; }
            let required_control = pattern.requires.iter()
                .filter(|required| matches!(required.as_str(), "if" | "else" | "for" |
                    "while" | "switch" | "case" | "default" | "do"));
            let controls: Vec<&String> = required_control.collect();
            if !controls.is_empty()
                && !controls.iter().any(|required| token.control.contains(required)) {
                continue;
            }
            if !reach_evaluator(&pattern.evaluator, token) { continue; }
            findings.push(lifetime_proto::NativeTemporalFinding {
                function: skeleton.source_function.clone(),
                pattern: pattern.matcher_pattern.clone(),
                path: Some(lifetime_proto::Path {
                    root: token.object_root.clone(),
                    selectors: token.object_selectors.clone(),
                }),
                line: token.line,
                has_line: token.has_line,
                node: token.node.clone(),
                witness_nodes: token.source_witness_nodes.clone(),
                witness_complete: !token.source_witness_nodes.is_empty(),
                source_witness_nodes: token.source_witness_nodes.clone(),
                source_reachable: token.source_reachable,
                guards: token.guards.clone(),
                guarded: token.guarded,
                family: token.family.clone(), pattern_id: pattern.id.clone(),
                evaluator: pattern.evaluator.clone(), tier: pattern.tier,
            });
        }
    }
    if findings.is_empty() { return None; }
    findings.sort_by(|left, right| (&left.pattern, &left.node, left.line)
        .cmp(&(&right.pattern, &right.node, right.line)));
    Some(lifetime_proto::NativeTemporalFunction {
        id: format!("native:reach:{ordinal}:{}", skeleton.context),
        findings,
        transfers: skeleton.tokens.len() as u64,
        widenings: 0,
        capped: !skeleton.complete,
    })
}

fn reach_evaluator(name: &str, token: &lifetime_proto::NativeSkeletonToken) -> bool {
    match name {
        "reachability" => token.tainted,
        "relational" => token.tainted && token.bound == "unbounded",
        "presence" => true,
        "missing-guard" => token.guard_status == "fall-through",
        "inverted-capacity-guard" => {
            if !token.tainted || token.size_expression.is_empty() { return false; }
            let size = token.size_expression.replace(' ', "");
            token.control.iter().map(|item| item.replace(' ', "")).any(|predicate|
                predicate.contains(&format!("{}>=", size))
                    || predicate.contains(&format!("{}>", size)))
        }
        "arithmetic-overflow-guard" => token.tainted && token.guarded
            && token.control.iter().any(|predicate|
                predicate.contains('+') && (predicate.contains('<') || predicate.contains("<="))),
        "allocation-overflow-size" => token.family == "alloc-size" && token.tainted
            && token.size_expression.contains('*')
            && token.size_expression.split('*').any(|part|
                part.chars().any(|character| character.is_ascii_alphabetic() || character == '_')),
        "typestate" => false,
        _ => false,
    }
}

fn match_stitched_result(result: lifetime_proto::NativeSemanticResult)
    -> lifetime_proto::NativeTemporalResult
{
    let mut nodes = Vec::new();
    let mut edges = Vec::new();
    let mut exits = Vec::new();
    let entry = "native:stitched:event-entry".to_owned();
    let callee_ids: HashSet<String> = result.seams.iter()
        .filter(|edge| edge.seam_kind == "call")
        .map(|edge| edge.callee.clone()).collect();
    for function in result.functions {
        if function.nodes.is_empty() { continue; }
        exits.extend(function.exits.iter().cloned());
        if !callee_ids.contains(&function.id) {
            edges.push(lifetime_proto::NativeSemanticEdge {
                source: entry.clone(), target: function.entry.clone(), kind: "normal".into(),
                ..Default::default()
            });
        }
        nodes.extend(function.nodes);
        edges.extend(function.edges);
    }
    nodes.push(lifetime_proto::NativeSemanticNode {
        id: entry.clone(), event_kind: String::new(), ..Default::default()
    });
    edges.extend(result.seams);
    let function = lifetime_proto::NativeSemanticFunction {
        id: "native:stitched".into(), entry, exits, nodes, edges,
        language: "mixed".into(), source_launch_nodes: Vec::new(),
        parameter_roots: Vec::new(),
    };
    let matched = match_function(&function);
    lifetime_proto::NativeTemporalResult { functions: vec![matched] }
}

fn skeleton_event_kind(family: &str, token_kind: &str) -> String {
    if token_kind == "control" || family == "control" { return String::new(); }
    match family {
        "memory.alloc" | "lifecycle.acquire" => "ORIGIN".into(),
        "memory.free" | "lifecycle.release" => "memory.free".into(),
        "memory.deref" | "lifecycle.use" => "memory.deref".into(),
        "lifecycle.escape" => "ESCAPE".into(),
        "lifecycle.invalidate" => "INVALIDATE".into(),
        "lifecycle.derive" => "DERIVE".into(),
        "lifecycle.return" => "RETURN_VALUE".into(),
        "lifecycle.pointer_arithmetic" => "POINTER_ARITHMETIC".into(),
        "lifecycle.uninitialized" => "UNINITIALIZED".into(),
        _ => family.to_owned(),
    }
}

/// Convert one binary Claus skeleton back into the compact native matcher
/// representation.  This is an in-process Rust projection: it does not cross
/// Python, serialize JSON, or reopen the graph.  Anchors retained by the
/// skeleton keep the original branch and seam edges intact.
fn match_skeleton(
    skeleton: &lifetime_proto::NativeFlowSkeleton,
    ordinal: usize,
) -> Option<lifetime_proto::NativeTemporalFunction> {
    let mut nodes = Vec::new();
    let mut seen = HashSet::default();
    for token in &skeleton.tokens {
        if token.node.is_empty() || !seen.insert(token.node.clone()) { continue; }
        nodes.push(lifetime_proto::NativeSemanticNode {
            id: token.node.clone(), function: token.function.clone(),
            event_kind: if token.event_kind.is_empty() {
                skeleton_event_kind(&token.family, &token.kind)
            } else {
                token.event_kind.clone()
            },
            object_root: token.object_root.clone(), object_selectors: token.object_selectors.clone(),
            generation: if token.generation.is_empty() { "g0".into() } else { token.generation.clone() },
            line: token.line, has_line: token.has_line,
            anchor: token.node.clone(), source_witness_nodes: token.source_witness_nodes.clone(),
            source_reachable: token.source_reachable, stack_local: token.stack_local,
            is_null: token.is_null, access: token.access.clone(),
            value_root: token.value_root.clone(), value_selectors: token.value_selectors.clone(),
            ..Default::default()
        });
    }
    if nodes.is_empty() { return None; }
    let node_ids: HashSet<&str> = nodes.iter().map(|node| node.id.as_str()).collect();
    let mut edges = Vec::new();
    let mut edge_keys = HashSet::default();
    for edge in &skeleton.edges {
        if !node_ids.contains(edge.source.as_str()) || !node_ids.contains(edge.target.as_str()) {
            continue;
        }
        let key = (&edge.source, &edge.target, &edge.kind, &edge.seam_kind, &edge.return_to);
        if edge_keys.insert(key) { edges.push(edge.clone()); }
    }
    let outgoing: HashSet<&str> = edges.iter().map(|edge| edge.source.as_str()).collect();
    let entry = nodes.iter().find(|node| node.function == skeleton.entry)
        .or_else(|| nodes.first()).map(|node| node.id.clone())?;
    let mut exits: Vec<String> = nodes.iter().filter(|node| !outgoing.contains(node.id.as_str()))
        .map(|node| node.id.clone()).collect();
    if exits.is_empty() { exits.push(nodes.last()?.id.clone()); }
    Some(match_function(&lifetime_proto::NativeSemanticFunction {
        id: format!("native:skeleton:{ordinal}:{}", skeleton.context),
        entry, exits, nodes, edges, language: String::new(), source_launch_nodes: Vec::new(),
        parameter_roots: Vec::new(),
    }))
}

fn match_skeletons(
    skeletons: Vec<lifetime_proto::NativeFlowSkeleton>,
) -> lifetime_proto::NativeTemporalResult {
    lifetime_proto::NativeTemporalResult {
        functions: skeletons.iter().enumerate()
            .filter_map(|(ordinal, skeleton)| match_skeleton(skeleton, ordinal))
            .collect(),
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
            source_witness_nodes: Vec::new(), source_reachable: None,
        }
    }

    fn function(nodes: Vec<lifetime_proto::NativeSemanticNode>)
        -> lifetime_proto::NativeSemanticFunction
    {
        let ids: Vec<String> = nodes.iter().map(|item| item.id.clone()).collect();
        let edges = ids.windows(2).map(|pair| lifetime_proto::NativeSemanticEdge {
            source: pair[0].clone(), target: pair[1].clone(), kind: "normal".to_owned(), guards: Vec::new(),
            ..Default::default()
        }).collect();
        lifetime_proto::NativeSemanticFunction {
            id: "f".to_owned(), entry: ids[0].clone(), exits: vec![ids[ids.len() - 1].clone()],
            nodes, edges, language: "c".to_owned(), source_launch_nodes: Vec::new(),
            parameter_roots: Vec::new(),
        }
    }

    #[test]
    fn finds_double_free_on_a_reachable_lifecycle_path() {
        let result = match_result(lifetime_proto::NativeSemanticResult {
            functions: vec![function(vec![node("o", "ORIGIN", 1),
                                             node("r1", "RELEASE", 2),
                                             node("r2", "RELEASE", 3)])],
            complete: true,
            ..Default::default()
        });
        assert_eq!(result.functions[0].findings.len(), 1);
        assert_eq!(result.functions[0].findings[0].pattern, "double-free");
        assert_eq!(result.functions[0].findings[0].line, 3);
    }

    #[test]
    fn fresh_generation_is_not_use_after_free() {
        let mut reorigin = node("o2", "ORIGIN", 3);
        reorigin.generation = "g1".into();
        let mut use_new = node("u2", "READ_STORAGE", 4);
        use_new.generation = "g1".into();
        let result = match_result(lifetime_proto::NativeSemanticResult {
            functions: vec![function(vec![node("o", "ORIGIN", 1),
                                             node("r", "RELEASE", 2),
                                             reorigin, use_new])],
            complete: true,
            ..Default::default()
        });
        assert!(!result.functions[0].findings.iter()
            .any(|finding| finding.pattern == "uaf.deref"));
    }

    #[test]
    fn catalog_selects_generic_finding_routes() {
        let result = lifetime_proto::NativeSemanticResult {
            functions: vec![function(vec![node("o", "ORIGIN", 1),
                                             node("r", "memory.free", 2),
                                             node("u", "memory.deref", 3)])],
            ..Default::default()
        };
        let catalog = crate::atropos_proto::PatternCatalog {
            patterns: vec![crate::atropos_proto::Pattern {
                matcher_pattern: "uaf.deref".into(), ..Default::default()
            }],
            ..Default::default()
        };
        let matched = match_result_with_catalog(result, Some(&catalog));
        assert_eq!(matched.functions[0].findings.len(), 1);
        assert_eq!(matched.functions[0].findings[0].pattern, "uaf.deref");
    }

    #[test]
    fn matcher_consumes_a_binary_skeleton_lifecycle_path() {
        let token = |node: &str, family: &str| lifetime_proto::NativeSkeletonToken {
            kind: "event".into(), function: "source".into(), node: node.into(),
            family: family.into(), object_root: "p".into(), ..Default::default()
        };
        let skeleton = lifetime_proto::NativeFlowSkeleton {
            kind: "source-rooted".into(), entry: "source".into(), source_function: "source".into(),
            context: "ctx".into(),
            complete: true,
            tokens: vec![token("alloc", "memory.alloc"), token("free", "memory.free"),
                         token("use", "memory.deref")],
            edges: vec![
                lifetime_proto::NativeSemanticEdge { source: "alloc".into(), target: "free".into(), ..Default::default() },
                lifetime_proto::NativeSemanticEdge { source: "free".into(), target: "use".into(), ..Default::default() },
            ],
            is_source: true,
        };
        let matched = match_result(lifetime_proto::NativeSemanticResult {
            skeletons: vec![skeleton], ..Default::default()
        });
        assert_eq!(matched.functions.len(), 1);
        assert_eq!(matched.functions[0].findings.len(), 1);
        assert_eq!(matched.functions[0].findings[0].pattern, "uaf.deref");
    }

    #[test]
    fn matcher_evaluates_catalogued_reach_skeleton_without_function_names() {
        let catalog = crate::atropos_proto::PatternCatalog {
            patterns: vec![crate::atropos_proto::Pattern {
                matcher_pattern: "relational".into(),
                matcher_families: vec!["buffer-size".into()],
                evaluator: "relational".into(),
                ..Default::default()
            }, crate::atropos_proto::Pattern {
                matcher_pattern: "mem.copy.in.loop-unbounded".into(),
                matcher_families: vec!["buffer-size".into()],
                evaluator: "relational".into(),
                // This pattern is an in-loop copy: its loop requirement is DATA,
                // not inferred from the pattern name, so it must not match a sink
                // whose skeleton carries no loop control.
                requires: vec!["for".into()],
                ..Default::default()
            }],
            kind_evaluator: [("buffer-size".into(), "relational".into())]
                .into_iter().collect(),
            ..Default::default()
        };
        let skeleton = lifetime_proto::NativeFlowSkeleton {
            kind: "reach".into(), entry: "source".into(),
            source_function: "source".into(), context: "__entry__".into(), complete: true,
            tokens: vec![lifetime_proto::NativeSkeletonToken {
                kind: "sink".into(), family: "buffer-size".into(),
                object_root: "input".into(), tainted: true, bound: "unbounded".into(),
                ..Default::default()
            }], ..Default::default()
        };
        let matched = match_result_with_catalog(
            lifetime_proto::NativeSemanticResult { skeletons: vec![skeleton], ..Default::default() },
            Some(&catalog));
        assert_eq!(matched.functions.len(), 1);
        assert_eq!(matched.functions[0].findings.len(), 1);
        assert_eq!(matched.functions[0].findings[0].pattern, "relational");
    }

    #[test]
    fn reports_the_effective_guard_on_a_finding() {
        let nodes = vec![node("o", "ORIGIN", 1), node("r1", "RELEASE", 2),
                         node("r2", "RELEASE", 3)];
        let edges = vec![
            lifetime_proto::NativeSemanticEdge {
                source: "o".into(), target: "r1".into(), kind: "normal".into(),
                ..Default::default()
            },
            lifetime_proto::NativeSemanticEdge {
                source: "r1".into(), target: "r2".into(), kind: "normal".into(),
                guards: vec![lifetime_proto::GuardProof {
                    kind: "NONNULL".into(), value: "p#g0".into(),
                }],
                ..Default::default()
            },
        ];
        let mut function = function(nodes);
        function.edges = edges;
        let result = match_result(lifetime_proto::NativeSemanticResult {
            functions: vec![function], complete: true, ..Default::default()
        });
        let finding = result.functions[0].findings.iter()
            .find(|finding| finding.pattern == "double-free")
            .expect("guarded double-free finding");
        assert!(finding.guarded);
        assert_eq!(finding.guards[0].kind, "NONNULL");
    }

    #[test]
    fn finds_use_after_free_on_a_reachable_lifecycle_path() {
        let result = match_result(lifetime_proto::NativeSemanticResult {
            functions: vec![function(vec![node("o", "ORIGIN", 1),
                                             node("r", "RELEASE", 2),
                                             node("u", "READ_STORAGE", 3)])],
            complete: true,
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
        });
        assert!(result.functions[0].findings.is_empty());
    }

    #[test]
    fn contradictory_nonnull_guard_prunes_null_release_path() {
        let nodes = vec![node("n", "WRITE_STORAGE_NULL", 1), node("r", "RELEASE", 2)];
        let edges = vec![lifetime_proto::NativeSemanticEdge {
            source: "n".to_owned(),
            target: "r".to_owned(),
            kind: "normal".to_owned(),
            guards: vec![lifetime_proto::GuardProof {
                kind: "NONNULL".to_owned(), value: "p#g0".to_owned(),
            }],
            ..Default::default()
        }];
        let result = match_result(lifetime_proto::NativeSemanticResult {
            functions: vec![lifetime_proto::NativeSemanticFunction {
                id: "f".to_owned(), entry: "n".to_owned(), exits: vec!["r".to_owned()],
                nodes, edges, language: "c".to_owned(), source_launch_nodes: Vec::new(),
                parameter_roots: Vec::new(),
            }],
            complete: true,
            ..Default::default()
        });
        assert!(result.functions[0].findings.is_empty());
    }

    #[test]
    fn stitches_lifetime_identity_across_a_call_seam() {
        let mut origin = node("a-origin", "ORIGIN", 1);
        origin.function = "a".to_owned();
        origin.object_root = "actual".to_owned();
        let mut release = node("b-release", "RELEASE", 2);
        release.function = "b".to_owned();
        release.object_root = "formal".to_owned();
        let mut read = node("b-read", "READ_STORAGE", 3);
        read.function = "b".to_owned();
        read.object_root = "formal".to_owned();
        let seam = lifetime_proto::NativeSemanticEdge {
            source: "a-origin".to_owned(), target: "b-release".to_owned(), kind: "seam".into(),
            seam_kind: "call".into(), callee: "b".into(),
            bindings: vec![lifetime_proto::NativeSeamBinding {
                caller: "a".into(), callee: "b".into(), call_node: "call".into(),
                formal_to_actual: vec!["formal\u{1f}actual".into()], return_to: String::new(),
            }],
            ..Default::default()
        };
        let result = match_result(lifetime_proto::NativeSemanticResult {
            functions: vec![
                lifetime_proto::NativeSemanticFunction {
                    id: "a".into(), entry: "a-origin".into(), exits: vec!["a-origin".into()],
                    nodes: vec![origin], edges: Vec::new(), language: "c".into(), source_launch_nodes: Vec::new(),
                    parameter_roots: Vec::new(),
                },
                lifetime_proto::NativeSemanticFunction {
                    id: "b".into(), entry: "b-release".into(), exits: vec!["b-read".into()],
                    nodes: vec![release, read],
                    edges: vec![lifetime_proto::NativeSemanticEdge {
                        source: "b-release".into(), target: "b-read".into(), kind: "normal".into(),
                        ..Default::default()
                    }], language: "c".into(), source_launch_nodes: Vec::new(),
                    parameter_roots: Vec::new(),
                },
            ],
            complete: true, seams: vec![seam], ..Default::default()
        });
        assert!(result.functions[0].findings.iter().any(|finding|
            finding.pattern == "uaf.deref" && finding.function == "b"),
            "findings: {:?}", result.functions[0].findings);
    }

    #[test]
    fn carries_return_value_identity_back_to_the_caller() {
        let mut origin = node("a-origin", "ORIGIN", 1);
        origin.function = "a".into();
        origin.object_root = "actual".into();
        let mut release = node("b-release", "RELEASE", 2);
        release.function = "b".into();
        release.object_root = "formal".into();
        let mut returned = node("b-return", "RETURN_VALUE", 3);
        returned.function = "b".into();
        returned.object_root = "formal".into();
        let mut caller_read = node("a-read", "READ_STORAGE", 4);
        caller_read.function = "a".into();
        caller_read.object_root = "result".into();
        let binding = lifetime_proto::NativeSeamBinding {
            caller: "a".into(), callee: "b".into(), call_node: "call".into(),
            formal_to_actual: vec!["formal\u{1f}actual".into()], return_to: "result".into(),
        };
        let edges = vec![
            lifetime_proto::NativeSemanticEdge {
                source: "b-release".into(), target: "b-return".into(), kind: "normal".into(),
                ..Default::default()
            },
            lifetime_proto::NativeSemanticEdge {
                source: "a-origin".into(), target: "b-release".into(), kind: "seam".into(),
                seam_kind: "call".into(), callee: "b".into(), return_to: "a-read".into(),
                bindings: vec![binding.clone()],
                ..Default::default()
            },
            lifetime_proto::NativeSemanticEdge {
                source: "b-return".into(), target: "a-read".into(), kind: "seam".into(),
                seam_kind: "return".into(), callee: "a".into(), return_to: "result".into(),
                bindings: vec![binding], ..Default::default()
            },
        ];
        let result = match_result(lifetime_proto::NativeSemanticResult {
            functions: vec![
                lifetime_proto::NativeSemanticFunction {
                    id: "a".into(), entry: "a-origin".into(), exits: vec!["a-read".into()],
                    nodes: vec![origin, caller_read], edges: Vec::new(), language: "c".into(),
                    source_launch_nodes: Vec::new(), parameter_roots: Vec::new(),
                },
                lifetime_proto::NativeSemanticFunction {
                    id: "b".into(), entry: "b-release".into(), exits: vec!["b-return".into()],
                    nodes: vec![release, returned], edges: Vec::new(), language: "c".into(),
                    source_launch_nodes: Vec::new(), parameter_roots: Vec::new(),
                },
            ], complete: true, seams: edges, ..Default::default()
        });
        assert!(result.functions[0].findings.iter().any(|finding|
            finding.pattern == "uaf.deref" && finding.function == "a"),
            "findings: {:?}", result.functions[0].findings);
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
            ..Default::default()
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
            ..Default::default()
        });
        assert!(result.functions[0].findings.iter()
            .any(|finding| finding.pattern == "mem.lifetime.realloc-failure-leak"));
    }

    #[test]
    fn escaped_object_is_not_reported_as_a_leak() {
        let result = match_result(lifetime_proto::NativeSemanticResult {
            functions: vec![function(vec![node("o", "ORIGIN", 1),
                                             node("e", "ESCAPE", 2)])],
            complete: true,
            ..Default::default()
        });
        assert!(result.functions[0].findings.is_empty());
    }
}
