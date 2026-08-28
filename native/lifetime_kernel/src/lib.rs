//! Native state-transition kernel for Pass 2's object-lifetime analysis.
//!
//! This crate intentionally has no Python or graph dependency.  The eventual Python
//! bridge will submit one compact function batch (CFG + operations) at a time.  Keeping
//! the domain here value-oriented avoids allocating Python dictionaries and tuples for
//! every transfer while preserving the existing analysis semantics.

use std::collections::VecDeque;
use std::hash::{Hash, Hasher};
use std::ffi::CStr;
use std::os::raw::c_char;
use std::fs;
use hashbrown::{HashMap, HashSet};
use rustc_hash::FxHasher;
use std::slice;
use std::sync::Arc;
use prost::Message;

use serde::{Deserialize, Serialize};

mod atropos_bind;

mod lifetime_proto {
    include!(concat!(env!("OUT_DIR"), "/lachesis.lifetime.rs"));
}
mod graph_proto {
    include!(concat!(env!("OUT_DIR"), "/lachesis.graph.rs"));
}
mod prepare;
mod native_graph;
mod planner;
mod pass2;
mod control_flow;
mod dispatch;
mod taint;
mod dynamic_behavior;
mod async_events;
mod interprocedural;
mod branch_history;
mod reaching_def;
mod module_initialization;
mod property_effects;
mod heap;
mod summary;
mod sidecar_project;
mod semantic_match;
mod claus;
mod skeleton;
mod reach;

/// Apply one additive overlay to the shared graph and retain its records for
/// publication.  Keeping this in one place guarantees that every subsequent
/// overlay sees the preceding overlay's facts and that edge deduplication is
/// applied consistently.
fn absorb_native_delta(
    graph: &mut pass2::Graph,
    delta: pass2::Delta,
    writer: &mut pass2::DataflowStreamWriter,
) -> Result<(), String> {
    writer.append(&delta)?;
    graph.absorb(delta)
}

fn report_native_phase(
    enabled: bool, started: std::time::Instant, name: &str,
    nodes: usize, edges: usize,
) {
    if enabled {
        eprintln!("[lachesis native pass2] {name}: {:.3}s (+{} nodes, +{} edges)",
            started.elapsed().as_secs_f64(), nodes, edges);
    }
}

/// Project a semantic function onto its event nodes while preserving CFG
/// reachability through removed anchor nodes.  The event sidecar is used by
/// the matcher, so dropping the anchors must not drop branch/order semantics.
pub(crate) fn compact_event_function(
    mut function: lifetime_proto::NativeSemanticFunction,
) -> Option<lifetime_proto::NativeSemanticFunction> {
    let full_entry = function.entry.clone();
    let full_exits = function.exits.clone();
    // The full function is owned by this projection and its original edge
    // objects are not needed after indexed adjacency is built. Move them out
    // instead of cloning the entire edge vector during every function pass.
    let full_edges = std::mem::take(&mut function.edges);
    // Use dense node indices while projecting.  The old implementation
    // rebuilt string-keyed adjacency and cloned IDs on every walk from every
    // event.  A semantic function's node table is already fixed, so indices
    // are a lossless and allocation-light representation for this phase.
    let node_count = function.nodes.len();
    let node_ids: Vec<String> = function.nodes.iter().map(|node| node.id.clone()).collect();
    let mut by_id: HashMap<&str, usize> = HashMap::with_capacity(node_count);
    for (index, node) in function.nodes.iter().enumerate() {
        by_id.insert(node.id.as_str(), index);
    }
    let event_indices: Vec<usize> = function.nodes.iter().enumerate()
        .filter_map(|(index, node)| (!node.event_kind.is_empty()).then_some(index))
        .collect();
    if event_indices.is_empty() { return None; }
    let mut event_flags = vec![false; node_count];
    for &index in &event_indices {
        event_flags[index] = true;
    }
    let mut outgoing = vec![Vec::new(); node_count];
    let mut incoming = vec![Vec::new(); node_count];
    let mut edge_metadata: HashMap<(usize, usize), lifetime_proto::NativeSemanticEdge> = HashMap::new();
    for edge in full_edges {
        let (Some(&source), Some(&target)) =
            (by_id.get(edge.source.as_str()), by_id.get(edge.target.as_str()))
        else { continue };
        outgoing[source].push(target);
        incoming[target].push(source);
        edge_metadata.entry((source, target)).or_insert(edge);
    }

    // Walk through non-event anchors until the next event(s).  Each event is
    // expanded independently, so loops are bounded by the visited set and
    // branch arms remain separate in the projected graph.
    let mut visited_marks = vec![0u32; node_count];
    let mut found_marks = vec![0u32; node_count];
    let mut walk_stamp = 0u32;
    let mut pending = Vec::new();
    let mut found = Vec::new();
    let mut walk = |start: usize, graph: &[Vec<usize>], result: &mut Vec<usize>| {
        walk_stamp = walk_stamp.wrapping_add(1);
        if walk_stamp == 0 {
            visited_marks.fill(0);
            found_marks.fill(0);
            walk_stamp = 1;
        }
        let stamp = walk_stamp;
        pending.clear();
        result.clear();
        pending.push(start);
        while let Some(current) = pending.pop() {
            if visited_marks[current] == stamp { continue; }
            visited_marks[current] = stamp;
            for target in graph.get(current).into_iter().flatten() {
                if event_flags[*target] {
                    if found_marks[*target] != stamp {
                        found_marks[*target] = stamp;
                        result.push(*target);
                    }
                } else {
                    pending.push(*target);
                }
            }
        }
    };

    let mut projected: Vec<(usize, usize)> = Vec::new();
    for &source in &event_indices {
        walk(source, &outgoing, &mut found);
        for &target in &found {
            if source != target {
                projected.push((source, target));
            }
        }
    }
    projected.sort_unstable();
    projected.dedup();

    let entry_events: Vec<usize> = by_id.get(full_entry.as_str()).copied()
        .map(|entry| if event_flags[entry] {
            vec![entry]
        } else {
            walk(entry, &outgoing, &mut found);
            found.clone()
        })
        .unwrap_or_default();
    let mut exit_events = Vec::new();
    let mut exit_flags = vec![false; node_count];
    for exit in &full_exits {
        let Some(&exit) = by_id.get(exit.as_str()) else { continue };
        if event_flags[exit] {
            if !exit_flags[exit] {
                exit_flags[exit] = true;
                exit_events.push(exit);
            }
        } else {
            walk(exit, &incoming, &mut found);
            for &event in &found {
                if !exit_flags[event] {
                    exit_flags[event] = true;
                    exit_events.push(event);
                }
            }
        }
    }
    if exit_events.is_empty() {
        let mut has_outgoing = vec![false; node_count];
        for (source, _) in &projected {
            has_outgoing[*source] = true;
        }
        exit_events.extend(event_indices.iter().copied()
            .filter(|index| !has_outgoing[*index]));
    }

    let entry = format!("native:{}:event-entry", function.id);
    let exit = format!("native:{}:event-exit", function.id);
    let mut projected_edges: Vec<_> = projected.iter().map(|&(source, target)| {
        let mut edge = edge_metadata.remove(&(source, target)).unwrap_or_default();
        edge.source = node_ids[source].clone();
        edge.target = node_ids[target].clone();
        if edge.kind.is_empty() { edge.kind = "normal".to_owned(); }
        edge
    }).collect();
    projected_edges.reserve(entry_events.len() + exit_events.len());
    for target in entry_events {
        projected_edges.push(lifetime_proto::NativeSemanticEdge {
            source: entry.clone(), target: node_ids[target].clone(), kind: "normal".to_owned(), guards: Vec::new(),
            bindings: Vec::new(), seam_kind: String::new(), callee: String::new(),
            return_to: String::new(), provenance: String::new(),
        });
    }
    for source in exit_events {
        projected_edges.push(lifetime_proto::NativeSemanticEdge {
            source: node_ids[source].clone(),
            target: exit.clone(), kind: "normal".to_owned(), guards: Vec::new(),
            bindings: Vec::new(), seam_kind: String::new(), callee: String::new(),
            return_to: String::new(), provenance: String::new(),
        });
    }
    projected_edges.sort_by(|left, right| (&left.source, &left.target).cmp(&(&right.source, &right.target)));
    projected_edges.dedup_by(|left, right| left.source == right.source && left.target == right.target);

    drop(by_id);
    let event_ids: HashSet<&str> = event_indices.iter()
        .map(|&index| node_ids[index].as_str())
        .collect();
    function.nodes.retain(|node| event_ids.contains(node.id.as_str()));

    function.nodes.push(lifetime_proto::NativeSemanticNode {
        id: entry.clone(), function: function.id.clone(), event_kind: String::new(),
        object_root: String::new(), object_selectors: Vec::new(), generation: String::new(),
        line: 0, has_line: false, anchor: String::new(), stack_local: false,
        is_null: false, access: String::new(), value_root: String::new(),
        value_selectors: Vec::new(),
        source_witness_nodes: Vec::new(), source_reachable: None,
    });
    function.nodes.push(lifetime_proto::NativeSemanticNode {
        id: exit.clone(), function: function.id.clone(), event_kind: String::new(),
        object_root: String::new(), object_selectors: Vec::new(), generation: String::new(),
        line: 0, has_line: false, anchor: String::new(), stack_local: false,
        is_null: false, access: String::new(), value_root: String::new(),
        value_selectors: Vec::new(),
        source_witness_nodes: Vec::new(), source_reachable: None,
    });
    function.edges = projected_edges;
    function.entry = entry;
    function.exits = vec![exit];
    Some(function)
}

/// Native-chain runner for the binary Pass-2 path.  The ordering mirrors the
/// canonical Python registry so each later overlay observes the preceding
/// additive facts.
fn run_native_overlay_chain(
    input: &std::path::Path, catalog: Option<&std::path::Path>, output: &std::path::Path,
) -> Result<(usize, usize), String> {
    let timing_enabled = std::env::var_os("LACHESIS_NATIVE_PASS2_TIMINGS").is_some();
    let started = std::time::Instant::now();
    let mut graph = pass2::read_path(input)?;
    if timing_enabled {
        eprintln!("[lachesis native pass2] read graph: {:.3}s ({} nodes, {} edges)",
            started.elapsed().as_secs_f64(), graph.nodes.len(), graph.edges.len());
    }
    let mut writer = pass2::DataflowStreamWriter::begin(
        output, &input.to_string_lossy(), &graph.core_content_hash,
    )?;
    if let Some(catalog) = catalog {
        let catalog = atropos_proto::Request::decode(
            fs::read(catalog).map_err(|error| format!("cannot read binary Atropos catalog: {error}"))?.as_slice()
        ).map_err(|error| format!("invalid binary Atropos catalog: {error}"))?;
        let delta = taint::catalog_delta(&graph, &catalog);
        absorb_native_delta(&mut graph, delta, &mut writer)?;
        report_native_phase(timing_enabled, started, "atropos source-sink catalog", writer.nodes, writer.edges);
    }
    let delta = control_flow::enrich(&graph);
    absorb_native_delta(&mut graph, delta, &mut writer)?;
    report_native_phase(timing_enabled, started, "control-flow", writer.nodes, writer.edges);
    let delta = branch_history::enrich(&mut graph);
    absorb_native_delta(&mut graph, delta, &mut writer)?;
    report_native_phase(timing_enabled, started, "branch-history", writer.nodes, writer.edges);
    let delta = reaching_def::enrich(&graph);
    absorb_native_delta(&mut graph, delta, &mut writer)?;
    report_native_phase(timing_enabled, started, "reaching-definitions", writer.nodes, writer.edges);
    let delta = dispatch::enrich(&graph);
    absorb_native_delta(&mut graph, delta, &mut writer)?;
    report_native_phase(timing_enabled, started, "dynamic-dispatch", writer.nodes, writer.edges);
    let delta = dynamic_behavior::enrich(&graph);
    absorb_native_delta(&mut graph, delta, &mut writer)?;
    report_native_phase(timing_enabled, started, "dynamic-behavior", writer.nodes, writer.edges);
    let delta = interprocedural::enrich(&graph);
    absorb_native_delta(&mut graph, delta, &mut writer)?;
    report_native_phase(timing_enabled, started, "interprocedural-contexts", writer.nodes, writer.edges);
    let delta = heap::enrich(&mut graph);
    absorb_native_delta(&mut graph, delta, &mut writer)?;
    report_native_phase(timing_enabled, started, "heap-identity", writer.nodes, writer.edges);
    let delta = module_initialization::enrich(&graph);
    absorb_native_delta(&mut graph, delta, &mut writer)?;
    report_native_phase(timing_enabled, started, "module-initialization", writer.nodes, writer.edges);
    let delta = property_effects::enrich(&graph);
    absorb_native_delta(&mut graph, delta, &mut writer)?;
    report_native_phase(timing_enabled, started, "parameter-property-effects", writer.nodes, writer.edges);
    let delta = async_events::enrich(&graph);
    absorb_native_delta(&mut graph, delta, &mut writer)?;
    report_native_phase(timing_enabled, started, "async-events", writer.nodes, writer.edges);
    let delta = taint::enrich(&graph);
    absorb_native_delta(&mut graph, delta, &mut writer)?;
    report_native_phase(timing_enabled, started, "taint-propagation", writer.nodes, writer.edges);
    writer.finish()
}

mod atropos_proto {
    include!(concat!(env!("OUT_DIR"), "/lachesis.atropos.rs"));
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct Path {
    pub root: String,
    pub selectors: Vec<String>,
}

impl Path {
    pub fn root(root: impl Into<String>) -> Self {
        Self { root: root.into(), selectors: Vec::new() }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum Fact {
    Allocated,
    Freed,
    Null,
    Unknown,
}

type FactMask = u8;

#[inline]
fn fact_bit(fact: Fact) -> FactMask { 1 << fact as u8 }

fn fact_values(mask: FactMask) -> Vec<Fact> {
    [Fact::Allocated, Fact::Freed, Fact::Null, Fact::Unknown].into_iter()
        .filter(|fact| mask & fact_bit(*fact) != 0).collect()
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum Kind {
    Alloc,
    Clobber,
    Copy,
    Free,
    Realloc,
    Use,
    Summary,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct Operation {
    pub kind: Kind,
    pub node: String,
    pub target: Option<Path>,
    pub source: Option<Path>,
    pub site: String,
    pub line: Option<i64>,
    pub is_null: bool,
    pub access: String,
    pub generation: Option<String>,
    pub fresh_generation: Option<String>,
    pub alternatives: Vec<Vec<Operation>>,
}

/// Stable metadata for converting native IDs back to Python's tuple-shaped ObjectIds.
/// The solver uses compact string handles internally; snapshots never expose those
/// handles without this table.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum ObjectMeta {
    Param { position: u32, selectors: Vec<String> },
    UnknownRoot { root: String },
    UnknownSlot { base: String, selector: String },
    Allocation { kind: Kind, generation: String, site: String, target: Path },
    Phi { tag: String, node: String, index: usize },
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum Effect {
    Param { kind: Kind, position: u32, selectors: Vec<String> },
    Return { position: u32, selectors: Vec<String> },
}

#[derive(Clone, Debug, Default)]
pub struct State {
    pub env: HashMap<String, String>,
    pub facts: HashMap<String, FactMask>,
    pub slots: HashMap<(String, String), String>,
    pub trace: Vec<Effect>,
    pub freed_paths: HashMap<Path, String>,
    pub objects: HashMap<String, ObjectMeta>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Findings {
    pub double_free: Vec<(Option<i64>, Path, String)>,
    pub use_after_free: Vec<(Option<i64>, Path, String)>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Snapshot {
    pub env: Vec<(String, String)>,
    pub facts: Vec<(String, Vec<Fact>)>,
    pub slots: Vec<((String, String), String)>,
    pub trace: Vec<Effect>,
    pub freed_paths: Vec<(Path, String)>,
    pub objects: Vec<(String, ObjectMeta)>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LinearResult {
    pub point_states: Vec<(String, Vec<Snapshot>)>,
    pub post_states: Vec<(String, Vec<Snapshot>)>,
    pub exit_state: Snapshot,
    pub exit_states: Vec<Snapshot>,
    pub findings: Findings,
    pub transfers: u64,
    pub widenings: u64,
    pub capped: bool,
}

impl State {
    pub fn snapshot(&self) -> Snapshot {
        let mut env: Vec<_> = self.env.iter().map(|(root, oid)| (root.clone(), oid.clone())).collect();
        env.sort_by(|left, right| left.0.cmp(&right.0));
        let mut facts: Vec<_> = self.facts.iter().map(|(oid, values)| {
            (oid.clone(), fact_values(*values))
        }).collect();
        facts.sort_by(|left, right| left.0.cmp(&right.0));
        let mut slots: Vec<_> = self.slots.iter().map(|((base, selector), oid)| {
            ((base.clone(), selector.clone()), oid.clone())
        }).collect();
        slots.sort_by(|left, right| left.0.cmp(&right.0));
        let mut freed_paths: Vec<_> = self.freed_paths.iter().map(|(path, oid)| (path.clone(), oid.clone())).collect();
        freed_paths.sort_by(|left, right| path_name(&left.0).cmp(&path_name(&right.0)));
        // Keep only metadata reachable from this snapshot.  Allocation
        // generations are intentionally retained in `State::objects` for
        // identity continuity, but serializing every historical generation
        // into every point/post snapshot needlessly multiplies the result.
        let mut needed: HashSet<String> = self.env.values().cloned().collect();
        needed.extend(self.facts.keys().cloned());
        needed.extend(self.slots.keys().map(|(base, _)| base.clone()));
        needed.extend(self.slots.values().cloned());
        needed.extend(self.freed_paths.values().cloned());
        let mut pending: Vec<String> = needed.iter().cloned().collect();
        while let Some(oid) = pending.pop() {
            if let Some(ObjectMeta::UnknownSlot { base, .. }) = self.objects.get(&oid) {
                if needed.insert(base.clone()) {
                    pending.push(base.clone());
                }
            }
        }
        let mut objects: Vec<_> = self.objects.iter()
            .filter(|(oid, _)| needed.contains(*oid))
            .map(|(oid, meta)| (oid.clone(), meta.clone()))
            .collect();
        objects.sort_by(|left, right| left.0.cmp(&right.0));
        Snapshot { env, facts, slots, trace: self.trace.clone(), freed_paths, objects }
    }

    /// Snapshot used at operation points by the semantic emitter.
    ///
    /// Point/post consumers only resolve access paths through `env` and `slots`;
    /// they do not inspect the complete fact lattice or historical freed-path
    /// bookkeeping.  Keeping those fields out of every observation avoids
    /// serializing the same large maps once per operation while the full exit
    /// snapshot still preserves summaries and the public result contract.
    pub fn compact_snapshot(&self) -> Snapshot {
        let mut env: Vec<_> = self.env.iter()
            .map(|(root, oid)| (root.clone(), oid.clone()))
            .collect();
        env.sort_by(|left, right| left.0.cmp(&right.0));
        let mut slots: Vec<_> = self.slots.iter().map(|((base, selector), oid)| {
            ((base.clone(), selector.clone()), oid.clone())
        }).collect();
        slots.sort_by(|left, right| left.0.cmp(&right.0));

        // Retain metadata for every handle that path resolution can return,
        // including the parent chain of synthetic unknown slots.
        let mut needed: HashSet<String> = self.env.values().cloned().collect();
        needed.extend(self.slots.keys().map(|(base, _)| base.clone()));
        needed.extend(self.slots.values().cloned());
        let mut pending: Vec<String> = needed.iter().cloned().collect();
        while let Some(oid) = pending.pop() {
            if let Some(ObjectMeta::UnknownSlot { base, .. }) = self.objects.get(&oid) {
                if needed.insert(base.clone()) { pending.push(base.clone()); }
            }
        }
        let mut objects: Vec<_> = self.objects.iter()
            .filter(|(oid, _)| needed.contains(*oid))
            .map(|(oid, meta)| (oid.clone(), meta.clone()))
            .collect();
        objects.sort_by(|left, right| left.0.cmp(&right.0));
        Snapshot { env, facts: Vec::new(), slots, trace: Vec::new(),
                   freed_paths: Vec::new(), objects }
    }

    pub fn seed_parameter(&mut self, path: Path, position: u32) {
        let oid = param_id(position, &path.selectors);
        self.objects.entry(oid.clone()).or_insert_with(|| ObjectMeta::Param {
            position,
            selectors: path.selectors.clone(),
        });
        self.env.insert(path.root, oid.clone());
        *self.facts.entry(oid).or_default() |= fact_bit(Fact::Unknown);
    }

    fn resolve(&mut self, path: &Path, create: bool) -> Option<String> {
        let mut oid = self.env.get(&path.root).cloned();
        if oid.is_none() && create {
            let fresh = format!("unknown-root:{}", path.root);
            self.objects.entry(fresh.clone()).or_insert_with(|| ObjectMeta::UnknownRoot {
                root: path.root.clone(),
            });
            self.env.insert(path.root.clone(), fresh.clone());
            *self.facts.entry(fresh.clone()).or_default() |= fact_bit(Fact::Unknown);
            oid = Some(fresh);
        }
        for selector in &path.selectors {
            let base = oid?;
            let key = (base.clone(), selector.clone());
            let child = if let Some(existing) = self.slots.get(&key) {
                existing.clone()
            } else if create {
                let fresh = if let Some((position, selectors)) = parse_param(&base) {
                    let mut next = selectors;
                    next.push(selector.clone());
                    param_id(position, &next)
                } else {
                    format!("unknown-slot:{}:{}", base, selector)
                };
                self.objects.entry(fresh.clone()).or_insert_with(|| {
                    if let Some((position, selectors)) = parse_param(&base) {
                        let mut next = selectors;
                        next.push(selector.clone());
                        ObjectMeta::Param { position, selectors: next }
                    } else {
                        ObjectMeta::UnknownSlot { base: base.clone(), selector: selector.clone() }
                    }
                });
                self.slots.insert(key, fresh.clone());
                *self.facts.entry(fresh.clone()).or_default() |= fact_bit(Fact::Unknown);
                fresh
            } else {
                return None;
            };
            oid = Some(child);
        }
        oid
    }

    fn bind(&mut self, path: &Path, oid: String) {
        if path.selectors.is_empty() {
            self.env.insert(path.root.clone(), oid);
            return;
        }
        let mut parent = Path { root: path.root.clone(), selectors: path.selectors[..path.selectors.len() - 1].to_vec() };
        let Some(parent_id) = self.resolve(&mut parent, true) else { return };
        self.slots.insert((parent_id, path.selectors.last().unwrap().clone()), oid);
    }

    fn merge_object(&mut self, destination: &str, source: &str) {
        let source_facts = self.facts.get(source).copied().unwrap_or_else(|| fact_bit(Fact::Unknown));
        *self.facts.entry(destination.to_owned()).or_default() |= source_facts;
        for oid in self.env.values_mut() {
            if oid == source { *oid = destination.to_owned(); }
        }
        for oid in self.slots.values_mut() {
            if oid == source { *oid = destination.to_owned(); }
        }
    }

    fn is_summary_object(&self, oid: &str) -> bool {
        fn visit(state: &State, oid: &str, seen: &mut HashSet<String>) -> bool {
            if !seen.insert(oid.to_owned()) { return false; }
            if oid.split('|').nth(1) == Some("summary") { return true; }
            match state.objects.get(oid) {
                Some(ObjectMeta::Param { selectors, .. }) =>
                    selectors.iter().any(|selector| selector == "<?>") ,
                Some(ObjectMeta::Allocation { target, .. }) =>
                    target.selectors.iter().any(|selector| selector == "<?>") ,
                Some(ObjectMeta::UnknownSlot { base, selector }) =>
                    selector == "<?>" || visit(state, base, seen),
                _ => false,
            }
        }
        visit(self, oid, &mut HashSet::new())
    }

    fn age(&mut self, recent: &str, summary: &str) {
        if !self.facts.contains_key(recent) { return; }
        self.merge_object(summary, recent);
        let old_slots: Vec<_> = self.slots.iter()
            .filter(|((base, _), _)| base == recent)
            .map(|((base, selector), child)| (base.clone(), selector.clone(), child.clone()))
            .collect();
        for (base, selector, child) in old_slots {
            self.slots.remove(&(base, selector.clone()));
            let destination = (summary.to_owned(), selector);
            if let Some(previous) = self.slots.get(&destination).cloned() {
                if previous != child { self.merge_object(&previous, &child); }
            } else {
                self.slots.insert(destination, child);
            }
        }
        self.facts.remove(recent);
    }

    fn compensate_reassignment(&mut self, path: Option<&Path>) {
        let Some(path) = path else { return };
        if path.selectors.is_empty() { return; }
        let Some(oid) = self.freed_paths.remove(path) else { return };
        self.record_param(Kind::Alloc, &oid);
    }

    fn record_param(&mut self, kind: Kind, oid: &str) {
        let Some((position, selectors)) = parse_param(oid) else { return };
        let effect = Effect::Param { kind, position, selectors };
        if self.trace.iter().filter(|item| **item == effect).count() < 2 && self.trace.len() < 16 {
            self.trace.push(effect);
        }
    }

    fn record_return(&mut self, oid: &str) {
        let Some((position, selectors)) = parse_param(oid) else { return };
        let effect = Effect::Return { position, selectors };
        if self.trace.iter().filter(|item| **item == effect).count() < 2 && self.trace.len() < 16 {
            self.trace.push(effect);
        }
    }

    fn fresh(&mut self, op: &Operation, fact: Fact) {
        let Some(target) = op.target.as_ref() else { return };
        let recent = format!("{}|recent|{}|{}", kind_name(op.kind), op.site, path_name(target));
        let summary = format!("{}|summary|{}|{}", kind_name(op.kind), op.site, path_name(target));
        self.objects.entry(recent.clone()).or_insert_with(|| ObjectMeta::Allocation {
            kind: op.kind, generation: "recent".into(),
            site: op.site.clone(),
            target: target.clone(),
        });
        self.objects.entry(summary.clone()).or_insert_with(|| ObjectMeta::Allocation {
            kind: op.kind, generation: "summary".into(),
            site: op.site.clone(),
            target: target.clone(),
        });
        self.age(&recent, &summary);
        self.facts.insert(recent.clone(), fact_bit(fact));
        self.bind(target, recent);
    }

    fn free(&mut self, op: &Operation, findings: &mut Findings) {
        let Some(target) = op.target.as_ref() else { return };
        let Some(oid) = self.resolve(target, true) else { return };
        self.record_param(Kind::Free, &oid);
        if target.selectors.len() > 0 && parse_param(&oid).is_some() {
            self.freed_paths.insert(target.clone(), oid.clone());
        }
        let weak = self.is_summary_object(&oid);
        let facts = self.facts.entry(oid.clone()).or_insert(fact_bit(Fact::Unknown));
        if *facts & fact_bit(Fact::Freed) != 0 && !weak {
            findings.double_free.push((op.line, target.clone(), op.node.clone()));
        }
        if *facts != fact_bit(Fact::Null) {
            if weak { *facts |= fact_bit(Fact::Freed); }
            else { *facts = fact_bit(Fact::Freed); }
        }
    }

    pub fn apply(&mut self, op: &Operation, findings: &mut Findings) {
        match op.kind {
            Kind::Alloc => {
                self.compensate_reassignment(op.target.as_ref());
                self.fresh(op, Fact::Allocated)
            }
            Kind::Clobber => {
                self.compensate_reassignment(op.target.as_ref());
                self.fresh(op, if op.is_null { Fact::Null } else { Fact::Unknown })
            }
            Kind::Copy => {
                let Some(source) = op.source.as_ref().cloned() else { return };
                let mut source = source;
                let Some(oid) = self.resolve(&mut source, true) else { return };
                let Some(target) = op.target.as_ref() else { return };
                self.compensate_reassignment(Some(target));
                self.bind(target, oid);
            }
            Kind::Free => self.free(op, findings),
            Kind::Realloc => {
                if let Some(source) = &op.source {
                    let mut free_op = op.clone();
                    free_op.kind = Kind::Free;
                    free_op.target = Some(source.clone());
                    self.free(&free_op, findings);
                }
                self.compensate_reassignment(op.target.as_ref());
                self.fresh(op, Fact::Allocated);
            }
            Kind::Use => {
                let Some(target) = op.target.as_ref() else { return };
                let mut target_path = target.clone();
                let Some(oid) = self.resolve(&mut target_path, false) else { return };
                self.record_param(Kind::Use, &oid);
                if op.access_is_return() { self.record_return(&oid); }
                if !self.is_summary_object(&oid)
                    && self.facts.get(&oid).is_some_and(|facts| *facts & fact_bit(Fact::Freed) != 0) {
                    findings.use_after_free.push((op.line, target.clone(), op.node.clone()));
                }
            }
            // Summary operations are expanded by `apply_variants` at the graph
            // transfer boundary. Keeping this arm fail-closed prevents a
            // malformed direct call from silently changing state.
            Kind::Summary => {}
        }
    }

    fn apply_variants(self, op: &Operation, findings: &mut Findings) -> Vec<State> {
        if op.kind != Kind::Summary {
            let mut state = self;
            state.apply(op, findings);
            return vec![state];
        }
        if op.alternatives.is_empty() {
            return vec![self];
        }
        op.alternatives.iter().map(|effects| {
            let mut state = self.clone();
            for effect in effects {
                state.apply(effect, findings);
            }
            state
        }).collect()
    }

    fn semantically_equal(&self, other: &State) -> bool {
        // Length checks reject the overwhelmingly common non-equal states
        // without walking several hash maps. Objects are intentionally not
        // compared: historical allocation metadata is not part of the
        // abstract state semantics.
        self.env.len() == other.env.len()
            && self.facts.len() == other.facts.len()
            && self.slots.len() == other.slots.len()
            && self.trace.len() == other.trace.len()
            && self.freed_paths.len() == other.freed_paths.len()
            && self.env == other.env
            && self.facts == other.facts
            && self.slots == other.slots
            && self.trace == other.trace
            && self.freed_paths == other.freed_paths
    }
}

/// Execute the straight-line subset as one native batch.  The Python analyzer already
/// recognizes this shape; this function exists so the bridge can move the common case
/// without crossing the FFI boundary for every operation or snapshot.
pub fn solve_linear(nodes: &[String], operations: &[Operation], mut state: State) -> LinearResult {
    let mut at: HashMap<String, Vec<&Operation>> = HashMap::new();
    for operation in operations {
        at.entry(operation.node.clone()).or_default().push(operation);
    }
    let mut tracked = at.keys().cloned().collect::<HashSet<_>>();
    if let Some(first) = nodes.first() { tracked.insert(first.clone()); }
    if let Some(last) = nodes.last() { tracked.insert(last.clone()); }
    let mut point_states = Vec::with_capacity(tracked.len());
    let mut post_states = Vec::with_capacity(tracked.len());
    let mut findings = Findings::default();
    let mut transfers = 0;
    for node in nodes {
        if tracked.contains(node) {
            point_states.push((node.clone(), vec![state.snapshot()]));
        }
        for operation in at.get(node).into_iter().flatten() {
            state.apply(operation, &mut findings);
            transfers += 1;
        }
        if tracked.contains(node) {
            post_states.push((node.clone(), vec![state.snapshot()]));
        }
    }
    let exit_state = state.snapshot();
    LinearResult {
        point_states,
        post_states,
        exit_state: exit_state.clone(),
        exit_states: vec![exit_state],
        findings,
        transfers,
        widenings: 0,
        capped: false,
    }
}

/// Straight-line lifetime solving for callers that only need findings.  Do
/// not retain point/post/exit snapshots for the compact temporal sidecar.
pub fn solve_linear_findings(nodes: &[String], operations: &[Operation], mut state: State)
    -> LinearResult {
    let mut at: HashMap<String, Vec<&Operation>> = HashMap::new();
    for operation in operations {
        at.entry(operation.node.clone()).or_default().push(operation);
    }
    let mut findings = Findings::default();
    let mut transfers = 0;
    for node in nodes {
        for operation in at.get(node).into_iter().flatten() {
            state.apply(operation, &mut findings);
            transfers += 1;
        }
    }
    LinearResult {
        point_states: Vec::new(), post_states: Vec::new(),
        exit_state: State::default().snapshot(), exit_states: Vec::new(),
        findings, transfers, widenings: 0, capped: false,
    }
}

/// Return the unique acyclic CFG path when every node has at most one
/// successor.  Such a function needs no worklist or state deduplication: each
/// state has exactly one next location, so the linear transfer is equivalent.
pub fn linear_cfg_order(nodes: &[String], successors: &HashMap<String, Vec<String>>)
    -> Option<Vec<String>> {
    let first = nodes.first()?.clone();
    let known: HashSet<String> = nodes.iter().cloned().collect();
    let mut order = Vec::with_capacity(nodes.len());
    let mut seen = HashSet::new();
    let mut current = first;
    loop {
        if !known.contains(&current) || !seen.insert(current.clone()) {
            return None;
        }
        order.push(current.clone());
        let next = successors.get(&current).map(Vec::as_slice).unwrap_or(&[]);
        if next.is_empty() { break; }
        if next.len() != 1 { return None; }
        current = next[0].clone();
    }
    (order.len() == nodes.len()).then_some(order)
}

fn proto_path(path: lifetime_proto::Path) -> Path {
    Path { root: path.root, selectors: path.selectors }
}

fn proto_kind(kind: i32) -> Result<Kind, String> {
    use lifetime_proto::operation::Kind as ProtoKind;
    match ProtoKind::try_from(kind).map_err(|_| format!("unknown operation kind {kind}"))? {
        ProtoKind::Alloc => Ok(Kind::Alloc),
        ProtoKind::Clobber => Ok(Kind::Clobber),
        ProtoKind::Copy => Ok(Kind::Copy),
        ProtoKind::Free => Ok(Kind::Free),
        ProtoKind::Realloc => Ok(Kind::Realloc),
        ProtoKind::Use => Ok(Kind::Use),
        ProtoKind::Summary => Ok(Kind::Summary),
        ProtoKind::Unspecified => Err("operation kind is unspecified".into()),
    }
}

pub(crate) fn proto_operation(operation: lifetime_proto::Operation) -> Result<Operation, String> {
    let alternatives = operation.alternatives.into_iter().map(|alternative| {
        alternative.effects.into_iter().map(proto_operation).collect::<Result<Vec<_>, _>>()
    }).collect::<Result<Vec<_>, _>>()?;
    Ok(Operation {
        kind: proto_kind(operation.kind)?,
        node: operation.node,
        target: operation.target.map(proto_path),
        source: operation.source.map(proto_path),
        site: operation.site,
        line: operation.has_line.then_some(operation.line),
        is_null: operation.is_null,
        access: operation.access,
        generation: (!operation.generation.is_empty()).then_some(operation.generation),
        fresh_generation: (!operation.fresh_generation.is_empty()).then_some(operation.fresh_generation),
        alternatives,
    })
}

pub(crate) fn proto_operation_message(operation: Operation) -> lifetime_proto::Operation {
    lifetime_proto::Operation {
        kind: proto_kind_value(operation.kind),
        node: operation.node,
        target: operation.target.map(|path| lifetime_proto::Path {
            root: path.root,
            selectors: path.selectors,
        }),
        source: operation.source.map(|path| lifetime_proto::Path {
            root: path.root,
            selectors: path.selectors,
        }),
        site: operation.site,
        line: operation.line.unwrap_or_default(),
        has_line: operation.line.is_some(),
        is_null: operation.is_null,
        access: operation.access,
        generation: operation.generation.unwrap_or_default(),
        fresh_generation: operation.fresh_generation.unwrap_or_default(),
        alternatives: operation.alternatives.into_iter().map(|effects| {
            lifetime_proto::Alternative {
                effects: effects.into_iter().map(proto_operation_message).collect(),
            }
        }).collect(),
    }
}

fn solve_proto(input: &[u8]) -> Result<LinearResult, String> {
    let request = lifetime_proto::Request::decode(input)
        .map_err(|error| format!("invalid lifetime protobuf: {error}"))?;
    let nodes = request.nodes;
    let successors = request.successors.into_iter().map(|entry| (entry.node, entry.targets)).collect();
    let operations = request.operations.into_iter().map(proto_operation).collect::<Result<Vec<_>, String>>()?;
    let mut state = State::default();
    for parameter in request.parameters {
        state.seed_parameter(Path::root(parameter.root), parameter.position);
    }
    for operation in &operations {
        for path in [operation.target.as_ref(), operation.source.as_ref()].into_iter().flatten() {
            let mut path = path.clone();
            if state.env.contains_key(&path.root) && !path.selectors.is_empty() {
                let _ = state.resolve(&mut path, true);
            }
        }
    }
    Ok(solve_graph(&nodes, &successors, &operations, state, 32))
}

fn proto_effect(effect: Effect) -> lifetime_proto::Effect {
    let value = match effect {
        Effect::Param { kind, position, selectors } => {
            lifetime_proto::effect::Value::Param(lifetime_proto::ParamEffect {
                kind: proto_kind_value(kind), position, selectors,
            })
        }
        Effect::Return { position, selectors } => {
            lifetime_proto::effect::Value::ReturnValue(lifetime_proto::ReturnEffect {
                position, selectors,
            })
        }
    };
    lifetime_proto::Effect { value: Some(value) }
}

fn proto_kind_value(kind: Kind) -> i32 {
    use lifetime_proto::operation::Kind as ProtoKind;
    match kind {
        Kind::Alloc => ProtoKind::Alloc as i32,
        Kind::Clobber => ProtoKind::Clobber as i32,
        Kind::Copy => ProtoKind::Copy as i32,
        Kind::Free => ProtoKind::Free as i32,
        Kind::Realloc => ProtoKind::Realloc as i32,
        Kind::Use => ProtoKind::Use as i32,
        Kind::Summary => ProtoKind::Summary as i32,
    }
}

fn proto_meta(meta: ObjectMeta) -> lifetime_proto::ObjectMeta {
    use lifetime_proto::object_meta::Value;
    let value = match meta {
        ObjectMeta::Param { position, selectors } => Value::Param(lifetime_proto::ParamMeta { position, selectors }),
        ObjectMeta::UnknownRoot { root } => Value::UnknownRoot(lifetime_proto::UnknownRootMeta { root }),
        ObjectMeta::UnknownSlot { base, selector } => Value::UnknownSlot(lifetime_proto::UnknownSlotMeta { base, selector }),
        ObjectMeta::Allocation { kind, generation, site, target } => Value::Allocation(lifetime_proto::AllocationMeta {
            kind: proto_kind_value(kind), generation, site,
            target: Some(lifetime_proto::Path { root: target.root, selectors: target.selectors }),
        }),
        ObjectMeta::Phi { tag, node, index } => Value::Phi(lifetime_proto::PhiMeta { tag, node, index: index as u64 }),
    };
    lifetime_proto::ObjectMeta { value: Some(value) }
}

fn proto_snapshot(snapshot: Snapshot) -> lifetime_proto::Snapshot {
    lifetime_proto::Snapshot {
        env: snapshot.env.into_iter().map(|(root, object_id)| lifetime_proto::Binding { root, object_id }).collect(),
        facts: snapshot.facts.into_iter().map(|(object_id, values)| lifetime_proto::FactSet {
            object_id,
            values: values.into_iter().map(|value| value as u32).collect(),
        }).collect(),
        slots: snapshot.slots.into_iter().map(|((base, selector), object_id)| lifetime_proto::Slot { base, selector, object_id }).collect(),
        trace: snapshot.trace.into_iter().map(proto_effect).collect(),
        freed_paths: snapshot.freed_paths.into_iter().map(|(path, object_id)| lifetime_proto::FreedPath {
            path: Some(lifetime_proto::Path { root: path.root, selectors: path.selectors }), object_id,
        }).collect(),
        objects: snapshot.objects.into_iter().map(|(id, meta)| lifetime_proto::Object { id, meta: Some(proto_meta(meta)) }).collect(),
    }
}

pub(crate) fn proto_result(result: LinearResult) -> lifetime_proto::Result {
    let states = |items: Vec<(String, Vec<Snapshot>)>| items.into_iter().map(|(node, snapshots)| {
        lifetime_proto::StateAt { node, states: snapshots.into_iter().map(proto_snapshot).collect() }
    }).collect();
    let mut findings = result.findings.double_free.into_iter().map(|(line, path, node)| {
        lifetime_proto::Finding {
            pattern: "double-free".into(),
            path: Some(lifetime_proto::Path { root: path.root, selectors: path.selectors }),
            line: line.unwrap_or_default(), has_line: line.is_some(), node,
        }
    }).collect::<Vec<_>>();
    findings.extend(result.findings.use_after_free.into_iter().map(|(line, path, node)| {
        lifetime_proto::Finding {
            pattern: "use-after-free".into(),
            path: Some(lifetime_proto::Path { root: path.root, selectors: path.selectors }),
            line: line.unwrap_or_default(), has_line: line.is_some(), node,
        }
    }));
    lifetime_proto::Result {
        point_states: states(result.point_states),
        post_states: states(result.post_states),
        exit_state: Some(proto_snapshot(result.exit_state)),
        exit_states: result.exit_states.into_iter().map(proto_snapshot).collect(),
        transfers: result.transfers,
        widenings: result.widenings,
        capped: result.capped,
        findings,
    }
}

/// Binary protobuf lifetime ABI. Both request and response stay typed binary data;
/// JSON is not involved in the internal solver boundary.
#[no_mangle]
pub extern "C" fn lachesis_lifetime_kernel_version() -> *const c_char {
    // A static NUL-terminated stamp keeps the diagnostic ABI allocation-free.
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr() as *const c_char
}

#[no_mangle]
pub unsafe extern "C" fn lachesis_lifetime_solve_pb(
    input: *const u8, length: usize, output_length: *mut usize,
) -> *mut u8 {
    let result = (|| {
        let bytes = slice::from_raw_parts(input, length);
        let mut output = Vec::new();
        proto_result(solve_proto(bytes)?).encode(&mut output)
            .map_err(|error| error.to_string())?;
        Ok::<Vec<u8>, String>(output)
    })();
    let mut payload = result.unwrap_or_else(|error| {
        // A malformed request has no normal Result representation. Return an
        // empty buffer; the caller treats zero length as an ABI error.
        eprintln!("native lifetime protobuf error: {error}");
        Vec::new()
    });
    if !output_length.is_null() {
        *output_length = payload.len();
    }
    let pointer = payload.as_mut_ptr();
    std::mem::forget(payload);
    pointer
}

#[no_mangle]
pub unsafe extern "C" fn lachesis_lifetime_free_bytes(pointer: *mut u8, length: usize) {
    if !pointer.is_null() {
        drop(Vec::from_raw_parts(pointer, length, length));
    }
}

/// Binary protobuf ABI for native CFG/operation preparation. The input is raw
/// function graph data; the output is a solver-ready function batch.
#[no_mangle]
pub unsafe extern "C" fn lachesis_lifetime_prepare_pb(
    input: *const u8, length: usize, output_length: *mut usize,
) -> *mut u8 {
    let result = (|| {
        let bytes = slice::from_raw_parts(input, length);
        prepare::solve(bytes)
    })();
    let mut payload = result.unwrap_or_else(|error| {
        eprintln!("native lifetime preparation error: {error}");
        Vec::new()
    });
    if !output_length.is_null() { *output_length = payload.len(); }
    let pointer = payload.as_mut_ptr();
    std::mem::forget(payload);
    pointer
}

/// Prepare and solve a batch without returning through Python between the two
/// native phases. Python sends raw binary graph records and receives binary
/// lifetime results only.
#[no_mangle]
pub unsafe extern "C" fn lachesis_lifetime_prepare_solve_pb(
    input: *const u8, length: usize, output_length: *mut usize,
) -> *mut u8 {
    let result = (|| {
        let bytes = slice::from_raw_parts(input, length);
        prepare::prepare_and_solve(bytes)
    })();
    let mut payload = result.unwrap_or_else(|error| {
        eprintln!("native lifetime prepare/solve error: {error}");
        Vec::new()
    });
    if !output_length.is_null() { *output_length = payload.len(); }
    let pointer = payload.as_mut_ptr();
    std::mem::forget(payload);
    pointer
}

/// Solve an already prepared binary batch. This lets one native graph preparation
/// feed both translation consumers and lifetime solving without rebuilding CFGs.
#[no_mangle]
pub unsafe extern "C" fn lachesis_lifetime_solve_prepared_pb(
    input: *const u8, length: usize, output_length: *mut usize,
) -> *mut u8 {
    let result = (|| {
        let bytes = slice::from_raw_parts(input, length);
        prepare::solve_prepared(bytes)
    })();
    let mut payload = result.unwrap_or_else(|error| {
        eprintln!("native prepared lifetime solve error: {error}");
        Vec::new()
    });
    if !output_length.is_null() { *output_length = payload.len(); }
    let pointer = payload.as_mut_ptr();
    std::mem::forget(payload);
    pointer
}

/// Read the complete framed Pass-1 substrate directly in Rust, then prepare
/// all function inputs without Python-side graph reconstruction.
#[no_mangle]
pub unsafe extern "C" fn lachesis_lifetime_prepare_graph_pb(
    input: *const u8, length: usize, output_length: *mut usize,
) -> *mut u8 {
    let result = (|| {
        let bytes = slice::from_raw_parts(input, length);
        let request = native_graph::sidecar_to_request(bytes)?;
        prepare::solve_request(request)
    })();
    let mut payload = result.unwrap_or_else(|error| {
        eprintln!("native graph preparation error: {error}");
        Vec::new()
    });
    if !output_length.is_null() { *output_length = payload.len(); }
    let pointer = payload.as_mut_ptr();
    std::mem::forget(payload);
    pointer
}

/// Read the framed substrate and return only compact native translation facts.
#[no_mangle]
pub unsafe extern "C" fn lachesis_lifetime_translate_graph_pb(
    input: *const u8, length: usize, output_length: *mut usize,
) -> *mut u8 {
    let result = (|| {
        let bytes = slice::from_raw_parts(input, length);
        native_graph::sidecar_to_translation(bytes)
    })();
    let mut payload = result.unwrap_or_else(|error| {
        eprintln!("native graph translation error: {error}");
        Vec::new()
    });
    if !output_length.is_null() { *output_length = payload.len(); }
    let pointer = payload.as_mut_ptr();
    std::mem::forget(payload);
    pointer
}

/// Path-based ABI for whole-graph Pass-2 input.  Python passes an immutable
/// filesystem path; Rust owns opening and reading the framed substrate so the
/// launcher never reconstructs or mmaps graph records.
#[no_mangle]
pub unsafe extern "C" fn lachesis_lifetime_translate_graph_path(
    input_path: *const c_char, output_length: *mut usize,
) -> *mut u8 {
    let result = (|| {
        if input_path.is_null() {
            return Err("native graph path is null".to_owned());
        }
        let path = CStr::from_ptr(input_path)
            .to_str().map_err(|error| format!("invalid native graph path: {error}"))?;
        let bytes = native_graph::map_path(path)?;
        native_graph::sidecar_to_translation(&bytes)
    })();
    let mut payload = result.unwrap_or_else(|error| {
        eprintln!("native graph path translation error: {error}");
        Vec::new()
    });
    if !output_length.is_null() { *output_length = payload.len(); }
    let pointer = payload.as_mut_ptr();
    std::mem::forget(payload);
    pointer
}

/// Translate a framed Pass-3 substrate and write the protobuf facts directly
/// to a path.  This keeps the facts artifact binary end-to-end: the Python
/// launcher supplies paths and receives only a status code.
#[no_mangle]
pub unsafe extern "C" fn lachesis_lifetime_translate_graph_write_path(
    input_path: *const c_char, output_path: *const c_char,
) -> i32 {
    let result = (|| {
        if input_path.is_null() || output_path.is_null() {
            return Err("native graph translation path is null".to_owned());
        }
        let input = CStr::from_ptr(input_path)
            .to_str().map_err(|error| format!("invalid input path: {error}"))?;
        let output = CStr::from_ptr(output_path)
            .to_str().map_err(|error| format!("invalid output path: {error}"))?;
        let bytes = native_graph::map_path(input)?;
        let payload = native_graph::sidecar_to_translation(&bytes)?;
        let output_path = std::path::Path::new(output);
        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        }
        let temporary = output_path.with_extension(format!(
            "{}.tmp-{}", output_path.extension().and_then(|value| value.to_str()).unwrap_or("pb"),
            std::process::id(),
        ));
        fs::write(&temporary, payload).map_err(|error| error.to_string())?;
        fs::rename(&temporary, output_path).map_err(|error| error.to_string())?;
        Ok::<(), String>(())
    })();
    match result {
        Ok(()) => 0,
        Err(error) => { eprintln!("native graph translation write error: {error}"); 1 }
    }
}

/// Path-based ABI for whole-graph preparation.  The substrate is opened only
/// by Rust and the prepared protobuf is returned through the existing allocator
/// contract until the complete sidecar-writing engine replaces this boundary.
#[no_mangle]
pub unsafe extern "C" fn lachesis_lifetime_prepare_graph_path(
    input_path: *const c_char, output_length: *mut usize,
) -> *mut u8 {
    let result = (|| {
        if input_path.is_null() {
            return Err("native graph path is null".to_owned());
        }
        let path = CStr::from_ptr(input_path)
            .to_str().map_err(|error| format!("invalid native graph path: {error}"))?;
        let bytes = native_graph::map_path(path)?;
        let request = native_graph::sidecar_to_request(&bytes)?;
        prepare::solve_request(request)
    })();
    let mut payload = result.unwrap_or_else(|error| {
        eprintln!("native graph path preparation error: {error}");
        Vec::new()
    });
    if !output_length.is_null() { *output_length = payload.len(); }
    let pointer = payload.as_mut_ptr();
    std::mem::forget(payload);
    pointer
}

/// Native control-flow overlay endpoint.  It consumes the complete Pass-2
/// input path and returns an additive protobuf delta; the final Pass-2 runner
/// will chain this delta with the remaining native overlays before publishing
/// the sidecar.
#[no_mangle]
pub unsafe extern "C" fn lachesis_pass2_control_flow_path(
    input_path: *const c_char, output_length: *mut usize,
) -> *mut u8 {
    let result = (|| {
        if input_path.is_null() {
            return Err("native graph path is null".to_owned());
        }
        let path = CStr::from_ptr(input_path)
            .to_str().map_err(|error| format!("invalid native graph path: {error}"))?;
        let graph = pass2::read_path(path)?;
        let delta = control_flow::enrich(&graph);
        let mut output = Vec::new();
        graph_proto::DataflowOverlay {
            overlay_id: "control-flow".to_owned(),
            source: path.to_owned(),
            version: 1,
            core_content_hash: String::new(),
            derived_nodes: delta.nodes,
            derived_edges: delta.edges,
        }.encode(&mut output).map_err(|error| error.to_string())?;
        Ok::<Vec<u8>, String>(output)
    })();
    let mut payload = result.unwrap_or_else(|error| {
        eprintln!("native control-flow error: {error}");
        Vec::new()
    });
    if !output_length.is_null() { *output_length = payload.len(); }
    let pointer = payload.as_mut_ptr();
    std::mem::forget(payload);
    pointer
}

/// Run the complete native Pass-2 overlay chain from a framed Pass-1 input
/// sidecar and publish the additive dataflow sidecar.  The ABI deliberately
/// returns only a status code: no graph records cross into Python.
///
/// Return value: 0 on success, 1 on invalid/null paths or a native failure.
#[no_mangle]
pub unsafe extern "C" fn lachesis_pass2_run_path(
    input_path: *const c_char, catalog_path: *const c_char, output_path: *const c_char,
) -> i32 {
    let result = (|| {
        if input_path.is_null() || output_path.is_null() {
            return Err("native Pass-2 path is null".to_owned());
        }
        let input = CStr::from_ptr(input_path)
            .to_str().map_err(|error| format!("invalid native Pass-2 input path: {error}"))?;
        let output = CStr::from_ptr(output_path)
            .to_str().map_err(|error| format!("invalid native Pass-2 output path: {error}"))?;
        let catalog = if catalog_path.is_null() { None } else {
            Some(CStr::from_ptr(catalog_path).to_str()
                .map_err(|error| format!("invalid Atropos catalog path: {error}"))?.to_owned())
        };
        run_native_overlay_chain(std::path::Path::new(input),
            catalog.as_deref().map(std::path::Path::new), std::path::Path::new(output))
            .map(|(nodes, edges)| {
                eprintln!("[lachesis native pass2] published {nodes} nodes and {edges} edges");
            })
    })();
    match result {
        Ok(()) => 0,
        Err(error) => { eprintln!("native Pass-2 error: {error}"); 1 }
    }
}

/// Project one native Pass-1 shard into the complete Pass-2 input and compact
/// Pass-3 substrate.  Only paths and scalar metadata cross the ABI; Rust owns
/// protobuf decoding, filtering, framing, and atomic publication.
#[no_mangle]
pub unsafe extern "C" fn lachesis_pass1_project_shard(
    nodes_path: *const c_char,
    edges_path: *const c_char,
    pass2_output: *const c_char,
    pass3_output: *const c_char,
    store_version: *const c_char,
    core_content_hash: *const c_char,
    source_content_hash: *const c_char,
    build_fingerprint: *const c_char,
    prune: i32,
) -> i32 {
    let result = (|| {
        let paths = [nodes_path, edges_path, pass2_output, pass3_output]
            .into_iter().map(|path| {
                if path.is_null() { return Err("native Pass-1 projector path is null".to_owned()); }
                CStr::from_ptr(path).to_str()
                    .map(|value| value.to_owned())
                    .map_err(|error| format!("invalid native Pass-1 projector path: {error}"))
            }).collect::<Result<Vec<_>, _>>()?;
        let metadata = [store_version, core_content_hash, source_content_hash, build_fingerprint]
            .into_iter().map(|path| {
                if path.is_null() { return Ok(String::new()); }
                CStr::from_ptr(path).to_str()
                    .map(|value| value.to_owned())
                    .map_err(|error| format!("invalid native Pass-1 metadata: {error}"))
            }).collect::<Result<Vec<_>, String>>()?;
        sidecar_project::project_shard(
            std::path::Path::new(&paths[0]), std::path::Path::new(&paths[1]),
            std::path::Path::new(&paths[2]), std::path::Path::new(&paths[3]),
            &metadata[0], &metadata[1], &metadata[2], &metadata[3], prune != 0,
        )
    })();
    match result {
        Ok(()) => 0,
        Err(error) => { eprintln!("native Pass-1 projector error: {error}"); 1 }
    }
}

/// Project several language frontend shards together.  Rust first collects
/// retained node IDs across all shards, then streams every edge shard, so
/// cross-language edges are preserved without a Python graph reconstruction.
#[no_mangle]
pub unsafe extern "C" fn lachesis_pass1_project_shards(
    shard_set_path: *const c_char,
    pass2_output: *const c_char,
    pass3_output: *const c_char,
    store_version: *const c_char,
    core_content_hash: *const c_char,
    source_content_hash: *const c_char,
    build_fingerprint: *const c_char,
    prune: i32,
) -> i32 {
    let result = (|| {
        let paths = [shard_set_path, pass2_output, pass3_output]
            .into_iter().map(|path| {
                if path.is_null() { return Err("native Pass-1 shard-set path is null".to_owned()); }
                CStr::from_ptr(path).to_str()
                    .map(|value| value.to_owned())
                    .map_err(|error| format!("invalid native Pass-1 shard-set path: {error}"))
            }).collect::<Result<Vec<_>, _>>()?;
        let metadata = [store_version, core_content_hash, source_content_hash, build_fingerprint]
            .into_iter().map(|path| {
                if path.is_null() { return Ok(String::new()); }
                CStr::from_ptr(path).to_str()
                    .map(|value| value.to_owned())
                    .map_err(|error| format!("invalid native Pass-1 metadata: {error}"))
            }).collect::<Result<Vec<_>, String>>()?;
        let request = graph_proto::NativeShardSet::decode(
            fs::read(&paths[0]).map_err(|error| format!("cannot read native shard set: {error}"))?
                .as_slice(),
        ).map_err(|error| format!("invalid native shard set: {error}"))?;
        if request.shards.is_empty() {
            return Err("native Pass-1 shard set is empty".to_owned());
        }
        let shard_paths = request.shards.into_iter().map(|shard| {
            if shard.nodes_path.is_empty() || shard.edges_path.is_empty() {
                return Err("native Pass-1 shard has an empty record path".to_owned());
            }
            Ok((std::path::PathBuf::from(shard.nodes_path),
                std::path::PathBuf::from(shard.edges_path)))
        }).collect::<Result<Vec<_>, String>>()?;
        sidecar_project::project_shards(
            &shard_paths, std::path::Path::new(&paths[1]),
            std::path::Path::new(&paths[2]), &metadata[0], &metadata[1],
            &metadata[2], &metadata[3], prune != 0,
        )
    })();
    match result {
        Ok(()) => 0,
        Err(error) => { eprintln!("native Pass-1 shard-set projector error: {error}"); 1 }
    }
}

/// Scan a framed Pass-1 substrate and bind the Atropos catalog entirely in
/// Rust. The report is written as protobuf to `output_path`; no graph or report
/// payload crosses the Python ABI.
#[no_mangle]
pub unsafe extern "C" fn lachesis_atropos_bind_path(
    input_path: *const c_char, catalog_path: *const c_char, output_path: *const c_char,
) -> i32 {
    let result = (|| {
        if input_path.is_null() || catalog_path.is_null() || output_path.is_null() {
            return Err("native Atropos bind path is null".to_owned());
        }
        let input = CStr::from_ptr(input_path).to_str()
            .map_err(|error| format!("invalid input path: {error}"))?;
        let catalog = CStr::from_ptr(catalog_path).to_str()
            .map_err(|error| format!("invalid catalog path: {error}"))?;
        let output = CStr::from_ptr(output_path).to_str()
            .map_err(|error| format!("invalid output path: {error}"))?;
        atropos_bind::bind_path(std::path::Path::new(input), std::path::Path::new(catalog),
                                std::path::Path::new(output))
    })();
    match result {
        Ok(()) => 0,
        Err(error) => { eprintln!("native Atropos path bind error: {error}"); 1 }
    }
}

/// Run native source discovery and coverage planning from binary sidecars.
/// The catalog file is the compiled Atropos `Request` protobuf; only source
/// entries are projected into the planner's compact input in Rust.
#[no_mangle]
pub unsafe extern "C" fn lachesis_lifetime_plan_path(
    facts_path: *const c_char, catalog_path: *const c_char, output_path: *const c_char,
) -> i32 {
    let result = (|| {
        if facts_path.is_null() || catalog_path.is_null() || output_path.is_null() {
            return Err("native planner path is null".to_owned());
        }
        let facts = CStr::from_ptr(facts_path).to_str()
            .map_err(|error| format!("invalid facts path: {error}"))?;
        let catalog = CStr::from_ptr(catalog_path).to_str()
            .map_err(|error| format!("invalid catalog path: {error}"))?;
        let output = CStr::from_ptr(output_path).to_str()
            .map_err(|error| format!("invalid output path: {error}"))?;
        let translation = lifetime_proto::TranslationResult::decode(
            fs::read(facts).map_err(|error| format!("cannot read translation facts: {error}"))?.as_slice()
        ).map_err(|error| format!("invalid translation facts: {error}"))?;
        let catalog_request = atropos_proto::Request::decode(
            fs::read(catalog).map_err(|error| format!("cannot read binary catalog: {error}"))?.as_slice()
        ).map_err(|error| format!("invalid binary catalog: {error}"))?;
        let source_entries = catalog_request.models.into_iter()
            .filter(|model| model.role == "source")
            .map(|model| lifetime_proto::SourceCatalogEntry {
                name: if model.package.is_empty() || model.package == "builtins" {
                    model.method
                } else {
                    format!("{}.{}", model.package, model.method)
                },
                kind: model.role,
            }).collect();
        let request = lifetime_proto::NativePlanRequest {
            translation: Some(translation), sources: source_entries,
        };
        let result = planner::plan(request);
        let mut bytes = Vec::new();
        result.encode(&mut bytes).map_err(|error| format!("cannot encode plan: {error}"))?;
        let temporary = format!("{output}.tmp.{}", std::process::id());
        fs::write(&temporary, bytes).map_err(|error| format!("cannot write plan: {error}"))?;
        fs::rename(&temporary, output).map_err(|error| format!("cannot publish plan: {error}"))?;
        Ok::<(), String>(())
    })();
    match result {
        Ok(()) => 0,
        Err(error) => { eprintln!("native planner path error: {error}"); 1 }
    }
}

/// Compose reach-only interprocedural summaries from binary translation facts.
/// The result is a compact protobuf sidecar; no Python F records are created.
#[no_mangle]
pub unsafe extern "C" fn lachesis_lifetime_summaries_path(
    facts_path: *const c_char, catalog_path: *const c_char, output_path: *const c_char,
) -> i32 {
    let result = (|| {
        if facts_path.is_null() || catalog_path.is_null() || output_path.is_null() {
            return Err("native summary path is null".to_owned());
        }
        let facts = CStr::from_ptr(facts_path).to_str()
            .map_err(|error| format!("invalid facts path: {error}"))?;
        let catalog = CStr::from_ptr(catalog_path).to_str()
            .map_err(|error| format!("invalid catalog path: {error}"))?;
        let output = CStr::from_ptr(output_path).to_str()
            .map_err(|error| format!("invalid output path: {error}"))?;
        let mut translation = lifetime_proto::TranslationResult::decode(
            fs::read(facts).map_err(|error| format!("cannot read translation facts: {error}"))?.as_slice()
        ).map_err(|error| format!("invalid translation facts: {error}"))?;
        let catalog = atropos_proto::Request::decode(
            fs::read(catalog).map_err(|error| format!("cannot read binary catalog: {error}"))?.as_slice()
        ).map_err(|error| format!("invalid binary catalog: {error}"))?;
        native_graph::annotate_translation_roles(&mut translation, &catalog);
        let result = summary::summarize(translation, catalog);
        let mut bytes = Vec::new();
        result.encode(&mut bytes).map_err(|error| format!("cannot encode summaries: {error}"))?;
        let temporary = format!("{output}.tmp.{}", std::process::id());
        fs::write(&temporary, bytes).map_err(|error| format!("cannot write summaries: {error}"))?;
        fs::rename(&temporary, output).map_err(|error| format!("cannot publish summaries: {error}"))?;
        Ok::<(), String>(())
    })();
    match result {
        Ok(()) => 0,
        Err(error) => { eprintln!("native summary path error: {error}"); 1 }
    }
}

/// Build a compact Rust-owned semantic event graph from the framed substrate.
/// Only event nodes and control-flow edges are written to the output sidecar.
#[no_mangle]
pub unsafe extern "C" fn lachesis_lifetime_semantic_path(
    input_path: *const c_char, catalog_path: *const c_char, output_path: *const c_char,
) -> i32 {
    let result = (|| {
        let timing_enabled = std::env::var("LACHESIS_TIMINGS").ok().as_deref() == Some("1");
        let semantic_started = std::time::Instant::now();
        if input_path.is_null() || output_path.is_null() {
            return Err("native semantic path is null".to_owned());
        }
        let input = CStr::from_ptr(input_path).to_str()
            .map_err(|error| format!("invalid semantic input path: {error}"))?;
        let output = CStr::from_ptr(output_path).to_str()
            .map_err(|error| format!("invalid semantic output path: {error}"))?;
        let bytes = native_graph::map_path(input)?;
        let catalog = if catalog_path.is_null() {
            None
        } else {
            let catalog = CStr::from_ptr(catalog_path).to_str()
                .map_err(|error| format!("invalid lifecycle catalog path: {error}"))?;
            Some(atropos_proto::Request::decode(
                fs::read(catalog)
                    .map_err(|error| format!("cannot read binary lifecycle catalog: {error}"))?
                    .as_slice(),
            ).map_err(|error| format!("invalid binary lifecycle catalog: {error}"))?)
        };
        let request = match catalog.as_ref() {
            Some(catalog) => native_graph::sidecar_to_request_with_catalog(&bytes, catalog)?,
            None => native_graph::sidecar_to_request(&bytes)?,
        };
        report_native_phase(timing_enabled, semantic_started, "semantic translation", 0, 0);
        // Pass 2 publishes taint witnesses in the sibling binary overlay.  Use
        // the same graph path convention as the Python store, but keep the
        // lookup and decoding native so semantic findings receive computed
        // provenance without rebuilding Python graph objects.
        let source_evidence = input.strip_suffix(".pass2.input.pb")
            .map(|base| format!("{base}.dataflow.pb"))
            .filter(|path| std::path::Path::new(path).is_file())
            .map(pass2::read_taint_evidence_path)
            .transpose()?;
        let mut full = prepare::semantic_request(request)?;
        report_native_phase(timing_enabled, semantic_started, "semantic prepare", full.functions.len(), full.seams.len());
        if let Some(source_evidence) = source_evidence.as_ref() {
            for function in &mut full.functions {
                for node in &mut function.nodes {
                    if let Some(witness) = source_evidence.witnesses.get(&node.anchor) {
                        node.source_witness_nodes = witness.clone();
                        node.source_reachable = Some(true);
                    } else if !source_evidence.truncated
                        && source_evidence.observed_sinks.contains(&node.anchor) {
                        node.source_reachable = Some(false);
                    }
                }
            }
        }
        // Match the old Python Pass-3 production flow: reach skeletons are
        // emitted once per native summary flow, while typestate skeletons are
        // emitted for each lifecycle stream.  The region-wide structural
        // Claus renderer is retained as a diagnostic helper, but must not be
        // mixed into the production result because it changes the skeleton
        // set and therefore matcher output.
        full.regions = claus::pick_regions(&full);
        full.skeletons = skeleton::build(&full);
        report_native_phase(timing_enabled, semantic_started, "claus skeleton", full.regions.len(), full.skeletons.len());
        if let Some(catalog) = catalog.as_ref() {
            let translation_bytes = if let Some(path) = input.strip_suffix(".pass2.input.pb")
                .map(|base| format!("{base}.pass2.translation.pb"))
                .filter(|path| std::path::Path::new(path).is_file()) {
                fs::read(path)
                    .map_err(|error| format!("cannot read native translation facts: {error}"))?
            } else {
                native_graph::sidecar_to_translation(&bytes)?
            };
            let mut translation = lifetime_proto::TranslationResult::decode(
                translation_bytes.as_slice(),
            ).map_err(|error| format!("invalid native translation facts: {error}"))?;
            native_graph::annotate_translation_roles(&mut translation, catalog);
            let summaries = summary::summarize_with_evidence(
                translation.clone(), catalog.clone(),
                source_evidence.as_ref().map(|evidence| &evidence.witnesses));
            if !summaries.complete { full.complete = false; }
            full.skeletons.extend(reach::build_sink_graphs(
                &full, &translation, &summaries, catalog));
            full.skeletons.extend(reach::build(&translation, &summaries, catalog));
            if !summaries.complete {
                for skeleton in &mut full.skeletons {
                    skeleton.complete = false;
                }
            }
            report_native_phase(timing_enabled, semantic_started, "reach summaries", summaries.functions.len(), full.skeletons.len());
        }
        // Temporal candidate enumeration only needs operation-derived event
        // nodes. Publish that compact view beside the full semantic graph so
        // Python queries never parse the large anchor/control-flow payload.
        let result = full.encode_to_vec();
        report_native_phase(timing_enabled, semantic_started, "semantic serialize", 0, result.len());
        let temporary = format!("{output}.tmp.{}", std::process::id());
        fs::write(&temporary, &result)
            .map_err(|error| format!("cannot write semantic result: {error}"))?;
        fs::rename(&temporary, output)
            .map_err(|error| format!("cannot publish semantic result: {error}"))?;
        // The full sidecar is already durable. Release its encoded byte
        // buffer before building the compact event projection so peak memory
        // is not graph + full bytes + event bytes at once.
        drop(result);
        let events = lifetime_proto::NativeSemanticResult {
            functions: full.functions.into_iter()
                .filter_map(compact_event_function).collect(),
            complete: full.complete,
            seams: full.seams,
            regions: full.regions,
            skeletons: full.skeletons,
        }.encode_to_vec();
        let events_output = format!("{output}.events.pb");
        let events_temporary = format!("{events_output}.tmp.{}", std::process::id());
        fs::write(&events_temporary, events)
            .map_err(|error| format!("cannot write semantic events: {error}"))?;
        fs::rename(&events_temporary, events_output)
            .map_err(|error| format!("cannot publish semantic events: {error}"))?;
        Ok::<(), String>(())
    })();
    match result {
        Ok(()) => 0,
        Err(error) => { eprintln!("native semantic path error: {error}"); 1 }
    }
}

/// Match the compact native semantic sidecar and publish final temporal leads.
/// The input and output are protobuf files; no graph or JSON representation is
/// reconstructed by the Python boundary.
#[no_mangle]
pub unsafe extern "C" fn lachesis_lifetime_match_semantic_path(
    input_path: *const c_char, output_path: *const c_char,
    catalog_path: *const c_char,
) -> i32 {
    let result = (|| {
        if input_path.is_null() || output_path.is_null() {
            return Err("native semantic matcher path is null".to_owned());
        }
        let input = CStr::from_ptr(input_path).to_str()
            .map_err(|error| format!("invalid semantic matcher input path: {error}"))?;
        let output = CStr::from_ptr(output_path).to_str()
            .map_err(|error| format!("invalid semantic matcher output path: {error}"))?;
        let catalog = if catalog_path.is_null() {
            None
        } else {
            let path = CStr::from_ptr(catalog_path).to_str()
                .map_err(|error| format!("invalid binary pattern catalog path: {error}"))?;
            atropos_proto::Request::decode(
                fs::read(path)
                    .map_err(|error| format!("cannot read binary pattern catalog: {error}"))?
                    .as_slice(),
            ).map_err(|error| format!("invalid binary pattern catalog: {error}"))?.pattern_catalog
        };
        let mapped = native_graph::map_path(input)?;
        let result = lifetime_proto::NativeSemanticResult::decode(mapped.as_ref())
            .map_err(|error| format!("invalid semantic sidecar: {error}"))?;
        let matched = semantic_match::match_result_with_catalog(result, catalog.as_ref())
            .encode_to_vec();
        let temporary = format!("{output}.tmp.{}", std::process::id());
        fs::write(&temporary, matched)
            .map_err(|error| format!("cannot write native match result: {error}"))?;
        fs::rename(&temporary, output)
            .map_err(|error| format!("cannot publish native match result: {error}"))?;
        Ok::<(), String>(())
    })();
    match result {
        Ok(()) => 0,
        Err(error) => { eprintln!("native semantic matcher error: {error}"); 1 }
    }
}

/// Plan source launches, formal/actual seams, and coverage regions directly
/// from compact translation facts and catalog entries.
#[no_mangle]
pub unsafe extern "C" fn lachesis_lifetime_plan_pb(
    input: *const u8, length: usize, output_length: *mut usize,
) -> *mut u8 {
    let result = (|| {
        let bytes = slice::from_raw_parts(input, length);
        let request = lifetime_proto::NativePlanRequest::decode(bytes)
            .map_err(|error| format!("invalid native plan protobuf: {error}"))?;
        let mut output = Vec::new();
        planner::plan(request).encode(&mut output)
            .map_err(|error| error.to_string())?;
        Ok::<Vec<u8>, String>(output)
    })();
    let mut payload = result.unwrap_or_else(|error| {
        eprintln!("native Pass-2 planning error: {error}");
        Vec::new()
    });
    if !output_length.is_null() { *output_length = payload.len(); }
    let pointer = payload.as_mut_ptr();
    std::mem::forget(payload);
    pointer
}

/// Read the complete framed substrate and run native preparation plus solving
/// without returning through Python between the two phases.
#[no_mangle]
pub unsafe extern "C" fn lachesis_lifetime_prepare_graph_solve_pb(
    input: *const u8, length: usize, output_length: *mut usize,
) -> *mut u8 {
    let result = (|| {
        let bytes = slice::from_raw_parts(input, length);
        let request = native_graph::sidecar_to_request(bytes)?;
        prepare::prepare_and_solve_request(request)
    })();
    let mut payload = result.unwrap_or_else(|error| {
        eprintln!("native whole-graph prepare/solve error: {error}");
        Vec::new()
    });
    if !output_length.is_null() { *output_length = payload.len(); }
    let pointer = payload.as_mut_ptr();
    std::mem::forget(payload);
    pointer
}

/// Read the framed substrate in Rust, retain only the function IDs in the
/// binary selection request, and return prepared metadata plus lifetime
/// results for that slice. This avoids materializing the whole prepared graph
/// in Python when Pass 3 requests a small set of functions.
#[no_mangle]
pub unsafe extern "C" fn lachesis_lifetime_prepare_graph_solve_selected_pb(
    input: *const u8, length: usize,
    selection: *const u8, selection_length: usize,
    output_length: *mut usize,
) -> *mut u8 {
    let result = (|| {
        let bytes = slice::from_raw_parts(input, length);
        let selected_bytes = slice::from_raw_parts(selection, selection_length);
        let selected = lifetime_proto::PrepareRequest::decode(selected_bytes)
            .map_err(|error| format!("invalid lifetime selection protobuf: {error}"))?;
        let selected_ids: HashSet<String> = selected.functions.into_iter()
            .map(|function| function.id)
            .collect();
        let request = native_graph::sidecar_to_request_selected(bytes, &selected_ids)?;
        prepare::prepare_and_solve_request_with_metadata(request)
    })();
    let mut payload = result.unwrap_or_else(|error| {
        eprintln!("native selected graph prepare/solve error: {error}");
        Vec::new()
    });
    if !output_length.is_null() { *output_length = payload.len(); }
    let pointer = payload.as_mut_ptr();
    std::mem::forget(payload);
    pointer
}

/// Prepare only the selected function slice.  This diagnostic/production
/// boundary keeps graph preparation measurable independently from fixpoint
/// solving and avoids retaining unselected edges.
#[no_mangle]
pub unsafe extern "C" fn lachesis_lifetime_prepare_graph_selected_pb(
    input: *const u8, length: usize,
    selection: *const u8, selection_length: usize,
    output_length: *mut usize,
) -> *mut u8 {
    let result = (|| {
        let bytes = slice::from_raw_parts(input, length);
        let selected_bytes = slice::from_raw_parts(selection, selection_length);
        let selected = lifetime_proto::PrepareRequest::decode(selected_bytes)
            .map_err(|error| format!("invalid lifetime selection protobuf: {error}"))?;
        let selected_ids: HashSet<String> = selected.functions.into_iter()
            .map(|function| function.id)
            .collect();
        let request = native_graph::sidecar_to_request_selected(bytes, &selected_ids)?;
        prepare::solve_request(request)
    })();
    let mut payload = result.unwrap_or_else(|error| {
        eprintln!("native selected graph preparation error: {error}");
        Vec::new()
    });
    if !output_length.is_null() { *output_length = payload.len(); }
    let pointer = payload.as_mut_ptr();
    std::mem::forget(payload);
    pointer
}

impl Operation {
    fn access_is_return(&self) -> bool { self.access == "return" }
}

fn deduplicate_shared(states: Vec<Arc<State>>) -> Vec<Arc<State>> {
    let mut unique: Vec<Arc<State>> = Vec::with_capacity(states.len());
    let mut buckets: HashMap<u64, Vec<usize>> = HashMap::new();
    for state in states {
        let fingerprint = state_fingerprint(state.as_ref());
        let duplicate = buckets.get(&fingerprint).into_iter().flatten().any(|index| {
            unique[*index].as_ref().semantically_equal(state.as_ref())
        });
        if !duplicate {
            let index = unique.len();
            unique.push(state);
            buckets.entry(fingerprint).or_default().push(index);
        }
    }
    unique
}

/// Hash exactly the fields used by `semantically_equal`.  The hash is computed
/// once per post-transfer deduplication batch, never after each operation.  A
/// bucket still performs the exact equality check, so this is an optimization
/// only and cannot alter abstract-state semantics.
fn state_fingerprint(state: &State) -> u64 {
    let mut hasher = FxHasher::default();
    let mut env: Vec<_> = state.env.iter().collect();
    env.sort_by(|left, right| left.0.cmp(right.0));
    env.hash(&mut hasher);
    let mut facts: Vec<_> = state.facts.iter().map(|(object, values)| (object, values)).collect();
    facts.sort_by(|left, right| left.0.cmp(right.0));
    facts.hash(&mut hasher);
    let mut slots: Vec<_> = state.slots.iter().collect();
    slots.sort_by(|left, right| left.0.cmp(right.0));
    slots.hash(&mut hasher);
    state.trace.hash(&mut hasher);
    let mut freed: Vec<_> = state.freed_paths.iter().collect();
    freed.sort_by(|left, right| path_name(left.0).cmp(&path_name(right.0)));
    freed.hash(&mut hasher);
    hasher.finish()
}

fn attach_joined(states: &[State], node: &str, new_oid: String,
                 signature: Vec<Option<String>>, joined: &mut State,
                 queued: &mut Vec<(String, Vec<Option<String>>)>) {
    let mut facts = 0u8;
    for (state, old_oid) in states.iter().zip(signature.iter()) {
        if let Some(old_oid) = old_oid {
            facts |= state.facts.get(old_oid).copied()
                .unwrap_or_else(|| fact_bit(Fact::Unknown));
        } else {
            facts |= fact_bit(Fact::Unknown);
        }
    }
    joined.facts.insert(new_oid.clone(), facts);
    let tag = new_oid.split('|').nth(1).unwrap_or("phi").to_string();
    joined.objects.insert(new_oid.clone(), ObjectMeta::Phi {
        tag, node: node.into(), index: 0,
    });
    queued.push((new_oid, signature));
}

fn join_states(states: &[State], node: &str) -> State {
    assert!(!states.is_empty());
    if states.len() == 1 {
        return states[0].clone();
    }
    let mut joined = State::default();
    let mut roots: Vec<String> = states.iter()
        .flat_map(|state| state.env.keys().cloned())
        .collect();
    roots.sort();
    roots.dedup();
    let mut signatures: HashMap<(String, Vec<Option<String>>), String> = HashMap::new();
    let mut queued: Vec<(String, Vec<Option<String>>)> = Vec::new();
    let mut seen = HashSet::new();
    let mut phi_index = 0usize;

    let mut object_for = |tag: &str, signature: &[Option<String>]| -> String {
        if signature.first().is_some_and(|first| first.is_some())
            && signature.iter().all(|item| item.as_ref() == signature[0].as_ref())
        {
            return signature[0].clone().unwrap();
        }
        let key = (tag.to_owned(), signature.to_vec());
        if let Some(existing) = signatures.get(&key) {
            return existing.clone();
        }
        // Keep the merge node in the synthetic identity, matching the Python
        // domain's (tag, node, ordinal) phi key.  Omitting it aliases unrelated
        // joins and causes later loop signatures to churn instead of converging.
        let value = format!("phi|{}|{}|{}", tag, node, phi_index);
        phi_index += 1;
        signatures.insert(key, value.clone());
        value
    };

    for root in roots {
        let signature: Vec<_> = states.iter().map(|state| state.env.get(&root).cloned()).collect();
        let oid = object_for("phi", &signature);
        joined.env.insert(root, oid.clone());
        if seen.insert(oid.clone()) {
            attach_joined(states, node, oid, signature, &mut joined, &mut queued);
        }
    }

    while let Some((new_base, old_bases)) = queued.pop() {
        let mut selectors: Vec<String> = states.iter().zip(old_bases.iter())
            .flat_map(|(state, old_base)| state.slots.keys()
                .filter(move |(base, _)| Some(base) == old_base.as_ref())
                .map(|(_, selector)| selector.clone()))
            .collect();
        selectors.sort();
        selectors.dedup();
        for selector in selectors {
            let signature: Vec<_> = states.iter().zip(old_bases.iter())
                .map(|(state, old_base)| old_base.as_ref()
                    .and_then(|base| state.slots.get(&(base.clone(), selector.clone())).cloned()))
                .collect();
            let child = object_for("phi-slot", &signature);
            joined.slots.insert((new_base.clone(), selector), child.clone());
            if seen.insert(child.clone()) {
                attach_joined(states, node, child, signature, &mut joined, &mut queued);
            }
        }
    }

    for state in states {
        for effect in &state.trace {
            if joined.trace.iter().filter(|item| *item == effect).count() < 2
                && joined.trace.len() < 16
            {
                joined.trace.push(effect.clone());
            }
        }
        for (path, oid) in &state.freed_paths {
            joined.freed_paths.entry(path.clone()).or_insert_with(|| oid.clone());
        }
    }
    joined
}

/// Widen with identities independent of the incoming path signature.  Once a
/// loop has exceeded the disjunct budget, retaining the full signature creates
/// a fresh phi/object graph on every revisit.  Stable identities turn this into
/// a finite may-state while preserving the union of all object facts.
fn stable_join_states(states: &[State], node: &str) -> State {
    assert!(!states.is_empty());
    let mut joined = State::default();
    let mut roots: Vec<String> = states.iter()
        .flat_map(|state| state.env.keys().cloned())
        .collect();
    roots.sort();
    roots.dedup();
    let mut maps = Vec::with_capacity(states.len());
    let mut slots_by_base = Vec::with_capacity(states.len());
    let mut pending = Vec::new();

    for (index, state) in states.iter().enumerate() {
        let mut map = HashMap::new();
        for root in &roots {
            if let Some(old) = state.env.get(root) {
                let candidate = format!("phi|stable|{}|root|{}", node, root);
                let stable = map.entry(old.clone()).or_insert_with(|| {
                    pending.push((index, old.clone(), candidate.clone()));
                    candidate
                }).clone();
                joined.env.insert(root.clone(), stable);
            }
        }
        let mut by_base: HashMap<String, Vec<(String, String)>> = HashMap::new();
        for ((base, selector), child) in &state.slots {
            by_base.entry(base.clone()).or_default()
                .push((selector.clone(), child.clone()));
        }
        slots_by_base.push(by_base);
        maps.push(map);
    }
    while let Some((index, old_base, stable_base)) = pending.pop() {
        let Some(entries) = slots_by_base[index].get(&old_base) else { continue };
        for (selector, old_child) in entries {
            let stable_child = format!("{}|slot|{}", stable_base, selector);
            let map = &mut maps[index];
            let child = map.entry(old_child.clone()).or_insert_with(|| {
                pending.push((index, old_child.clone(), stable_child.clone()));
                stable_child
            }).clone();
            joined.slots.insert((stable_base.clone(), selector.clone()), child);
        }
    }
    for (index, state) in states.iter().enumerate() {
        for (old, stable) in &maps[index] {
            *joined.facts.entry(stable.clone()).or_default() |=
                state.facts.get(old).copied().unwrap_or_default();
            joined.objects.entry(stable.clone()).or_insert_with(|| ObjectMeta::Phi {
                tag: "stable".into(), node: node.into(), index: 0,
            });
        }
        for effect in &state.trace {
            if joined.trace.iter().filter(|item| *item == effect).count() < 2
                && joined.trace.len() < 16 {
                joined.trace.push(effect.clone());
            }
        }
        for (path, old) in &state.freed_paths {
            if let Some(stable) = maps[index].get(old) {
                joined.freed_paths.entry(path.clone()).or_insert_with(|| stable.clone());
            }
        }
    }
    joined
}

/// Execute the non-SUMMARY fixpoint subset.  This mirrors Python's worklist shape:
/// states are deduplicated at each transfer, joins become sticky after the disjunct
/// budget is exceeded, and snapshots are retained for the semantic emitter.
pub fn solve_graph(nodes: &[String], successors: &HashMap<String, Vec<String>>,
                   operations: &[Operation], initial: State,
                   max_disjuncts: usize) -> LinearResult {
    solve_graph_mode(nodes, successors, operations, initial, max_disjuncts, true)
}

/// Graph lifetime solving without retaining semantic snapshots.  The worklist
/// still computes the same abstract states and findings; only the projection
/// needed by the Python semantic emitter is omitted.
pub fn solve_graph_findings(nodes: &[String], successors: &HashMap<String, Vec<String>>,
                            operations: &[Operation], initial: State,
                            max_disjuncts: usize) -> LinearResult {
    solve_graph_mode(nodes, successors, operations, initial, max_disjuncts, false)
}

fn solve_graph_mode(nodes: &[String], successors: &HashMap<String, Vec<String>>,
                    operations: &[Operation], initial: State,
                    max_disjuncts: usize, retain_snapshots: bool) -> LinearResult {
    let mut at: HashMap<String, Vec<Operation>> = HashMap::new();
    for operation in operations {
        at.entry(operation.node.clone()).or_default().push(operation.clone());
    }
    for placed in at.values_mut() {
        // The Python side has already ordered operations, but preserve the contract if
        // the native API is called directly.
        placed.sort_by_key(|operation| operation.line.unwrap_or(0));
    }
    // State transfer still walks every CFG node, but only operation points,
    // the entry, and exits are observed by the semantic emitter.  Avoid
    // cloning/snapshotting large abstract states at every no-op CFG node.
    let mut tracked_nodes: HashSet<String> = at.keys().cloned().collect();
    if let Some(first) = nodes.first() {
        tracked_nodes.insert(first.clone());
    }
    tracked_nodes.extend(nodes.iter().filter(|node| {
        successors.get(*node).is_some_and(Vec::is_empty)
    }).cloned());
    let mut incoming: HashMap<String, Vec<Arc<State>>> = nodes.iter()
        .map(|node| (node.clone(), Vec::new()))
        .collect();
    if let Some(first) = nodes.first() {
        incoming.insert(first.clone(), vec![Arc::new(initial)]);
    }
    let mut point_snapshots: HashMap<String, Vec<Snapshot>> = HashMap::new();
    let mut post_snapshots: HashMap<String, Vec<Snapshot>> = HashMap::new();
    let mut exit_snapshots: Vec<Snapshot> = Vec::new();
    let mut queue = VecDeque::new();
    let mut queued = HashSet::new();
    let mut widened = HashSet::new();
    // Widening is part of the native production solver.  Stable identities
    // prevent recursive alias/phi graphs from allocating a fresh object graph
    // on every loop revisit while retaining the joined may-facts.
    let stable_widen = true;
    if let Some(first) = nodes.first() {
        queue.push_back(first.clone());
        queued.insert(first.clone());
    }
    let mut findings = Findings::default();
    let mut transfers = 0u64;
    let mut widenings = 0u64;
    let cap = max_disjuncts.max(1);
    // Keep pathological loop/alias graphs from monopolizing the native batch.
    // This is an analysis-work guard, not a wall-clock limit.  The native
    // setting has a production-specific name; retain the diagnostic variable
    // as a compatibility override for focused experiments.
    let transfer_cap = std::env::var("LACHESIS_NATIVE_TRANSFER_CAP")
        .or_else(|_| std::env::var("LACHESIS_DIAGNOSTIC_TRANSFER_CAP"))
        .ok().and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        // Match the old engine's graph-relative budget.  Small functions keep
        // the same minimum guard; large functions are not silently truncated
        // at the same flat count regardless of their CFG size.
        .unwrap_or_else(|| 10_000u64.max((nodes.len() as u64).saturating_mul(500)));
    while transfers < transfer_cap {
        let Some(node) = queue.pop_front() else { break };
        queued.remove(&node);
        let mut current = incoming.get_mut(&node).map(std::mem::take).unwrap_or_default();
        for operation in at.get(&node).into_iter().flatten() {
            let mut next = Vec::with_capacity(current.len());
            for shared in current {
                let state = Arc::try_unwrap(shared)
                    .unwrap_or_else(|shared| (*shared).clone());
                next.extend(state.apply_variants(operation, &mut findings)
                    .into_iter().map(Arc::new));
            }
            current = deduplicate_shared(next);
        }
        transfers += current.len() as u64;
        let outgoing = successors.get(&node).map(Vec::as_slice).unwrap_or(&[]);
        if outgoing.len() == 1 {
            // The common CFG case: no branch means the states have exactly one
            // destination, so move them instead of cloning every abstract state.
            let successor = &outgoing[0];
            if !incoming.contains_key(successor) {
                continue;
            }
            let mut target = incoming.get_mut(successor).map(std::mem::take).unwrap_or_default();
            let mut new_items = current.into_iter().filter(|state| {
                !target.iter().any(|existing| existing.as_ref().semantically_equal(state.as_ref()))
            }).collect::<Vec<_>>();
            if new_items.is_empty() {
                incoming.insert(successor.clone(), target);
                continue;
            }
            let should_widen = target.len() + new_items.len() > cap
                || widened.contains(successor);
            let (replacement, changed) = if should_widen {
                let previous = (target.len() == 1).then(|| target[0].clone());
                target.append(&mut new_items);
                let candidates = target.iter().map(|state| (**state).clone()).collect::<Vec<_>>();
                let merged = if stable_widen {
                    stable_join_states(&candidates, successor)
                } else {
                    join_states(&candidates, successor)
                };
                let changed = previous.is_none_or(|old| !old.as_ref().semantically_equal(&merged));
                widened.insert(successor.clone());
                widenings += 1;
                (vec![Arc::new(merged)], changed)
            } else {
                target.append(&mut new_items);
                (target, true)
            };
            incoming.insert(successor.clone(), replacement);
            if changed && queued.insert(successor.clone()) {
                queue.push_back(successor.clone());
            }
            continue;
        }
        for successor in outgoing {
            if !incoming.contains_key(successor) {
                continue;
            }
            let target = incoming.get(successor).cloned().unwrap_or_default();
            let mut new_items = current.iter().filter(|state| {
                !target.iter().any(|existing| existing.as_ref().semantically_equal(state.as_ref()))
            }).cloned().collect::<Vec<_>>();
            if new_items.is_empty() {
                continue;
            }
            let should_widen = target.len() + new_items.len() > cap
                || widened.contains(successor);
            let (replacement, changed) = if should_widen {
                let previous = (target.len() == 1).then(|| target[0].clone());
                let mut candidates = target.iter().map(|state| (**state).clone()).collect::<Vec<_>>();
                candidates.extend(new_items.iter().map(|state| (**state).clone()));
                let merged = if stable_widen {
                    stable_join_states(&candidates, successor)
                } else {
                    join_states(&candidates, successor)
                };
                let changed = previous.is_none_or(|old| !old.as_ref().semantically_equal(&merged));
                widened.insert(successor.clone());
                widenings += 1;
                (vec![Arc::new(merged)], changed)
            } else {
                let mut replacement = target;
                replacement.append(&mut new_items);
                (replacement, true)
            };
            incoming.insert(successor.clone(), replacement);
            if changed && queued.insert(successor.clone()) {
                queue.push_back(successor.clone());
            }
        }
    }

    // Worklist nodes can be revisited many times before a loop reaches a fixpoint.
    // Snapshots are only consumed after convergence, so materializing them inside
    // the loop needlessly cloned the same large abstract states over and over.
    // Reconstruct the final point/post view once from the converged incoming map.
    if retain_snapshots {
        for node in nodes.iter().filter(|node| tracked_nodes.contains(*node)) {
            let current = incoming.get(node).map(Vec::as_slice).unwrap_or(&[]);
            point_snapshots.insert(
                node.clone(),
                current.iter().map(|state| state.compact_snapshot()).collect(),
            );
            let mut post = current.iter().cloned().collect::<Vec<_>>();
            let mut ignored_findings = Findings::default();
            for operation in at.get(node).into_iter().flatten() {
                let mut next = Vec::with_capacity(post.len());
                for shared in post {
                    let state = Arc::try_unwrap(shared)
                        .unwrap_or_else(|shared| (*shared).clone());
                    next.extend(state.apply_variants(operation, &mut ignored_findings)
                        .into_iter().map(Arc::new));
                }
                post = deduplicate_shared(next);
            }
            post_snapshots.insert(
                node.clone(),
                post.iter().map(|state| state.compact_snapshot()).collect(),
            );
            if successors.get(node).is_none_or(Vec::is_empty) {
                exit_snapshots.extend(post.iter().map(|state| state.snapshot()));
            }
        }
    }

    let point_states = nodes.iter().filter_map(|node| {
        point_snapshots.get(node).map(|states| (node.clone(), states.clone()))
    }).collect();
    let post_states = nodes.iter().filter_map(|node| {
        post_snapshots.get(node).map(|states| (node.clone(), states.clone()))
    }).collect();
    let exit_states = exit_snapshots;
    let exit_state = exit_states.first().cloned()
        .unwrap_or_else(|| State::default().snapshot());
    LinearResult {
        point_states,
        post_states,
        exit_state,
        exit_states,
        findings,
        transfers,
        widenings,
        capped: !queue.is_empty(),
    }
}

fn kind_name(kind: Kind) -> &'static str {
    match kind { Kind::Alloc => "alloc", Kind::Clobber => "clobber", Kind::Copy => "copy", Kind::Free => "free", Kind::Realloc => "realloc", Kind::Use => "use", Kind::Summary => "summary" }
}

fn path_name(path: &Path) -> String {
    if path.selectors.is_empty() { return path.root.clone(); }
    format!("{}->{}", path.root, path.selectors.join("->"))
}

fn param_id(position: u32, selectors: &[String]) -> String {
    format!("param|{}|{}", position, selectors.join("/"))
}

fn parse_param(value: &str) -> Option<(u32, Vec<String>)> {
    let mut parts = value.split('|');
    if parts.next()? != "param" { return None; }
    let position = parts.next()?.parse().ok()?;
    let selectors = parts.next().unwrap_or("").split('/').filter(|item| !item.is_empty()).map(str::to_owned).collect();
    Some((position, selectors))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_overlay_ids_match_v2_identity_layout() {
        assert_eq!(
            pass2::stable_id("core", "dynamic-behavior", "dynamic-behavior", &["unresolved-call", "call-1"]),
            "v2:core:dynamic-behavior:dynamic-behavior:b54e24b565df5a12f534",
        );
    }

    fn op(kind: Kind, target: Path, site: &str) -> Operation {
        Operation { kind, node: site.into(), target: Some(target), source: None, site: site.into(), line: Some(1), is_null: false, access: "deref".into(), generation: None, fresh_generation: None, alternatives: Vec::new() }
    }

    #[test]
    fn parameter_free_then_use_preserves_lifetime_facts() {
        let mut state = State::default();
        state.seed_parameter(Path::root("p"), 0);
        let path = Path::root("p");
        let mut findings = Findings::default();
        state.apply(&op(Kind::Free, path.clone(), "free"), &mut findings);
        state.apply(&op(Kind::Use, path, "use"), &mut findings);
        assert_eq!(findings.use_after_free.len(), 1);
        assert!(state.trace.contains(&Effect::Param { kind: Kind::Free, position: 0, selectors: vec![] }));
    }

    #[test]
    fn unknown_index_parameter_is_a_weak_summary_object() {
        let mut state = State::default();
        let path = Path { root: "p".into(), selectors: vec!["<?>".into()] };
        state.seed_parameter(path.clone(), 0);
        let mut findings = Findings::default();
        state.apply(&op(Kind::Free, path.clone(), "free-1"), &mut findings);
        state.apply(&op(Kind::Free, path.clone(), "free-2"), &mut findings);
        state.apply(&op(Kind::Use, path, "use"), &mut findings);
        assert!(findings.double_free.is_empty());
        assert!(findings.use_after_free.is_empty());
    }

    #[test]
    fn copy_preserves_aliasing() {
        let mut state = State::default();
        state.seed_parameter(Path::root("p"), 0);
        let mut findings = Findings::default();
        let mut copy = op(Kind::Copy, Path::root("q"), "copy");
        copy.source = Some(Path::root("p"));
        state.apply(&copy, &mut findings);
        let q = state.resolve(&mut Path::root("q"), false).unwrap();
        let p = state.resolve(&mut Path::root("p"), false).unwrap();
        assert_eq!(p, q);
    }

    #[test]
    fn linear_batch_keeps_pre_and_post_snapshots() {
        let nodes = vec!["alloc".to_string(), "free".to_string()];
        let target = Path::root("p");
        let operations = vec![
            op(Kind::Alloc, target.clone(), "alloc"),
            op(Kind::Free, target, "free"),
        ];
        let result = solve_linear(&nodes, &operations, State::default());
        assert_eq!(result.point_states.len(), 2);
        assert_eq!(result.post_states.len(), 2);
        assert_eq!(result.transfers, 2);
        assert!(result.findings.double_free.is_empty());
    }

    #[test]
    fn linear_cfg_order_rejects_branches_and_cycles() {
        let nodes = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        let successors = HashMap::from([
            ("a".into(), vec!["b".into()]),
            ("b".into(), vec!["c".into()]),
            ("c".into(), Vec::new()),
        ]);
        assert_eq!(linear_cfg_order(&nodes, &successors), Some(nodes.clone()));
        let branch = HashMap::from([
            ("a".into(), vec!["b".into(), "c".into()]),
            ("b".into(), Vec::new()),
            ("c".into(), Vec::new()),
        ]);
        assert_eq!(linear_cfg_order(&nodes, &branch), None);
        let cycle = HashMap::from([
            ("a".into(), vec!["b".into()]),
            ("b".into(), vec!["a".into()]),
            ("c".into(), Vec::new()),
        ]);
        assert_eq!(linear_cfg_order(&nodes, &cycle), None);
    }

    #[test]
    fn graph_batch_publishes_findings_from_transfers() {
        let nodes = vec!["alloc".to_string(), "free1".to_string(), "free2".to_string()];
        let mut successors = HashMap::new();
        successors.insert("alloc".into(), vec!["free1".into()]);
        successors.insert("free1".into(), vec!["free2".into()]);
        let target = Path::root("p");
        let operations = vec![
            op(Kind::Alloc, target.clone(), "alloc"),
            op(Kind::Free, target.clone(), "free1"),
            op(Kind::Free, target, "free2"),
        ];
        let result = solve_graph(&nodes, &successors, &operations, State::default(), 32);
        assert_eq!(result.findings.double_free.len(), 1);
    }
}
