//! Native state-transition kernel for Pass 2's object-lifetime analysis.
//!
//! This crate intentionally has no Python or graph dependency.  The eventual Python
//! bridge will submit one compact function batch (CFG + operations) at a time.  Keeping
//! the domain here value-oriented avoids allocating Python dictionaries and tuples for
//! every transfer while preserving the existing analysis semantics.

use std::collections::{HashMap, HashSet, VecDeque};
use std::slice;
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
    pub facts: HashMap<String, HashSet<Fact>>,
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
            let mut values: Vec<_> = values.iter().copied().collect();
            values.sort_by_key(|value| *value as u8);
            (oid.clone(), values)
        }).collect();
        facts.sort_by(|left, right| left.0.cmp(&right.0));
        let mut slots: Vec<_> = self.slots.iter().map(|((base, selector), oid)| {
            ((base.clone(), selector.clone()), oid.clone())
        }).collect();
        slots.sort_by(|left, right| left.0.cmp(&right.0));
        let mut freed_paths: Vec<_> = self.freed_paths.iter().map(|(path, oid)| (path.clone(), oid.clone())).collect();
        freed_paths.sort_by(|left, right| path_name(&left.0).cmp(&path_name(&right.0)));
        let mut objects: Vec<_> = self.objects.iter().map(|(oid, meta)| (oid.clone(), meta.clone())).collect();
        objects.sort_by(|left, right| left.0.cmp(&right.0));
        Snapshot { env, facts, slots, trace: self.trace.clone(), freed_paths, objects }
    }

    pub fn seed_parameter(&mut self, path: Path, position: u32) {
        let oid = param_id(position, &path.selectors);
        self.objects.entry(oid.clone()).or_insert_with(|| ObjectMeta::Param {
            position,
            selectors: path.selectors.clone(),
        });
        self.env.insert(path.root, oid.clone());
        self.facts.entry(oid).or_default().insert(Fact::Unknown);
    }

    fn resolve(&mut self, path: &Path, create: bool) -> Option<String> {
        let mut oid = self.env.get(&path.root).cloned();
        if oid.is_none() && create {
            let fresh = format!("unknown-root:{}", path.root);
            self.objects.entry(fresh.clone()).or_insert_with(|| ObjectMeta::UnknownRoot {
                root: path.root.clone(),
            });
            self.env.insert(path.root.clone(), fresh.clone());
            self.facts.entry(fresh.clone()).or_default().insert(Fact::Unknown);
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
                self.facts.entry(fresh.clone()).or_default().insert(Fact::Unknown);
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
        let source_facts = self.facts.get(source).cloned()
            .unwrap_or_else(|| [Fact::Unknown].into_iter().collect());
        self.facts.entry(destination.to_owned()).or_default().extend(source_facts);
        for oid in self.env.values_mut() {
            if oid == source { *oid = destination.to_owned(); }
        }
        for oid in self.slots.values_mut() {
            if oid == source { *oid = destination.to_owned(); }
        }
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
        self.facts.insert(recent.clone(), [fact].into_iter().collect());
        self.bind(target, recent);
    }

    fn free(&mut self, op: &Operation, findings: &mut Findings) {
        let Some(target) = op.target.as_ref() else { return };
        let Some(oid) = self.resolve(target, true) else { return };
        self.record_param(Kind::Free, &oid);
        if target.selectors.len() > 0 && parse_param(&oid).is_some() {
            self.freed_paths.insert(target.clone(), oid.clone());
        }
        let facts = self.facts.entry(oid.clone()).or_insert_with(|| [Fact::Unknown].into_iter().collect());
        let weak = oid.split('|').nth(1) == Some("summary");
        if facts.contains(&Fact::Freed) && !weak {
            findings.double_free.push((op.line, target.clone(), op.node.clone()));
        }
        if *facts != [Fact::Null].into_iter().collect::<HashSet<_>>() {
            if weak { facts.insert(Fact::Freed); }
            else { *facts = [Fact::Freed].into_iter().collect(); }
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
                if self.facts.get(&oid).is_some_and(|facts| facts.contains(&Fact::Freed)) {
                    findings.use_after_free.push((op.line, target.clone(), op.node.clone()));
                }
            }
            // Summary operations are expanded by `apply_variants` at the graph
            // transfer boundary. Keeping this arm fail-closed prevents a
            // malformed direct call from silently changing state.
            Kind::Summary => {}
        }
    }

    fn apply_variants(&self, op: &Operation) -> Vec<State> {
        if op.kind != Kind::Summary {
            let mut state = self.clone();
            state.apply(op, &mut Findings::default());
            return vec![state];
        }
        if op.alternatives.is_empty() {
            return vec![self.clone()];
        }
        op.alternatives.iter().map(|effects| {
            let mut state = self.clone();
            let mut findings = Findings::default();
            for effect in effects {
                state.apply(effect, &mut findings);
            }
            state
        }).collect()
    }

    fn semantically_equal(&self, other: &State) -> bool {
        self.env == other.env
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
    let mut point_states = Vec::with_capacity(nodes.len());
    let mut post_states = Vec::with_capacity(nodes.len());
    let mut findings = Findings::default();
    let mut transfers = 0;
    for node in nodes {
        point_states.push((node.clone(), vec![state.snapshot()]));
        for operation in operations.iter().filter(|operation| operation.node == *node) {
            state.apply(operation, &mut findings);
            transfers += 1;
        }
        post_states.push((node.clone(), vec![state.snapshot()]));
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
    lifetime_proto::Result {
        point_states: states(result.point_states),
        post_states: states(result.post_states),
        exit_state: Some(proto_snapshot(result.exit_state)),
        exit_states: result.exit_states.into_iter().map(proto_snapshot).collect(),
        transfers: result.transfers,
        widenings: result.widenings,
        capped: result.capped,
    }
}

/// Binary protobuf lifetime ABI. Both request and response stay typed binary data;
/// JSON is not involved in the internal solver boundary.
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

/// Read the complete framed Pass-1 substrate directly in Rust, then prepare
/// all function inputs without Python-side graph reconstruction.
#[no_mangle]
pub unsafe extern "C" fn lachesis_lifetime_prepare_graph_pb(
    input: *const u8, length: usize, output_length: *mut usize,
) -> *mut u8 {
    let result = (|| {
        let bytes = slice::from_raw_parts(input, length);
        let request = native_graph::sidecar_to_request(bytes)?;
        prepare::solve(&request)
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

/// Read the complete framed substrate and run native preparation plus solving
/// without returning through Python between the two phases.
#[no_mangle]
pub unsafe extern "C" fn lachesis_lifetime_prepare_graph_solve_pb(
    input: *const u8, length: usize, output_length: *mut usize,
) -> *mut u8 {
    let result = (|| {
        let bytes = slice::from_raw_parts(input, length);
        let request = native_graph::sidecar_to_request(bytes)?;
        prepare::prepare_and_solve(&request)
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

impl Operation {
    fn access_is_return(&self) -> bool { self.access == "return" }
}

fn deduplicate(states: Vec<State>) -> Vec<State> {
    let mut unique = Vec::with_capacity(states.len());
    'candidate: for state in states {
        if unique.iter().any(|existing: &State| existing.semantically_equal(&state)) {
            continue 'candidate;
        }
        unique.push(state);
    }
    unique
}

fn attach_joined(states: &[State], node: &str, new_oid: String,
                 signature: Vec<Option<String>>, joined: &mut State,
                 queued: &mut Vec<(String, Vec<Option<String>>)>) {
    let mut facts = HashSet::new();
    for (state, old_oid) in states.iter().zip(signature.iter()) {
        if let Some(old_oid) = old_oid {
            facts.extend(state.facts.get(old_oid).cloned()
                .unwrap_or_else(|| [Fact::Unknown].into_iter().collect()));
        } else {
            facts.insert(Fact::Unknown);
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
    let mut signatures: HashMap<String, String> = HashMap::new();
    let mut queued: Vec<(String, Vec<Option<String>>)> = Vec::new();
    let mut seen = HashSet::new();
    let mut phi_index = 0usize;

    let mut object_for = |tag: &str, signature: &[Option<String>]| -> String {
        if signature.first().is_some_and(|first| first.is_some())
            && signature.iter().all(|item| item.as_ref() == signature[0].as_ref())
        {
            return signature[0].clone().unwrap();
        }
        let key = format!("{}|{}", tag, signature.iter().map(|item| item.as_deref().unwrap_or("<none>")).collect::<Vec<_>>().join(";"));
        if let Some(existing) = signatures.get(&key) {
            return existing.clone();
        }
        let value = format!("phi|{}|{}", tag, phi_index);
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

/// Execute the non-SUMMARY fixpoint subset.  This mirrors Python's worklist shape:
/// states are deduplicated at each transfer, joins become sticky after the disjunct
/// budget is exceeded, and snapshots are retained for the semantic emitter.
pub fn solve_graph(nodes: &[String], successors: &HashMap<String, Vec<String>>,
                   operations: &[Operation], initial: State,
                   max_disjuncts: usize) -> LinearResult {
    let mut at: HashMap<String, Vec<Operation>> = HashMap::new();
    for operation in operations {
        at.entry(operation.node.clone()).or_default().push(operation.clone());
    }
    for placed in at.values_mut() {
        // The Python side has already ordered operations, but preserve the contract if
        // the native API is called directly.
        placed.sort_by_key(|operation| operation.line.unwrap_or(0));
    }
    let mut incoming: HashMap<String, Vec<State>> = nodes.iter()
        .map(|node| (node.clone(), Vec::new()))
        .collect();
    if let Some(first) = nodes.first() {
        incoming.insert(first.clone(), vec![initial]);
    }
    let mut post: HashMap<String, Vec<State>> = HashMap::new();
    let mut queue = VecDeque::new();
    let mut queued = HashSet::new();
    let mut widened = HashSet::new();
    if let Some(first) = nodes.first() {
        queue.push_back(first.clone());
        queued.insert(first.clone());
    }
    let findings = Findings::default();
    let mut transfers = 0u64;
    let mut widenings = 0u64;
    let cap = max_disjuncts.max(1);

    while let Some(node) = queue.pop_front() {
        queued.remove(&node);
        let mut current = incoming.get(&node).cloned().unwrap_or_default();
        for operation in at.get(&node).into_iter().flatten() {
            let mut next = Vec::with_capacity(current.len());
            for state in current {
                next.extend(state.apply_variants(operation));
            }
            current = deduplicate(next);
        }
        transfers += current.len() as u64;
        post.insert(node.clone(), current.clone());
        for successor in successors.get(&node).into_iter().flatten() {
            if !incoming.contains_key(successor) {
                continue;
            }
            let target = incoming.get(successor).cloned().unwrap_or_default();
            let mut new_items = current.iter().filter(|state| {
                !target.iter().any(|existing| existing.semantically_equal(state))
            }).cloned().collect::<Vec<_>>();
            if new_items.is_empty() {
                continue;
            }
            let should_widen = target.len() + new_items.len() > cap
                || widened.contains(successor);
            let (replacement, changed) = if should_widen {
                let mut candidates = target.clone();
                candidates.append(&mut new_items);
                let merged = join_states(&candidates, successor);
                let changed = target.len() != 1
                    || !target.first().is_some_and(|old| old.semantically_equal(&merged));
                widened.insert(successor.clone());
                widenings += 1;
                (vec![merged], changed)
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

    let point_states = nodes.iter().filter_map(|node| {
        incoming.get(node).map(|states| (
            node.clone(), states.iter().map(State::snapshot).collect(),
        ))
    }).collect();
    let post_states = nodes.iter().filter_map(|node| {
        post.get(node).map(|states| (
            node.clone(), states.iter().map(State::snapshot).collect(),
        ))
    }).collect();
    let exit_states: Vec<_> = nodes.iter()
        .filter(|node| successors.get(*node).is_none_or(Vec::is_empty))
        .flat_map(|node| post.get(node).into_iter().flatten().map(State::snapshot))
        .collect();
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

    fn op(kind: Kind, target: Path, site: &str) -> Operation {
        Operation { kind, node: site.into(), target: Some(target), source: None, site: site.into(), line: Some(1), is_null: false, access: "deref".into(), alternatives: Vec::new() }
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
}
