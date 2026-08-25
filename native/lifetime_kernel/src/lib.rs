//! Native state-transition kernel for Pass 2's object-lifetime analysis.
//!
//! This crate intentionally has no Python or graph dependency.  The eventual Python
//! bridge will submit one compact function batch (CFG + operations) at a time.  Keeping
//! the domain here value-oriented avoids allocating Python dictionaries and tuples for
//! every transfer while preserving the existing analysis semantics.

use std::collections::{HashMap, HashSet};
use std::ffi::{c_char, CStr, CString};

use serde::{Deserialize, Serialize};

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
}

/// Stable metadata for converting native IDs back to Python's tuple-shaped ObjectIds.
/// The solver uses compact string handles internally; snapshots never expose those
/// handles without this table.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum ObjectMeta {
    Param { position: u32, selectors: Vec<String> },
    UnknownRoot { root: String },
    UnknownSlot { base: String, selector: String },
    Allocation { kind: Kind, site: String, target: Path },
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
    pub point_states: Vec<(String, Snapshot)>,
    pub post_states: Vec<(String, Snapshot)>,
    pub exit_state: Snapshot,
    pub findings: Findings,
    pub transfers: u64,
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
                    ObjectMeta::UnknownSlot { base: base.clone(), selector: selector.clone() }
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
        let parent_id = self.resolve(&mut parent, true).expect("created path parent");
        self.slots.insert((parent_id, path.selectors.last().unwrap().clone()), oid);
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
        let target = op.target.as_ref().expect("fresh operation target");
        let recent = format!("{}|recent|{}|{}", kind_name(op.kind), op.site, path_name(target));
        self.objects.entry(recent.clone()).or_insert_with(|| ObjectMeta::Allocation {
            kind: op.kind,
            site: op.site.clone(),
            target: target.clone(),
        });
        self.facts.insert(recent.clone(), [fact].into_iter().collect());
        self.bind(target, recent);
    }

    fn free(&mut self, op: &Operation, findings: &mut Findings) {
        let target = op.target.as_ref().expect("free operation target");
        let Some(oid) = self.resolve(target, true) else { return };
        self.record_param(Kind::Free, &oid);
        let facts = self.facts.entry(oid.clone()).or_insert_with(|| [Fact::Unknown].into_iter().collect());
        if facts.contains(&Fact::Freed) {
            findings.double_free.push((op.line, target.clone(), op.node.clone()));
        }
        *facts = [Fact::Freed].into_iter().collect();
    }

    pub fn apply(&mut self, op: &Operation, findings: &mut Findings) {
        match op.kind {
            Kind::Alloc => self.fresh(op, Fact::Allocated),
            Kind::Clobber => self.fresh(op, if op.is_null { Fact::Null } else { Fact::Unknown }),
            Kind::Copy => {
                let mut source = op.source.as_ref().expect("copy source").clone();
                let oid = self.resolve(&mut source, true).expect("copy source resolves");
                self.bind(op.target.as_ref().expect("copy target"), oid);
            }
            Kind::Free => self.free(op, findings),
            Kind::Realloc => {
                if let Some(source) = &op.source {
                    let mut source = source.clone();
                    if let Some(oid) = self.resolve(&mut source, true) {
                        self.record_param(Kind::Free, &oid);
                        self.facts.insert(oid, [Fact::Freed].into_iter().collect());
                    }
                }
                self.fresh(op, Fact::Allocated);
            }
            Kind::Use => {
                let target = op.target.as_ref().expect("use target");
                let mut target_path = target.clone();
                let Some(oid) = self.resolve(&mut target_path, false) else { return };
                self.record_param(Kind::Use, &oid);
                if op.access_is_return() { self.record_return(&oid); }
                if self.facts.get(&oid).is_some_and(|facts| facts.contains(&Fact::Freed)) {
                    findings.use_after_free.push((op.line, target.clone(), op.node.clone()));
                }
            }
        }
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
        point_states.push((node.clone(), state.snapshot()));
        for operation in operations.iter().filter(|operation| operation.node == *node) {
            state.apply(operation, &mut findings);
            transfers += 1;
        }
        post_states.push((node.clone(), state.snapshot()));
    }
    LinearResult { point_states, post_states, exit_state: state.snapshot(), findings, transfers }
}

#[derive(Debug, Deserialize)]
struct WireBatch {
    nodes: Vec<String>,
    operations: Vec<Operation>,
    parameters: Vec<(String, u32)>,
}

fn solve_wire(batch: WireBatch) -> LinearResult {
    let mut state = State::default();
    for (root, position) in batch.parameters {
        state.seed_parameter(Path::root(root), position);
    }
    // The Python initializer materializes parameter-relative fields mentioned by the
    // batch.  Resolve them once with creation enabled so the native state has the same
    // stable parameter identities before the first transfer.
    for operation in &batch.operations {
        for path in [operation.target.as_ref(), operation.source.as_ref()].into_iter().flatten() {
            let mut path = path.clone();
            if state.env.contains_key(&path.root) && !path.selectors.is_empty() {
                let _ = state.resolve(&mut path, true);
            }
        }
    }
    solve_linear(&batch.nodes, &batch.operations, state)
}

/// Solve one prepared linear function batch.  The ABI is intentionally tiny: Python
/// passes one UTF-8 JSON document and receives one owned UTF-8 JSON document.  This is
/// an opt-in bridge during development; the normal Python solver remains the fallback
/// until parity is established.
#[no_mangle]
pub unsafe extern "C" fn lachesis_lifetime_solve_json(input: *const c_char) -> *mut c_char {
    let result = (|| {
        let input = CStr::from_ptr(input).to_str().map_err(|error| error.to_string())?;
        let batch: WireBatch = serde_json::from_str(input).map_err(|error| error.to_string())?;
        serde_json::to_string(&solve_wire(batch)).map_err(|error| error.to_string())
    })();
    let payload = result.unwrap_or_else(|error| serde_json::json!({"error": error}).to_string());
    CString::new(payload).expect("JSON cannot contain NUL").into_raw()
}

#[no_mangle]
pub unsafe extern "C" fn lachesis_lifetime_free_json(value: *mut c_char) {
    if !value.is_null() {
        drop(CString::from_raw(value));
    }
}

impl Operation {
    fn access_is_return(&self) -> bool { self.access == "return" }
}

fn kind_name(kind: Kind) -> &'static str {
    match kind { Kind::Alloc => "alloc", Kind::Clobber => "clobber", Kind::Copy => "copy", Kind::Free => "free", Kind::Realloc => "realloc", Kind::Use => "use" }
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
        Operation { kind, node: site.into(), target: Some(target), source: None, site: site.into(), line: Some(1), is_null: false, access: "deref".into() }
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
