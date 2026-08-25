//! Native implementation of Atropos's model-to-callsite binder.
//!
//! The neutral symbol-index and model JSON shapes are deliberately kept identical to
//! Atropos's stdlib binder.  This lets the Python side remain an adapter while the
//! expensive model/callsite matching and attachment construction runs on compact Rust
//! values.  The output is the existing `atropos-binding-report` contract.

use std::collections::{BTreeSet, HashMap};
use std::ffi::{c_char, CStr, CString};

use serde::{Deserialize, Serialize, Serializer, ser::SerializeMap};

const STATUS: [&str; 5] = [
    "bound", "symbol-not-found", "ambiguous", "arity-mismatch", "unsupported-path",
];

#[derive(Clone, Debug, Deserialize)]
pub struct Model {
    pub id: Option<String>,
    pub language: Option<String>,
    pub method: Option<String>,
    pub package: Option<String>,
    #[serde(rename = "type")]
    pub receiver_type: Option<String>,
    pub arity: Option<i64>,
    pub access_path: Option<String>,
    pub role: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Index {
    pub language: Option<String>,
    pub source: Option<String>,
    #[serde(default)]
    pub callsites: Vec<Callsite>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Callsite {
    pub id: String,
    pub callee: Callee,
    pub call_value_id: Option<String>,
    pub receiver_value_id: Option<String>,
    #[serde(default)]
    pub arg_value_ids: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Callee {
    pub name: String,
    pub module: Option<String>,
    pub receiver_type: Option<String>,
    pub arity: Option<i64>,
}

#[derive(Clone, Debug)]
struct Attachment {
    callsite: String,
    node: Option<String>,
    edge: Option<Edge>,
    kind: Option<String>,
    index: Option<usize>,
    from_kind: Option<String>,
    to_kind: Option<String>,
}

impl Serialize for Attachment {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        let fields = if self.node.is_some() { 4 } else { 4 };
        let mut map = serializer.serialize_map(Some(fields))?;
        map.serialize_entry("callsite", &self.callsite)?;
        if let Some(node) = &self.node {
            map.serialize_entry("node", node)?;
            map.serialize_entry("kind", self.kind.as_ref().unwrap())?;
            map.serialize_entry("index", &self.index)?;
        } else {
            map.serialize_entry("edge", self.edge.as_ref().unwrap())?;
            map.serialize_entry("from_kind", self.from_kind.as_ref().unwrap())?;
            map.serialize_entry("to_kind", self.to_kind.as_ref().unwrap())?;
        }
        map.end()
    }
}

#[derive(Clone, Debug, Serialize)]
struct Edge {
    from: String,
    to: String,
}

#[derive(Clone, Debug, Serialize)]
struct Skipped {
    callsite: String,
    detail: String,
}

#[derive(Clone, Debug, Serialize)]
struct ResultRow {
    model_id: Option<String>,
    method: Option<String>,
    access_path: Option<String>,
    role: Option<String>,
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    candidates: Option<Vec<Candidate>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    attachments: Option<Vec<Attachment>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    skipped: Option<Vec<Skipped>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
struct Candidate {
    module: Option<String>,
    receiver_type: Option<String>,
    arity: Option<i64>,
}

#[derive(Clone, Debug, Serialize)]
struct Summary {
    #[serde(rename = "symbol-not-found")]
    symbol_not_found: usize,
    ambiguous: usize,
    #[serde(rename = "arity-mismatch")]
    arity_mismatch: usize,
    #[serde(rename = "unsupported-path")]
    unsupported_path: usize,
    bound: usize,
    attempted: usize,
}

#[derive(Clone, Debug, Serialize)]
struct Report {
    format: &'static str,
    version: u32,
    index: Option<String>,
    summary: Summary,
    results: Vec<ResultRow>,
}

fn matches(model: &Model, callee: &Callee) -> bool {
    if model.method.as_deref() != Some(callee.name.as_str()) {
        return false;
    }
    if let (Some(expected), Some(actual)) = (model.package.as_ref(), callee.module.as_ref()) {
        if expected != actual { return false; }
    }
    if let (Some(expected), Some(actual)) =
        (model.receiver_type.as_ref(), callee.receiver_type.as_ref())
    {
        if expected != actual { return false; }
    }
    if let (Some(expected), Some(actual)) = (model.arity, callee.arity) {
        if expected != actual { return false; }
    }
    true
}

fn endpoint(term: &str) -> Option<(&str, Option<usize>)> {
    if term == "ReturnValue" { return Some(("return", None)); }
    if term == "Receiver" { return Some(("receiver", None)); }
    let value = term.strip_prefix("Argument[")?.strip_suffix(']')?;
    if value.is_empty() || !value.chars().all(|c| c.is_ascii_digit()) { return None; }
    Some(("argument", Some(value.parse().ok()?)))
}

fn resolve(kind: &str, index: Option<usize>, callsite: &Callsite)
    -> Result<(String, String, Option<usize>), (String, String)>
{
    match kind {
        "return" => callsite.call_value_id.clone()
            .map(|id| (id, "return".into(), None))
            .ok_or_else(|| ("unsupported".into(), "callsite has no call_value_id".into())),
        "receiver" => callsite.receiver_value_id.clone()
            .map(|id| (id, "receiver".into(), None))
            .ok_or_else(|| ("unsupported".into(), "model expects a receiver; callsite has none".into())),
        "argument" => {
            let position = index.expect("argument endpoint has an index");
            if position >= callsite.arg_value_ids.len()
                || callsite.callee.arity.is_some_and(|arity| position as i64 >= arity)
            {
                let arity = callsite.callee.arity
                    .filter(|value| *value != 0)
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| callsite.arg_value_ids.len().to_string());
                return Err(("arity".into(), format!("Argument[{position}] out of range (callsite arity {arity})")));
            }
            Ok((callsite.arg_value_ids[position].clone(), "argument".into(), Some(position)))
        }
        _ => unreachable!(),
    }
}

fn bind_model(model: &Model, index: &Index) -> ResultRow {
    let callsites: Vec<&Callsite> = index.callsites.iter()
        .filter(|_| index.language.is_none() || model.language == index.language)
        .filter(|callsite| matches(model, &callsite.callee))
        .collect();
    let base = || ResultRow {
        model_id: model.id.clone(), method: model.method.clone(),
        access_path: model.access_path.clone(), role: model.role.clone(),
        status: String::new(), candidates: None, attachments: None,
        skipped: None, detail: None,
    };
    if callsites.is_empty() {
        let mut row = base(); row.status = "symbol-not-found".into(); return row;
    }

    let identities: BTreeSet<(Option<String>, Option<String>)> = callsites.iter()
        .map(|c| (c.callee.module.clone(), c.callee.receiver_type.clone())).collect();
    if identities.len() > 1 {
        let mut row = base(); row.status = "ambiguous".into();
        let distinct: BTreeSet<(Option<String>, Option<String>, Option<i64>)> = callsites.iter()
            .map(|c| (c.callee.module.clone(), c.callee.receiver_type.clone(), c.callee.arity)).collect();
        let candidates = distinct.into_iter().map(|(module, receiver_type, arity)|
            Candidate { module, receiver_type, arity }).collect();
        row.candidates = Some(candidates); return row;
    }

    let path = match model.access_path.as_deref() {
        Some(path) => path,
        None => { let mut row = base(); row.status = "unsupported-path".into(); return row; }
    };
    let terms: Vec<&str> = path.split("->").map(str::trim).collect();
    let endpoints: Option<Vec<_>> = terms.iter().map(|term| endpoint(term)).collect();
    let endpoints = match endpoints {
        Some(value) => value,
        None => { let mut row = base(); row.status = "unsupported-path".into(); return row; }
    };
    let mut attachments = Vec::new();
    let mut skipped = Vec::new();
    let mut unsupported = None;
    for callsite in callsites {
        let mut resolved = Vec::new();
        for (kind, position) in &endpoints {
            match resolve(kind, *position, callsite) {
                Ok(value) => resolved.push(value),
                Err((status, detail)) if status == "arity" => {
                    skipped.push(Skipped { callsite: callsite.id.clone(), detail });
                    resolved.clear();
                    break;
                }
                Err((_, detail)) => { unsupported = Some(detail); break; }
            }
        }
        if unsupported.is_some() { break; }
        if resolved.is_empty() { continue; }
        if resolved.len() == 1 {
            let (node, kind, position) = resolved.remove(0);
            attachments.push(Attachment {
                callsite: callsite.id.clone(), node: Some(node), edge: None,
                kind: Some(kind), index: position, from_kind: None, to_kind: None,
            });
        } else {
            let (from, from_kind, from_index) = resolved.first().cloned().unwrap();
            let (to, to_kind, to_index) = resolved.last().cloned().unwrap();
            let _ = (from_index, to_index);
            attachments.push(Attachment {
                callsite: callsite.id.clone(), node: None,
                edge: Some(Edge { from, to }), kind: None, index: None,
                from_kind: Some(from_kind), to_kind: Some(to_kind),
            });
        }
    }
    let mut row = base();
    if let Some(detail) = unsupported {
        row.status = "unsupported-path".into(); row.detail = Some(detail); return row;
    }
    if attachments.is_empty() {
        row.status = "arity-mismatch".into();
        row.detail = skipped.first().map(|item| item.detail.clone())
            .or_else(|| Some("no bindable callsite".into()));
        return row;
    }
    row.status = "bound".into();
    row.attachments = Some(attachments);
    if !skipped.is_empty() { row.skipped = Some(skipped); }
    row
}

fn bind_all(models: &[Model], index: &Index) -> Report {
    let mut results = Vec::new();
    for model in models {
        if index.language.is_none() || model.language == index.language {
            results.push(bind_model(model, index));
        }
    }
    let mut counts = HashMap::<String, usize>::new();
    for status in STATUS { counts.insert(status.into(), 0); }
    for row in &results { *counts.get_mut(&row.status).unwrap() += 1; }
    Report {
        format: "atropos-binding-report", version: 1,
        index: index.source.clone(),
        summary: Summary {
            bound: counts["bound"], symbol_not_found: counts["symbol-not-found"],
            ambiguous: counts["ambiguous"], arity_mismatch: counts["arity-mismatch"],
            unsupported_path: counts["unsupported-path"], attempted: results.len(),
        }, results,
    }
}

#[derive(Debug, Deserialize)]
struct Input { models: Vec<Model>, index: Index }

#[no_mangle]
pub unsafe extern "C" fn lachesis_atropos_bind_json(input: *const c_char) -> *mut c_char {
    let result = (|| {
        let input = CStr::from_ptr(input).to_str().map_err(|error| error.to_string())?;
        let input: Input = serde_json::from_str(input).map_err(|error| error.to_string())?;
        serde_json::to_string(&bind_all(&input.models, &input.index)).map_err(|error| error.to_string())
    })();
    let payload = result.unwrap_or_else(|error| serde_json::json!({"error": error}).to_string());
    CString::new(payload).expect("JSON cannot contain NUL").into_raw()
}
