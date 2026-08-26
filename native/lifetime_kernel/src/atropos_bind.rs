//! Native implementation of Atropos's model-to-callsite binder.
//!
//! The neutral symbol-index and model JSON shapes are deliberately kept identical to
//! Atropos's stdlib binder.  This lets the Python side remain an adapter while the
//! expensive model/callsite matching and attachment construction runs on compact Rust
//! values.  The output is the existing `atropos-binding-report` contract.

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::path::Path;
use hashbrown::HashMap;
use prost::Message;

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

fn python_sort_key(candidate: &Candidate) -> String {
    // Atropos's oracle uses ``sorted(distinct, key=str)`` for ambiguity
    // candidates.  Reproduce Python's tuple spelling rather than Rust's Option
    // ordering (where None would otherwise sort before every string).
    fn quoted(value: &Option<String>) -> String {
        match value {
            None => "None".into(),
            Some(value) => format!("'{}'", value.replace('\\', "\\\\").replace('\'', "\\'")),
        }
    }
    let arity = candidate.arity.map_or_else(|| "None".into(), |value| value.to_string());
    format!("({}, {}, {})", quoted(&candidate.module),
            quoted(&candidate.receiver_type), arity)
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
        let mut candidates: Vec<_> = distinct.into_iter().map(|(module, receiver_type, arity)|
            Candidate { module, receiver_type, arity }).collect();
        candidates.sort_by_key(python_sort_key);
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

fn property(node: &crate::graph_proto::NodeRecord, key: &str) -> Option<String> {
    node.properties.iter().find_map(|field| {
        if field.key != key { return None; }
        let value = field.value.as_ref()?.kind.as_ref()?;
        Some(match value {
            crate::graph_proto::value::Kind::Text(value) => value.clone(),
            crate::graph_proto::value::Kind::Integer(value) => value.to_string(),
            crate::graph_proto::value::Kind::Boolean(value) => value.to_string(),
            _ => return None,
        })
    })
}

fn simple_identifier(value: &str) -> bool {
    !value.is_empty() && value.chars().enumerate().all(|(index, ch)|
        if index == 0 { ch == '_' || ch.is_ascii_alphabetic() }
        else { ch == '_' || ch.is_ascii_alphanumeric() })
}

fn framed_record(reader: &mut BufReader<File>) -> Result<Option<Vec<u8>>, String> {
    let mut header = [0u8; 4];
    match reader.read_exact(&mut header) {
        Ok(()) => {},
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(format!("cannot read graph frame: {error}")),
    }
    let length = u32::from_be_bytes(header) as usize;
    let mut payload = vec![0u8; length];
    reader.read_exact(&mut payload)
        .map_err(|error| format!("cannot read graph frame payload: {error}"))?;
    Ok(Some(payload))
}

/// Build the neutral Atropos index directly from the complete Pass-1 stream.
///
/// Only call nodes, argument nodes, and HAS_ARGUMENT edges are retained. The
/// million-node graph never becomes a Python object graph and the full edge
/// stream is not retained in Rust either.
fn index_from_path(path: &Path) -> Result<Index, String> {
    let file = File::open(path).map_err(|error| format!("cannot open Pass-1 input: {error}"))?;
    let mut reader = BufReader::new(file);
    let mut calls = Vec::<crate::graph_proto::NodeRecord>::new();
    let mut arguments: HashMap<String, Vec<(usize, String)>> = HashMap::new();
    let mut has_arguments: HashMap<String, Vec<(usize, String)>> = HashMap::new();
    let mut language: Option<&str> = None;
    let mut mixed_languages = false;
    while let Some(mut payload) = framed_record(&mut reader)? {
        if payload.is_empty() { continue; }
        let tag = payload.remove(0);
        match tag {
            b'N' => {
                let node = crate::graph_proto::NodeRecord::decode(payload.as_slice())
                    .map_err(|error| format!("invalid Pass-1 node: {error}"))?;
                let node_language = if node.id.contains(":clang-c:") { Some("c") }
                    else if node.id.contains(":cpython-ast:") { Some("python") }
                    else if node.id.contains(":typescript-compiler-api:") { Some("typescript") }
                    else { None };
                if let Some(current) = node_language {
                    if let Some(previous) = language {
                        mixed_languages |= previous != current;
                    } else if !mixed_languages {
                        language = Some(current);
                    }
                }
                if node.kind == "call" || node.kind == "construct" {
                    calls.push(node);
                } else if node.kind == "argument" {
                    let call = property(&node, "callsite_id");
                    let position = property(&node, "position")
                        .and_then(|value| value.parse().ok()).unwrap_or(0);
                    if let Some(call) = call {
                        arguments.entry(call).or_default().push((position, node.id));
                    }
                }
            }
            b'E' => {
                let edge = crate::graph_proto::EdgeRecord::decode(payload.as_slice())
                    .map_err(|error| format!("invalid Pass-1 edge: {error}"))?;
                if edge.kind == "HAS_ARGUMENT" {
                    let position = edge.properties.iter().find_map(|field| {
                        (field.key == "position").then(|| field.value.as_ref()?.kind.as_ref())
                    }).and_then(|value| match value? {
                        crate::graph_proto::value::Kind::Integer(value) => (*value).try_into().ok(),
                        crate::graph_proto::value::Kind::Text(value) => value.parse().ok(),
                        _ => None,
                    }).unwrap_or(0);
                    has_arguments.entry(edge.source).or_default().push((position, edge.target));
                }
            }
            // The first frame is the graph header Document. It is metadata only.
            _ => {}
        }
    }
    let callsites = calls.into_iter().filter_map(|node| {
        let raw_name = property(&node, "callee")
            .or_else(|| property(&node, "method_name"))
            .or_else(|| property(&node, "callee_name"))?;
        let mut name = raw_name;
        let mut receiver = property(&node, "receiver");
        if receiver.is_none() {
            if let Some((prefix, leaf)) = name.rsplit_once('.').map(|(prefix, leaf)|
                (prefix.to_owned(), leaf.to_owned())) {
                if simple_identifier(&prefix) {
                    name = leaf;
                    receiver = Some(prefix);
                }
            }
        }
        let module = property(&node, "module").or_else(|| receiver.as_deref()
            .filter(|value| simple_identifier(value)).map(str::to_owned));
        let receiver_type = property(&node, "receiver_type");
        let call_value_id = property(&node, "value_id").or_else(|| Some(node.id.clone()));
        let receiver_value_id = property(&node, "receiver_value_id");
        let mut args = arguments.remove(&node.id)
            .or_else(|| has_arguments.remove(&node.id)).unwrap_or_default();
        args.sort_by_key(|item| item.0);
        Some(Callsite {
            id: node.id,
            callee: Callee {
                name, module, receiver_type,
                arity: Some(args.len() as i64),
            },
            call_value_id,
            receiver_value_id,
            arg_value_ids: args.into_iter().map(|(_, id)| id).collect(),
        })
    }).collect();
    Ok(Index { language: if mixed_languages { None } else { language.map(str::to_owned) },
              source: Some(path.display().to_string()), callsites })
}

fn load_models_path(path: &Path) -> Result<Vec<Model>, String> {
    let bytes = fs::read(path)
        .map_err(|error| format!("cannot read binary catalog {path:?}: {error}"))?;
    let request = crate::atropos_proto::Request::decode(bytes.as_slice())
        .map_err(|error| format!("invalid binary catalog {path:?}: {error}"))?;
    Ok(from_proto(request).0)
}

pub(crate) fn bind_path(input: &Path, catalog: &Path, output: &Path) -> Result<(), String> {
    let index = index_from_path(input)?;
    let models = load_models_path(catalog)?;
    let report = to_proto(bind_all(&models, &index));
    let mut bytes = Vec::new();
    report.encode(&mut bytes).map_err(|error| format!("cannot encode bind report: {error}"))?;
    let temporary = output.with_extension(format!("tmp.{}", std::process::id()));
    fs::write(&temporary, bytes).map_err(|error| format!("cannot write bind report: {error}"))?;
    fs::rename(&temporary, output).map_err(|error| format!("cannot publish bind report: {error}"))?;
    Ok(())
}

fn optional_string(value: String) -> Option<String> {
    (!value.is_empty()).then_some(value)
}

fn from_proto(request: crate::atropos_proto::Request) -> (Vec<Model>, Index) {
    let models = request.models.into_iter().map(|model| Model {
        id: optional_string(model.id), language: optional_string(model.language),
        method: optional_string(model.method), package: optional_string(model.package),
        receiver_type: optional_string(model.receiver_type),
        arity: model.has_arity.then_some(model.arity),
        access_path: optional_string(model.access_path), role: optional_string(model.role),
    }).collect();
    let index = request.index.unwrap_or_default();
    let callsites = index.callsites.into_iter().map(|callsite| {
        let callee = callsite.callee.unwrap_or_default();
        Callsite {
            id: callsite.id,
            callee: Callee {
                name: callee.name, module: optional_string(callee.module),
                receiver_type: optional_string(callee.receiver_type),
                arity: callee.has_arity.then_some(callee.arity),
            },
            call_value_id: optional_string(callsite.call_value_id),
            receiver_value_id: optional_string(callsite.receiver_value_id),
            arg_value_ids: callsite.arg_value_ids,
        }
    }).collect();
    (models, Index { language: optional_string(index.language), source: optional_string(index.source), callsites })
}

fn to_proto(report: Report) -> crate::atropos_proto::Report {
    let rows = report.results.into_iter().map(|row| crate::atropos_proto::ResultRow {
        model_id: row.model_id.unwrap_or_default(), method: row.method.unwrap_or_default(),
        access_path: row.access_path.unwrap_or_default(), role: row.role.unwrap_or_default(),
        status: row.status,
        candidates: row.candidates.unwrap_or_default().into_iter().map(|candidate| crate::atropos_proto::Candidate {
            module: candidate.module.unwrap_or_default(), receiver_type: candidate.receiver_type.unwrap_or_default(),
            arity: candidate.arity.unwrap_or_default(), has_arity: candidate.arity.is_some(),
        }).collect(),
        attachments: row.attachments.unwrap_or_default().into_iter().map(|attachment| {
            let target = if let Some(node) = attachment.node {
                crate::atropos_proto::attachment::Target::Node(crate::atropos_proto::NodeAttachment {
                    node, kind: attachment.kind.unwrap_or_default(), index: attachment.index.unwrap_or_default() as i64,
                    has_index: attachment.index.is_some(),
                })
            } else {
                let edge = attachment.edge.unwrap();
                crate::atropos_proto::attachment::Target::Edge(crate::atropos_proto::Edge {
                    from: edge.from, to: edge.to,
                })
            };
            crate::atropos_proto::Attachment {
                callsite: attachment.callsite, target: Some(target),
                from_kind: attachment.from_kind.unwrap_or_default(),
                to_kind: attachment.to_kind.unwrap_or_default(),
            }
        }).collect(),
        skipped: row.skipped.unwrap_or_default().into_iter().map(|item| crate::atropos_proto::Skipped {
            callsite: item.callsite, detail: item.detail,
        }).collect(),
        detail: row.detail.unwrap_or_default(),
    }).collect();
    crate::atropos_proto::Report {
        format: report.format.into(), version: report.version,
        index: report.index.unwrap_or_default(),
        summary: Some(crate::atropos_proto::Summary {
            symbol_not_found: report.summary.symbol_not_found as u64,
            ambiguous: report.summary.ambiguous as u64,
            arity_mismatch: report.summary.arity_mismatch as u64,
            unsupported_path: report.summary.unsupported_path as u64,
            bound: report.summary.bound as u64,
            attempted: report.summary.attempted as u64,
        }),
        results: rows,
    }
}

#[no_mangle]
pub unsafe extern "C" fn lachesis_atropos_bind_pb(
    input: *const u8, length: usize, output_length: *mut usize,
) -> *mut u8 {
    let result = (|| {
        let bytes = std::slice::from_raw_parts(input, length);
        let request = crate::atropos_proto::Request::decode(bytes)
            .map_err(|error| error.to_string())?;
        let (models, index) = from_proto(request);
        let mut output = Vec::new();
        to_proto(bind_all(&models, &index)).encode(&mut output)
            .map_err(|error| error.to_string())?;
        Ok::<Vec<u8>, String>(output)
    })();
    let mut payload = result.unwrap_or_default();
    if !output_length.is_null() { *output_length = payload.len(); }
    let pointer = payload.as_mut_ptr();
    std::mem::forget(payload);
    pointer
}
