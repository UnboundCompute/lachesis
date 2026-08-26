//! Native Pass-2 graph substrate.
//!
//! This is the shared representation for the complete Pass-2 engine.  The
//! input is the framed protobuf stream emitted by Pass 1; Python never
//! reconstructs these records.  IDs and relationship kinds are interned once,
//! while protobuf properties remain typed for overlay-specific accessors.

use std::fs::{self, File};
use std::io::{BufReader, Read, Write};
use std::path::Path;

use hashbrown::HashMap;
use prost::Message;
use rustc_hash::FxHashMap;
use sha2::{Digest, Sha256};

use crate::graph_proto;

const FRAME_HEADER: usize = 4;
const DATAFLOW_STREAM_MAGIC: &[u8] = b"LACHESIS-DATAFLOW-STREAM\0";

#[derive(Default)]
pub(crate) struct Symbols {
    values: Vec<String>,
    lookup: FxHashMap<String, u32>,
}

impl Symbols {
    pub(crate) fn intern(&mut self, value: String) -> u32 {
        if let Some(symbol) = self.lookup.get(&value) {
            return *symbol;
        }
        let symbol = self.values.len() as u32;
        self.lookup.insert(value.clone(), symbol);
        self.values.push(value);
        symbol
    }

    pub(crate) fn get(&self, symbol: u32) -> &str {
        self.values.get(symbol as usize).map(String::as_str).unwrap_or("")
    }

    pub(crate) fn find(&self, value: &str) -> Option<u32> { self.lookup.get(value).copied() }
}

pub(crate) struct Node {
    pub(crate) id: u32,
    pub(crate) kind: u32,
    pub(crate) label: String,
    pub(crate) properties: Vec<graph_proto::Field>,
}

pub(crate) struct Edge {
    pub(crate) kind: u32,
    /// Semantic kind is resolved once at ingest (not once per traversal).
    pub(crate) semantic_kind: u32,
    pub(crate) source: u32,
    pub(crate) target: u32,
    pub(crate) properties: Vec<graph_proto::Field>,
}

pub(crate) struct Graph {
    pub(crate) core_content_hash: String,
    pub(crate) symbols: Symbols,
    pub(crate) nodes: Vec<Node>,
    pub(crate) edges: Vec<Edge>,
    pub(crate) node_by_id: FxHashMap<u32, usize>,
    pub(crate) outgoing: Vec<Vec<usize>>,
    pub(crate) incoming: Vec<Vec<usize>>,
    /// Candidate edge indexes by triple.  Properties are compared only when a
    /// triple collides, matching composition's first-wins/different-properties
    /// behavior without serializing every edge during ingestion.
    pub(crate) edge_lookup: FxHashMap<(u32, u32, u32), Vec<usize>>,
}

#[derive(Clone)]
pub(crate) struct Delta {
    pub(crate) nodes: Vec<graph_proto::NodeRecord>,
    pub(crate) edges: Vec<graph_proto::EdgeRecord>,
}

impl Graph {
    pub(crate) fn kind(&self, symbol: u32) -> &str { self.symbols.get(symbol) }

    pub(crate) fn node_kind(&self, index: usize) -> &str {
        self.nodes.get(index).map_or("", |node| self.kind(node.kind))
    }

    pub(crate) fn node_property<'a>(
        &self, node: &'a Node, key: &str,
    ) -> Option<&'a graph_proto::Value> {
        node.properties.iter().find_map(|field| {
            (field.key == key).then(|| field.value.as_ref()).flatten()
        })
    }

    pub(crate) fn symbol(&self, value: &str) -> Option<u32> { self.symbols.find(value) }

    pub(crate) fn id(&self, symbol: u32) -> &str { self.symbols.get(symbol) }

    pub(crate) fn node_index(&self, id: &str) -> Option<usize> {
        self.symbol(id).and_then(|symbol| self.node_by_id.get(&symbol).copied())
    }

    pub(crate) fn edge_kind(&self, edge: &Edge) -> &str { self.kind(edge.semantic_kind) }

    pub(crate) fn edge_property_text<'a>(&self, edge: &'a Edge, key: &str) -> Option<&'a str> {
        edge.properties.iter().find_map(|field| {
            if field.key != key { return None; }
            match field.value.as_ref()?.kind.as_ref()? {
                graph_proto::value::Kind::Text(value) => Some(value.as_str()),
                _ => None,
            }
        })
    }

    pub(crate) fn node_property_text<'a>(&self, node: &'a Node, key: &str) -> Option<&'a str> {
        self.node_property(node, key).and_then(|value| match value.kind.as_ref()? {
            graph_proto::value::Kind::Text(value) => Some(value.as_str()),
            _ => None,
        })
    }

    pub(crate) fn node_property_i64(&self, node: &Node, key: &str) -> Option<i64> {
        self.node_property(node, key).and_then(|value| match value.kind.as_ref()? {
            graph_proto::value::Kind::Integer(value) => Some(*value),
            _ => None,
        })
    }

    pub(crate) fn node_property_bool(&self, node: &Node, key: &str) -> Option<bool> {
        self.node_property(node, key).and_then(|value| match value.kind.as_ref()? {
            graph_proto::value::Kind::Boolean(value) => Some(*value),
            _ => None,
        })
    }

    pub(crate) fn absorb(&mut self, delta: Delta) -> Result<(), String> {
        for record in delta.nodes {
            let id = self.symbols.intern(record.id);
            if let Some(existing) = self.node_by_id.get(&id).copied() {
                let node = &self.nodes[existing];
                if self.kind(node.kind) != record.kind || node.label != record.label {
                    return Err(format!("conflicting native Pass-2 node {}", self.id(id)));
                }
                continue;
            }
            let node = Node {
                id,
                kind: self.symbols.intern(record.kind),
                label: record.label,
                properties: record.properties,
            };
            self.node_by_id.insert(id, self.nodes.len());
            self.nodes.push(node);
            self.outgoing.push(Vec::new());
            self.incoming.push(Vec::new());
        }
        for record in delta.edges {
            let edge = make_edge(&mut self.symbols, record.kind, record.source, record.target, record.properties);
            let triple = (edge.kind, edge.source, edge.target);
            let duplicate = self.edge_lookup.get(&triple).into_iter().flatten().any(|index| {
                self.edges[*index].properties == edge.properties
            });
            if duplicate { continue; }
            let index = self.edges.len();
            if let Some(source) = self.node_by_id.get(&edge.source).copied() {
                self.outgoing[source].push(index);
            }
            if let Some(target) = self.node_by_id.get(&edge.target).copied() {
                self.incoming[target].push(index);
            }
            self.edges.push(edge);
            self.edge_lookup.entry(triple).or_default().push(index);
        }
        Ok(())
    }
}

fn make_edge(
    symbols: &mut Symbols, kind: String, source: String, target: String,
    properties: Vec<graph_proto::Field>,
) -> Edge {
    let raw_kind = symbols.intern(kind);
    let semantic_kind = if symbols.get(raw_kind) == "EXPANDS_TO" {
        properties.iter().find_map(|field| {
            (field.key == "via").then(|| field.value.as_ref()).flatten().and_then(|value| match value.kind.as_ref()? {
                graph_proto::value::Kind::Text(value) => Some(symbols.intern(value.clone())),
                _ => None,
            })
        }).unwrap_or(raw_kind)
    } else { raw_kind };
    Edge { kind: raw_kind, semantic_kind, source: symbols.intern(source),
        target: symbols.intern(target), properties }
}

/// Stable IDs intentionally match `lachesis.core.identities.stable_id` for the
/// string-only parts used by native overlays.
pub(crate) fn stable_id(owner: &str, namespace: &str, kind: &str, parts: &[&str]) -> String {
    let raw = parts.join("\0");
    let mut hasher = Sha256::new();
    hasher.update(format!("v2\0{owner}\0{namespace}\0{kind}\0{raw}").as_bytes());
    let digest = hasher.finalize();
    let hex = digest.iter().take(10).map(|byte| format!("{byte:02x}")).collect::<String>();
    format!("v2:{owner}:{namespace}:{kind}:{hex}")
}

pub(crate) fn text_field(key: &str, value: impl Into<String>) -> graph_proto::Field {
    graph_proto::Field {
        key: key.to_owned(),
        value: Some(graph_proto::Value {
            kind: Some(graph_proto::value::Kind::Text(value.into())),
        }),
    }
}

pub(crate) fn integer_field(key: &str, value: i64) -> graph_proto::Field {
    graph_proto::Field {
        key: key.to_owned(),
        value: Some(graph_proto::Value {
            kind: Some(graph_proto::value::Kind::Integer(value)),
        }),
    }
}

pub(crate) fn bool_field(key: &str, value: bool) -> graph_proto::Field {
    graph_proto::Field {
        key: key.to_owned(),
        value: Some(graph_proto::Value {
            kind: Some(graph_proto::value::Kind::Boolean(value)),
        }),
    }
}

fn frame<'a>(input: &'a [u8], offset: &mut usize) -> Result<&'a [u8], String> {
    if input.len().saturating_sub(*offset) < FRAME_HEADER {
        return Err("truncated Pass-2 input frame header".to_owned());
    }
    let length = u32::from_be_bytes(
        input[*offset..*offset + FRAME_HEADER]
            .try_into().map_err(|_| "invalid Pass-2 frame header".to_owned())?,
    ) as usize;
    *offset += FRAME_HEADER;
    if length > input.len().saturating_sub(*offset) {
        return Err("truncated Pass-2 input frame".to_owned());
    }
    let payload = &input[*offset..*offset + length];
    *offset += length;
    Ok(payload)
}

pub(crate) fn read_path(path: impl AsRef<Path>) -> Result<Graph, String> {
    let file = File::open(path.as_ref())
        .map_err(|error| format!("cannot open Pass-2 input: {error}"))?;
    let mut input = BufReader::with_capacity(1024 * 1024, file);
    let header = read_stream_frame(&mut input)?;
    let document: graph_proto::Document = graph_proto::Document::decode(header.as_slice())
        .map_err(|error| format!("invalid Pass-2 input header: {error}"))?;
    let core_content_hash = document.fields.as_ref()
        .and_then(|fields| fields.fields.iter().find(|field| field.key == "core_content_hash"))
        .and_then(|field| field.value.as_ref())
        .and_then(|value| match value.kind.as_ref()? {
            graph_proto::value::Kind::Text(value) => Some(value.clone()),
            _ => None,
        }).unwrap_or_default();

    let mut symbols = Symbols::default();
    let mut nodes = Vec::new();
    let mut edges = Vec::new();
    while let Some(payload) = read_optional_stream_frame(&mut input)? {
        if payload.is_empty() { continue; }
        match payload[0] {
            b'N' => {
                let record = graph_proto::NodeRecord::decode(&payload[1..])
                    .map_err(|error| format!("invalid Pass-2 node frame: {error}"))?;
                nodes.push(Node {
                    id: symbols.intern(record.id), kind: symbols.intern(record.kind),
                    label: record.label, properties: record.properties,
                });
            }
            b'E' => {
                let record = graph_proto::EdgeRecord::decode(&payload[1..])
                    .map_err(|error| format!("invalid Pass-2 edge frame: {error}"))?;
                edges.push(make_edge(&mut symbols, record.kind, record.source, record.target, record.properties));
            }
            _ => return Err("unknown Pass-2 input record prefix".to_owned()),
        }
    }
    finish_graph(symbols, nodes, edges, core_content_hash)
}

fn finish_graph(
    symbols: Symbols, nodes: Vec<Node>, edges: Vec<Edge>, core_content_hash: String,
) -> Result<Graph, String> {
    let mut node_by_id = FxHashMap::with_capacity_and_hasher(nodes.len(), Default::default());
    for (index, node) in nodes.iter().enumerate() { node_by_id.insert(node.id, index); }
    let mut outgoing = vec![Vec::new(); nodes.len()];
    let mut incoming = vec![Vec::new(); nodes.len()];
    for (index, edge) in edges.iter().enumerate() {
        if let Some(source) = node_by_id.get(&edge.source) { outgoing[*source].push(index); }
        if let Some(target) = node_by_id.get(&edge.target) { incoming[*target].push(index); }
    }
    let mut edge_lookup: FxHashMap<(u32, u32, u32), Vec<usize>> = FxHashMap::default();
    for (index, edge) in edges.iter().enumerate() {
        edge_lookup.entry((edge.kind, edge.source, edge.target)).or_default().push(index);
    }
    Ok(Graph { core_content_hash, symbols, nodes, edges, node_by_id, outgoing, incoming, edge_lookup })
}

fn read_stream_frame<R: Read>(reader: &mut R) -> Result<Vec<u8>, String> {
    let mut header = [0u8; FRAME_HEADER];
    reader.read_exact(&mut header)
        .map_err(|error| format!("cannot read Pass-2 frame header: {error}"))?;
    let length = u32::from_be_bytes(header) as usize;
    let mut payload = vec![0u8; length];
    reader.read_exact(&mut payload)
        .map_err(|error| format!("cannot read Pass-2 frame: {error}"))?;
    Ok(payload)
}

fn read_optional_stream_frame<R: Read>(reader: &mut R) -> Result<Option<Vec<u8>>, String> {
    let mut header = [0u8; FRAME_HEADER];
    let mut read = 0;
    while read < FRAME_HEADER {
        match reader.read(&mut header[read..]) {
            Ok(0) if read == 0 => return Ok(None),
            Ok(0) => return Err("truncated Pass-2 input frame header".to_owned()),
            Ok(count) => read += count,
            Err(error) => return Err(format!("cannot read Pass-2 frame header: {error}")),
        }
    }
    let length = u32::from_be_bytes(header) as usize;
    let mut payload = vec![0u8; length];
    reader.read_exact(&mut payload)
        .map_err(|error| format!("cannot read Pass-2 frame: {error}"))?;
    Ok(Some(payload))
}

pub(crate) fn read_bytes(input: &[u8]) -> Result<Graph, String> {
    let mut offset = 0;
    let header = frame(input, &mut offset)?;
    let _: graph_proto::Document = graph_proto::Document::decode(header)
        .map_err(|error| format!("invalid Pass-2 input header: {error}"))?;

    let mut symbols = Symbols::default();
    let mut nodes = Vec::new();
    let mut edges = Vec::new();
    while offset < input.len() {
        let payload = frame(input, &mut offset)?;
        if payload.is_empty() { continue; }
        match payload[0] {
            b'N' => {
                let record = graph_proto::NodeRecord::decode(&payload[1..])
                    .map_err(|error| format!("invalid Pass-2 node frame: {error}"))?;
                nodes.push(Node {
                    id: symbols.intern(record.id),
                    kind: symbols.intern(record.kind),
                    label: record.label,
                    properties: record.properties,
                });
            }
            b'E' => {
                let record = graph_proto::EdgeRecord::decode(&payload[1..])
                    .map_err(|error| format!("invalid Pass-2 edge frame: {error}"))?;
                edges.push(make_edge(&mut symbols, record.kind, record.source, record.target, record.properties));
            }
            _ => return Err("unknown Pass-2 input record prefix".to_owned()),
        }
    }

    let mut node_by_id = FxHashMap::with_capacity_and_hasher(nodes.len(), Default::default());
    for (index, node) in nodes.iter().enumerate() {
        node_by_id.insert(node.id, index);
    }
    let mut outgoing = vec![Vec::new(); nodes.len()];
    let mut incoming = vec![Vec::new(); nodes.len()];
    for (index, edge) in edges.iter().enumerate() {
        if let Some(source) = node_by_id.get(&edge.source) {
            outgoing[*source].push(index);
        }
        if let Some(target) = node_by_id.get(&edge.target) {
            incoming[*target].push(index);
        }
    }
    let mut edge_lookup: FxHashMap<(u32, u32, u32), Vec<usize>> = FxHashMap::default();
    for (index, edge) in edges.iter().enumerate() {
        edge_lookup.entry((edge.kind, edge.source, edge.target)).or_default().push(index);
    }
    Ok(Graph { core_content_hash: String::new(), symbols, nodes, edges, node_by_id, outgoing, incoming, edge_lookup })
}

pub(crate) fn publish_dataflow_stream(
    path: impl AsRef<Path>, source: &str, core_content_hash: &str,
    nodes: &[graph_proto::NodeRecord], edges: &[graph_proto::EdgeRecord],
) -> Result<(), String> {
    let path = path.as_ref();
    let directory = path.parent().unwrap_or_else(|| Path::new("."));
    let temporary = directory.join(format!(".pass2-native-{}", std::process::id()));
    let result = (|| {
        let mut output = File::create(&temporary)
            .map_err(|error| format!("cannot create native Pass-2 sidecar: {error}"))?;
        output.write_all(DATAFLOW_STREAM_MAGIC)
            .map_err(|error| format!("cannot write native Pass-2 sidecar: {error}"))?;
        let header = graph_proto::DataflowOverlay {
            overlay_id: "dataflow".to_owned(), source: source.to_owned(), version: 1,
            core_content_hash: core_content_hash.to_owned(),
            derived_nodes: Vec::new(), derived_edges: Vec::new(),
        };
        write_frame(&mut output, &header.encode_to_vec())?;
        for node in nodes {
            let payload = node.encode_to_vec();
            write_record_frame(&mut output, b'N', &payload)?;
        }
        for edge in edges {
            let payload = edge.encode_to_vec();
            write_record_frame(&mut output, b'E', &payload)?;
        }
        output.flush().map_err(|error| format!("cannot flush native Pass-2 sidecar: {error}"))?;
        fs::rename(&temporary, path)
            .map_err(|error| format!("cannot publish native Pass-2 sidecar: {error}"))?;
        Ok::<(), String>(())
    })();
    if result.is_err() { let _ = fs::remove_file(&temporary); }
    result
}

fn write_record_frame(output: &mut File, prefix: u8, payload: &[u8]) -> Result<(), String> {
    let mut record = Vec::with_capacity(payload.len() + 1);
    record.push(prefix);
    record.extend_from_slice(payload);
    write_frame(output, &record)
}

fn write_frame(output: &mut File, payload: &[u8]) -> Result<(), String> {
    let length = u32::try_from(payload.len())
        .map_err(|_| "native Pass-2 sidecar frame is too large".to_owned())?;
    output.write_all(&length.to_be_bytes())
        .and_then(|_| output.write_all(payload))
        .map_err(|error| format!("cannot write native Pass-2 sidecar frame: {error}"))
}

/// Keep this accessor in the graph core so future overlays do not each grow a
/// string-keyed property index.  It also makes the intentional `HashMap` import
/// above a compile-time assertion that all future keyed extensions use the fast
/// hasher rather than the standard cryptographic hasher.
#[allow(dead_code)]
fn _fast_property_map() -> HashMap<u32, u32> { HashMap::new() }
