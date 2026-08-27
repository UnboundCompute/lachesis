//! Stream native Pass-1 shard records into the two immutable Pass-1 sidecars.
//!
//! Native frontends already emit typed protobuf frames.  Keeping this small
//! projection in Rust avoids decoding every native record into Python merely to
//! copy the lossless Pass-2 stream and build the scalar Pass-3 substrate.

use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use hashbrown::HashSet;
use prost::Message;

use crate::graph_proto;

const FRAME_HEADER: usize = 4;

const SUBSTRATE_NODE_KINDS: &[&str] = &[
    "ArraySubscriptExpr", "BinaryOperator", "BreakStmt", "CallExpr", "CaseStmt",
    "CompoundAssignOperator", "CompoundStmt", "ConditionalOperator", "ContinueStmt",
    "CXXMemberCallExpr", "CXXNullPtrLiteralExpr", "CXXOperatorCallExpr", "DeclRefExpr",
    "DeclStmt", "DefaultStmt", "DoStmt", "ForStmt", "GNUNullExpr", "GotoStmt",
    "IfStmt", "ImplicitCastExpr", "ImplicitValueInitExpr", "IntegerLiteral", "LabelStmt",
    "MemberExpr", "ParenExpr", "ParmVarDecl", "ReturnStmt", "StringLiteral", "SwitchStmt",
    "UnaryOperator", "UnaryExprOrTypeTraitExpr", "VarDecl", "WhileStmt", "cfg-entry",
    "cfg-exit", "cfg-merge", "cfg-condition", "function", "method", "constructor",
    "FunctionDecl", "CXXMethodDecl", "CXXConstructorDecl", "CXXDestructorDecl",
    "FunctionDef", "AsyncFunctionDef", "FunctionDeclaration", "ArrowFunction",
    "MethodDeclaration", "MethodDefinition", "Call", "CallExpression", "construct",
    "NewExpression", "Return", "ReturnStatement", "return", "allocation", "release",
    "realloc", "parameter", "arg",
];

const SUBSTRATE_PROPERTY_KEYS: &[&str] = &[
    "absolute_file", "end_line", "end_offset", "file", "function_id", "operator",
    "owner_function_id", "receiver", "receiver_id", "receiver_member_id",
    "receiver_symbol_id", "receiver_value", "receiver_value_id", "start_line",
    "start_offset", "syntax_kind", "type", "callee", "form", "method_name",
    "primary_target_id", "callee_name", "callee_form", "argument_count", "release_method",
    "release_name", "release_line", "target_id", "value_id", "resolution",
    "allocation_kind", "allocated_type", "control_kind", "is_alloc", "is_release",
    "is_realloc", "is_aggregate_copy", "declaration_only", "storage_class", "owner_id",
];

fn frame_read<R: Read>(reader: &mut R) -> Result<Option<Vec<u8>>, String> {
    let mut header = [0u8; FRAME_HEADER];
    match reader.read_exact(&mut header) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(format!("cannot read protobuf frame header: {error}")),
    }
    let length = u32::from_be_bytes(header) as usize;
    let mut payload = vec![0u8; length];
    reader.read_exact(&mut payload)
        .map_err(|error| format!("truncated protobuf frame: {error}"))?;
    Ok(Some(payload))
}

fn frame_write<W: Write>(writer: &mut W, payload: &[u8]) -> Result<(), String> {
    let length = u32::try_from(payload.len())
        .map_err(|_| "protobuf record exceeds 4 GiB frame limit".to_owned())?;
    writer.write_all(&length.to_be_bytes())
        .and_then(|_| writer.write_all(payload))
        .map_err(|error| format!("cannot write protobuf frame: {error}"))
}

fn scalar<'a>(record: &'a graph_proto::NodeRecord, key: &str)
    -> Option<&'a graph_proto::Value>
{
    record.properties.iter().find_map(|field| {
        (field.key == key).then_some(field.value.as_ref()).flatten()
    })
}

fn scalar_edge<'a>(record: &'a graph_proto::EdgeRecord, key: &str)
    -> Option<&'a graph_proto::Value>
{
    record.properties.iter().find_map(|field| {
        (field.key == key).then_some(field.value.as_ref()).flatten()
    })
}

fn text_value(value: &graph_proto::Value) -> Option<&str> {
    match value.kind.as_ref()? {
        graph_proto::value::Kind::Text(value) => Some(value.as_str()),
        _ => None,
    }
}

fn semantic_kind(record: &graph_proto::EdgeRecord) -> &str {
    scalar_edge(record, "semantic_kind")
        .and_then(text_value)
        .unwrap_or(record.kind.as_str())
}

fn syntax_kind(record: &graph_proto::NodeRecord) -> &str {
    scalar(record, "syntax_kind")
        .and_then(text_value)
        .unwrap_or(record.kind.as_str())
}

fn compact_node(record: graph_proto::NodeRecord) -> graph_proto::NodeRecord {
    let properties = record.properties.into_iter().filter(|field| {
        SUBSTRATE_PROPERTY_KEYS.contains(&field.key.as_str())
            && field.value.as_ref().and_then(|value| value.kind.as_ref()).is_some_and(|kind| {
                matches!(kind,
                    graph_proto::value::Kind::Text(_)
                    | graph_proto::value::Kind::Integer(_)
                    | graph_proto::value::Kind::Real(_)
                    | graph_proto::value::Kind::Boolean(_))
            })
    }).collect();
    graph_proto::NodeRecord {
        id: record.id,
        kind: record.kind,
        label: record.label,
        properties,
        tier: String::new(),
    }
}

fn compact_edge(record: graph_proto::EdgeRecord) -> Option<graph_proto::EdgeRecord> {
    let kind = semantic_kind(&record).to_owned();
    let properties = match kind.as_str() {
        "AST_CHILD" => record.properties.into_iter().filter(|field| {
            field.key == "role" || field.key == "position"
        }).collect(),
        "REFERS_TO" | "CFG_NEXT" => Vec::new(),
        "VALUE_FLOWS_TO" => {
            let properties: Vec<_> = record.properties.into_iter().filter(|field| {
                field.key == "reason" && field.value.as_ref()
                    .and_then(text_value).is_some_and(|value| value == "initializer")
            }).collect();
            if properties.is_empty() { return None; }
            properties
        }
        _ => return None,
    };
    Some(graph_proto::EdgeRecord {
        kind,
        source: record.source,
        target: record.target,
        properties,
        source_tier: String::new(),
        relationship_class: String::new(),
    })
}

fn text_field(key: &str, value: &str) -> graph_proto::Field {
    graph_proto::Field {
        key: key.to_owned(),
        value: Some(graph_proto::Value {
            kind: Some(graph_proto::value::Kind::Text(value.to_owned())),
        }),
    }
}

fn integer_field(key: &str, value: i64) -> graph_proto::Field {
    graph_proto::Field {
        key: key.to_owned(),
        value: Some(graph_proto::Value {
            kind: Some(graph_proto::value::Kind::Integer(value)),
        }),
    }
}

fn optional_text_field(key: &str, value: &str) -> graph_proto::Field {
    if value.is_empty() {
        graph_proto::Field {
            key: key.to_owned(),
            value: Some(graph_proto::Value {
                kind: Some(graph_proto::value::Kind::NullValue(graph_proto::NullValue {})),
            }),
        }
    } else {
        text_field(key, value)
    }
}

fn optional_integer_field(key: &str, value: &str) -> graph_proto::Field {
    match value.parse::<i64>() {
        Ok(value) => integer_field(key, value),
        Err(_) => graph_proto::Field {
            key: key.to_owned(),
            value: Some(graph_proto::Value {
                kind: Some(graph_proto::value::Kind::NullValue(graph_proto::NullValue {})),
            }),
        },
    }
}

fn record_frame(prefix: u8, payload: Vec<u8>) -> Vec<u8> {
    let mut record = Vec::with_capacity(payload.len() + 1);
    record.push(prefix);
    record.extend_from_slice(&payload);
    record
}

fn document(fields: Vec<graph_proto::Field>) -> Vec<u8> {
    graph_proto::Document {
        format_version: 1,
        fields: Some(graph_proto::ObjectValue { fields }),
    }.encode_to_vec()
}

fn copy_frames(source: &Path, output: &mut BufWriter<File>) -> Result<(), String> {
    let mut input = BufReader::new(File::open(source)
        .map_err(|error| format!("cannot open staged sidecar: {error}"))?);
    let mut buffer = [0u8; 1024 * 1024];
    loop {
        let count = input.read(&mut buffer)
            .map_err(|error| format!("cannot read staged sidecar: {error}"))?;
        if count == 0 { break; }
        output.write_all(&buffer[..count])
            .map_err(|error| format!("cannot copy staged sidecar: {error}"))?;
    }
    Ok(())
}

fn temporary_path(output: &Path, label: &str) -> PathBuf {
    output.with_file_name(format!(".pass1-{label}-{}", std::process::id()))
}

/// Project one already-framed native shard into Pass-2 and Pass-3 sidecars.
/// The input remains on disk; records are decoded one at a time and no graph
/// sized Python or Rust collection is created.
pub(crate) fn project_shards(
    shard_paths: &[(PathBuf, PathBuf)],
    pass2_output: &Path,
    pass3_output: &Path,
    store_version: &str,
    core_content_hash: &str,
    source_content_hash: &str,
    build_fingerprint: &str,
    prune: bool,
) -> Result<(), String> {
    let pass2_nodes = temporary_path(pass2_output, "pass2-nodes");
    let pass2_edges = temporary_path(pass2_output, "pass2-edges");
    let pass3_nodes = temporary_path(pass3_output, "pass3-nodes");
    let pass3_edges = temporary_path(pass3_output, "pass3-edges");
    let cleanup = || {
        for path in [&pass2_nodes, &pass2_edges, &pass3_nodes, &pass3_edges] {
            let _ = fs::remove_file(path);
        }
    };
    let result = (|| {
        let mut kept_ids = HashSet::new();
        let mut pass2_node_count = 0usize;
        let mut pass3_node_count = 0usize;
        let mut member_count = 0usize;
        {
            let mut complete = BufWriter::new(File::create(&pass2_nodes)
                .map_err(|error| format!("cannot create Pass-2 node staging: {error}"))?);
            let mut compact = BufWriter::new(File::create(&pass3_nodes)
                .map_err(|error| format!("cannot create Pass-3 node staging: {error}"))?);
            for (nodes_path, _) in shard_paths {
                let input = File::open(nodes_path)
                    .map_err(|error| format!("cannot open native node shard: {error}"))?;
                let mut input = BufReader::new(input);
                while let Some(payload) = frame_read(&mut input)? {
                    let record = graph_proto::NodeRecord::decode(payload.as_slice())
                        .map_err(|error| format!("invalid native node protobuf: {error}"))?;
                    if prune && matches!(record.kind.as_str(), "token" | "source-span") {
                        continue;
                    }
                    kept_ids.insert(record.id.clone());
                    frame_write(&mut complete, &record_frame(b'N', record.encode_to_vec()))?;
                    pass2_node_count += 1;
                    let syntax = syntax_kind(&record).to_owned();
                    if !SUBSTRATE_NODE_KINDS.contains(&syntax.as_str()) { continue; }
                    let compact_record = compact_node(record);
                    frame_write(&mut compact, &record_frame(b'N', compact_record.encode_to_vec()))?;
                    pass3_node_count += 1;
                    if syntax == "MemberExpr" { member_count += 1; }
                }
            }
            complete.flush().map_err(|error| format!("flush Pass-2 node staging: {error}"))?;
            compact.flush().map_err(|error| format!("flush Pass-3 node staging: {error}"))?;
        }
        let mut pass2_edge_count = 0usize;
        let mut pass3_edge_count = 0usize;
        {
            let mut complete = BufWriter::new(File::create(&pass2_edges)
                .map_err(|error| format!("cannot create Pass-2 edge staging: {error}"))?);
            let mut compact = BufWriter::new(File::create(&pass3_edges)
                .map_err(|error| format!("cannot create Pass-3 edge staging: {error}"))?);
            for (_, edges_path) in shard_paths {
                let input = File::open(edges_path)
                    .map_err(|error| format!("cannot open native edge shard: {error}"))?;
                let mut input = BufReader::new(input);
                while let Some(payload) = frame_read(&mut input)? {
                    let record = graph_proto::EdgeRecord::decode(payload.as_slice())
                        .map_err(|error| format!("invalid native edge protobuf: {error}"))?;
                    if !kept_ids.contains(&record.source) || !kept_ids.contains(&record.target) {
                        continue;
                    }
                    frame_write(&mut complete, &record_frame(b'E', record.encode_to_vec()))?;
                    pass2_edge_count += 1;
                    if let Some(compact_record) = compact_edge(record) {
                        frame_write(&mut compact, &record_frame(b'E', compact_record.encode_to_vec()))?;
                        pass3_edge_count += 1;
                    }
                }
            }
            complete.flush().map_err(|error| format!("flush Pass-2 edge staging: {error}"))?;
            compact.flush().map_err(|error| format!("flush Pass-3 edge staging: {error}"))?;
        }
        let pass2_header = document(vec![
            text_field("format", "lachesis-pass2-input"),
            integer_field("version", 1),
            integer_field("node_count", pass2_node_count as i64),
            integer_field("edge_count", pass2_edge_count as i64),
            optional_integer_field("store_version", store_version),
            optional_text_field("core_content_hash", core_content_hash),
            optional_text_field("source_content_hash", source_content_hash),
            optional_text_field("build_fingerprint", build_fingerprint),
        ]);
        let pass3_header = document(vec![
            text_field("type", "header"),
            text_field("format", "lachesis-pass3-substrate"),
            integer_field("version", 4),
            integer_field("edge_count", pass3_edge_count as i64),
            integer_field("node_count", pass3_node_count as i64),
            integer_field("member_count", member_count as i64),
            optional_integer_field("store_version", store_version),
            optional_text_field("core_content_hash", core_content_hash),
            optional_text_field("source_content_hash", source_content_hash),
            optional_text_field("build_fingerprint", build_fingerprint),
        ]);
        publish(&pass2_header, &pass2_nodes, &pass2_edges, pass2_output)?;
        publish(&pass3_header, &pass3_nodes, &pass3_edges, pass3_output)?;
        Ok(())
    })();
    cleanup();
    result
}

pub(crate) fn project_shard(
    nodes_path: &Path,
    edges_path: &Path,
    pass2_output: &Path,
    pass3_output: &Path,
    store_version: &str,
    core_content_hash: &str,
    source_content_hash: &str,
    build_fingerprint: &str,
    prune: bool,
) -> Result<(), String> {
    project_shards(
        &[(nodes_path.to_owned(), edges_path.to_owned())], pass2_output,
        pass3_output, store_version, core_content_hash, source_content_hash,
        build_fingerprint, prune,
    )
}

fn publish(header: &[u8], nodes: &Path, edges: &Path, output: &Path) -> Result<(), String> {
    let temporary = output.with_file_name(format!(".{}-{}", output.file_name().unwrap_or_default().to_string_lossy(), std::process::id()));
    let result = (|| {
        let file = File::create(&temporary)
            .map_err(|error| format!("cannot create native sidecar: {error}"))?;
        let mut output_file = BufWriter::new(file);
        frame_write(&mut output_file, header)?;
        copy_frames(nodes, &mut output_file)?;
        copy_frames(edges, &mut output_file)?;
        output_file.flush().map_err(|error| format!("cannot flush native sidecar: {error}"))?;
        fs::rename(&temporary, output)
            .map_err(|error| format!("cannot publish native sidecar: {error}"))?;
        Ok(())
    })();
    if result.is_err() { let _ = fs::remove_file(&temporary); }
    result
}
