use clang_sys::*;
use prost::Message;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::env;
use std::ffi::{CStr, CString};
use std::fs::{self, File};
use std::io::{self, Write};
use std::os::raw::{c_char, c_int, c_void};
use std::path::{Path, PathBuf};
use std::ptr;

mod graph {
    include!(concat!(env!("OUT_DIR"), "/lachesis.graph.rs"));
}

const SHARD_FORMAT_VERSION: u32 = 2;

fn frame(file: &mut File, payload: &[u8]) -> io::Result<()> {
    let size = u32::try_from(payload.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "record exceeds 4 GiB"))?;
    file.write_all(&size.to_be_bytes())?;
    file.write_all(payload)
}

fn text(value: &str) -> graph::Value {
    graph::Value {
        kind: Some(graph::value::Kind::Text(value.to_owned())),
    }
}

fn integer(value: i64) -> graph::Value {
    graph::Value {
        kind: Some(graph::value::Kind::Integer(value)),
    }
}

fn field(key: &str, value: graph::Value) -> graph::Field {
    graph::Field {
        key: key.to_owned(),
        value: Some(value),
    }
}

fn text_list(values: impl IntoIterator<Item = String>) -> graph::Value {
    graph::Value {
        kind: Some(graph::value::Kind::List(graph::ListValue {
            values: values.into_iter().map(|value| text(&value)).collect(),
        })),
    }
}

fn stable_id(kind: &str, file: &str, offset: u32, end: u32, spelling: &str) -> String {
    let raw = format!("{file}\0{offset}\0{end}\0{spelling}");
    let mut digest = Sha256::new();
    digest.update(b"v2\0frontend\0clang-c\0");
    digest.update(kind.as_bytes());
    digest.update(b"\0");
    digest.update(raw.as_bytes());
    let hex = format!("{:x}", digest.finalize());
    format!("v2:frontend:clang-c:{kind}:{}", &hex[..20])
}

fn stable_id_parts(kind: &str, parts: &[String]) -> String {
    let raw = parts.join("\0");
    let mut digest = Sha256::new();
    digest.update(b"v2\0frontend\0clang-c\0");
    digest.update(kind.as_bytes());
    digest.update(b"\0");
    digest.update(raw.as_bytes());
    let hex = format!("{:x}", digest.finalize());
    format!("v2:frontend:clang-c:{kind}:{}", &hex[..20])
}

unsafe fn cx_string(value: CXString) -> String {
    let pointer = clang_getCString(value);
    let result = if pointer.is_null() {
        String::new()
    } else {
        CStr::from_ptr(pointer).to_string_lossy().into_owned()
    };
    clang_disposeString(value);
    result
}

unsafe fn cursor_file(cursor: CXCursor) -> (String, u32, u32, u32, u32) {
    let location = clang_getCursorLocation(cursor);
    let mut file = ptr::null_mut();
    let mut line = 0;
    let mut column = 0;
    let mut offset = 0;
    clang_getSpellingLocation(location, &mut file, &mut line, &mut column, &mut offset);
    let filename = if file.is_null() {
        String::new()
    } else {
        let raw = cx_string(clang_getFileName(file));
        PathBuf::from(&raw)
            .canonicalize()
            .unwrap_or_else(|_| PathBuf::from(raw))
            .to_string_lossy()
            .into_owned()
    };

    let extent = clang_getCursorExtent(cursor);
    let end_location = clang_getRangeEnd(extent);
    let mut end_file = ptr::null_mut();
    let mut end_line = 0;
    let mut end_column = 0;
    let mut end_offset = offset;
    clang_getSpellingLocation(
        end_location,
        &mut end_file,
        &mut end_line,
        &mut end_column,
        &mut end_offset,
    );
    (filename, line, column, offset, end_offset)
}

struct Emitter {
    nodes: File,
    edges: File,
    node_ids: HashSet<String>,
    edge_ids: HashSet<(String, String, String)>,
    node_count: u64,
    edge_count: u64,
    file_ids: HashMap<String, String>,
    root_files: HashSet<String>,
}

impl Emitter {
    fn node(&mut self, record: graph::NodeRecord) -> io::Result<()> {
        if !self.node_ids.insert(record.id.clone()) {
            return Ok(());
        }
        frame(&mut self.nodes, &record.encode_to_vec())?;
        self.node_count += 1;
        Ok(())
    }

    fn edge(&mut self, record: graph::EdgeRecord) -> io::Result<()> {
        let key = (record.kind.clone(), record.source.clone(), record.target.clone());
        if !self.edge_ids.insert(key) {
            return Ok(());
        }
        frame(&mut self.edges, &record.encode_to_vec())?;
        self.edge_count += 1;
        Ok(())
    }
}

fn emit_file_node(emitter: &mut Emitter, path: &str, source_dir: &str) -> io::Result<()> {
    let absolute = Path::new(path)
        .canonicalize()
        .unwrap_or_else(|_| PathBuf::from(path));
    let absolute_text = absolute.to_string_lossy().into_owned();
    let display = Path::new(&absolute_text)
        .strip_prefix(source_dir)
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_else(|_| absolute_text.clone());
    let bytes = fs::read(&absolute).unwrap_or_default();
    let mut digest = Sha256::new();
    digest.update(&bytes);
    let content_hash = format!("{:x}", digest.finalize());
    let lines = bytes.iter().filter(|byte| **byte == b'\n').count() as i64
        + if !bytes.is_empty() && !bytes.ends_with(b"\n") { 1 } else { 0 };
    let id = stable_id_parts("file", &[absolute_text.clone()]);
    emitter.file_ids.insert(absolute_text.clone(), id.clone());
    emitter.node(graph::NodeRecord {
        id,
        kind: "file".to_owned(),
        label: display.clone(),
        properties: vec![
            field("file", text(&display)),
            field("absolute_file", text(&absolute_text)),
            field("content_hash", text(&content_hash)),
            field("lines", integer(lines)),
            field("language", text("c")),
            field("provenance", text("project-root")),
            field("is_external", graph::Value { kind: Some(graph::value::Kind::Boolean(false)) }),
            field("is_system", graph::Value { kind: Some(graph::value::Kind::Boolean(false)) }),
            field("included_because", text("project-root")),
        ],
        tier: "T0".to_owned(),
    })
}

fn emit_macros_for_file(emitter: &mut Emitter, path: &str) -> io::Result<()> {
    let bytes = fs::read(path).unwrap_or_default();
    let source = String::from_utf8_lossy(&bytes);
    let file_id = match emitter.file_ids.get(path) {
        Some(id) => id.clone(),
        None => return Ok(()),
    };
    let mut line_offset = 0u32;
    for line in source.split_inclusive('\n') {
        let without_newline = line.strip_suffix('\n').unwrap_or(line);
        let leading = without_newline.len() - without_newline.trim_start().len();
        let definition = without_newline[leading..].strip_prefix("#define");
        if let Some(definition) = definition {
            let definition = definition.trim_start();
            let name_end = definition
                .find(|character: char| !(character == '_' || character.is_ascii_alphanumeric()))
                .unwrap_or(definition.len());
            if name_end == 0 {
                line_offset = line_offset.saturating_add(line.len() as u32);
                continue;
            }
            let name = &definition[..name_end];
            let mut rest = &definition[name_end..];
            let mut parameters = Vec::new();
            let form = if rest.starts_with('(') {
                if let Some(close) = rest.find(')') {
                    parameters.extend(
                        rest[1..close]
                            .split(',')
                            .map(str::trim)
                            .filter(|value| !value.is_empty())
                            .map(str::to_owned),
                    );
                    rest = &rest[close + 1..];
                    "function-like"
                } else {
                    "object-like"
                }
            } else {
                "object-like"
            };
            let body = rest.trim().to_owned();
            let macro_id = stable_id_parts(
                "macro",
                &[path.to_owned(), line_offset.to_string(), name.to_owned()],
            );
            let signature = if form == "function-like" {
                format!("{}({})", name, parameters.join(", "))
            } else {
                name.to_owned()
            };
            let end_column = without_newline.len().max(1) as i64;
            emitter.node(graph::NodeRecord {
                id: macro_id.clone(), kind: "macro".to_owned(), label: name.to_owned(),
                properties: vec![
                    field("file", text(path)), field("absolute_file", text(path)),
                    field("start_offset", integer(line_offset as i64)),
                    field("end_offset", integer(line_offset as i64 + without_newline.len() as i64)),
                    field("start_line", integer(source[..line_offset as usize].bytes().filter(|b| *b == b'\n').count() as i64 + 1)),
                    field("start_column", integer(leading as i64 + 1)),
                    field("end_line", integer(source[..line_offset as usize].bytes().filter(|b| *b == b'\n').count() as i64 + 1)),
                    field("end_column", integer(end_column)), field("syntax_kind", text("macro")),
                    field("form", text(form)), field("parameters", text_list(parameters)),
                    field("body", text(&body)), field("signature", text(&signature)),
                ], tier: "T1".to_owned(),
            })?;
            emitter.edge(graph::EdgeRecord {
                kind: "DECLARES".to_owned(), source: file_id.clone(), target: macro_id,
                properties: Vec::new(), source_tier: "T0".to_owned(),
                relationship_class: "DECLARES".to_owned(),
            })?;
        }
        line_offset = line_offset.saturating_add(line.len() as u32);
    }
    Ok(())
}

extern "C" fn visit(cursor: CXCursor, parent: CXCursor, data: CXClientData) -> CXChildVisitResult {
    unsafe {
        let emitter = &mut *(data as *mut Emitter);
        if let Err(error) = visit_one(cursor, parent, emitter) {
            eprintln!("native clang frontend: {error}");
            return CXChildVisit_Break;
        }
    }
    CXChildVisit_Recurse
}

unsafe fn visit_one(cursor: CXCursor, parent: CXCursor, emitter: &mut Emitter) -> io::Result<()> {
    let syntax_kind = cx_string(clang_getCursorKindSpelling(clang_getCursorKind(cursor)));
    let spelling = cx_string(clang_getCursorSpelling(cursor));
    let (file, line, column, offset, end_offset) = cursor_file(cursor);
    if file.is_empty() || (!emitter.root_files.is_empty() && !emitter.root_files.contains(&file)) {
        return Ok(());
    }

    let (node_kind, tier, id) = if let Some(mapped_kind) = match syntax_kind.as_str() {
        "FunctionDecl" => Some("function"),
        "RecordDecl" | "StructDecl" | "UnionDecl" => Some("record"),
        "EnumDecl" => Some("enum"),
        "TypedefDecl" => Some("type"),
        "ParmVarDecl" | "ParmDecl" => Some("parameter"),
        "VarDecl" => Some("variable"),
        "FieldDecl" => Some("property"),
        "EnumConstantDecl" => Some("constant"),
        _ => None,
    } {
        let id_kind = if matches!(syntax_kind.as_str(), "ParmVarDecl" | "VarDecl" | "FieldDecl" | "EnumConstantDecl") {
            "value"
        } else {
            mapped_kind
        };
        (
            mapped_kind.to_owned(),
            if id_kind == "value" { "T2" } else { "T1" }.to_owned(),
            stable_id(id_kind, &file, offset, end_offset, &spelling),
        )
    } else if syntax_kind == "CallExpr"
        || syntax_kind.ends_with("Stmt")
        || syntax_kind.ends_with("Expr")
        || syntax_kind.ends_with("Operator")
        || matches!(syntax_kind.as_str(), "IntegerLiteral" | "StringLiteral" | "CharacterLiteral")
    {
        (
            if syntax_kind == "CallExpr" { "call" } else if syntax_kind.ends_with("Stmt") { "statement" } else { "expression" }.to_owned(),
            "T3".to_owned(),
            stable_id("body", &file, offset, end_offset, &syntax_kind),
        )
    } else {
        return Ok(());
    };

    let type_spelling = cx_string(clang_getTypeSpelling(clang_getCursorType(cursor)));
    let mut properties = vec![
        field("file", text(&file)),
        field("absolute_file", text(&file)),
        field("start_offset", integer(offset as i64)),
        field("end_offset", integer(end_offset as i64)),
        field("start_line", integer(line as i64)),
        field("start_column", integer(column as i64)),
        field("syntax_kind", text(&syntax_kind)),
        field("type", text(&type_spelling)),
    ];
    let owner_id = function_owner(cursor);
    if let Some(owner_id) = &owner_id {
        properties.push(field("owner_function_id", text(owner_id)));
    }
    let mut call_target = None;
    if syntax_kind == "CallExpr" {
        let referenced = clang_getCursorReferenced(cursor);
        if clang_is_null(referenced) == 0 {
            let target_kind = cx_string(clang_getCursorKindSpelling(clang_getCursorKind(referenced)));
            let target_name = cx_string(clang_getCursorSpelling(referenced));
            let (target_file, _, _, target_offset, target_end) = cursor_file(referenced);
            if !target_file.is_empty() {
                let target_id_kind = match target_kind.as_str() {
                    "FunctionDecl" => Some("function"),
                    "VarDecl" | "ParmVarDecl" | "ParmDecl" | "FieldDecl" => Some("value"),
                    _ => None,
                };
                if let Some(target_id_kind) = target_id_kind {
                    let target_id = stable_id(target_id_kind, &target_file, target_offset, target_end, &target_name);
                    properties.push(field("callee", text(&target_name)));
                    properties.push(field("primary_target_id", text(&target_id)));
                    properties.push(field("resolution", text("exact")));
                    call_target = Some(target_id.clone());
                    emitter.edge(graph::EdgeRecord {
                        kind: "INVOKES".to_owned(),
                        source: id.clone(),
                        target: target_id,
                        properties: Vec::new(),
                        source_tier: tier.clone(),
                        relationship_class: "INVOKES".to_owned(),
                    })?;
                }
            }
        }
    }
    emitter.node(graph::NodeRecord {
        id: id.clone(),
        kind: node_kind.clone(),
        label: if spelling.is_empty() { syntax_kind.clone() } else { spelling },
        properties,
        tier: tier.clone(),
    })?;

    if syntax_kind == "CallExpr" {
        if let (Some(owner_id), Some(target_id)) = (owner_id, call_target) {
            emitter.edge(graph::EdgeRecord {
                kind: "CALLS".to_owned(), source: owner_id, target: target_id,
                properties: Vec::new(), source_tier: "T1".to_owned(),
                relationship_class: "CALLS".to_owned(),
            })?;
        }
    } else if syntax_kind == "DeclRefExpr" {
        let referenced = clang_getCursorReferenced(cursor);
        if clang_is_null(referenced) == 0 {
            let target_kind = cx_string(clang_getCursorKindSpelling(clang_getCursorKind(referenced)));
            let target_name = cx_string(clang_getCursorSpelling(referenced));
            let (target_file, _, _, target_offset, target_end) = cursor_file(referenced);
            let id_kind = match target_kind.as_str() {
                "FunctionDecl" => Some("function"),
                "VarDecl" | "ParmVarDecl" | "ParmDecl" | "FieldDecl" => Some("value"),
                _ => None,
            };
            if let (Some(id_kind), Some(_owner_id)) = (id_kind, owner_id) {
                let target_id = stable_id(id_kind, &target_file, target_offset, target_end, &target_name);
                emitter.edge(graph::EdgeRecord {
                    kind: "REFERS_TO".to_owned(), source: id.clone(), target: target_id.clone(),
                    properties: Vec::new(), source_tier: tier.clone(), relationship_class: "REFERS_TO".to_owned(),
                })?;
                emitter.edge(graph::EdgeRecord {
                    kind: "VALUE_FLOWS_TO".to_owned(), source: target_id, target: id.clone(),
                    properties: vec![field("reason", text("read"))], source_tier: tier.clone(),
                    relationship_class: "VALUE_FLOWS_TO".to_owned(),
                })?;
            }
        }
    }

    let (parent_file, _parent_line, _parent_column, parent_offset, parent_end) = cursor_file(parent);
    let parent_kind = cx_string(clang_getCursorKindSpelling(clang_getCursorKind(parent)));
    let parent_spelling = cx_string(clang_getCursorSpelling(parent));
    if let Some((_parent_kind, parent_tier, parent_id)) = cursor_identity(
        &parent_kind, &parent_file, parent_offset, parent_end, &parent_spelling,
    ) {
        let edge_kind = if node_kind == "function" || node_kind == "record" || node_kind == "enum" || node_kind == "type" {
            "DECLARES"
        } else if node_kind == "parameter" || node_kind == "variable" || node_kind == "property" || node_kind == "constant" {
            "DECLARES_VALUE"
        } else if tier == "T3" && parent_tier == "T1" {
            "CONTAINS_BODY"
        } else {
            "AST_CHILD"
        };
        emitter.edge(graph::EdgeRecord {
            kind: edge_kind.to_owned(),
            source: parent_id,
            target: id,
            properties: Vec::new(),
            source_tier: parent_tier,
            relationship_class: edge_kind.to_owned(),
        })?;
    } else if let Some(file_id) = emitter.file_ids.get(&file) {
        let edge_kind = if tier == "T3" { "CONTAINS_BODY" } else if node_kind == "parameter" || node_kind == "variable" || node_kind == "property" || node_kind == "constant" { "DECLARES_VALUE" } else { "DECLARES" };
        emitter.edge(graph::EdgeRecord {
            kind: edge_kind.to_owned(), source: file_id.clone(), target: id,
            properties: Vec::new(), source_tier: "T0".to_owned(), relationship_class: edge_kind.to_owned(),
        })?;
    }
    Ok(())
}

unsafe fn function_owner(cursor: CXCursor) -> Option<String> {
    let mut current = clang_getCursorSemanticParent(cursor);
    for _ in 0..32 {
        let (file, _, _, offset, end_offset) = cursor_file(current);
        if file.is_empty() || clang_is_null(current) != 0 {
            return None;
        }
        let syntax_kind = cx_string(clang_getCursorKindSpelling(clang_getCursorKind(current)));
        let spelling = cx_string(clang_getCursorSpelling(current));
        if syntax_kind == "FunctionDecl" {
            return Some(stable_id("function", &file, offset, end_offset, &spelling));
        }
        let next = clang_getCursorSemanticParent(current);
        if clang_is_null(next) != 0 {
            return None;
        }
        current = next;
    }
    None
}

unsafe fn clang_is_null(cursor: CXCursor) -> c_int {
    (clang_sys::clang_equalCursors(cursor, clang_sys::clang_getNullCursor()) != 0) as c_int
}

fn cursor_identity(
    syntax_kind: &str, file: &str, offset: u32, end_offset: u32, spelling: &str,
) -> Option<(String, String, String)> {
    if file.is_empty() {
        return None;
    }
    let (kind, tier, id_kind) = match syntax_kind {
        "FunctionDecl" => ("function", "T1", "function"),
        "RecordDecl" | "StructDecl" | "UnionDecl" => ("record", "T1", "record"),
        "EnumDecl" => ("enum", "T1", "enum"),
        "TypedefDecl" => ("type", "T1", "type"),
        "ParmVarDecl" | "ParmDecl" => ("parameter", "T2", "value"),
        "VarDecl" => ("variable", "T2", "value"),
        "FieldDecl" => ("property", "T2", "value"),
        "EnumConstantDecl" => ("constant", "T2", "value"),
        "CallExpr" => ("call", "T3", "body"),
        value if value.ends_with("Stmt") => ("statement", "T3", "body"),
        value if value.ends_with("Expr") || value.ends_with("Operator") => ("expression", "T3", "body"),
        "IntegerLiteral" | "StringLiteral" | "CharacterLiteral" => ("expression", "T3", "body"),
        _ => return None,
    };
    Some((kind.to_owned(), tier.to_owned(), stable_id(id_kind, file, offset, end_offset, spelling)))
}

fn write_manifests(output: &Path, frontend_id: &str, node_count: u64, edge_count: u64) -> io::Result<()> {
    let manifest = graph::ShardManifest {
        format_version: SHARD_FORMAT_VERSION,
        frontend_id: frontend_id.to_owned(),
        shard_id: "0".to_owned(),
        node_count,
        edge_count,
        nodes_file: "nodes.pb".to_owned(),
        edges_file: "edges.pb".to_owned(),
    };
    let manifest_bytes = manifest.encode_to_vec();
    fs::write(output.join("manifest.pb"), manifest_bytes)?;
    let entry = graph::ShardSetEntry {
        shard_id: "0".to_owned(),
        directory: "shard-0".to_owned(),
        status: "complete".to_owned(),
        node_count,
        edge_count,
    };
    let set = graph::ShardSetManifest {
        format_version: SHARD_FORMAT_VERSION,
        frontend_id: frontend_id.to_owned(),
        shards: vec![entry],
    };
    fs::write(output.parent().unwrap_or(output).join("shards.pb"), set.encode_to_vec())
}

fn parse_unit(
    index: CXIndex,
    unit: &graph::NativeTranslationUnit,
    emitter: &mut Emitter,
) -> Result<(), Box<dyn std::error::Error>> {
    let source_c = CString::new(unit.path.as_bytes())?;
    let clang_args: Vec<CString> = unit
        .arguments
        .iter()
        .map(|argument| CString::new(argument.as_str()))
        .collect::<Result<_, _>>()?;
    let argument_ptrs: Vec<*const c_char> = clang_args.iter().map(|argument| argument.as_ptr()).collect();

    unsafe {
        let mut translation_unit = ptr::null_mut();
        let error = clang_parseTranslationUnit2(
            index,
            source_c.as_ptr(),
            argument_ptrs.as_ptr(),
            argument_ptrs.len() as c_int,
            ptr::null_mut(),
            0,
            CXTranslationUnit_DetailedPreprocessingRecord,
            &mut translation_unit,
        );
        if error != CXError_Success || translation_unit.is_null() {
            return Err(format!("clang_parseTranslationUnit2 failed for {}: {error}", unit.path).into());
        }
        let root = clang_getTranslationUnitCursor(translation_unit);
        // libclang returns the number of visited children here, not a success
        // status; zero is valid for an empty or diagnostic-only translation unit.
        clang_visitChildren(root, visit, emitter as *mut Emitter as *mut c_void);
        clang_disposeTranslationUnit(translation_unit);
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // clang-sys's `runtime` feature keeps libclang out of the process until
    // the frontend is actually used.  Loading it here also makes the binary
    // self-contained from the Python caller's perspective: Python passes
    // paths and compiler arguments, while Rust owns parsing and protobuf I/O.
    clang_sys::load().map_err(|error| format!("load libclang: {error}"))?;
    let arguments: Vec<String> = env::args().collect();
    if arguments.len() < 3 {
        eprintln!("usage: lachesis-clang-frontend SOURCE OUTPUT_DIR [-- clang-args ...]");
        eprintln!("   or: lachesis-clang-frontend --request REQUEST.pb OUTPUT_DIR");
        std::process::exit(2);
    }
    let request = if arguments[1] == "--request" {
        if arguments.len() < 4 {
            return Err("--request requires REQUEST.pb and OUTPUT_DIR".into());
        }
        Some(graph::NativeFrontendRequest::decode(fs::read(&arguments[2])?.as_slice())?)
    } else {
        None
    };
    let output = PathBuf::from(if request.is_some() { &arguments[3] } else { &arguments[2] });
    let shard = output.join("shard-0");
    fs::create_dir_all(&shard)?;

    unsafe {
        let index = clang_createIndex(0, 0);
        if index.is_null() {
            return Err("clang_createIndex failed".into());
        }
        let mut emitter = Emitter {
            nodes: File::create(shard.join("nodes.pb"))?,
            edges: File::create(shard.join("edges.pb"))?,
            node_ids: HashSet::new(),
            edge_ids: HashSet::new(),
            node_count: 0,
            edge_count: 0,
            file_ids: HashMap::new(),
            root_files: HashSet::new(),
        };
        if let Some(request) = request.as_ref() {
            emitter.root_files.extend(request.translation_units.iter().map(|unit| {
                PathBuf::from(&unit.path)
                    .canonicalize()
                    .unwrap_or_else(|_| PathBuf::from(&unit.path))
                    .to_string_lossy()
                    .into_owned()
            }));
            for unit in &request.translation_units {
                let path = PathBuf::from(&unit.path)
                    .canonicalize()
                    .unwrap_or_else(|_| PathBuf::from(&unit.path));
                let path_text = path.to_string_lossy().into_owned();
                emit_file_node(&mut emitter, &path_text, &request.source_dir)?;
                emit_macros_for_file(&mut emitter, &path_text)?;
            }
        } else {
            let path = PathBuf::from(&arguments[1])
                .canonicalize()
                .unwrap_or_else(|_| PathBuf::from(&arguments[1]));
            let path_text = path.to_string_lossy().into_owned();
            emitter.root_files.insert(path_text.clone());
            let source_dir = path.parent().unwrap_or_else(|| Path::new(".")).to_string_lossy();
            emit_file_node(&mut emitter, &path_text, &source_dir)?;
            emit_macros_for_file(&mut emitter, &path_text)?;
        }
        if let Some(request) = request {
            if request.translation_units.is_empty() {
                clang_disposeIndex(index);
                return Err("native frontend request contains no translation units".into());
            }
            for unit in &request.translation_units {
                parse_unit(index, unit, &mut emitter)?;
            }
        } else {
            let source = PathBuf::from(&arguments[1]);
            let mut unit = graph::NativeTranslationUnit {
                path: source.to_string_lossy().into_owned(),
                arguments: Vec::new(),
            };
            if let Some(separator) = arguments.iter().position(|argument| argument == "--") {
                unit.arguments.extend(arguments[separator + 1..].iter().cloned());
            }
            parse_unit(index, &unit, &mut emitter)?;
        }
        emitter.nodes.flush()?;
        emitter.edges.flush()?;
        let node_count = emitter.node_count;
        let edge_count = emitter.edge_count;
        clang_disposeIndex(index);
        write_manifests(&shard, "clang-c-native", node_count, edge_count)?;
        println!("native clang emitted {node_count} nodes and {edge_count} edges to {}", output.display());
    }
    Ok(())
}
