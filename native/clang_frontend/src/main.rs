use clang_sys::*;
use prost::Message;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
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
        cx_string(clang_getFileName(file))
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
    let kind = cx_string(clang_getCursorKindSpelling(clang_getCursorKind(cursor)));
    let spelling = cx_string(clang_getCursorSpelling(cursor));
    let (file, line, column, offset, end_offset) = cursor_file(cursor);
    if file.is_empty() {
        return Ok(());
    }
    let id = stable_id(&kind, &file, offset, end_offset, &spelling);
    let properties = vec![
        field("file", text(&file)),
        field("absolute_file", text(&file)),
        field("start_offset", integer(offset as i64)),
        field("end_offset", integer(end_offset as i64)),
        field("start_line", integer(line as i64)),
        field("start_column", integer(column as i64)),
        field("syntax_kind", text(&kind)),
    ];
    emitter.node(graph::NodeRecord {
        id: id.clone(),
        kind: kind.clone(),
        label: if spelling.is_empty() { kind.clone() } else { spelling },
        properties,
        tier: "T1".to_owned(),
    })?;

    let parent_file = cursor_file(parent).0;
    if !parent_file.is_empty() {
        let parent_kind = cx_string(clang_getCursorKindSpelling(clang_getCursorKind(parent)));
        let parent_spelling = cx_string(clang_getCursorSpelling(parent));
        let (_, _, _, parent_offset, parent_end) = cursor_file(parent);
        let parent_id = stable_id(&parent_kind, &parent_file, parent_offset, parent_end, &parent_spelling);
        emitter.edge(graph::EdgeRecord {
            kind: "AST_CHILD".to_owned(),
            source: parent_id,
            target: id,
            properties: Vec::new(),
            source_tier: "T1".to_owned(),
            relationship_class: "AST_CHILD".to_owned(),
        })?;
    }
    Ok(())
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // clang-sys's `runtime` feature keeps libclang out of the process until
    // the frontend is actually used.  Loading it here also makes the binary
    // self-contained from the Python caller's perspective: Python passes
    // paths and compiler arguments, while Rust owns parsing and protobuf I/O.
    clang_sys::load().map_err(|error| format!("load libclang: {error}"))?;
    let arguments: Vec<String> = env::args().collect();
    if arguments.len() < 3 {
        eprintln!("usage: lachesis-clang-frontend SOURCE OUTPUT_DIR [-- clang-args ...]");
        std::process::exit(2);
    }
    let source = PathBuf::from(&arguments[1]);
    let output = PathBuf::from(&arguments[2]);
    let shard = output.join("shard-0");
    fs::create_dir_all(&shard)?;
    let mut clang_args = Vec::new();
    if let Some(separator) = arguments.iter().position(|argument| argument == "--") {
        clang_args.extend(arguments[separator + 1..].iter().map(|argument| {
            CString::new(argument.as_str()).expect("clang argument contains NUL")
        }));
    }
    let source_c = CString::new(source.to_string_lossy().as_bytes())?;
    let argument_ptrs: Vec<*const c_char> = clang_args.iter().map(|argument| argument.as_ptr()).collect();

    unsafe {
        let index = clang_createIndex(0, 0);
        if index.is_null() {
            return Err("clang_createIndex failed".into());
        }
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
            clang_disposeIndex(index);
            return Err(format!("clang_parseTranslationUnit2 failed: {error}").into());
        }
        let mut emitter = Emitter {
            nodes: File::create(shard.join("nodes.pb"))?,
            edges: File::create(shard.join("edges.pb"))?,
            node_ids: HashSet::new(),
            edge_ids: HashSet::new(),
            node_count: 0,
            edge_count: 0,
        };
        let root = clang_getTranslationUnitCursor(translation_unit);
        clang_visitChildren(root, visit, &mut emitter as *mut Emitter as *mut c_void);
        emitter.nodes.flush()?;
        emitter.edges.flush()?;
        let node_count = emitter.node_count;
        let edge_count = emitter.edge_count;
        clang_disposeTranslationUnit(translation_unit);
        clang_disposeIndex(index);
        write_manifests(&shard, "clang-c-native", node_count, edge_count)?;
        println!("native clang emitted {node_count} nodes and {edge_count} edges to {}", output.display());
    }
    Ok(())
}
