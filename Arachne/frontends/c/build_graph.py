#!/usr/bin/env python3
"""Emit the language-neutral layered frontend contract from Clang's C AST.

The frontend intentionally shells out to the installed compiler instead of
reimplementing C preprocessing or parsing.  It accepts a source directory and
an output directory, matching every other Arachne command frontend.
"""
from __future__ import annotations

import hashlib
import json
import os
import shlex
import subprocess
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple


CONTRACT_VERSION = 2
FRONTEND_ID = "clang-c"
TIERS = {
    "T0": "perimeter", "T1": "reachability", "T2": "path",
    "T3": "body", "T4": "proof",
}
SOURCE_SUFFIXES = {".c", ".h"}
ENTITY_KINDS = {
    "FunctionDecl": "function",
    "RecordDecl": "record",
    "EnumDecl": "enum",
    "TypedefDecl": "type",
}
VALUE_KINDS = {
    "ParmVarDecl": "parameter",
    "VarDecl": "variable",
    "FieldDecl": "property",
    "EnumConstantDecl": "constant",
}
CONTENT_HASHES: Dict[Path, str] = {}


def stable_id(kind: str, *parts: object) -> str:
    raw = "\0".join(str(part) for part in parts)
    identity_digest = hashlib.sha256(
        f"v2\0frontend\0{FRONTEND_ID}\0{kind}\0{raw}".encode("utf-8")
    ).hexdigest()[:20]
    return f"v2:frontend:{FRONTEND_ID}:{kind}:{identity_digest}"


def content_hash(path: Path) -> str:
    absolute = path.resolve()
    if absolute not in CONTENT_HASHES:
        try:
            contents = absolute.read_bytes()
        except OSError:
            contents = b""
        CONTENT_HASHES[absolute] = hashlib.sha256(contents).hexdigest()
    return CONTENT_HASHES[absolute]


def compact(value: object, limit: int = 300) -> str:
    text = " ".join(str(value or "").split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def read_roots(roots_file: str) -> List[Path]:
    """Ingest exactly the discovery-provided root list.

    The Python driver (Arachne/core/runner.py) writes ARACHNE_ROOTS_FILE after it
    has already pruned vendor directories and excluded tests via
    nav.symbol_index.is_test_path.  Honoring it means the C frontend inherits that
    single discovery instead of re-walking the tree and re-introducing what was
    filtered out — mirroring the TypeScript frontend's readRoots().
    """
    roots: List[Path] = []
    try:
        lines = Path(roots_file).read_text(encoding="utf-8").splitlines()
    except OSError:
        return roots
    for line in lines:
        trimmed = line.strip()
        if not trimmed:
            continue
        candidate = Path(trimmed).resolve()
        if candidate.suffix.lower() in SOURCE_SUFFIXES and candidate.is_file():
            roots.append(candidate)
    return sorted(set(roots))


def walk(source_dir: Path) -> List[Path]:
    # Discovery owns file selection: when the driver hands us an explicit root set
    # (ARACHNE_ROOTS_FILE — vendor/test files already excluded), ingest exactly that
    # list so the walker can't re-introduce what was filtered out.  Absent the env
    # var (standalone CLI run), fall back to a full source-tree walk.
    roots_file = os.environ.get("ARACHNE_ROOTS_FILE")
    if roots_file:
        roots = read_roots(roots_file)
        if roots:
            return roots
    return sorted(
        path.resolve() for path in source_dir.rglob("*")
        if path.is_file() and path.suffix.lower() in SOURCE_SUFFIXES
    )


def system_include_dirs() -> List[Path]:
    """Directories the toolchain treats as system / standard-library headers.

    Parsed from the compiler's own verbose include-search list (`-E -v` on empty
    input), so "external vs application" is decided by the installed toolchain, never
    by a hardcoded path literal like /usr/include.
    """
    configured = shlex.split(os.environ.get("CLANG", "clang"))
    try:
        proc = subprocess.run(
            configured + ["-E", "-v", "-x", "c", os.devnull],
            text=True, capture_output=True, check=False,
        )
    except OSError:
        return []
    dirs: List[Path] = []
    capturing = False
    for line in proc.stderr.splitlines():
        stripped = line.strip()
        if stripped.endswith("search starts here:"):
            capturing = True
            continue
        if stripped.startswith("End of search list"):
            capturing = False
            continue
        if capturing and stripped:
            # Clang annotates framework dirs with a trailing " (framework directory)".
            candidate = stripped.split(" (", 1)[0]
            try:
                dirs.append(Path(candidate).resolve())
            except OSError:
                continue
    return dirs


def classify_provenance(
    path: Path, root_set: set, system_dirs: List[Path],
) -> Tuple[str, bool, bool]:
    """(provenance, is_external, is_system) from rootset membership + toolchain dirs.

    Membership in the discovered root set — not the file extension — decides
    application vs external, matching the TS frontend's sourceProvenance().
    """
    if path in root_set:
        return "application", False, False
    for directory in system_dirs:
        try:
            path.relative_to(directory)
            return "standard-library", True, True
        except ValueError:
            continue
    return "dependency", True, False


def clang_command(source_dir: Path, path: Path, *arguments: str) -> List[str]:
    configured = shlex.split(os.environ.get("CLANG", "clang"))
    language = ["-x", "c-header"] if path.suffix.lower() == ".h" else []
    extra = shlex.split(os.environ.get("ARACHNE_CFLAGS", ""))
    return configured + ["-I", str(source_dir)] + extra + language + list(arguments) + [str(path)]


def run_clang(source_dir: Path, path: Path, *arguments: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        clang_command(source_dir, path, *arguments),
        text=True, capture_output=True, check=False,
    )


def source_text(path: Path, cache: Dict[Path, str]) -> str:
    if path not in cache:
        try:
            cache[path] = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            cache[path] = ""
    return cache[path]


def line_offsets(text: str) -> List[int]:
    offsets = [0]
    for offset, character in enumerate(text):
        if character == "\n":
            offsets.append(offset + 1)
    return offsets


def parse_clang_token(line: str) -> Optional[Tuple[str, str, Path, int, int]]:
    """Decode one compiler token-dump record without interpreting C source."""
    location_marker = "Loc=<"
    location_start = line.rfind(location_marker)
    if location_start < 0 or not line.endswith(">"):
        return None
    prefix = line[:location_start]
    first_quote = prefix.find("'")
    last_quote = prefix.rfind("'")
    if first_quote < 0 or last_quote <= first_quote:
        return None
    kind = prefix[:first_quote].strip().split(None, 1)[0]
    token_text = prefix[first_quote + 1:last_quote]
    location = line[location_start + len(location_marker):-1]
    parts = location.rsplit(":", 2)
    if len(parts) != 3:
        return None
    try:
        return kind, token_text, Path(parts[0]), int(parts[1]), int(parts[2])
    except ValueError:
        return None


def position_from_ast(
    ast_node: dict, path: Path, texts: Dict[Path, str],
) -> dict:
    begin = ast_node.get("range", {}).get("begin", {})
    end = ast_node.get("range", {}).get("end", {})
    loc = ast_node.get("loc", {})
    start = begin.get("offset", loc.get("offset", 0))
    finish = end.get("offset", start) + end.get("tokLen", loc.get("tokLen", 0))
    text = source_text(path, texts)
    starts = line_offsets(text)

    def line_col(offset: int) -> Tuple[int, int]:
        low, high = 0, len(starts)
        while low + 1 < high:
            middle = (low + high) // 2
            if starts[middle] <= offset:
                low = middle
            else:
                high = middle
        return low + 1, offset - starts[low] + 1

    start_line, start_column = line_col(max(0, start))
    end_line, end_column = line_col(max(start, finish - 1))
    return {
        "file": str(path), "absolute_file": str(path),
        "start_offset": start, "end_offset": finish,
        "start_line": loc.get("line", begin.get("line", start_line)),
        "start_column": loc.get("col", begin.get("col", start_column)),
        "end_line": end.get("line", end_line),
        "end_column": end.get("col", end_column),
    }


class Graph:
    def __init__(self) -> None:
        self.nodes: Dict[str, dict] = {}
        self.node_tier: Dict[str, str] = {}
        self.edges: List[dict] = []
        self.edge_keys = set()

    def node(self, tier: str, node_id: str, kind: str, label: str, **properties) -> str:
        canonical = {
            "fact_origin": "compiler", "confidence": "exact", "evidence_ids": [],
            **properties,
        }
        absolute_file = canonical.get("absolute_file")
        if absolute_file:
            absolute = Path(absolute_file).resolve()
            canonical.update({
                "frontend_id": FRONTEND_ID,
                "language": "c",
                "absolute_file": str(absolute),
                "content_hash": canonical.get("content_hash")
                    or content_hash(absolute),
                "compiler_node_id": canonical.get("compiler_node_id") or node_id,
            })
        if node_id not in self.nodes:
            self.nodes[node_id] = {
                "id": node_id, "kind": kind, "label": label,
                "properties": canonical,
            }
            self.node_tier[node_id] = tier
        else:
            self.nodes[node_id]["properties"].update(canonical)
        return node_id

    def edge(self, kind: str, source: Optional[str], target: Optional[str], **properties) -> None:
        if not source or not target or source == target:
            return
        canonical = {
            "fact_origin": "compiler", "confidence": "exact", "evidence_ids": [],
            **properties,
        }
        key = (kind, source, target, json.dumps(canonical, sort_keys=True))
        if key in self.edge_keys:
            return
        self.edge_keys.add(key)
        self.edges.append({
            "kind": kind, "source": source, "target": target,
            "properties": canonical,
        })


def referenced_decl(node: dict) -> Optional[dict]:
    """Resolve the callable expression, not arbitrary argument references."""
    if node.get("kind") == "MemberExpr" and node.get("referencedMemberDecl"):
        return {
            "id": node["referencedMemberDecl"], "kind": "FieldDecl",
            "name": node.get("name", "<computed-member>"),
        }
    if isinstance(node.get("referencedDecl"), dict):
        return node["referencedDecl"]
    for child in node.get("inner", []):
        found = referenced_decl(child)
        if found:
            return found
    return None


def referenced_decls(node: dict) -> List[dict]:
    """Return every declaration reference below an expression in AST order."""
    result = []
    if node.get("kind") == "MemberExpr" and node.get("referencedMemberDecl"):
        result.append({
            "id": node["referencedMemberDecl"], "kind": "FieldDecl",
            "name": node.get("name", "<computed-member>"),
        })
    if isinstance(node.get("referencedDecl"), dict):
        result.append(node["referencedDecl"])
    for child in node.get("inner", []):
        result.extend(referenced_decls(child))
    return result


def main() -> int:
    source_dir = Path(sys.argv[1] if len(sys.argv) > 1 else "src").resolve()
    output_dir = Path(sys.argv[2] if len(sys.argv) > 2 else "graph_out/clang_layered").resolve()
    files = walk(source_dir)
    translation_units = [path for path in files if path.suffix.lower() == ".c"]
    if not translation_units:
        translation_units = files
    if not files:
        raise SystemExit(f"No C source files found under {source_dir}")

    # Provenance is decided by rootset membership + the toolchain's own system
    # include dirs, not by file extension (parity with TS sourceProvenance).
    root_set = set(files)
    system_dirs = system_include_dirs()

    graph = Graph()
    texts: Dict[Path, str] = {}
    file_ids: Dict[Path, str] = {}
    declarations_by_raw_id: Dict[str, str] = {}
    declarations_by_name: Dict[Tuple[str, str], List[str]] = defaultdict(list)
    function_parameters: Dict[str, List[str]] = defaultdict(list)
    asts: List[Tuple[Path, dict]] = []
    diagnostics: List[Tuple[Path, str]] = []

    for path in files:
        text = source_text(path, texts)
        file_id = stable_id("file", path)
        provenance, is_external, is_system = classify_provenance(path, root_set, system_dirs)
        file_ids[path] = graph.node(
            "T0", file_id, "file", str(path.relative_to(source_dir)),
            file=str(path.relative_to(source_dir)), absolute_file=str(path),
            content_hash=hashlib.sha256(text.encode("utf-8")).hexdigest(),
            lines=len(text.splitlines()), language="c",
            provenance=provenance, is_external=is_external, is_system=is_system,
            included_because="project-root",
        )

    # Compiler dependency extraction makes framework/header ownership explicit.
    for path in translation_units:
        dependency = run_clang(source_dir, path, "-MM")
        flattened = dependency.stdout.replace("\\\n", " ")
        dependencies = flattened.split(":", 1)[1].split() if ":" in flattened else []
        for raw in dependencies:
            target = (Path.cwd() / raw).resolve() if not os.path.isabs(raw) else Path(raw).resolve()
            if target == path or not target.exists():
                continue
            if target not in file_ids:
                text = source_text(target, texts)
                target_id = stable_id("file", target)
                provenance, is_external, is_system = classify_provenance(target, root_set, system_dirs)
                file_ids[target] = graph.node(
                    "T0", target_id, "file", str(target),
                    file=str(target), absolute_file=str(target),
                    content_hash=hashlib.sha256(text.encode("utf-8")).hexdigest(),
                    lines=len(text.splitlines()), language="c",
                    provenance=provenance, is_external=is_external, is_system=is_system,
                    included_because="included-header",
                )
            graph.edge("DEPENDS_ON", file_ids[path], file_ids[target], directive="#include")

    # Parse headers independently as compiler roots. This retains their exact
    # offsets; Clang otherwise reports included declarations using header-local
    # offsets but only the including-file provenance.
    for path in files:
        result = run_clang(source_dir, path, "-Xclang", "-ast-dump=json", "-fsyntax-only", "-Wno-everything")
        if result.returncode != 0 or not result.stdout.strip():
            diagnostics.extend((path, line) for line in result.stderr.splitlines() if line.strip())
            continue
        try:
            asts.append((path, json.loads(result.stdout)))
        except json.JSONDecodeError as error:
            diagnostics.append((path, f"invalid Clang AST JSON: {error}"))
        diagnostics.extend((path, line) for line in result.stderr.splitlines() if "error:" in line or "warning:" in line)

    def eligible(node: dict, inherited_included: bool) -> bool:
        loc = node.get("loc", {})
        begin = node.get("range", {}).get("begin", {})
        return not (inherited_included or loc.get("includedFrom") or begin.get("includedFrom"))

    # Declaration pass.
    def declarations(node: dict, path: Path, owner: Optional[str] = None, included: bool = False) -> None:
        is_included = not eligible(node, included)
        kind = node.get("kind", "")
        current_owner = owner
        if not node.get("isImplicit") and not is_included and kind in ENTITY_KINDS:
            entity_kind = ENTITY_KINDS[kind]
            name = node.get("name") or f"<anonymous@{node.get('id', '')}>"
            position = position_from_ast(node, path, texts)
            entity_id = stable_id(entity_kind, path, position["start_offset"], position["end_offset"], name)
            graph.node(
                "T1", entity_id, entity_kind, name, **position,
                syntax_kind=kind, type=node.get("type", {}).get("qualType"),
                storage_class=node.get("storageClass"), inline=bool(node.get("inline")),
                form="function" if kind == "FunctionDecl" else entity_kind,
                owner_id=owner,
            )
            graph.edge("DECLARES_MEMBER" if owner else "DECLARES", owner or file_ids[path], entity_id)
            declarations_by_raw_id[node.get("id", "")] = entity_id
            declarations_by_name[(kind, name)].append(entity_id)
            if kind == "FunctionDecl":
                current_owner = entity_id
                # External linkage = the file's exported symbol surface (parity with
                # TS EXPORTS). A non-static function *definition* (has a body) is what
                # this file makes externally visible; static/inline-only and pure
                # prototypes are not exports.
                has_body = any(child.get("kind") == "CompoundStmt" for child in node.get("inner", []))
                if owner is None and has_body and node.get("storageClass") != "static":
                    graph.edge("EXPORTS", file_ids[path], entity_id, name=name)
        elif not node.get("isImplicit") and not is_included and kind in VALUE_KINDS:
            value_kind = VALUE_KINDS[kind]
            name = node.get("name") or "<anonymous>"
            position = position_from_ast(node, path, texts)
            value_id = stable_id("value", path, position["start_offset"], position["end_offset"], name)
            graph.node(
                "T2", value_id, value_kind, name, **position,
                syntax_kind=kind, type=node.get("type", {}).get("qualType"),
                owner_function_id=owner,
            )
            graph.edge("DECLARES_VALUE", owner or file_ids[path], value_id)
            declarations_by_raw_id[node.get("id", "")] = value_id
            declarations_by_name[(kind, name)].append(value_id)
            if kind == "ParmVarDecl" and owner:
                function_parameters[owner].append(value_id)
            # A file-scope global with external linkage is exported; a `static`
            # global is file-local and `extern` only imports a symbol defined elsewhere.
            if owner is None and kind == "VarDecl" and node.get("storageClass") not in {"static", "extern"}:
                graph.edge("EXPORTS", file_ids[path], value_id, name=name)
        for child in node.get("inner", []):
            declarations(child, path, current_owner, is_included)

    for path, ast in asts:
        declarations(ast, path)

    # Indirect-dispatch binding pre-pass. Function pointers reach their targets
    # through ops-struct slots (`.read = ext4_file_read`) and pointer variables
    # (`fp = handler`); on C/kernel this indirection *is* the control flow. We
    # resolve those bindings here so the call pass can attach MAY_INVOKE to the
    # dispatch call-site (parity with the TS frontend). Genuinely unresolved
    # pointers keep their READS_CALLEE slot edge — the indirection is never dropped.
    record_fields_by_type: Dict[str, List[Optional[str]]] = {}

    def collect_record_fields(node: dict) -> None:
        if node.get("kind") == "RecordDecl" and node.get("name") and node.get("tagUsed"):
            key = f'{node["tagUsed"]} {node["name"]}'
            record_fields_by_type[key] = [
                declarations_by_raw_id.get(child.get("id", ""))
                for child in node.get("inner", []) if child.get("kind") == "FieldDecl"
            ]
        for child in node.get("inner", []):
            collect_record_fields(child)

    for path, ast in asts:
        collect_record_fields(ast)

    def normalize_type(text: str) -> str:
        for qualifier in ("const ", "volatile ", "restrict ", "_Atomic "):
            while text.startswith(qualifier):
                text = text[len(qualifier):]
        return text.strip()

    def function_refs(node: dict) -> List[str]:
        """Function declaration node-ids referenced anywhere below an expression."""
        ids = []
        for reference in referenced_decls(node):
            node_id = declarations_by_raw_id.get(reference.get("id", ""))
            if node_id and graph.nodes.get(node_id, {}).get("kind") == "function":
                ids.append(node_id)
        return ids

    def callback_argument(argument: dict) -> Optional[str]:
        """Function node-id when an argument *is* a bare function reference.

        Unwraps the function-to-pointer decay / casts so a passed callback
        (`register(cb)`) is recognised, while a called function (`foo(bar())`)
        is not mistaken for one.
        """
        node = argument
        while node.get("kind") in {"ImplicitCastExpr", "ParenExpr", "CStyleCastExpr"} and node.get("inner"):
            node = node["inner"][0]
        if node.get("kind") == "DeclRefExpr":
            node_id = declarations_by_raw_id.get(node.get("referencedDecl", {}).get("id", ""))
            if node_id and graph.nodes.get(node_id, {}).get("kind") == "function":
                return node_id
        return None

    field_bindings: Dict[str, set] = defaultdict(set)   # property slot -> {function ids}
    var_bindings: Dict[str, set] = defaultdict(set)     # pointer variable -> {function ids}

    def bind_init_list(init_list: dict) -> None:
        # Clang emits initializer values in record-field order (holes filled with
        # ImplicitValueInitExpr), so element position maps to the ordered fields.
        type_name = normalize_type(init_list.get("type", {}).get("qualType", ""))
        fields = record_fields_by_type.get(type_name)
        if not fields:
            return
        for position, element in enumerate(init_list.get("inner", [])):
            if position >= len(fields) or not fields[position]:
                continue
            for function_id in function_refs(element):
                field_bindings[fields[position]].add(function_id)

    def slot_of_lvalue(lvalue: dict) -> Optional[Tuple[str, str]]:
        for reference in referenced_decls(lvalue):
            node_id = declarations_by_raw_id.get(reference.get("id", ""))
            kind = graph.nodes.get(node_id, {}).get("kind") if node_id else None
            if kind in {"property", "variable"}:
                return node_id, kind
        return None

    def collect_bindings(node: dict) -> None:
        kind = node.get("kind", "")
        if kind == "VarDecl":
            init_list = next((c for c in node.get("inner", []) if c.get("kind") == "InitListExpr"), None)
            if init_list is not None:
                bind_init_list(init_list)
            else:
                variable_id = declarations_by_raw_id.get(node.get("id", ""))
                if variable_id and graph.nodes.get(variable_id, {}).get("kind") == "variable":
                    for function_id in function_refs(node):
                        var_bindings[variable_id].add(function_id)
        elif kind in {"BinaryOperator", "CompoundAssignOperator"} and node.get("opcode") == "=":
            inner = node.get("inner", [])
            if len(inner) >= 2:
                functions = function_refs(inner[1])
                slot = slot_of_lvalue(inner[0]) if functions else None
                if slot:
                    slot_id, slot_kind = slot
                    target_map = field_bindings if slot_kind == "property" else var_bindings
                    for function_id in functions:
                        target_map[slot_id].add(function_id)
        for child in node.get("inner", []):
            collect_bindings(child)

    for path, ast in asts:
        collect_bindings(ast)

    # Body/reference/call pass.
    def body_identity(node: dict, path: Path) -> str:
        position = position_from_ast(node, path, texts)
        return stable_id(
            "body", path, position["start_offset"], position["end_offset"],
            node.get("kind", ""),
        )

    def ast_child_role(parent: Optional[dict], index: int) -> dict:
        if not parent:
            return {"role": "AST_CHILD"}
        kind = parent.get("kind")
        if kind == "CallExpr":
            return {"role": "CALLEE"} if index == 0 else {
                "role": "ARGUMENT", "position": index - 1,
            }
        if kind in {"BinaryOperator", "CompoundAssignOperator"}:
            return {"role": "LEFT_OPERAND" if index == 0 else "RIGHT_OPERAND"}
        if kind == "ConditionalOperator":
            return {"role": ("CONDITION", "TRUE_VALUE", "FALSE_VALUE")[min(index, 2)]}
        if kind in {"UnaryOperator", "ReturnStmt"}:
            return {"role": "RETURNED_VALUE" if kind == "ReturnStmt" else "OPERAND"}
        if kind == "MemberExpr":
            return {"role": "RECEIVER"}
        if kind == "ArraySubscriptExpr":
            return {"role": "RECEIVER" if index == 0 else "PROPERTY_KEY"}
        if kind == "IfStmt":
            return {"role": ("CONDITION", "TRUE_BRANCH", "FALSE_BRANCH")[min(index, 2)]}
        if kind in {"WhileStmt", "DoStmt"}:
            return {"role": "CONDITION" if index == 0 else "LOOP_BODY"}
        return {"role": "AST_CHILD"}

    def control_kind(kind: str) -> Optional[str]:
        return {
            "CompoundStmt": "block",
            "IfStmt": "if",
            "SwitchStmt": "switch",
            "CaseStmt": "case",
            "DefaultStmt": "default",
            "ForStmt": "for",
            "WhileStmt": "while",
            "DoStmt": "do-while",
            "ReturnStmt": "return",
            "BreakStmt": "break",
            "ContinueStmt": "continue",
            "GotoStmt": "goto",
            "IndirectGotoStmt": "computed-goto",
            "DeclStmt": "declaration",
        }.get(kind, "statement" if kind.endswith("Stmt") else None)

    def bodies(
        node: dict, path: Path, owner: Optional[str] = None,
        parent_body: Optional[str] = None, included: bool = False,
        parent_node: Optional[dict] = None, child_index: int = 0,
    ) -> None:
        is_included = not eligible(node, included)
        kind = node.get("kind", "")
        raw_id = node.get("id", "")
        if kind == "FunctionDecl" and raw_id in declarations_by_raw_id:
            owner = declarations_by_raw_id[raw_id]
        body_id = parent_body
        is_body = kind.endswith(("Stmt", "Expr", "Operator")) or kind in {
            "BinaryOperator", "UnaryOperator", "ConditionalOperator",
            "IntegerLiteral", "StringLiteral", "CharacterLiteral",
        }
        if not node.get("isImplicit") and not is_included and is_body:
            position = position_from_ast(node, path, texts)
            text = source_text(path, texts)
            snippet = compact(text[position["start_offset"]:position["end_offset"]])
            node_kind = "call" if kind == "CallExpr" else "statement" if kind.endswith("Stmt") else "expression"
            body_id = stable_id("body", path, position["start_offset"], position["end_offset"], kind)
            graph.node(
                "T3", body_id, node_kind, snippet or kind, **position,
                syntax_kind=kind, type=node.get("type", {}).get("qualType"),
                operator=node.get("opcode"), owner_function_id=owner,
                control_kind=control_kind(kind),
            )
            proof_id = stable_id("source-proof", path, position["start_offset"], position["end_offset"], kind)
            graph.node("T4", proof_id, "source-span", f"{path.name}:{position['start_line']}", **position, text=snippet, syntax_kind=kind)
            graph.edge("EVIDENCED_BY", body_id, proof_id)
            graph.edge(
                "AST_CHILD" if parent_body else "CONTAINS_BODY",
                parent_body or owner or file_ids[path], body_id,
                **(ast_child_role(parent_node, child_index) if parent_body else {}),
            )
            if kind == "CallExpr":
                # Clang stores the callee as the first CallExpr child. Looking
                # through the whole call can incorrectly select an argument.
                reference = referenced_decl(node.get("inner", [{}])[0])
                target = declarations_by_raw_id.get((reference or {}).get("id", ""))
                if not target and reference:
                    candidates = declarations_by_name.get((reference.get("kind", "FunctionDecl"), reference.get("name", "")), [])
                    target = candidates[0] if len(candidates) == 1 else None
                properties = graph.nodes[body_id]["properties"]
                callable_target = target and graph.nodes.get(target, {}).get("kind") == "function"
                properties.update({
                    "callee": (reference or {}).get("name", snippet.split("(", 1)[0]),
                    "form": "call", "method_name": (reference or {}).get("name"),
                    "resolution": "exact" if callable_target else
                        "function-pointer" if target else "dynamic-or-unresolved",
                    "primary_target_id": target if callable_target else None,
                    "receiver_member_id": target if target and not callable_target else None,
                    "argument_value_ids": [
                        next((
                            declarations_by_raw_id.get(reference.get("id", ""))
                            for reference in referenced_decls(argument)
                            if declarations_by_raw_id.get(reference.get("id", ""))
                        ), None)
                        for argument in node.get("inner", [])[1:]
                    ],
                })
                if target and not callable_target:
                    properties["receiver_value_id"] = next((
                        declarations_by_raw_id.get(reference.get("id", ""))
                        for reference in referenced_decls(node.get("inner", [{}])[0])
                        if reference.get("kind") != "FieldDecl"
                        and declarations_by_raw_id.get(reference.get("id", ""))
                    ), None)
                if callable_target:
                    graph.edge("INVOKES", body_id, target, resolution="compiler-local")
                    graph.edge("CALLS", owner, target, callsite=body_id)
                elif target:
                    # Unresolved slot stays visible; when the pointer's binding is
                    # known (ops-struct initializer / pointer assignment), also resolve
                    # the concrete target as MAY_INVOKE from the dispatch call-site.
                    graph.edge("READS_CALLEE", body_id, target, dispatch="function-pointer")
                    field_bound = field_bindings.get(target)
                    resolved = field_bound or var_bindings.get(target)
                    if resolved:
                        dispatch_label = "ops-struct" if field_bound else "function-pointer"
                        for function_id in sorted(resolved):
                            graph.edge(
                                "MAY_INVOKE", body_id, function_id,
                                dispatch=dispatch_label, resolution="binding",
                            )
                arguments = node.get("inner", [])[1:]
                parameters = function_parameters.get(target or "", [])
                for position_index, argument in enumerate(arguments):
                    argument_id = body_identity(argument, path)
                    graph.edge("HAS_ARGUMENT", body_id, argument_id, position=position_index)
                    # A function passed by name is a callback handed to the callee.
                    callback_id = callback_argument(argument)
                    if callback_id:
                        graph.edge("PASSES_CALLBACK", body_id, callback_id, position=position_index)
                    if position_index < len(parameters):
                        parameter_id = parameters[position_index]
                        graph.edge(
                            "ARGUMENT_BINDS_PARAMETER", argument_id, parameter_id,
                            position=position_index, callsite=body_id,
                        )
                        graph.edge(
                            "VALUE_FLOWS_TO", argument_id, parameter_id,
                            reason="call-argument", callsite=body_id,
                        )
            if kind == "ReturnStmt" and node.get("inner") and owner:
                graph.edge("RETURNS_VALUE", body_identity(node["inner"][0], path), owner)
            if kind in {"BinaryOperator", "CompoundAssignOperator"} and node.get("opcode") in {
                "=", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<=", ">>=",
            } and len(node.get("inner", [])) >= 2:
                left, right = node["inner"][:2]
                graph.edge(
                    "VALUE_FLOWS_TO", body_identity(right, path), body_identity(left, path),
                    reason="assignment", operator=node.get("opcode"),
                )
                left_references = referenced_decls(left)
                field_id = next((
                    declarations_by_raw_id.get(reference.get("id", ""))
                    for reference in left_references if reference.get("kind") == "FieldDecl"
                ), None)
                receiver_id = next((
                    declarations_by_raw_id.get(reference.get("id", ""))
                    for reference in left_references if reference.get("kind") == "ParmVarDecl"
                ), None)
                value_id = next((
                    declarations_by_raw_id.get(reference.get("id", ""))
                    for reference in referenced_decls(right)
                    if declarations_by_raw_id.get(reference.get("id", ""))
                ), None)
                parameters = function_parameters.get(owner or "", [])
                if field_id and receiver_id in parameters and value_id in parameters:
                    graph.edge(
                        "WRITES_PARAMETER_PROPERTY", owner, field_id,
                        receiver_position=parameters.index(receiver_id),
                        value_position=parameters.index(value_id),
                    )
        if not is_included and kind == "DeclRefExpr":
            reference = node.get("referencedDecl", {})
            target = declarations_by_raw_id.get(reference.get("id", ""))
            if target and body_id:
                graph.edge("REFERS_TO", body_id, target)
                graph.edge("VALUE_FLOWS_TO", target, body_id, reason="read")
        if not is_included and kind in {"ImplicitCastExpr", "ParenExpr"} and node.get("inner") and body_id:
            graph.edge(
                "VALUE_FLOWS_TO", body_identity(node["inner"][0], path), body_id,
                reason="value-preserving-expression",
            )
        for index, child in enumerate(node.get("inner", [])):
            bodies(child, path, owner, body_id, is_included, node, index)

    for path, ast in asts:
        bodies(ast, path)

    # Preprocessor-aware compiler tokens. These are deliberately partial: the
    # stream represents compiled tokens, while comments and inactive #if arms
    # require a separate raw-source trivia pass.
    for path in files:
        result = run_clang(source_dir, path, "-Xclang", "-dump-tokens", "-fsyntax-only", "-Wno-everything")
        previous = None
        for line in result.stderr.splitlines():
            parsed = parse_clang_token(line)
            if not parsed:
                continue
            token_kind, token_text, token_path, line_number, column = parsed
            if not token_path.is_absolute():
                token_path = (Path.cwd() / token_path).resolve()
            else:
                token_path = token_path.resolve()
            if token_path != path or path not in file_ids:
                continue
            text = source_text(path, texts)
            starts = line_offsets(text)
            start = starts[line_number - 1] + column - 1 if line_number <= len(starts) else 0
            end = start + len(token_text.encode("utf-8").decode("unicode_escape"))
            token_id = stable_id("token", path, start, end, token_kind)
            graph.node(
                "T4", token_id, "token", token_text,
                file=str(path.relative_to(source_dir)), absolute_file=str(path),
                start_offset=start, end_offset=end, start_line=line_number,
                start_column=column, end_line=line_number,
                end_column=column + max(0, end - start - 1),
                token_kind=token_kind, trivia=False,
            )
            graph.edge("HAS_TOKEN", file_ids[path], token_id)
            graph.edge("NEXT_TOKEN", previous, token_id)
            previous = token_id

    for path, message in diagnostics:
        diagnostic_id = stable_id("diagnostic", path, message)
        graph.node(
            "T4", diagnostic_id, "diagnostic", "clang",
            category="compiler", message=message, file=str(path),
        )
        graph.edge("HAS_DIAGNOSTIC", file_ids.get(path), diagnostic_id)

    structural = {
        "DECLARES", "DECLARES_MEMBER", "DECLARES_VALUE", "CONTAINS_BODY",
        "AST_CHILD", "EVIDENCED_BY", "HAS_ARGUMENT",
    }
    tier_payloads = {
        tier: {"tier": tier, "name": name, "nodes": [], "edges": [], "expands_to": [], "links": []}
        for tier, name in TIERS.items()
    }
    for node_id, node in graph.nodes.items():
        tier_payloads[graph.node_tier[node_id]]["nodes"].append(node)
    for edge in graph.edges:
        source_tier = graph.node_tier.get(edge["source"])
        target_tier = graph.node_tier.get(edge["target"])
        if not source_tier or not target_tier:
            continue
        if source_tier == target_tier:
            tier_payloads[source_tier]["edges"].append(edge)
        elif edge["kind"] in structural:
            tier_payloads[source_tier]["expands_to"].append({
                "kind": "EXPANDS_TO", "source": edge["source"], "target": edge["target"],
                "properties": {
                    "fact_origin": "compiler", "confidence": "exact", "evidence_ids": [],
                    "via": edge["kind"],
                },
            })
        else:
            linked = dict(edge)
            linked["properties"] = dict(edge["properties"], target_tier=target_tier)
            tier_payloads[source_tier]["links"].append(linked)
    for payload in tier_payloads.values():
        payload["nodes"].sort(key=lambda item: item["id"])
        for collection in ("edges", "expands_to", "links"):
            payload[collection].sort(key=lambda item: (item["kind"], item["source"], item["target"]))

    manifest = {
        "version": 2, "frontend_contract_version": CONTRACT_VERSION,
        "frontend_id": FRONTEND_ID, "generator": FRONTEND_ID, "languages": ["c"],
        "capabilities": {
            "lexical": "partial", "syntax": "complete", "modules": "complete",
            "dependency_sources": "complete",
            "symbols": "partial", "types": "partial", "calls": "partial",
            "control_flow": "partial", "direct_data_flow": "partial",
            "heap_identity": "none", "context_sensitivity": "none",
            "branch_histories": "none", "taint_policy": "none",
            "runtime_models": "none", "effects": "none", "async_events": "none",
            "dynamic_behavior": "partial", "framework_wiring": "partial",
            "security_roles": "none",
        },
        "compiler": subprocess.run(shlex.split(os.environ.get("CLANG", "clang")) + ["--version"], text=True, capture_output=True).stdout.splitlines()[0],
        "source_dir": str(source_dir), "root_file_count": len(files),
        "node_count": len(graph.nodes), "edge_count": len(graph.edges),
        "diagnostic_count": len(diagnostics),
        "identity_scheme": "v2:<owner>:<namespace>:<kind>:<digest>",
        "tiers": [
            {
                "tier": tier, "name": TIERS[tier],
                "file": f"{tier.lower()}_{TIERS[tier]}.json",
                "node_count": len(tier_payloads[tier]["nodes"]),
                "edge_count": len(tier_payloads[tier]["edges"]),
                "expands_to_count": len(tier_payloads[tier]["expands_to"]),
                "cross_tier_link_count": len(tier_payloads[tier]["links"]),
            }
            for tier in TIERS
        ],
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    for tier, payload in tier_payloads.items():
        (output_dir / f"{tier.lower()}_{TIERS[tier]}.json").write_text(
            json.dumps(payload, indent=2) + "\n", encoding="utf-8",
        )
    (output_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"Clang analyzed {len(files)} C files; emitted {len(graph.nodes)} nodes and {len(graph.edges)} edges to {output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
