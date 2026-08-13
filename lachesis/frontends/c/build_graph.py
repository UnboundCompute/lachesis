#!/usr/bin/env python3
"""Emit the language-neutral layered frontend contract from Clang's C AST.

The frontend intentionally shells out to the installed compiler instead of
reimplementing C preprocessing or parsing.  It accepts a source directory and
an output directory, matching every other Lachesis command frontend.
"""
from __future__ import annotations

import hashlib
import json
import os
import shlex
import subprocess
import sys
import tempfile
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Set, Tuple

try:  # run as a script (sys.path[0] is this directory) …
    from macros import parse_macro_definitions
except ImportError:  # … or imported as a package module.
    from lachesis.frontends.c.macros import parse_macro_definitions


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

    The Python driver (lachesis/core/runner.py) writes LACHESIS_ROOTS_FILE after it
    has already pruned vendor directories and excluded tests via
    lachesis.nav.symbol_index.is_test_path.  Honoring it means the C frontend inherits that
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
    # (LACHESIS_ROOTS_FILE — vendor/test files already excluded), ingest exactly that
    # list so the walker can't re-introduce what was filtered out.  Absent the env
    # var (standalone CLI run), fall back to a full source-tree walk.
    roots_file = os.environ.get("LACHESIS_ROOTS_FILE")
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


_PATH_FLAGS = ("-I", "-isystem", "-iquote", "-idirafter", "-include", "-F")


def _resolve_flag_path(value: str, directory: Path) -> str:
    # compile_commands paths are recorded relative to the entry's directory.
    return value if os.path.isabs(value) else str((directory / value).resolve())


def extract_compile_flags(arguments: List[str], directory: Path) -> List[str]:
    """Keep the parse-relevant flags (include paths / defines / std) from a
    compile_commands entry, resolving path-bearing flags against its directory and
    dropping the compiler, the input file, and output/dependency bookkeeping."""
    flags: List[str] = []
    index = 1  # skip argv[0] (the compiler)
    total = len(arguments)
    while index < total:
        argument = arguments[index]
        handled = False
        for prefix in _PATH_FLAGS:
            if argument == prefix and index + 1 < total:
                flags += [prefix, _resolve_flag_path(arguments[index + 1], directory)]
                index += 2
                handled = True
                break
            if argument.startswith(prefix) and len(argument) > len(prefix):
                flags.append(prefix + _resolve_flag_path(argument[len(prefix):], directory))
                index += 1
                handled = True
                break
        if handled:
            continue
        if argument in {"-D", "-U"} and index + 1 < total:
            flags += [argument, arguments[index + 1]]
            index += 2
            continue
        if argument.startswith(("-D", "-U", "-std=")) or argument in {"-ansi", "-nostdinc"}:
            flags.append(argument)
        index += 1
    return flags


def load_compile_commands(source_dir: Path) -> Dict[Path, List[str]]:
    """Map absolute source path -> per-file clang flags from compile_commands.json.

    Real multi-directory C projects need each file's own include paths / defines /
    std to parse; a single global -I mis-parses them. Looked up at
    LACHESIS_COMPILE_COMMANDS or <source_dir>/compile_commands.json; absent, callers
    fall back to the global flag model.
    """
    location = os.environ.get("LACHESIS_COMPILE_COMMANDS")
    candidates = [Path(location)] if location else [source_dir / "compile_commands.json"]
    db_path = next((candidate for candidate in candidates if candidate.is_file()), None)
    if not db_path:
        return {}
    try:
        entries = json.loads(db_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, ValueError):
        return {}
    flags_by_file: Dict[Path, List[str]] = {}
    for entry in entries if isinstance(entries, list) else []:
        file_field = entry.get("file")
        if not file_field:
            continue
        directory = Path(entry.get("directory", "."))
        file_path = (Path(file_field) if os.path.isabs(file_field) else directory / file_field).resolve()
        arguments = entry.get("arguments")
        if arguments is None and entry.get("command"):
            arguments = shlex.split(entry["command"])
        if arguments:
            flags_by_file[file_path] = extract_compile_flags(list(arguments), directory)
    return flags_by_file


def clang_command(
    source_dir: Path, path: Path, *arguments: str,
    file_flags: Optional[List[str]] = None,
) -> List[str]:
    configured = shlex.split(os.environ.get("CLANG", "clang"))
    language = ["-x", "c-header"] if path.suffix.lower() == ".h" else []
    if file_flags is not None:
        base = list(file_flags)
    else:
        base = ["-I", str(source_dir)] + shlex.split(os.environ.get("LACHESIS_CFLAGS", ""))
    return configured + base + language + list(arguments) + [str(path)]


def run_clang(
    source_dir: Path, path: Path, *arguments: str,
    file_flags: Optional[List[str]] = None,
) -> subprocess.CompletedProcess:
    return subprocess.run(
        clang_command(source_dir, path, *arguments, file_flags=file_flags),
        text=True, capture_output=True, check=False,
    )


def clang_jobs() -> int:
    """How many clang processes this frontend keeps in flight at once.

    Deliberately below the core count. Each pass holds one whole ``stdout`` per
    in-flight file, and for the AST pass that is the biggest buffer in the build — a
    real kernel translation unit re-expands its headers into hundreds of MB of JSON
    before the prune below trims it. Concurrency multiplies that peak, so the default
    trades some of the available parallelism for a resident set that does not grow with
    the machine. ``LACHESIS_C_JOBS`` overrides it, ``1`` restores the serial build.
    """
    configured = os.environ.get("LACHESIS_C_JOBS")
    if configured:
        try:
            return max(1, int(configured))
        except ValueError:
            pass
    return max(1, min(4, (os.cpu_count() or 1) // 2))


def emit_tokens() -> bool:
    """Whether to run the token pass at all. ``LACHESIS_EMIT_TOKENS=0`` turns it off.

    The pass is a whole extra clang parse of every file — a quarter of this frontend's
    compiles — and it exists to produce ``token`` nodes and their ``HAS_TOKEN`` /
    ``NEXT_TOKEN`` edges. Those are exactly what the store's ``prune`` lever deletes on
    the way in, so a pruned build was parsing the tree a fourth time to fill a bundle,
    load it, compose it, and then throw it away. A caller that knows it is pruning sets
    this to 0 and the parse never happens.

    Off is a real reduction in what the bundle contains, not a scheduling change, so it
    is recorded: ``lexical_tokens`` goes into the manifest and the ``lexical``
    capability drops from ``partial`` to ``none``. A consumer that wants tokens can
    therefore see that this bundle has none, rather than concluding the file had none.
    """
    return os.environ.get("LACHESIS_EMIT_TOKENS", "1") != "0"


def run_clang_over(
    paths: Iterable[Path], source_dir: Path, *arguments: str,
    file_flags_of: Optional[Dict[Path, List[str]]] = None,
    jobs: Optional[int] = None,
) -> Iterator[Tuple[Path, subprocess.CompletedProcess]]:
    """Run one clang invocation per path, several at a time, yielding in ``paths`` order.

    Every pass below is a serial loop whose per-file work is one ``run_clang`` — a pure
    function of (path, flags) that spends nearly all of its wall time inside a
    subprocess, doing nothing this interpreter needs the GIL for. So the compiles
    overlap on threads while the *consumption* stays exactly as serial and exactly as
    ordered as it was: results come back in the order the paths went in, never the order
    the compiles finished. The emitted graph is therefore byte-identical to the serial
    build, which matters here more than usual — node ids are content digests and the
    manifest hashes what was emitted, so a scheduling-dependent order would show up as a
    changed store.

    At most ``jobs`` compiles are in flight, so the window bounds memory as well as CPU:
    the pool is never handed the whole file list to buffer.
    """
    paths = list(paths)
    flags = file_flags_of or {}
    jobs = jobs or clang_jobs()
    if jobs <= 1 or len(paths) <= 1:
        for path in paths:
            yield path, run_clang(source_dir, path, *arguments,
                                  file_flags=flags.get(path))
        return
    upcoming = iter(paths)
    pending: deque = deque()
    with ThreadPoolExecutor(max_workers=jobs) as pool:
        def submit_next() -> bool:
            path = next(upcoming, None)
            if path is None:
                return False
            pending.append((path, pool.submit(
                run_clang, source_dir, path, *arguments, file_flags=flags.get(path),
            )))
            return True

        for _ in range(jobs):
            if not submit_next():
                break
        while pending:
            path, future = pending.popleft()
            result = future.result()
            # refill only after one result is retired, so the window stays at `jobs`
            submit_next()
            yield path, result


def source_text(path: Path, cache: Dict[Path, str]) -> str:
    if path not in cache:
        try:
            cache[path] = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            cache[path] = ""
    return cache[path]


def display_path(target: Path, source_dir: Path) -> str:
    """Canonical `properties.file` key for a file node.

    Files under the project source dir get a source-relative path (matching the
    root-TU convention); files outside it (system / vendor headers) stay absolute.
    Every file node routes its `file` key through this one helper so open_file /
    open_folder see a single, consistent convention regardless of whether a path
    arrived as a project root or an included header."""
    try:
        return str(target.relative_to(source_dir))
    except ValueError:
        return str(target)


def line_offsets(text: str) -> List[int]:
    offsets = [0]
    for offset, character in enumerate(text):
        if character == "\n":
            offsets.append(offset + 1)
    return offsets


def line_starts(path: Path, text: str, cache: Dict[Path, List[int]]) -> List[int]:
    """Memoize the line->offset table by path, parallel to the ``source_text``
    cache. The table depends only on the file text (already cached), but is looked
    up once per AST node and once per token — rebuilding it each time re-walks the
    whole fully-expanded TU source (headers included), an accidental O(N^2). Cache
    it so each distinct file is scanned exactly once."""
    starts = cache.get(path)
    if starts is None:
        starts = line_offsets(text)
        cache[path] = starts
    return starts


def token_source_length(token_text: str) -> int:
    """How many source characters a dumped token spelling occupies.

    `-dump-tokens` prints a token's spelling with C escapes still in it, so the
    printed length overstates the source length whenever the token contains one.
    Undoing the escapes recovers the real span, but the dump is a *partial* view
    of a preprocessed stream: a spelling can be truncated mid-escape, and then
    there is nothing to undo. Fall back to the printed length rather than fail
    the whole frontend over one token's end offset.
    """
    try:
        return len(token_text.encode("utf-8").decode("unicode_escape"))
    except (UnicodeDecodeError, UnicodeEncodeError):
        return len(token_text)


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
    line_starts_cache: Dict[Path, List[int]],
) -> dict:
    begin = ast_node.get("range", {}).get("begin", {})
    end = ast_node.get("range", {}).get("end", {})
    loc = ast_node.get("loc", {})
    start = begin.get("offset", loc.get("offset", 0))
    finish = end.get("offset", start) + end.get("tokLen", loc.get("tokLen", 0))
    text = source_text(path, texts)
    starts = line_starts(path, text, line_starts_cache)

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


def position_from_line(
    path: Path, line: int, texts: Dict[Path, str],
    line_starts_cache: Dict[Path, List[int]],
) -> dict:
    """A source position spanning the physical definition line (macros have no AST
    range). Backslash-continued lines are folded into a single logical span so
    ``read_body`` shows the whole ``#define``."""
    text = source_text(path, texts)
    starts = line_starts(path, text, line_starts_cache)
    lines = text.splitlines()
    index = max(0, min(line, len(starts)) - 1)
    start = starts[index]
    last = index
    while last < len(lines) and lines[last].endswith("\\"):
        last += 1
    end = starts[last + 1] - 1 if last + 1 < len(starts) else len(text)
    return {
        "file": str(path), "absolute_file": str(path),
        "start_offset": start, "end_offset": max(start, end),
        "start_line": index + 1, "start_column": 1,
        "end_line": last + 1, "end_column": len(lines[last]) + 1 if last < len(lines) else 1,
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


def _has_include_origin(node: dict) -> bool:
    """True when a Clang AST node originates from an ``#include``d file.

    Clang stamps ``includedFrom`` on the location of every node that comes from a
    header — repeated on each such node, even consecutive top-level siblings where
    the redundant ``file`` field is omitted — so its presence reliably identifies
    header/system content. Every descendant of such a node inherits the origin.
    """
    loc = node.get("loc", {})
    begin = node.get("range", {}).get("begin", {})
    return bool(loc.get("includedFrom") or begin.get("includedFrom"))


class AstStore:
    """Disk-backed sequence of Clang ASTs, re-parsed one translation unit at a time.

    A single real kernel translation unit dumps ~1 GB of JSON AST, and the
    declaration/binding and body passes each re-walk every TU; holding all of them
    parsed in memory simultaneously would exhaust it. Each recovered AST is spilled
    to a temp file and re-parsed on demand, so peak memory stays at one TU while the
    passes keep iterating ``(path, ast)`` unchanged. The trade is disk (~AST size
    per TU) and re-parsing each TU once per pass.
    """

    def __init__(self, directory: Path) -> None:
        self._directory = directory
        self._entries: List[Tuple[Path, Path]] = []

    def add(self, path: Path, ast_json: str) -> None:
        spill = self._directory / f"{len(self._entries)}.json"
        spill.write_text(ast_json, encoding="utf-8")
        self._entries.append((path, spill))

    def __iter__(self) -> Iterator[Tuple[Path, dict]]:
        for path, spill in self._entries:
            with spill.open(encoding="utf-8") as handle:
                yield path, json.load(handle)

    def __len__(self) -> int:
        return len(self._entries)


def main() -> int:
    if len(sys.argv) < 2:
        raise SystemExit(
            "Usage: python3 lachesis/frontends/c/build_graph.py SRC_DIR [OUT_DIR]")
    source_dir = Path(sys.argv[1]).resolve()
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
    # Per-file compiler flags (include paths / defines / std) so multi-directory
    # projects parse with their real build configuration; empty ⇒ global fallback.
    compile_commands = load_compile_commands(source_dir)

    graph = Graph()
    texts: Dict[Path, str] = {}
    line_starts_cache: Dict[Path, List[int]] = {}
    file_ids: Dict[Path, str] = {}
    declarations_by_raw_id: Dict[str, str] = {}
    declarations_by_name: Dict[Tuple[str, str], List[str]] = defaultdict(list)
    function_parameters: Dict[str, List[str]] = defaultdict(list)
    ast_spill = tempfile.TemporaryDirectory(prefix="lachesis-c-ast-")
    asts = AstStore(Path(ast_spill.name))
    diagnostics: List[Tuple[Path, str]] = []
    failed_files: Set[Path] = set()

    for path in files:
        text = source_text(path, texts)
        file_id = stable_id("file", path)
        provenance, is_external, is_system = classify_provenance(path, root_set, system_dirs)
        shown = display_path(path, source_dir)
        file_ids[path] = graph.node(
            "T0", file_id, "file", shown,
            file=shown, absolute_file=str(path),
            content_hash=hashlib.sha256(text.encode("utf-8")).hexdigest(),
            lines=len(text.splitlines()), language="c",
            provenance=provenance, is_external=is_external, is_system=is_system,
            included_because="project-root",
        )

    # Compiler dependency extraction makes framework/header ownership explicit.
    for path, dependency in run_clang_over(translation_units, source_dir, "-MM",
                                           file_flags_of=compile_commands):
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
                shown = display_path(target, source_dir)
                file_ids[target] = graph.node(
                    "T0", target_id, "file", shown,
                    file=shown, absolute_file=str(target),
                    content_hash=hashlib.sha256(text.encode("utf-8")).hexdigest(),
                    lines=len(text.splitlines()), language="c",
                    provenance=provenance, is_external=is_external, is_system=is_system,
                    included_because="included-header",
                )
            graph.edge("DEPENDS_ON", file_ids[path], file_ids[target], directive="#include")

    # Parse headers independently as compiler roots. This retains their exact
    # offsets; Clang otherwise reports included declarations using header-local
    # offsets but only the including-file provenance.
    for path, result in run_clang_over(
        files, source_dir, "-Xclang", "-ast-dump=json", "-fsyntax-only",
        "-Wno-everything", file_flags_of=compile_commands,
    ):
        # Clang emits a COMPLETE AST on stdout even when it exits nonzero from
        # residual (cross-config) diagnostics — routine for real kernel TUs, which
        # almost always have a few. Gating on returncode would discard that entire
        # AST and collapse the file to a lexical-only husk (file node + tokens, no
        # symbols/calls). So the AST is consumed whenever one is present; a file
        # only falls back to "failed" when nothing usable was recovered: empty
        # stdout, unparseable JSON, or a TranslationUnitDecl with no declarations.
        # Diagnostics are recorded either way.
        stderr_lines = [line for line in result.stderr.splitlines() if line.strip()]
        meaningful = [line for line in stderr_lines if "error:" in line or "warning:" in line]
        diagnostics.extend((path, line) for line in meaningful)
        recovered = False
        if result.stdout.strip():
            try:
                ast = json.loads(result.stdout)
            except json.JSONDecodeError as error:
                diagnostics.append((path, f"invalid Clang AST JSON: {error}"))
            else:
                # Clang injects an implicit built-in typedef preamble
                # (``__int128_t`` &c.) into every TU, present even when the source
                # is entirely unparseable — so "has inner decls" is too weak. A TU
                # is only genuinely recovered when it carries at least one
                # *non-implicit* declaration (an actual source/header symbol).
                if any(
                    isinstance(child, dict) and child.get("kind")
                    and not child.get("isImplicit")
                    for child in ast.get("inner", [])
                ):
                    # Prune header/system top-level subtrees before spilling. Every
                    # pass below emits only for non-included nodes (``eligible``), so
                    # the ~1 GB of re-expanded header AST the raw stdout carries is
                    # already discarded — dropping it here shrinks per-TU scratch from
                    # ~1 GB to tens of MB with no change to the emitted graph. The tiny
                    # implicit builtin preamble is kept so the bytes the passes consume
                    # are untouched; a header's own decls survive because every file is
                    # also parsed as its own compiler root.
                    #
                    # RecordDecls are the one exception that must survive pruning: an
                    # ops-struct initializer in a .c (``static const struct T x = {…}``)
                    # binds its handlers by the field *layout* of ``struct T`` — and for
                    # a kernel driver the struct is defined in a header outside the
                    # ingested tree (e.g. ``struct net_device_ops`` in netdevice.h), so
                    # the only place its field order/names are visible is the TU's own
                    # included copy. Keep those (small, body-less) so ``collect_record_fields``
                    # can still recover the layout the binding pass needs.
                    ast["inner"] = [
                        child for child in ast.get("inner", [])
                        if child.get("isImplicit")
                        or not _has_include_origin(child)
                        or child.get("kind") == "RecordDecl"
                    ]
                    asts.add(path, json.dumps(ast))
                    recovered = True
                else:
                    diagnostics.append((path, "Clang AST recovered no declarations"))
                del ast
        if not recovered:
            # Degrade, don't drop: the file node (emitted above) survives with its
            # compiler diagnostics attached as T4 proof; only the semantic layer for
            # this one file is unavailable. Capture fatal messages that carry no
            # error:/warning: prefix so nothing is lost.
            failed_files.add(path)
            diagnostics.extend(
                (path, line) for line in stderr_lines if line not in meaningful
            )

    def eligible(node: dict, inherited_included: bool) -> bool:
        return not (inherited_included or _has_include_origin(node))

    # Declaration pass.
    def declarations(node: dict, path: Path, owner: Optional[str] = None, included: bool = False) -> None:
        is_included = not eligible(node, included)
        kind = node.get("kind", "")
        current_owner = owner
        if not node.get("isImplicit") and not is_included and kind in ENTITY_KINDS:
            entity_kind = ENTITY_KINDS[kind]
            position = position_from_ast(node, path, texts, line_starts_cache)
            # An unnamed record or enum still needs something to be named by, and it
            # must not be clang's `id`: that is the AST node's *address*, which moves
            # between runs under ASLR. An identity built from it is not reproducible,
            # so two builds of unchanged source disagree and any fact anchored to the
            # declaration cannot be rejoined after a rebuild. The declaration's own
            # source span is stable and is already part of the identity below.
            name = node.get("name") or f"<anonymous@{position['start_offset']}>"
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
                # A bodyless prototype (header/forward declaration) twins the real
                # definition under the same name; flag it so the cross-TU pass and the
                # nav resolver can prefer the body-bearing node.
                graph.nodes[entity_id]["properties"]["declaration_only"] = not has_body
                if owner is None and has_body and node.get("storageClass") != "static":
                    graph.edge("EXPORTS", file_ids[path], entity_id, name=name)
        elif not node.get("isImplicit") and not is_included and kind in VALUE_KINDS:
            value_kind = VALUE_KINDS[kind]
            name = node.get("name") or "<anonymous>"
            position = position_from_ast(node, path, texts, line_starts_cache)
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

    # Indirect-dispatch binding pre-pass. Function pointers reach their targets
    # through ops-struct slots (`.read = ext4_file_read`) and pointer variables
    # (`fp = handler`); on C/kernel this indirection *is* the control flow. We
    # resolve those bindings here so the call pass can attach MAY_INVOKE to the
    # dispatch call-site (parity with the TS frontend). Genuinely unresolved
    # pointers keep their READS_CALLEE slot edge — the indirection is never dropped.
    record_fields_by_type: Dict[str, List[Tuple[Optional[str], Optional[str]]]] = {}

    def collect_record_fields(node: dict) -> None:
        if node.get("kind") == "RecordDecl" and node.get("name") and node.get("tagUsed"):
            key = f'{node["tagUsed"]} {node["name"]}'
            # Each slot is (field name, field node-id). The name is always present;
            # the node-id is None when the struct is defined in an un-ingested header
            # (its FieldDecls are never registered as graph nodes). The binding pass
            # uses the id for in-tree dispatch resolution and the name for ops-struct
            # registration, so a name-only layout still yields the registration edge.
            harvested = [
                (child.get("name"), declarations_by_raw_id.get(child.get("id", "")))
                for child in node.get("inner", []) if child.get("kind") == "FieldDecl"
            ]
            existing = record_fields_by_type.get(key)
            if existing is not None and len(existing) == len(harvested):
                # Same layout seen from multiple TUs (an included copy and the
                # header-as-root copy): prefer a real node-id over None so the
                # dispatch path keeps its slot, and never let a body-less forward
                # decl (no fields) clobber a real layout.
                record_fields_by_type[key] = [
                    (name or prev_name, fid or prev_id)
                    for (name, fid), (prev_name, prev_id) in zip(harvested, existing)
                ]
            elif harvested or existing is None:
                record_fields_by_type[key] = harvested
        for child in node.get("inner", []):
            collect_record_fields(child)

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
    # Ops-struct registrations: (ops-struct variable id, field slot id, handler id,
    # field name). `field_bindings` is keyed by slot only (a dispatch call-site
    # `ops->f()` knows the field, not which instance), but an *entry-point* handler is
    # registered into a concrete table and never dispatched in-tree — so its slot
    # binding is otherwise invisible to reverse navigation. Keeping the owning variable
    # lets us surface the registration as a MAY_INVOKE(table -> handler) edge, so
    # `callers(handler)` walks from a leaf handler back to the ops table it is
    # registered in. The field name labels the slot even when the struct is defined in
    # an un-ingested header (no field node, so `slot_id` is None).
    ops_registrations: List[Tuple[str, Optional[str], str, Optional[str]]] = []

    def bind_init_list(init_list: dict, variable_id: Optional[str] = None) -> None:
        # Clang emits initializer values in record-field order (holes filled with
        # ImplicitValueInitExpr), so element position maps to the ordered fields.
        type_name = normalize_type(init_list.get("type", {}).get("qualType", ""))
        fields = record_fields_by_type.get(type_name)
        if not fields:
            return
        for position, element in enumerate(init_list.get("inner", [])):
            if position >= len(fields):
                continue
            field_name, field_id = fields[position]
            for function_id in function_refs(element):
                # In-tree dispatch resolution keys on the field node; skip when the
                # struct is header-defined and has no field node.
                if field_id:
                    field_bindings[field_id].add(function_id)
                # Entry-point registration only needs the owning table and the slot
                # name, so it fires even for a header-defined ops struct.
                if variable_id is not None:
                    ops_registrations.append((variable_id, field_id, function_id, field_name))

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
            variable_id = declarations_by_raw_id.get(node.get("id", ""))
            is_variable = variable_id and graph.nodes.get(variable_id, {}).get("kind") == "variable"
            init_list = next((c for c in node.get("inner", []) if c.get("kind") == "InitListExpr"), None)
            if init_list is not None:
                # Pass the owning variable so ops-struct slot bindings record the
                # concrete table, not just the shared field slot.
                bind_init_list(init_list, variable_id if is_variable else None)
            elif is_variable:
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

    # One combined table-building pass over each TU: declarations (the global
    # symbol table), then record fields, then dispatch bindings — each reads what
    # the prior step produced for the *same* TU, and every TU is self-contained
    # (it includes its own headers), so the three fuse safely into a single reload.
    # The body pass below reloads each TU once more; peak memory stays at one TU.
    for path, ast in asts:
        declarations(ast, path)
        collect_record_fields(ast)
        collect_bindings(ast)

    # Ops-struct registration edges. A handler bound into a dispatch table
    # (`static const struct net_device_ops ops = { .ndo_start_xmit = handler }`) is an
    # entry point the runtime invokes through the table; there is no in-tree call-site,
    # so without this edge `callers(handler)` is empty and reverse navigation from a
    # leaf handler is blind. Model the registration as MAY_INVOKE(table -> handler) so
    # the handler's fan-in surfaces the ops table it belongs to (and the slot it fills).
    for variable_id, _slot_id, function_id, slot_name in ops_registrations:
        graph.edge(
            "MAY_INVOKE", variable_id, function_id,
            dispatch="ops-struct", resolution="registration", slot=slot_name,
        )

    # Body/reference/call pass.
    def body_identity(node: dict, path: Path) -> str:
        position = position_from_ast(node, path, texts, line_starts_cache)
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
            position = position_from_ast(node, path, texts, line_starts_cache)
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
    tokens_wanted = emit_tokens()
    for path, result in run_clang_over(
        files if tokens_wanted else [], source_dir, "-Xclang", "-dump-tokens",
        "-fsyntax-only", "-Wno-everything", file_flags_of=compile_commands,
    ):
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
            starts = line_starts(path, text, line_starts_cache)
            start = starts[line_number - 1] + column - 1 if line_number <= len(starts) else 0
            end = start + token_source_length(token_text)
            token_id = stable_id("token", path, start, end, token_kind)
            graph.node(
                "T4", token_id, "token", token_text,
                file=display_path(path, source_dir), absolute_file=str(path),
                start_offset=start, end_offset=end, start_line=line_number,
                start_column=column, end_line=line_number,
                end_column=column + max(0, end - start - 1),
                token_kind=token_kind, trivia=False,
            )
            graph.edge("HAS_TOKEN", file_ids[path], token_id)
            graph.edge("NEXT_TOKEN", previous, token_id)
            previous = token_id

    # Preprocessor macro recovery. The JSON AST is post-preprocessor, so macros
    # are reconstructed from a dedicated -E -dD pass (macros.py) and made
    # addressable. Preprocessing is lexical, so this succeeds even for a file
    # whose C body failed to parse — its #defines are still real.
    for path, result in run_clang_over(
        [path for path in files if path in file_ids], source_dir, "-E", "-dD",
        file_flags_of=compile_commands,
    ):
        if result.returncode != 0:
            continue
        for macro in parse_macro_definitions(result.stdout, path):
            position = position_from_line(path, int(macro["line"]), texts, line_starts_cache)
            signature = (
                f'{macro["name"]}({", ".join(macro["parameters"])})'
                if macro["form"] == "function-like" else macro["name"]
            )
            macro_id = stable_id(
                "macro", path, position["start_offset"], macro["name"],
            )
            graph.node(
                "T1", macro_id, "macro", macro["name"], **position,
                syntax_kind="macro", form=macro["form"],
                parameters=macro["parameters"], body=macro["body"],
                signature=signature,
            )
            graph.edge("DECLARES", file_ids[path], macro_id)

    for path, message in diagnostics:
        diagnostic_id = stable_id("diagnostic", path, message)
        graph.node(
            "T4", diagnostic_id, "diagnostic", "clang",
            category="compiler", message=message, file=str(path),
        )
        graph.edge("HAS_DIAGNOSTIC", file_ids.get(path), diagnostic_id)

    # ---- Cross-TU call linking ------------------------------------------------
    # Call resolution in the bodies pass is intra-TU: a CallExpr whose definition
    # lives in another translation unit only sees the header prototype (which twins
    # the real definition under the same name), so the single-candidate name
    # fallback is ambiguous and the call is left "dynamic-or-unresolved". Now that
    # every TU is merged into one graph, link those calls to the unique body-bearing
    # definition and collapse the prototype/definition twins. Ambiguity is bounded:
    # extern names are unique, and a name shared by two static definitions across TUs
    # is deliberately left unresolved rather than linked to an arbitrary twin.
    definitions_by_name: Dict[str, List[str]] = defaultdict(list)
    for node_id, node in graph.nodes.items():
        if node.get("kind") == "function" and not node["properties"].get("declaration_only"):
            definitions_by_name[node["label"]].append(node_id)

    def sole_definition(name: Optional[str]) -> Optional[str]:
        defs = definitions_by_name.get(name or "", ())
        return defs[0] if len(defs) == 1 else None

    # 1. Map each bodyless prototype to its unique definition and connect the twins,
    #    so the body is reachable from a header prototype.
    prototype_definition: Dict[str, str] = {}
    for node_id, node in graph.nodes.items():
        if node.get("kind") == "function" and node["properties"].get("declaration_only"):
            definition = sole_definition(node["label"])
            if definition and definition != node_id:
                prototype_definition[node_id] = definition
                graph.edge("REFERS_TO", node_id, definition, reason="prototype-of")

    # 2. Redirect any resolved CALLS/INVOKES/MAY_INVOKE that landed on a prototype
    #    (cross-TU or same-file forward declaration) onto the definition twin — so a
    #    dispatch or ops-struct registration edge points at the body, not the stub.
    #    A dispatch/registration edge keeps its own resolution tag (binding /
    #    registration); a plain resolved call is retagged cross-tu.
    for edge in graph.edges:
        if edge["kind"] in {"CALLS", "INVOKES", "MAY_INVOKE"}:
            definition = prototype_definition.get(edge["target"])
            if definition:
                edge["target"] = definition
                if edge["properties"].get("resolution") not in {"registration", "binding"}:
                    edge["properties"]["resolution"] = "cross-tu"

    # 3. Resolve each still-unresolved call-site whose callee name has a unique
    #    definition, and 4. repoint any call whose primary target was a prototype.
    for node_id, node in graph.nodes.items():
        if node.get("kind") != "call":
            continue
        props = node["properties"]
        target = props.get("primary_target_id")
        if target in prototype_definition:  # (4) repoint off the prototype twin
            props["primary_target_id"] = prototype_definition[target]
            props["resolution"] = "cross-tu"
        elif props.get("resolution") == "dynamic-or-unresolved" and not target:
            definition = sole_definition(props.get("callee"))
            if definition:
                props["resolution"] = "cross-tu"
                props["primary_target_id"] = definition
                graph.edge("INVOKES", node_id, definition, resolution="cross-tu")
                owner = props.get("owner_function_id")
                if owner:
                    graph.edge("CALLS", owner, definition, callsite=node_id)

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

    analyzed_file_count = len(files) - len(failed_files)
    # Honest coverage: a file that failed to parse contributes only its file node,
    # so any capability that depends on complete parsing can no longer claim it.
    # A "complete" claim collapses to "partial" the moment coverage has a hole.
    parse_complete = not failed_files
    complete_if_parsed = "complete" if parse_complete else "partial"
    manifest = {
        "version": 2, "frontend_contract_version": CONTRACT_VERSION,
        "frontend_id": FRONTEND_ID, "generator": FRONTEND_ID, "languages": ["c"],
        # A bundle built without the token pass holds no lexical stream at all, so the
        # claim is "none", not a weaker "partial". The distinction is the difference
        # between "this file had no tokens" and "nobody looked".
        "lexical_tokens": tokens_wanted,
        "capabilities": {
            "lexical": "partial" if tokens_wanted else "none",
            "syntax": complete_if_parsed, "modules": complete_if_parsed,
            "dependency_sources": complete_if_parsed,
            "symbols": "partial", "types": "partial", "calls": "partial",
            "control_flow": "partial", "direct_data_flow": "partial",
            "heap_identity": "none", "context_sensitivity": "none",
            "branch_histories": "none", "taint_policy": "none",
            "runtime_models": "none", "effects": "none", "async_events": "none",
            # dynamic_behavior: indirect dispatch (ops-struct + function pointers) is
            # resolved to MAY_INVOKE/PASSES_CALLBACK. framework_wiring: the C frontend
            # models no framework DI/registration convention, so it is honestly none.
            "dynamic_behavior": "partial", "framework_wiring": "none",
            "security_roles": "none",
        },
        "compiler": subprocess.run(shlex.split(os.environ.get("CLANG", "clang")) + ["--version"], text=True, capture_output=True).stdout.splitlines()[0],
        "source_dir": str(source_dir), "root_file_count": len(files),
        "analyzed_file_count": analyzed_file_count,
        "failed_file_count": len(failed_files),
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
    ast_spill.cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
