"""TypeScript import/export discovery and module-path resolution."""
import glob
import json
import os
import re
from typing import List, Optional, Tuple

from .types import ExportInfo, ImportBinding, ImportInfo

IMPORT_FROM_RE = re.compile(
    r"^\s*import\s+"
    r"(?P<type_only>type\s+)?"
    r"(?P<clause>(?:[A-Za-z_$][\w$]*\s*,\s*)?"
    r"(?:\{[^}]*\}|\*\s+as\s+[A-Za-z_$][\w$]*|[A-Za-z_$][\w$]*))"
    r"\s+from\s+['\"](?P<source>[^'\"]+)['\"]",
    re.MULTILINE,
)
SIDE_EFFECT_IMPORT_RE = re.compile(
    r"^\s*import\s*['\"](?P<source>[^'\"]+)['\"]", re.MULTILINE
)
IMPORT_EQUALS_RE = re.compile(
    r"^\s*import\s+(?P<name>[A-Za-z_$][\w$]*)\s*=\s*"
    r"require\s*\(\s*['\"](?P<source>[^'\"]+)['\"]\s*\)",
    re.MULTILINE,
)
DYNAMIC_IMPORT_RE = re.compile(
    r"\bimport\s*\(\s*['\"](?P<source>[^'\"]+)['\"]\s*\)"
)
DESTRUCTURED_REQUIRE_RE = re.compile(
    r"\b(?:const|let|var)\s+(?P<clause>\{[^}]+\})\s*=\s*"
    r"require\s*\(\s*['\"](?P<source>[^'\"]+)['\"]\s*\)",
    re.MULTILINE,
)
BOUND_REQUIRE_RE = re.compile(
    r"\b(?:const|let|var)\s+(?P<name>[A-Za-z_$][\w$]*)\s*=\s*"
    r"require\s*\(\s*['\"](?P<source>[^'\"]+)['\"]\s*\)",
    re.MULTILINE,
)
REQUIRE_RE = re.compile(
    r"\brequire\s*\(\s*['\"](?P<source>[^'\"]+)['\"]\s*\)"
)
EXPORT_LIST_RE = re.compile(
    r"^\s*export\s+(?P<type_only>type\s+)?"
    r"(?P<clause>\{[^}]*\}|\*(?:\s+as\s+[A-Za-z_$][\w$]*)?)"
    r"(?:\s+from\s+['\"](?P<source>[^'\"]+)['\"])?",
    re.MULTILINE,
)
EXPORT_DECLARATION_RE = re.compile(
    r"^\s*export\s+(?P<default>default\s+)?"
    r"(?:(?:declare|abstract|async)\s+)*"
    r"(?P<kind>function|class|const|let|var|interface|type|enum|namespace|module)\b"
    r"(?:\s+(?P<name>[A-Za-z_$][\w$]*))?",
    re.MULTILINE,
)
EXPORT_DEFAULT_RE = re.compile(r"^\s*export\s+default\b", re.MULTILINE)
EXPORT_ASSIGNMENT_RE = re.compile(
    r"^\s*export\s*=\s*(?P<name>[A-Za-z_$][\w$]*)", re.MULTILINE
)
EXPORT_NAMESPACE_RE = re.compile(
    r"^\s*export\s+as\s+namespace\s+(?P<name>[A-Za-z_$][\w$]*)", re.MULTILINE
)
COMMONJS_NAMED_EXPORT_RE = re.compile(
    r"^\s*(?:module\.)?exports\.(?P<name>[A-Za-z_$][\w$]*)\s*=", re.MULTILINE
)
COMMONJS_OBJECT_EXPORT_RE = re.compile(
    r"^\s*module\.exports\s*=\s*\{(?P<names>[^}]*)\}", re.MULTILINE
)

MODULE_EXTENSIONS = (
    "", ".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs", ".d.ts",
)
INDEX_FILES = tuple(f"index{extension}" for extension in MODULE_EXTENSIONS[1:])
JSON_CACHE = {}
TSCONFIG_CACHE = {}
WORKSPACE_CACHE = {}


def read_jsonc(path: str) -> dict:
    if path in JSON_CACHE:
        return JSON_CACHE[path]
    try:
        with open(path, "r", encoding="utf-8") as file_handle:
            text = file_handle.read()
        text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
        text = re.sub(r"(^|\s)//.*$", r"\1", text, flags=re.MULTILINE)
        text = re.sub(r",\s*([}\]])", r"\1", text)
        value = json.loads(text)
    except (OSError, ValueError):
        value = {}
    JSON_CACHE[path] = value
    return value


def find_upward(start_dir: str, filename: str) -> Optional[str]:
    current = os.path.abspath(start_dir)
    while True:
        candidate = os.path.join(current, filename)
        if os.path.isfile(candidate):
            return candidate
        parent = os.path.dirname(current)
        if parent == current:
            return None
        current = parent


def tsconfig_options(importer_dir: str) -> tuple:
    config_path = find_upward(importer_dir, "tsconfig.json")
    if not config_path:
        return None, {}
    if config_path not in TSCONFIG_CACHE:
        TSCONFIG_CACHE[config_path] = read_jsonc(config_path).get("compilerOptions", {})
    return config_path, TSCONFIG_CACHE[config_path]


def resolve_tsconfig_path(importer_dir: str, source: str) -> Optional[str]:
    config_path, options = tsconfig_options(importer_dir)
    if not config_path:
        return None
    config_dir = os.path.dirname(config_path)
    base_dir = os.path.abspath(os.path.join(config_dir, options.get("baseUrl", ".")))
    for pattern, targets in options.get("paths", {}).items():
        regex = "^" + re.escape(pattern).replace(r"\*", "(.*)") + "$"
        match = re.match(regex, source)
        if not match:
            continue
        wildcard = match.group(1) if match.groups() else ""
        for target in ([targets] if isinstance(targets, str) else targets):
            candidate = target.replace("*", wildcard)
            resolved = first_existing_module(os.path.join(base_dir, candidate))
            if resolved:
                return resolved
    if options.get("baseUrl"):
        return first_existing_module(os.path.join(base_dir, source))
    return None


def workspace_packages(importer_dir: str) -> dict:
    package_path = find_upward(importer_dir, "package.json")
    while package_path:
        package = read_jsonc(package_path)
        workspaces = package.get("workspaces")
        if workspaces:
            root = os.path.dirname(package_path)
            if root in WORKSPACE_CACHE:
                return WORKSPACE_CACHE[root]
            patterns = workspaces.get("packages", []) if isinstance(workspaces, dict) else workspaces
            if isinstance(patterns, str):
                patterns = [patterns]
            packages = {}
            for pattern in patterns or []:
                for directory in glob.glob(os.path.join(root, pattern)):
                    child_manifest = os.path.join(directory, "package.json")
                    child = read_jsonc(child_manifest)
                    if child.get("name"):
                        packages[child["name"]] = directory
            WORKSPACE_CACHE[root] = packages
            return packages
        parent = os.path.dirname(os.path.dirname(package_path))
        package_path = find_upward(parent, "package.json") if parent else None
    return {}


def conditional_export(value):
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        for item in value:
            selected = conditional_export(item)
            if selected:
                return selected
    if isinstance(value, dict):
        for condition in ("types", "import", "require", "node", "default"):
            if condition in value:
                selected = conditional_export(value[condition])
                if selected:
                    return selected
    return None


def package_entry(package_dir: str, subpath: str = "") -> Optional[str]:
    manifest = read_jsonc(os.path.join(package_dir, "package.json"))
    exports = manifest.get("exports")
    export_key = f"./{subpath}" if subpath else "."
    selected = None
    if isinstance(exports, str) and not subpath:
        selected = exports
    elif isinstance(exports, dict):
        selected = conditional_export(exports.get(export_key))
        if selected is None:
            for pattern, value in exports.items():
                if "*" not in str(pattern):
                    continue
                regex = "^" + re.escape(pattern).replace(r"\*", "(.*)") + "$"
                match = re.match(regex, export_key)
                if match:
                    selected = conditional_export(value)
                    if selected and match.groups():
                        selected = selected.replace("*", match.group(1))
                    break
        if selected is None and not any(str(key).startswith(".") for key in exports):
            selected = conditional_export(exports)
    if selected:
        resolved = first_existing_module(os.path.join(package_dir, selected))
        if resolved:
            return resolved
    if subpath:
        resolved = first_existing_module(os.path.join(package_dir, subpath))
        if resolved:
            return resolved
    for field in ("types", "typings", "module", "main"):
        if manifest.get(field):
            resolved = first_existing_module(os.path.join(package_dir, manifest[field]))
            if resolved:
                return resolved
    return first_existing_module(os.path.join(package_dir, "index"))


def first_existing_module(base_path: str) -> Optional[str]:
    for extension in MODULE_EXTENSIONS:
        candidate = base_path + extension
        if os.path.isfile(candidate):
            return os.path.abspath(candidate)
    if os.path.isdir(base_path):
        for filename in INDEX_FILES:
            candidate = os.path.join(base_path, filename)
            if os.path.isfile(candidate):
                return os.path.abspath(candidate)
    return None


def package_name_and_subpath(source: str) -> Tuple[str, str]:
    parts = source.split("/")
    package_parts = parts[:2] if source.startswith("@") else parts[:1]
    return "/".join(package_parts), "/".join(parts[len(package_parts):])


def resolve_import(importer_path: str, source: str) -> Optional[str]:
    if source.startswith("node:"):
        return source
    importer_dir = os.path.dirname(os.path.abspath(importer_path))
    if source.startswith("."):
        return first_existing_module(os.path.normpath(os.path.join(importer_dir, source)))

    configured = resolve_tsconfig_path(importer_dir, source)
    if configured:
        return configured

    package_name, subpath = package_name_and_subpath(source)
    workspace_dir = workspace_packages(importer_dir).get(package_name)
    if workspace_dir:
        return package_entry(workspace_dir, subpath) or os.path.abspath(workspace_dir)

    search_dir = importer_dir
    while True:
        package_dir = os.path.join(search_dir, "node_modules", package_name)
        if os.path.isdir(package_dir):
            return package_entry(package_dir, subpath) or os.path.abspath(package_dir)
        parent = os.path.dirname(search_dir)
        if parent == search_dir:
            return None
        search_dir = parent


def source_kind(source: str, resolved_path: Optional[str] = None) -> str:
    if source.startswith("."):
        return "local"
    if source.startswith("node:"):
        return "builtin"
    if resolved_path and os.path.isfile(resolved_path) and "node_modules" not in resolved_path:
        return "workspace/alias"
    return "package"


def normalized_clause(clause: str) -> str:
    return " ".join(clause.split())


def clause_kind(clause: str, type_only: bool) -> str:
    if type_only:
        return "type"
    brace_start = clause.find("{")
    brace_end = clause.rfind("}")
    if brace_start < 0 or brace_end < brace_start:
        return "value"
    items = [
        item.strip()
        for item in clause[brace_start + 1:brace_end].split(",")
        if item.strip()
    ]
    type_flags = [item.startswith("type ") for item in items]
    has_type = any(type_flags)
    has_value = bool(clause[:brace_start].strip(" ,\t\r\n")) or any(
        not flag for flag in type_flags
    )
    if has_type and not has_value:
        return "type"
    if has_type and has_value:
        return "mixed"
    return "value"


def import_bindings(symbols: str, form: str) -> List[ImportBinding]:
    if form in {"side-effect", "dynamic"}:
        return []
    if form == "import-equals":
        return [{"imported": "*", "local": symbols.strip()}]

    bindings = []
    brace_start = symbols.find("{")
    brace_end = symbols.rfind("}")
    prefix = symbols[:brace_start] if brace_start >= 0 else symbols
    default_name = prefix.strip(" ,\t\r\n")
    if default_name and not default_name.startswith("*"):
        bindings.append({"imported": "default", "local": default_name})

    namespace = re.search(r"\*\s+as\s+([A-Za-z_$][\w$]*)", symbols)
    if namespace:
        bindings.append({"imported": "*", "local": namespace.group(1)})

    if brace_start >= 0 and brace_end > brace_start:
        for item in symbols[brace_start + 1:brace_end].split(","):
            item = item.strip()
            if not item:
                continue
            if item.startswith("type "):
                item = item[5:].strip()
            names = (
                re.split(r"\s*:\s*", item)
                if form == "commonjs"
                else re.split(r"\s+as\s+", item)
            )
            bindings.append({"imported": names[0].strip(), "local": names[-1].strip()})
    return bindings


def import_record(
    source: str,
    symbols: str,
    form: str,
    import_kind: str,
    importer_path: Optional[str],
) -> ImportInfo:
    normalized_symbols = normalized_clause(symbols)
    resolved_path = resolve_import(importer_path, source) if importer_path else None
    return {
        "source": source,
        "symbols": normalized_symbols,
        "form": form,
        "source_kind": source_kind(source, resolved_path),
        "import_kind": import_kind,
        "resolved_path": resolved_path,
        "bindings": import_bindings(normalized_symbols, form),
    }


def find_imports(text: str, importer_path: Optional[str] = None) -> List[ImportInfo]:
    imports = []
    claimed_require_spans = []
    for match in IMPORT_FROM_RE.finditer(text):
        source = match.group("source")
        clause = match.group("clause")
        imports.append((match.start(), import_record(
            source, clause, "from",
            clause_kind(clause, bool(match.group("type_only"))), importer_path,
        )))
    for match in SIDE_EFFECT_IMPORT_RE.finditer(text):
        imports.append((match.start(), import_record(
            match.group("source"), "(side effect)", "side-effect", "value", importer_path,
        )))
    for match in IMPORT_EQUALS_RE.finditer(text):
        imports.append((match.start(), import_record(
            match.group("source"), match.group("name"), "import-equals", "value", importer_path,
        )))
    for match in DYNAMIC_IMPORT_RE.finditer(text):
        imports.append((match.start(), import_record(
            match.group("source"), "(dynamic)", "dynamic", "value", importer_path,
        )))
    for regex, clause_group in (
        (DESTRUCTURED_REQUIRE_RE, "clause"),
        (BOUND_REQUIRE_RE, "name"),
    ):
        for match in regex.finditer(text):
            claimed_require_spans.append((match.start(), match.end()))
            imports.append((match.start(), import_record(
                match.group("source"), match.group(clause_group),
                "commonjs", "value", importer_path,
            )))
    for match in REQUIRE_RE.finditer(text):
        if any(start <= match.start() < end for start, end in claimed_require_spans):
            continue
        imports.append((match.start(), import_record(
            match.group("source"), "(side effect)", "side-effect", "value", importer_path,
        )))
    return [record for _position, record in sorted(imports, key=lambda item: item[0])]


def exported_names(clause: str) -> List[str]:
    clause = clause.strip()
    if clause.startswith("*"):
        namespace = re.search(r"\bas\s+([A-Za-z_$][\w$]*)", clause)
        return [namespace.group(1) if namespace else "*"]
    names = []
    for item in clause[1:-1].split(","):
        item = item.strip()
        if not item:
            continue
        if item.startswith("type "):
            item = item[5:].strip()
        names.append(re.split(r"\s+as\s+", item)[-1].strip())
    return names


def reexported_source_name(clause: str, exported_name: str) -> Optional[str]:
    """Map a public re-export name back to its name in the source module."""
    clause = clause.strip()
    if clause.startswith("*"):
        namespace = re.search(r"\bas\s+([A-Za-z_$][\w$]*)", clause)
        if namespace:
            return "*" if namespace.group(1) == exported_name else None
        return exported_name
    for item in clause[1:-1].split(","):
        item = item.strip()
        if not item:
            continue
        if item.startswith("type "):
            item = item[5:].strip()
        names = re.split(r"\s+as\s+", item)
        source_name = names[0].strip()
        public_name = names[-1].strip()
        if public_name == exported_name:
            return source_name
    return None


def find_exports(
    text: str, exporter_path: Optional[str] = None,
) -> Tuple[List[str], List[ExportInfo]]:
    found = []
    details = []
    for match in EXPORT_LIST_RE.finditer(text):
        clause = match.group("clause")
        source = match.group("source")
        names = exported_names(clause)
        details.append((match.start(), {
            "symbols": normalized_clause(clause),
            "names": names,
            "form": "re-export" if source else "export-list",
            "export_kind": clause_kind(clause, bool(match.group("type_only"))),
            "source": source,
            "source_kind": source_kind(source) if source else None,
            "resolved_path": resolve_import(exporter_path, source) if exporter_path and source else None,
        }))
        found.extend((match.start(), name) for name in names)

    for match in EXPORT_DECLARATION_RE.finditer(text):
        name = "default" if match.group("default") else match.group("name")
        if not name:
            continue
        details.append((match.start(), {
            "symbols": name,
            "names": [name],
            "form": "declaration",
            "export_kind": "type" if match.group("kind") in {"interface", "type"} else "value",
            "source": None,
            "source_kind": None,
            "resolved_path": None,
        }))
        found.append((match.start(), name))

    declaration_positions = {position for position, _detail in details}
    for match in EXPORT_DEFAULT_RE.finditer(text):
        if match.start() not in declaration_positions:
            found.append((match.start(), "default"))
            details.append((match.start(), {
                "symbols": "default", "names": ["default"], "form": "default",
                "export_kind": "value", "source": None, "source_kind": None,
                "resolved_path": None,
            }))

    for regex, form in ((EXPORT_ASSIGNMENT_RE, "assignment"), (EXPORT_NAMESPACE_RE, "namespace")):
        for match in regex.finditer(text):
            name = match.group("name")
            found.append((match.start(), name))
            details.append((match.start(), {
                "symbols": name, "names": [name], "form": form,
                "export_kind": "value", "source": None, "source_kind": None,
                "resolved_path": None,
            }))

    for match in COMMONJS_NAMED_EXPORT_RE.finditer(text):
        name = match.group("name")
        found.append((match.start(), name))
        details.append((match.start(), {
            "symbols": name, "names": [name], "form": "commonjs",
            "export_kind": "value", "source": None, "source_kind": None,
            "resolved_path": None,
        }))
    for match in COMMONJS_OBJECT_EXPORT_RE.finditer(text):
        names = []
        for item in match.group("names").split(","):
            name = item.strip().split(":", 1)[0].strip()
            if re.fullmatch(r"[A-Za-z_$][\w$]*", name):
                names.append(name)
        found.extend((match.start(), name) for name in names)
        details.append((match.start(), {
            "symbols": normalized_clause("{ " + ", ".join(names) + " }"),
            "names": names, "form": "commonjs", "export_kind": "value",
            "source": None, "source_kind": None, "resolved_path": None,
        }))

    names = []
    for _position, name in sorted(found, key=lambda item: item[0]):
        if name not in names:
            names.append(name)
    ordered_details = [detail for _position, detail in sorted(details, key=lambda item: item[0])]
    return names, ordered_details
