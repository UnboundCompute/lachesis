"""CPython AST frontend: command-line entry point.

Usage: ``python -m Lachesis.frontends.python.build_graph <source_dir> <output_dir>``

Parses every in-root ``.py``/``.pyi`` file with CPython's own ``ast`` module and
writes the contract-v2 tier files plus ``manifest.json``. No third-party parser is
involved and nothing outside the root set is ever read.
"""
from __future__ import annotations

import ast
import json
import os
import platform
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

if __package__ in (None, ""):  # invoked as a bare script path, not with -m
    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
    __package__ = "Lachesis.frontends.python"

from .declarations import DeclarationWalk
from .emit import (
    CONTRACT_VERSION, FRONTEND_ID, LANGUAGE, TIERS, Graph, SourceFile, stable_id,
)
from .inventory import (
    FileFacts, ModuleIndex, collect_imports, dunder_all, emit_exports, emit_imports,
)
from .bodies import BODY_COUNTERS, BodyWalk
from .resolve import Resolver
from .scopes import ScopeWalk, build_symbol_table, emit_overrides

SOURCE_SUFFIXES = {".py", ".pyi"}

# Feature versions to retry a SyntaxError against, newest first. A file that fails
# on the running interpreter but parses at a lower feature version is using syntax
# this interpreter does not know, which is a version-skew diagnostic rather than
# broken source. ``ast.parse`` accepts feature_version down to (3, 4).
RETRY_FEATURE_VERSIONS = [(3, minor) for minor in range(12, 5, -1)]


def read_roots(roots_file: str) -> List[Path]:
    """Ingest exactly the discovery-provided root list.

    Lachesis/core/runner.py writes LACHESIS_ROOTS_FILE after it has already pruned
    vendor directories and excluded tests, so honoring it means this frontend
    inherits that one discovery instead of re-walking and re-introducing what was
    filtered out.
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
    roots_file = os.environ.get("LACHESIS_ROOTS_FILE")
    if roots_file:
        roots = read_roots(roots_file)
        if roots:
            return roots
    return sorted(
        path.resolve() for path in source_dir.rglob("*")
        if path.is_file() and path.suffix.lower() in SOURCE_SUFFIXES
    )


def display_path(path: Path, source_dir: Path) -> str:
    """Repo-relative path, the form nav/symbol_index.py keys provenance on."""
    try:
        return str(path.relative_to(source_dir))
    except ValueError:
        return str(path)


def read_source(path: Path) -> str:
    """Decode a file the way the Python compiler would.

    ``tokenize.open`` honors the PEP 263 coding declaration and the BOM, so a
    ``# -*- coding: latin-1 -*-`` file decodes to the same text ``ast.parse`` would
    see rather than to mojibake or a UnicodeDecodeError.
    """
    import tokenize

    with tokenize.open(str(path)) as handle:
        return handle.read()


def parse_module(text: str, path: Path) -> Tuple[Optional[ast.Module], Optional[dict]]:
    """Parse, and on failure classify why. Returns (module, diagnostic_facts)."""
    try:
        return ast.parse(text, filename=str(path)), None
    except SyntaxError as error:
        first = error
    except (ValueError, MemoryError, RecursionError) as error:
        return None, {
            "category": "parse-error", "message": f"{type(error).__name__}: {error}",
            "line": 1, "column": 1,
        }
    # The file did not parse here. If a lower feature version accepts it, the source
    # is fine and this interpreter is behind; if none does, it is a real error.
    for version in RETRY_FEATURE_VERSIONS:
        try:
            ast.parse(text, filename=str(path), feature_version=version)
        except SyntaxError:
            continue
        except (ValueError, MemoryError, RecursionError):
            break
        return None, {
            "category": "version-skew",
            "message": (
                f"parses at feature version {version[0]}.{version[1]} but not on "
                f"{platform.python_version()}: {first.msg}"
            ),
            "line": first.lineno or 1, "column": (first.offset or 1),
        }
    return None, {
        "category": "syntax-error", "message": first.msg or "invalid syntax",
        "line": first.lineno or 1, "column": (first.offset or 1),
    }


def emit_diagnostic(graph: Graph, source: SourceFile, file_id: str, facts: dict) -> str:
    line = max(1, min(int(facts["line"]), source.line_count))
    column = max(1, int(facts["column"]))
    offset = source.offset(line, column - 1)
    diagnostic_id = stable_id(
        "diagnostic", source.display, facts["category"], line, column, facts["message"],
    )
    graph.node(
        diagnostic_id, "diagnostic", facts["message"],
        file=source.display, absolute_file=source.absolute,
        content_hash=source.content_hash,
        start_offset=offset, end_offset=offset,
        start_line=line, start_column=column, end_line=line, end_column=column,
        category=facts["category"], severity="error",
    )
    graph.edge("HAS_DIAGNOSTIC", file_id, diagnostic_id)
    return diagnostic_id


def build(source_dir: Path, output_dir: Path) -> int:
    files = walk(source_dir)
    graph = Graph()
    diagnostics: List[str] = []
    failed_files: List[Path] = []
    file_ids: Dict[Path, str] = {}
    facts_by_path: Dict[Path, FileFacts] = {}
    uncorrelated_files: List[Path] = []
    binding_count = 0
    capture_count = 0

    # Pass one: parse each file on its own and emit everything that is decidable
    # from that file alone. The AST is dropped at the end of each iteration; what
    # pass two needs (import clauses, the export list, the module binding table) is
    # kept as plain records, so the whole tree's ASTs are never resident at once.
    for path in files:
        try:
            text = read_source(path)
        except (OSError, UnicodeDecodeError, SyntaxError, ValueError) as error:
            failed_files.append(path)
            # Without decoded text there is no SourceFile and therefore no file
            # node; record the failure in the manifest count and move on.
            print(f"lachesis-python: cannot read {path}: {error}", file=sys.stderr)
            continue

        source = SourceFile(path, display_path(path, source_dir), text)
        file_id = stable_id("file", source.display)
        file_ids[path] = file_id
        graph.node(
            file_id, "file", source.display,
            **source.whole_file_position(),
            lines=source.line_count,
            provenance="application", is_external=False, is_system=False,
            included_because="project-root",
            is_stub=path.suffix.lower() == ".pyi",
            is_package_init=path.name in ("__init__.py", "__init__.pyi"),
        )

        module, failure = parse_module(text, path)
        if failure is not None:
            failed_files.append(path)
            diagnostics.append(emit_diagnostic(graph, source, file_id, failure))
            # The file node stays in the graph on purpose: an unparseable file is
            # still findable in search, open_file and open_folder.
            continue

        walker = DeclarationWalk(
            graph, source, file_id, is_stub=path.suffix.lower() == ".pyi",
        )
        walker.run(module)

        scopes = ScopeWalk(
            graph, source, file_id,
            walker.declarations_by_node, walker.parameters_by_function,
        )
        scopes.run(module, build_symbol_table(text, path))
        binding_count += scopes.binding_count
        capture_count += scopes.capture_count
        if not scopes.correlated:
            uncorrelated_files.append(path)
            diagnostics.append(emit_diagnostic(graph, source, file_id, {
                "category": "scope-correlation",
                "message": (
                    "symtable blocks could not be matched to the AST scope tree; "
                    "bindings for this file are AST-derived and conservative"
                ),
                "line": 1, "column": 1,
            }))

        facts_by_path[path] = FileFacts(
            source=source, path=path, file_id=file_id,
            imports=collect_imports(source, module),
            exported_names=dunder_all(module),
            module_bindings=walker.module_bindings,
            class_members=walker.class_members,
            class_bases=walker.class_bases,
            function_ids=walker.function_ids,
            parameters_by_function=walker.parameters_by_function,
            import_targets={},
            import_modules={},
        )

    # Pass two: everything that needs the whole tree. Module names come from the
    # directory layout only, never from the running interpreter's sys.path.
    index = ModuleIndex(sorted(facts_by_path), source_dir)
    import_count = 0
    for path in sorted(facts_by_path):
        import_count += emit_imports(
            graph, index, facts_by_path[path], file_ids, facts_by_path,
        )
    export_count = 0
    for path in sorted(facts_by_path):
        # Exports run after every import, because a re-export names a binding that
        # only exists once the importing file's import nodes have been emitted.
        export_count += emit_exports(graph, index, facts_by_path[path], file_ids)
    # Overrides run last: a base class named through an import is only resolvable
    # once that import clause has been pointed at a file.
    override_count = emit_overrides(graph, facts_by_path)

    # Pass three: bodies. Call resolution needs every file's binding table, which
    # only exists now, so the file is re-parsed rather than held from pass one:
    # a bounded second parse in exchange for never holding the whole tree's ASTs.
    resolver = Resolver(facts_by_path)
    body_totals = dict.fromkeys(BODY_COUNTERS, 0)
    for path in sorted(facts_by_path):
        facts = facts_by_path[path]
        module, failure = parse_module(facts.source.text, path)
        if module is None:
            continue
        walker = BodyWalk(graph, facts.source, facts.file_id, facts, resolver)
        walker.run(module)
        for name in BODY_COUNTERS:
            body_totals[name] += getattr(walker, name)

    payloads = graph.tier_payloads()
    analyzed = len(files) - len(failed_files)
    # Honest coverage: a file that failed to parse contributes only its file node,
    # so any capability that depends on complete parsing can no longer claim it.
    complete_if_parsed = "complete" if not failed_files else "partial"
    manifest = {
        "version": 2, "frontend_contract_version": CONTRACT_VERSION,
        "frontend_id": FRONTEND_ID, "generator": FRONTEND_ID,
        "languages": [LANGUAGE],
        "capabilities": capabilities(complete_if_parsed),
        "compiler": f"CPython {platform.python_version()} ast",
        "interpreter_version": platform.python_version(),
        "source_dir": str(source_dir),
        "root_file_count": len(files),
        "analyzed_file_count": analyzed,
        "failed_file_count": len(failed_files),
        # An edge whose endpoint never became a node is not in any tier file, so
        # counting it here would make the manifest disagree with what was written.
        # It is reported on its own line instead, never silently.
        "node_count": len(graph.nodes),
        "edge_count": len(graph.edges) - graph.dropped_edges,
        "diagnostic_count": len(diagnostics),
        "import_count": import_count,
        "export_count": export_count,
        "binding_count": binding_count,
        "capture_count": capture_count,
        "override_count": override_count,
        "call_count": body_totals["call_count"],
        "construct_count": body_totals["construct_count"],
        "resolved_call_count": body_totals["resolved_count"],
        "dynamic_behavior_count": body_totals["dynamic_count"],
        "statement_count": body_totals["statement_count"],
        "condition_count": body_totals["condition_count"],
        "short_circuit_count": body_totals["short_circuit_count"],
        "throw_count": body_totals["throw_count"],
        "exception_branch_count": body_totals["exception_branch_count"],
        "scope_correlated_file_count": len(facts_by_path) - len(uncorrelated_files),
        "scope_uncorrelated_file_count": len(uncorrelated_files),
        "dropped_edge_count": graph.dropped_edges,
        "identity_scheme": "v2:<owner>:<namespace>:<kind>:<digest>",
        "tiers": [
            {
                "tier": tier, "name": TIERS[tier],
                "file": f"{tier.lower()}_{TIERS[tier]}.json",
                "node_count": len(payloads[tier]["nodes"]),
                "edge_count": len(payloads[tier]["edges"]),
                "expands_to_count": len(payloads[tier]["expands_to"]),
                "cross_tier_link_count": len(payloads[tier]["links"]),
            }
            for tier in TIERS
        ],
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    for tier, payload in payloads.items():
        (output_dir / f"{tier.lower()}_{TIERS[tier]}.json").write_text(
            json.dumps(payload, indent=2) + "\n", encoding="utf-8",
        )
    (output_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8",
    )
    print(
        f"CPython ast analyzed {analyzed} of {len(files)} Python files; emitted "
        f"{len(graph.nodes)} nodes and {len(graph.edges)} edges to {output_dir}"
    )
    # A non-zero exit is a ContractError that kills the whole multi-language build,
    # so it is reserved for "nothing at all was ingested".
    return 0 if files else 1


def capabilities(complete_if_parsed: str) -> Dict[str, str]:
    """What this frontend actually knows, at the current landing step.

    ``types`` is ``none`` and stays there: annotations are recorded as the source
    text that was written, and no type is ever resolved. Everything the later steps
    have not landed yet is ``none`` here and gets raised when its pass exists.
    """
    return {
        "lexical": "partial",
        "syntax": complete_if_parsed,
        # In-tree imports resolve from the directory layout; namespace packages
        # resolve only when unambiguous, and sys.path games and importlib do not
        # resolve at all, so the claim is partial and not complete.
        "modules": "partial",
        # Nothing outside the root set is ever read, so dependency source code is
        # honestly absent rather than partially modelled.
        "dependency_sources": "none",
        "symbols": "partial",
        "scopes": "partial",
        "types": "none",
        # Lexically and import-resolved calls are decided by the layout; attribute
        # dispatch on an unannotated value is not, so the claim stops at partial.
        "calls": "partial",
        # Branches, loops, try/except/finally and match are exact. Generator
        # resumption is not modelled (a yield folds onto its return value, losing
        # the point control comes back to) and neither is the with protocol, whose
        # branch lives in __enter__ and __exit__, so this stops at partial.
        "control_flow": "partial",
        "direct_data_flow": "none",
        "heap_identity": "none", "context_sensitivity": "none",
        "branch_histories": "none", "taint_policy": "none",
        "runtime_models": "none", "effects": "none", "async_events": "none",
        "dynamic_behavior": "partial", "framework_wiring": "none",
        "security_roles": "none",
    }


def main(argv: Optional[List[str]] = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if len(arguments) < 2:
        print(
            "usage: build_graph.py <source_dir> <output_dir>", file=sys.stderr,
        )
        return 2
    return build(Path(arguments[0]).resolve(), Path(arguments[1]).resolve())


if __name__ == "__main__":
    raise SystemExit(main())
