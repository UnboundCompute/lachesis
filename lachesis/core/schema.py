"""Canonical graph contract shared by every language frontend.

Contract v2 deliberately separates portable node/edge kinds from optional
frontend extensions. A language may attach additional data only below
``properties.frontend_extensions.<language>``; it must not create private node
or edge kinds that force the core to understand that language.
"""
from __future__ import annotations

CURRENT_CONTRACT_VERSION = 2
SUPPORTED_CONTRACT_VERSIONS = frozenset({CURRENT_CONTRACT_VERSION})

# Deprecated. Tiers were meant to make a graph progressively drillable — read T0 for
# the perimeter, descend when you need more — but nothing came to depend on them. The
# navigation layer selects no tier property, and the only code that reads one is the
# placement check in validation.py, which exists to check the tier a frontend was
# obliged to pick because of that check. Kept because they are stamped into every
# stored graph and into the layered projection, so removing them is a format change
# and not a cleanup. See docs/DEPRECATED.md before building anything new on them.
TIERS = frozenset({"T0", "T1", "T2", "T3", "T4"})
FACT_ORIGINS = frozenset({
    "compiler", "runtime-model", "framework-model", "core-inference",
})
CONFIDENCE_LEVELS = frozenset({
    "exact", "high", "conservative", "unresolved",
})

# Kinds are serialized in the existing lowercase/kebab-case convention. The
# families below correspond directly to the uppercase conceptual names in the
# architecture document.
PROJECT_STRUCTURE_NODE_KINDS = frozenset({
    "project", "package", "module", "file", "import", "export",
    "external-module", "route", "event", "registration", "import-cycle",
})
DECLARATION_NODE_KINDS = frozenset({
    "scope", "symbol", "declaration", "function", "method", "constructor",
    "class", "interface", "type", "enum", "record", "parameter", "variable",
    "binding", "property", "constant", "value", "decorator", "type-parameter",
    "macro",
})
EXECUTABLE_NODE_KINDS = frozenset({
    "statement", "expression", "operation", "identifier", "call", "construct",
    "call-value", "argument", "return", "return-value", "throw",
})
VALUE_NODE_KINDS = frozenset({
    "definition", "read", "write", "literal", "property-path", "allocation",
    "heap-object", "heap-location", "type-refinement", "generic-substitution",
    "call-context", "context-parameter", "context-return",
})
CONTROL_RUNTIME_NODE_KINDS = frozenset({
    "cfg-entry", "cfg-block", "cfg-condition", "cfg-merge", "cfg-exit", "phi",
    "async-event", "dynamic-behavior", "function-effect", "module-initializer",
    "static-initializer", "singleton", "module-state", "unreachable-region",
})
SECURITY_EVIDENCE_NODE_KINDS = frozenset({
    "source", "sink", "boundary", "guard", "taint-reach", "diagnostic",
    "source-span", "token",
})
CANONICAL_NODE_KINDS = frozenset().union(
    PROJECT_STRUCTURE_NODE_KINDS,
    DECLARATION_NODE_KINDS,
    EXECUTABLE_NODE_KINDS,
    VALUE_NODE_KINDS,
    CONTROL_RUNTIME_NODE_KINDS,
    SECURITY_EVIDENCE_NODE_KINDS,
)

# Deprecated with TIERS above: the legal tiers per node kind, and so the table that
# decides whether a frontend's tier choice is accepted. A new node kind still needs an
# entry here or its nodes are rejected, which is the maintenance cost the deprecation
# is about.
NODE_KIND_TIERS = {
    **{kind: frozenset({"T0"}) for kind in PROJECT_STRUCTURE_NODE_KINDS},
    **{kind: frozenset({"T1"}) for kind in {
        "declaration", "function", "method", "constructor", "class", "interface",
        "type", "enum", "record", "macro",
    }},
    **{kind: frozenset({"T2"}) for kind in {
        "scope", "symbol", "parameter", "variable", "binding", "property",
        "constant", "value", "decorator", "type-parameter", *VALUE_NODE_KINDS,
    }},
    **{kind: frozenset({"T3"}) for kind in {
        *EXECUTABLE_NODE_KINDS, *CONTROL_RUNTIME_NODE_KINDS,
    }},
    **{kind: frozenset({"T4"}) for kind in SECURITY_EVIDENCE_NODE_KINDS},
}
# Arguments and produced/returned values belong to the path tier even though
# their syntax nodes also participate in executable AST structure.
NODE_KIND_TIERS.update({
    kind: frozenset({"T2"})
    for kind in {"argument", "call-value", "return", "return-value"}
})
NODE_KIND_TIERS["module"] = frozenset({"T0", "T1"})

# Compiler frontends may emit language-level dynamic constructs and diagnostics,
# but policy judgments and runtime/heap conclusions belong to core/model layers.
FRONTEND_FORBIDDEN_NODE_KINDS = frozenset({
    "heap-object", "heap-location", "function-effect", "async-event",
    "source", "sink", "boundary", "guard", "taint-reach",
    "call-context", "context-parameter", "context-return",
    "singleton", "module-state", "import-cycle",
    "cfg-entry", "cfg-block", "cfg-condition", "cfg-merge", "cfg-exit",
    "phi", "unreachable-region",
})

STRUCTURE_EDGE_KINDS = frozenset({
    "CONTAINS", "DECLARES", "DECLARES_MEMBER", "DECLARES_VALUE",
    "DECLARES_SCOPE", "DECLARES_SYMBOL", "SYMBOL_DECLARES", "REFERS_TO",
    "TYPE_REFERS_TO", "HAS_TYPE", "DEPENDS_ON", "RUNTIME_DEPENDS_ON",
    "RUNTIME_IMPLEMENTATION", "IMPLEMENTED_BY", "PACKAGE_CONTAINS", "EXPORTS",
    "RE_EXPORTS", "AST_CHILD", "EXPANDS_TO", "HAS_TOKEN", "NEXT_TOKEN",
    "HAS_DIAGNOSTIC", "HAS_PROPERTY_PATH", "DECORATES", "DECORATOR_ARGUMENT",
    "INITIALIZES_WITH", "CONTAINS_BODY", "HAS_SCOPE",
    "HAS_TYPE_PARAMETER", "OVERLOAD_OF", "STRUCTURALLY_COMPATIBLE_WITH",
    "HAS_SINGLETON", "SINGLETON_OF", "HAS_MODULE_STATE", "STATE_OF",
    "PARTICIPATES_IN_IMPORT_CYCLE",
})
CALL_EDGE_KINDS = frozenset({
    "INVOKES", "MAY_INVOKE", "CALLS", "HAS_ARGUMENT",
    "BINDS_PARAMETER", "ARGUMENT_BINDS_PARAMETER", "RETURNS_VALUE", "THROWS_VALUE",
    "RETURN_EVIDENCED_BY", "READS_CALLEE", "PASSES_CALLBACK",
    "HAS_CALL_CONTEXT", "CONTEXT_CALLS", "CONTEXTUALIZES", "CONTEXT_RETURNS",
})
VALUE_EDGE_KINDS = frozenset({
    "DEFINES", "READS_FROM", "WRITES_TO", "WRITES_PARAMETER_PROPERTY",
    "VALUE_FLOWS_TO", "ALIASES", "ALIASES_VALUE", "POINTS_TO",
    "PREVIOUS_VERSION", "PROPERTY_READ", "READ_EVIDENCED_BY", "ALLOCATES",
    "CONTEXT_ALLOCATES",
    "PHI_INPUT", "PHI_FOR_SYMBOL", "BRANCH_READS_FROM", "BRANCH_PREVIOUS",
    "FUNCTION_VALUE", "NARROWS_TYPE", "REFINES_SYMBOL", "SUBSTITUTES_TYPE",
    "WRITES_HEAP", "READS_HEAP", "DYNAMIC_INPUT", "REACHING_DEF",
})
CONTROL_EDGE_KINDS = frozenset({
    "CFG_NEXT", "EXECUTES_BEFORE", "CONDITION", "TRUE_BRANCH", "FALSE_BRANCH",
    "LOOP_BACK", "LOOP_TRUE", "ITERATES", "EXCEPTION_BRANCH", "TRY_BODY", "RUNS_FINALLY",
    "MERGES_AT", "SHORT_CIRCUIT_LEFT", "SHORT_CIRCUIT_RIGHT",
    "SWITCH_CASE", "BREAKS_TO", "CONTINUES_TO", "PHI_AT",
})
RUNTIME_SECURITY_EDGE_KINDS = frozenset({
    "CAPTURES", "MUTATES", "APPLIES_EFFECT", "REGISTERS_CALLBACK", "HANDLED_BY",
    "ASYNC_CONTINUES_AT", "SCHEDULES", "EMITS_EVENT",
    "TAINT_FLOWS_TO", "GUARDED_BY", "EVIDENCED_BY",
    "DUPLICATES", "SHADOWS", "ROUTE_HANDLED_BY", "ENTRY_POINT_OF",
    "OVERRIDES", "IMPLEMENTS_MEMBER", "DYNAMIC_BEHAVIOR_AT",
    "TAINT_SOURCE", "TAINT_SINK", "TAINT_REACHES",
})
CANONICAL_EDGE_KINDS = frozenset().union(
    STRUCTURE_EDGE_KINDS,
    CALL_EDGE_KINDS,
    VALUE_EDGE_KINDS,
    CONTROL_EDGE_KINDS,
    RUNTIME_SECURITY_EDGE_KINDS,
)
FRONTEND_FORBIDDEN_EDGE_KINDS = frozenset({
    "POINTS_TO", "MUTATES", "APPLIES_EFFECT", "REGISTERS_CALLBACK", "HANDLED_BY",
    "ASYNC_CONTINUES_AT", "TAINT_FLOWS_TO", "GUARDED_BY",
    "HAS_CALL_CONTEXT", "CONTEXT_CALLS", "CONTEXTUALIZES", "CONTEXT_RETURNS",
    "WRITES_HEAP", "READS_HEAP", "REACHING_DEF",
})

SOURCE_DERIVED_NODE_KINDS = frozenset().union(
    DECLARATION_NODE_KINDS,
    EXECUTABLE_NODE_KINDS,
    {"definition", "read", "write", "literal", "property-path", "allocation",
     "type-refinement", "generic-substitution",
     "dynamic-behavior", "module-initializer", "static-initializer",
     "source-span", "token"},
)
