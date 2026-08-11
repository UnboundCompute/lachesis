"""Capability vocabulary for compiler frontends and canonical overlays."""

CAPABILITY_COMPLETE = "complete"
CAPABILITY_PARTIAL = "partial"
CAPABILITY_NONE = "none"
VALID_CAPABILITY_LEVELS = frozenset({
    CAPABILITY_COMPLETE, CAPABILITY_PARTIAL, CAPABILITY_NONE,
})

FRONTEND_OWNED_CAPABILITIES = {
    "lexical": (
        "tokens", "comments", "strings", "regex literals", "source offsets",
    ),
    "syntax": (
        "declarations", "statements", "expressions", "operators", "source spans",
    ),
    "modules": (
        "imports", "exports", "re-exports", "resolved module targets",
    ),
    "dependency_sources": (
        "library files", "package ownership", "declaration provenance",
        "framework source or declarations reached by the application",
    ),
    "symbols": (
        "scopes", "declarations", "references", "shadowing", "aliases",
    ),
    "scopes": (
        "module scopes", "function scopes", "block/control scopes",
        "lexical parents", "declaration ownership",
    ),
    "types": (
        "declared types", "inferred types", "signatures", "overloads",
        "generic substitutions", "narrowing facts",
    ),
    "calls": (
        "call expressions", "constructors", "selected signatures",
        "static targets", "overload candidates",
    ),
    "control_flow": (
        "execution order", "branches", "loops", "try/catch/finally",
        "break/continue", "merges", "unreachable code",
    ),
    "direct_data_flow": (
        "definitions", "reads", "assignments", "arguments", "parameters", "returns",
    ),
}

OVERLAY_OWNED_CAPABILITIES = {
    "heap_identity": (
        "allocation identities", "points-to sets", "property locations", "aliases",
    ),
    "context_sensitivity": (
        "per-call parameter instances", "receiver contexts", "contextual returns",
    ),
    "branch_histories": (
        "SSA versions", "phi nodes", "branch-sensitive reaching definitions",
    ),
    "taint_policy": (
        "attacker sources", "sinks", "sanitizers", "trust-boundary policy",
    ),
    "runtime_models": (
        "library effects", "external behavior", "framework behavior",
    ),
    "effects": (
        "function summaries", "argument mutations", "receiver/global/imported state",
    ),
    "async_events": (
        "callbacks", "events", "queues", "timers", "workers", "webhooks",
    ),
    "dynamic_behavior": (
        "eval", "reflection", "proxies", "runtime loading", "monkey patching",
    ),
    "framework_wiring": (
        "routes", "dependency injection", "decorators", "registries", "ORM wiring",
    ),
    "security_roles": (
        "entry points", "boundaries", "guards", "sources", "sinks", "state",
    ),
}

ALL_CAPABILITIES = frozenset({
    *FRONTEND_OWNED_CAPABILITIES,
    *OVERLAY_OWNED_CAPABILITIES,
})

