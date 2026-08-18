"""Translate the semantic C graph into object-identity lifetime operations.

This is the production adapter for :mod:`lachesis.flow.object_state`.  It does not
consume the legacy name-keyed typestate streams or test-oracle labels.  Assignments,
declaration initializers, call arguments, and dereferences are recovered from graph
roles; operations are then interpreted over the expression CFG shared with reaching
definitions.
"""
from __future__ import annotations

from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from typing import Iterable

from lachesis.nav.dataflow.ap_construct import APBuilder
from lachesis.nav.dataflow.reaching_def import ReachingDef
from lachesis.nav.dataflow.substrate import Substrate

from .normalize import normalizer
from .object_state import (
    AbstractState,
    AccessPath,
    ObjectFact,
    ObjectStateAnalyzer,
    OpKind,
    Operation,
    ParamEffect,
)
from .order import build_order


_CASTS = {
    "ImplicitCastExpr", "CStyleCastExpr", "ParenExpr", "CXXConstCastExpr",
    "CXXStaticCastExpr", "CXXReinterpretCastExpr", "CXXFunctionalCastExpr",
}
_NULL_KINDS = {"GNUNullExpr", "CXXNullPtrLiteralExpr"}


def _props(item):
    return (item or {}).get("properties") or {}


def _line(sub, node):
    props = sub.props(node)
    return props.get("start_line") if props.get("start_offset") else (
        props.get("end_line") or props.get("start_line"))


def _roles(sub, node):
    result = {}
    for edge in sub.idx.outgoing_of_kind(node, "AST_CHILD"):
        result.setdefault(_props(edge).get("role") or "AST_CHILD", []).append(edge["target"])
    return result


def _peel(sub, node, depth=0):
    if node is None or depth > 12:
        return node
    if sub.kind(node) in _CASTS:
        children = sub.ast_children.get(node, ())
        if children:
            return _peel(sub, children[0], depth + 1)
    return node


def _path(ap_builder, node):
    """Convert the access-path algebra's declaration-rooted result to engine form."""
    if node is None:
        return None
    built = ap_builder.build(node)
    if built is None or built[0][0] != "named":
        return None
    base, elements = built
    return AccessPath("decl:" + str(base[1]), tuple(element.s() for element in elements))


def _normalize_selectors(selectors: Iterable[str]) -> tuple[str, ...]:
    """Normalize an instantiated actual/formal access-path seam.

    APBuilder already normalizes each side.  Summary composition is the only place
    where a new seam appears (notably ``&field`` passed to a formal dereferenced as
    ``*formal``), so the small token stack below preserves the same cancellation rules.
    """
    out = []
    for selector in selectors:
        if out and ((out[-1], selector) in {("&", "*"), ("*", "&")}):
            out.pop()
        elif selector == "<0>":
            continue
        else:
            out.append(selector)
    return tuple(out)


def _compose(actual: AccessPath, relative: tuple[str, ...]) -> AccessPath:
    return AccessPath(actual.root, _normalize_selectors(actual.selectors + relative))


def _is_pointer(sub, node):
    return "*" in (sub.props(node).get("type") or "")


def _is_null(sub, node, depth=0):
    if node is None or depth > 16:
        return False
    kind = sub.kind(node)
    if kind in _NULL_KINDS:
        return True
    if kind in _CASTS:
        children = sub.ast_children.get(node, ())
        return bool(children) and _is_null(sub, children[0], depth + 1)
    if kind == "IntegerLiteral":
        return (sub.label(node) or "").strip() in {"0", "NULL", "nullptr"}
    return False


def _callee(sub, call):
    roles = _roles(sub, call)
    candidates = roles.get("CALLEE", [])
    if not candidates:
        candidates = list(sub.ast_children.get(call, ()))[:1]
    for candidate in candidates:
        base = _peel(sub, candidate)
        if base is not None and sub.kind(base) == "DeclRefExpr":
            return sub.label(base)
    label = sub.label(call) or ""
    return label.split("(", 1)[0].strip() or None


def _rhs_kind(sub, ap_builder, norm, rhs):
    rhs = _peel(sub, rhs)
    if rhs is None:
        return OpKind.CLOBBER, None, False
    if sub.is_call(rhs):
        return ((OpKind.ALLOC, None, False) if norm.is_alloc(_callee(sub, rhs))
                else (OpKind.CLOBBER, None, False))
    source = _path(ap_builder, rhs)
    if source is not None:
        return OpKind.COPY, source, False
    return OpKind.CLOBBER, None, _is_null(sub, rhs)


def _initializer(sub, declaration):
    for edge in sub.idx.incoming_of_kind(declaration, "VALUE_FLOWS_TO"):
        if _props(edge).get("reason") == "initializer":
            return edge["source"]
    return None


def _assignment_operands(sub, assignment):
    roles = _roles(sub, assignment)
    left = roles.get("LEFT_OPERAND", [])
    right = roles.get("RIGHT_OPERAND", [])
    if left and right:
        return left[0], right[0]
    children = list(sub.ast_children.get(assignment, ()))
    if len(children) < 2:
        return None, None
    # Compatibility with older stores lacking roles: a declaration-directed write
    # identifies the LHS without relying on offsets (macro RHS offsets can be zero).
    for child in children:
        if any(((_props(edge).get("reason") or "") == "write"
                or (_props(edge).get("reason") or "").endswith("-write"))
               for edge in sub.idx.outgoing_of_kind(child, "VALUE_FLOWS_TO")):
            return child, next(item for item in children if item != child)
    return children[0], children[1]


def _deref_base(sub, ap_builder, node):
    children = list(sub.ast_children.get(node, ()))
    kind = sub.kind(node)
    if kind == "UnaryOperator" and sub.operator(node) == "*":
        return _path(ap_builder, children[0]) if children else None
    if kind == "MemberExpr" and "->" in (sub.label(node) or ""):
        return _path(ap_builder, children[0]) if children else None
    if kind == "ArraySubscriptExpr" and children:
        typed = [child for child in children if _is_pointer(sub, child)]
        return _path(ap_builder, (typed or children)[0])
    return None


def _is_unevaluated(sub, node):
    queue, seen = deque([node]), set()
    while queue:
        current = queue.popleft()
        if current in seen:
            continue
        seen.add(current)
        if sub.kind(current) == "UnaryExprOrTypeTraitExpr":
            return True
        queue.extend(edge["source"] for edge in sub.idx.incoming_of_kind(current, "AST_CHILD"))
    return False


def _argument_path(sub, ap_builder, call_node, position):
    for edge in sub.idx.outgoing_of_kind(call_node, "HAS_ARGUMENT"):
        if _props(edge).get("position") == position:
            return _path(ap_builder, edge["target"])
    return None


def _place(sub, cfg_nodes, anchor, fallback=None):
    """Place a semantic event on its nearest expression-CFG representative."""
    for seed in (anchor, fallback):
        current, seen = seed, set()
        while current is not None and current not in seen:
            if current in cfg_nodes:
                return current
            seen.add(current)
            current = sub.ast_parent.get(current)
    if fallback is not None:
        # Value declarations live in the T2 value tier and are intentionally not
        # AST children of their T3 DeclStmt. Macro initializers can also belong to a
        # synthetic macro owner. The declaration's source line/span is the remaining
        # semantic join to its CFG placement node.
        fallback_line = _line(sub, fallback)
        candidates = [node for node in cfg_nodes
                      if sub.kind(node) == "DeclStmt" and _line(sub, node) == fallback_line]
        if candidates:
            return min(candidates, key=lambda node: abs(sub.offset(node) - sub.offset(fallback)))
    return anchor


def _op(kind, node, *, target=None, source=None, line=None, ordinal=0,
        is_null=False, alternatives=()):
    return Operation(kind, node, target=target, source=source, site=node, line=line,
                     ordinal=ordinal, is_null=is_null, alternatives=alternatives)


def extract_operations(sub, norm, function_id, function_ir, all_functions, summaries, cfg):
    """Extract graph-derived operations for one function; no expected result enters here."""
    owned = set(sub._owned(function_id))
    cfg_nodes = set(cfg["nodes"])
    ap_builder = APBuilder(sub)
    operations = []

    for node in owned:
        if sub.is_plain_assign(node):
            lhs, rhs = _assignment_operands(sub, node)
            if lhs is None or rhs is None:
                continue
            line = _line(sub, node)
            base = _deref_base(sub, ap_builder, lhs)
            if base is not None and not _is_unevaluated(sub, lhs):
                operations.append(_op(OpKind.USE, _place(sub, cfg_nodes, lhs, node),
                                      target=base, line=line, ordinal=0))
            # Only pointer-valued stores alter this lifetime environment. Scalar
            # ``*p = 0`` is a use of p, not a rebinding of p.
            if not _is_pointer(sub, lhs):
                continue
            target = _path(ap_builder, lhs)
            if target is None:
                continue
            kind, payload, is_null = _rhs_kind(sub, ap_builder, norm, rhs)
            operations.append(_op(kind, _place(sub, cfg_nodes, node), target=target,
                                  source=payload, line=line, ordinal=1, is_null=is_null))

        elif sub.kind(node) == "VarDecl" and _is_pointer(sub, node):
            initializer = _initializer(sub, node)
            if initializer is None:
                continue
            target = AccessPath("decl:" + str(node))
            kind, payload, is_null = _rhs_kind(sub, ap_builder, norm, initializer)
            anchor = _place(sub, cfg_nodes, _peel(sub, initializer), node)
            operations.append(_op(kind, anchor, target=target, source=payload,
                                  line=_line(sub, node), ordinal=1, is_null=is_null))

    # A real memory read/write through an access expression uses its base object.
    for node in owned:
        base = _deref_base(sub, ap_builder, node)
        if base is not None and not _is_unevaluated(sub, node):
            operations.append(_op(OpKind.USE, _place(sub, cfg_nodes, node), target=base,
                                  line=_line(sub, node), ordinal=0))

    for call in function_ir.get("calls", ()):
        call_node = call.get("node")
        if call_node is None:
            continue
        anchor = _place(sub, cfg_nodes, call_node)
        callee = call.get("callee")
        line = call.get("line")
        if norm.is_dealloc(callee):
            target = _argument_path(sub, ap_builder, call_node, 0)
            if target is not None:
                operations.append(_op(OpKind.FREE, anchor, target=target,
                                      line=line, ordinal=20))
            continue

        callee_summary = summaries.get(callee)
        if callee in all_functions and callee_summary is not None:
            alternatives = []
            for alternative in callee_summary:
                effects = []
                for effect in alternative:
                    actual = _argument_path(sub, ap_builder, call_node, effect.position)
                    if actual is None:
                        continue
                    target = _compose(actual, effect.selectors)
                    effects.append(_op(effect.kind, anchor, target=target, line=line,
                                       ordinal=20 + len(effects)))
                alternatives.append(tuple(effects))
            if alternatives and any(alternatives):
                operations.append(_op(OpKind.SUMMARY, anchor, line=line, ordinal=20,
                                      alternatives=tuple(alternatives)))
            continue

        # Unknown callees may dereference pointer arguments. Lifecycle primitives are
        # modeled by their contracts above and allocator arguments are not pointee uses.
        if not norm.is_alloc(callee):
            for argument in call.get("args", ()):
                target = _argument_path(sub, ap_builder, call_node, argument.get("pos"))
                if target is not None:
                    operations.append(_op(OpKind.USE, anchor, target=target, line=line,
                                          ordinal=10 + int(argument.get("pos") or 0)))

    # Returning a freed pointer is the escape form of this family. Preserve the
    # existing public pattern name by representing the observation as USE for now.
    for node in owned:
        if sub.kind(node) != "ReturnStmt":
            continue
        for child in sub.ast_children.get(node, ()):
            target = _path(ap_builder, child)
            if target is not None:
                operations.append(_op(OpKind.USE, _place(sub, cfg_nodes, child, node),
                                      target=target, line=_line(sub, node), ordinal=30))
                break

    # The same semantic event can be visible via the assignment scan and the generic
    # dereference scan. Deduplicate by meaning, not by line or source spelling.
    unique = {}
    for operation in operations:
        key = (operation.kind, operation.node, operation.target, operation.source,
               operation.is_null, operation.alternatives)
        unique[key] = operation
    return tuple(sorted(unique.values(), key=lambda item: (
        sub.offset(item.node) if item.node in owned else 0, item.ordinal, item.kind.value,
    )))


def _initial_state(cfg, operations):
    initial = AbstractState()
    formal_roots = {}
    for position, declaration in enumerate(cfg.get("params", ())):
        path = AccessPath("decl:" + str(declaration))
        initial.seed_parameter(path, position)
        formal_roots[path.root] = position
    # Materialize parameter-relative fields mentioned by this function so a USE (which
    # intentionally does not create arbitrary unknown objects) still exports an effect.
    for operation in operations:
        for path in (operation.target, operation.source):
            if path is None or path.root not in formal_roots or not path.selectors:
                continue
            position = formal_roots[path.root]
            oid = ("param", position, path.selectors)
            initial.bind(path, oid)
            initial.facts[oid] = frozenset({ObjectFact.UNKNOWN})
    return initial


def _summary_for(sub, norm, function_id, function_ir, all_functions, summaries, cfg):
    operations = extract_operations(
        sub, norm, function_id, function_ir, all_functions, summaries, cfg)
    result = ObjectStateAnalyzer().analyze(
        cfg["nodes"], cfg["succ"], operations, initial=_initial_state(cfg, operations))
    alternatives = {state.trace for state in result.exit_states}
    return tuple(sorted(alternatives, key=repr)), result


@dataclass(frozen=True)
class ObjectLifetimeResult:
    leads: tuple[dict, ...]
    summaries: dict[str, tuple[tuple[ParamEffect, ...], ...]]
    diagnostics: dict


def analyze_object_lifetimes(store, functions, call_successors, *, lang="c"):
    """Run object-identity lifetime analysis over all defined functions in ``functions``."""
    sub = Substrate(store.index).load()
    norm = normalizer(lang)
    by_name = {}
    for node in store.index.nodes_of_kind("function", "method", "constructor"):
        if _props(node).get("declaration_only"):
            continue
        name = node.get("label")
        if name in functions and name not in by_name:
            by_name[name] = node["id"]

    cfgs = {}
    cfg_failures = {name: "no-function-node" for name in functions if name not in by_name}
    for name, function_id in by_name.items():
        cfg = ReachingDef(sub).analyze(function_id, reaching_defs=False)
        if cfg is None or cfg.get("bailed"):
            cfg_failures[name] = "too-large" if cfg and cfg.get("bailed") else "no-cfg"
        else:
            cfgs[name] = cfg

    # Absence means "no analyzable summary", not "proven to have no effects". That
    # distinction makes callers of a CFG failure take the conservative external-call
    # path instead of silently treating the callee as pure.
    summaries = {}
    artifacts = {}
    summary_capped = set()
    summary_runs = Counter()
    summary_transfers = 0
    for group in build_order(functions, call_successors):
        members = group["members"]
        analysable = [name for name in members if name in cfgs]
        if not group["cyclic"]:
            if not analysable:
                continue
            name = analysable[0]
            summary, result = _summary_for(
                sub, norm, by_name[name], functions[name], functions, summaries, cfgs[name])
            summaries[name] = summary
            artifacts[name] = result
            summary_runs[name] += 1
            summary_transfers += result.transfers
            continue

        # A cyclic component is a local monotone dataflow problem over summaries.
        # Recompute a caller only when one of its in-component callees changed;
        # the old len(SCC)+3 nested loop re-ran every member on every round.
        for name in analysable:
            summaries.setdefault(name, tuple())
        member_set = set(analysable)
        callers = defaultdict(set)
        for caller in analysable:
            for callee in call_successors.get(caller, ()):
                if callee in member_set:
                    callers[callee].add(caller)
        queue = deque(analysable)
        queued = set(analysable)
        per_function_cap = max(8, min(32, len(analysable) * 2 + 4))
        while queue:
            name = queue.popleft()
            queued.discard(name)
            if summary_runs[name] >= per_function_cap:
                summary_capped.update(analysable)
                break
            summary, result = _summary_for(
                sub, norm, by_name[name], functions[name], functions, summaries, cfgs[name])
            summary_runs[name] += 1
            summary_transfers += result.transfers
            artifacts[name] = result
            if summary == summaries.get(name):
                continue
            summaries[name] = summary
            for caller in callers.get(name, ()):
                if caller not in queued:
                    queue.append(caller)
                    queued.add(caller)

    leads = []
    diagnostics = {
        "functions": len(functions), "analyzed": 0, "cfg_failures": cfg_failures,
        "unplaced": 0, "unplaced_functions": {}, "capped": [],
        "summary_capped": sorted(summary_capped),
        "summary_analyses": sum(summary_runs.values()),
        "summary_recomputations": sum(max(0, count - 1) for count in summary_runs.values()),
        "summary_transfers": summary_transfers,
        "widenings": 0, "transfers": 0,
    }
    for name in sorted(functions):
        if name not in cfgs:
            continue
        result = artifacts.get(name)
        if result is None:
            cfg_failures[name] = "no-summary-artifact"
            continue
        # The summary run seeds parameters as UNKNOWN solely to record ParamEffects.
        # That is the same lifetime fact a direct FREE creates in an unseeded run, so
        # findings are identical. Reuse the stable run instead of walking every CFG a
        # second time just to collect the same local findings.
        diagnostics["analyzed"] += 1
        diagnostics["unplaced"] += len(result.unplaced)
        if result.unplaced:
            diagnostics["unplaced_functions"][name] = len(result.unplaced)
        diagnostics["widenings"] += result.widenings
        diagnostics["transfers"] += result.transfers
        if result.capped:
            diagnostics["capped"].append(name)
        for finding in sorted(result.findings):
            root_id = finding.path.root.removeprefix("decl:")
            root = sub.label(root_id) or root_id
            suffix = "".join(finding.path.selectors)
            leads.append({
                "pattern": finding.pattern, "var": root + suffix, "entry": name,
                "line": finding.line, "node": finding.node, "engine": "object-identity",
            })

    unsafe = (set(cfg_failures) | summary_capped
              | set(diagnostics["unplaced_functions"]) | set(diagnostics["capped"]))
    reverse_calls = defaultdict(set)
    for caller, callees in call_successors.items():
        for callee in callees:
            reverse_calls[callee].add(caller)
    queue = deque(unsafe)
    while queue:
        callee = queue.popleft()
        for caller in reverse_calls.get(callee, ()):
            if caller not in unsafe:
                unsafe.add(caller)
                queue.append(caller)
    diagnostics["unsafe_functions"] = sorted(unsafe)

    return ObjectLifetimeResult(tuple(leads), summaries, diagnostics)
