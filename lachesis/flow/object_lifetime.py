"""Translate the semantic C graph into object-identity lifetime operations.

This is the production adapter for :mod:`lachesis.flow.object_state`.  It does not
consume the legacy name-keyed typestate streams or test-oracle labels.  Assignments,
declaration initializers, call arguments, and dereferences are recovered from graph
roles; operations are then interpreted over the expression CFG shared with reaching
definitions.
"""
from __future__ import annotations

from collections import Counter, defaultdict, deque
from concurrent.futures import ProcessPoolExecutor
from contextlib import nullcontext
from dataclasses import dataclass, field
import os
from time import perf_counter
from typing import Iterable

from lachesis.nav.dataflow.ap_construct import APBuilder
from lachesis.nav.dataflow.reaching_def import ReachingDef
from lachesis.nav.dataflow.substrate import Substrate, cached_substrate
from lachesis.timeit import timeit

from .normalize import normalizer
from .object_state import (
    AbstractState,
    AccessPath,
    ObjectFact,
    ObjectStateAnalyzer,
    OpKind,
    Operation,
    ParamEffect,
    ReturnEffect,
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
    return sub.ast_by_role.get(node, {})


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
    if sub.kind(rhs) == "ConditionalOperator":
        # A common ownership idiom stores a field or alias on the non-null arm
        # and NULL on the other arm.  Preserve the value-producing arm as a
        # COPY fact; treating the whole conditional as an opaque clobber loses
        # the alias relation before any interprocedural matcher can use it.
        # Do not infer the arm from child position: Clang's child ordering puts
        # the condition between the true and false expressions for some
        # conditional forms.  The typed TRUE_VALUE role is the stable semantic
        # boundary and preserves nested field paths such as `n->meta->name`.
        candidates = tuple(_roles(sub, rhs).get("TRUE_VALUE", ()))
        if not candidates:
            children = sub.ast_children.get(rhs, ())
            candidates = tuple(children[1:])
        for candidate in candidates:
            source = _path(ap_builder, candidate)
            if source is not None:
                return OpKind.COPY, source, False
        children = sub.ast_children.get(rhs, ())
        return OpKind.CLOBBER, None, any(_is_null(sub, child) for child in children[1:])
    if sub.is_call(rhs):
        callee = _callee(sub, rhs)
        # realloc BEFORE alloc: it frees the old block its first argument names (source)
        # and returns a fresh one bound to the target. The engine's REALLOC op carries
        # both halves, so an interior pointer not rebased to the result dangles.
        if norm.is_realloc(callee):
            return OpKind.REALLOC, _argument_path(sub, ap_builder, rhs, 0), False
        return ((OpKind.ALLOC, None, False) if norm.is_alloc(callee)
                else (OpKind.CLOBBER, None, False))
    source = _path(ap_builder, rhs)
    if source is not None:
        return OpKind.COPY, source, False
    return OpKind.CLOBBER, None, _is_null(sub, rhs)


def _pointer_arithmetic_source(sub, ap_builder, rhs):
    """Return the pointer base of a declaration initialized by pointer arithmetic."""
    expression = _peel(sub, rhs)
    if expression is None or sub.kind(expression) != "BinaryOperator":
        return None
    if (sub.operator(expression) or "") not in {"+", "-"}:
        return None
    for child in sub.ast_children.get(expression, ()):
        path = _path(ap_builder, child)
        if path is not None:
            return path
    return None


def _initializer(sub, declaration):
    return sub.initializer_source.get(declaration)


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
    current, seen = node, set()
    while current is not None and current not in seen:
        seen.add(current)
        if sub.kind(current) == "UnaryExprOrTypeTraitExpr":
            return True
        current = sub.ast_parent.get(current)
    return False


def _is_pointer_comparison(sub, node):
    """Whether a binary expression observes pointer values without dereferencing."""
    if sub.kind(node) != "BinaryOperator":
        return False
    operator = sub.operator(node) or ""
    return operator in {"==", "!=", "<", "<=", ">", ">="}


def _argument_path(sub, ap_builder, call_node, position):
    argument = sub.role_child_at(call_node, "ARGUMENT", position)
    return _path(ap_builder, argument)


def _receiver_path(sub, ap_builder, call_node):
    """Resolve a method receiver as an object access path.

    C-style deallocators take the object in argument zero, but managed and
    C++-style release operations can put ownership on the receiver
    (``handle.close()`` / ``owner.reset()``). The graph overlay records that
    receiver independently of positional arguments.
    """
    props = sub.props(call_node)
    receiver = (props.get("receiver_value_id") or props.get("receiver_symbol_id")
                or props.get("receiver_id"))
    if receiver is not None:
        path = _path(ap_builder, _peel(sub, receiver))
        if path is not None:
            return path
    receiver_node = sub.role_child_at(call_node, "RECEIVER", 0)
    return _path(ap_builder, _peel(sub, receiver_node))


def _aggregate_type_key(type_name):
    """Normalize frontend spelling for aggregate-field catalogue lookup."""
    if not type_name:
        return "<unknown>"
    text = " ".join(str(type_name).split()).lower()
    for qualifier in ("const ", "volatile ", "restrict ", "struct ",
                      "class ", "union ", "enum "):
        text = text.replace(qualifier, "")
    return text.replace("*", "").strip() or "<unknown>"


@timeit
def _aggregate_field_paths(sub, ap_builder, type_key=None) -> tuple[tuple[str, ...], ...]:
    """Collect field paths present in the program for bulk struct copies.

    ``memcpy(dst, src, sizeof(T))`` has no field AST children of its own.  The
    surrounding CPG still contains the member accesses used by constructors and
    destructors, which gives us the field layout needed to materialize the
    field-wise alias facts without teaching the matcher about memcpy.
    """
    cache = getattr(sub, "_aggregate_field_paths_cache", None)
    if cache is None:
        cache = defaultdict(set)
        sub._aggregate_field_paths_cache = cache
    if not getattr(sub, "_aggregate_field_paths_loaded", False):
        if hasattr(sub.idx, "member_expression_nodes"):
            expression_items = sub.idx.member_expression_nodes()
        else:
            expression_items = sub.idx.nodes_of_kind("expression")
        for item in expression_items:
            node = item.get("id") if isinstance(item, dict) else item
            item_props = item.get("properties", {}) if isinstance(item, dict) else {}
            item_kind = item_props.get("syntax_kind") or (item.get("kind") if isinstance(item, dict) else None)
            if node is None or item_kind != "MemberExpr":
                continue
            path = _path(ap_builder, node)
            # A bulk copy aliases the destination's direct fields.  Nested paths are
            # recovered by following those field objects later; emitting every nested
            # combination here causes avoidable state multiplication in summaries.
            if path is not None and len(path.selectors) == 2 and path.selectors[0] == "*":
                root_id = path.root[len("decl:"):] if path.root.startswith("decl:") else None
                root_type = (sub.props(root_id).get("type") if root_id else None) or "<unknown>"
                cache[root_type].add(path.selectors)
                cache[_aggregate_type_key(root_type)].add(path.selectors)
        sub._aggregate_field_paths_loaded = True
    if type_key is None:
        paths = set().union(*cache.values()) if cache else set()
    else:
        paths = (cache.get(type_key)
                 or cache.get(_aggregate_type_key(type_key))
                 or cache.get("<unknown>", set()))
    return tuple(sorted(paths, key=repr))


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
        is_null=False, alternatives=(), access="deref"):
    return Operation(kind, node, target=target, source=source, site=node, line=line,
                     ordinal=ordinal, is_null=is_null, alternatives=alternatives,
                     access=access)


@timeit
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
                rhs_source = _path(ap_builder, rhs)
                operations.append(_op(OpKind.USE, _place(sub, cfg_nodes, lhs, node),
                                      target=base, source=rhs_source, line=line, ordinal=0,
                                      access="write"))
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
                # Preserve an uninitialized pointer declaration as a semantic
                # fact.  It is not an allocation or a NULL origin: the
                # matcher must keep the indeterminate state until a
                # path-compatible assignment initializes the slot.
                target = AccessPath("decl:" + str(node))
                operations.append(_op(
                    OpKind.CLOBBER, _place(sub, cfg_nodes, node, node),
                    target=target, line=_line(sub, node), ordinal=1,
                    access="uninitialized"))
                continue
            target = AccessPath("decl:" + str(node))
            kind, payload, is_null = _rhs_kind(sub, ap_builder, norm, initializer)
            anchor = _place(sub, cfg_nodes, _peel(sub, initializer), node)
            operations.append(_op(kind, anchor, target=target, source=payload,
                                  line=_line(sub, node), ordinal=1, is_null=is_null))
            arithmetic_source = _pointer_arithmetic_source(sub, ap_builder, initializer)
            if arithmetic_source is not None:
                # Preserve the derived pointer and its source object as a
                # semantic fact. The lifetime engine may ignore this USE, but
                # the reusable skeleton can match a later dereference against
                # the derived pointer without reparsing the expression.
                operations.append(_op(
                    OpKind.USE, anchor, target=target, source=arithmetic_source,
                    line=_line(sub, node), ordinal=2,
                    access="pointer-arithmetic"))

    # A real memory read/write through an access expression uses its base object.
    for node in owned:
        if _is_pointer_comparison(sub, node):
            for child in sub.ast_children.get(node, ()):
                path = _path(ap_builder, child)
                if path is not None and _is_pointer(sub, child):
                    operations.append(_op(OpKind.USE, _place(sub, cfg_nodes, child, node),
                                          target=path, line=_line(sub, node), ordinal=1,
                                          access="compare"))
            continue
        parent = sub.ast_parent.get(node)
        if parent is not None and sub.is_plain_assign(parent):
            lhs, _rhs = _assignment_operands(sub, parent)
            if lhs is not None and _peel(sub, lhs) == _peel(sub, node):
                # The assignment scan above emits the LHS as WRITE_STORAGE.  Do not
                # duplicate it as a READ_STORAGE merely because the same access
                # expression is also visited by the generic dereference scan.
                continue
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
        # `is_release` is the language-neutral lifecycle predicate.  It includes
        # C deallocators and the Atropos-managed method vocabulary (close,
        # dispose, release, ...), so the object engine consumes the same
        # catalogue-backed fact that the translator emits.
        if norm.is_release(callee):
            target = (_argument_path(sub, ap_builder, call_node, 0)
                      or _receiver_path(sub, ap_builder, call_node))
            if target is not None:
                operations.append(_op(OpKind.FREE, anchor, target=target,
                                      line=line, ordinal=20))
            continue

        if norm.is_aggregate_copy(callee, sub.label(call_node) or ""):
            destination = _argument_path(sub, ap_builder, call_node, 0)
            source = _argument_path(sub, ap_builder, call_node, 1)
            if destination is not None and source is not None:
                source_id = source.root[len("decl:"):] if source.root.startswith("decl:") else None
                source_type = sub.props(source_id).get("type") if source_id else None
                if source_type is None:
                    # Access paths may retain the source-level declaration name
                    # rather than its T2 id (notably parameters crossing a
                    # frontend/macro boundary). Resolve that name within the
                    # current function before falling back to the all-field
                    # catalogue.
                    source_type = next((
                        sub.props(item.get("id")).get("type")
                        for kind in ("parameter", "variable")
                        for item in sub.idx.nodes_of_kind(kind)
                        if item.get("label") == source.root
                        and sub.props(item.get("id")).get("owner_function_id") == function_id
                    ), None)
                for selectors in _aggregate_field_paths(sub, ap_builder, source_type):
                    operations.append(_op(
                        OpKind.COPY, anchor,
                        target=AccessPath(destination.root,
                                          destination.selectors + selectors),
                        source=AccessPath(source.root, source.selectors + selectors),
                        line=line, ordinal=15 + len(operations), access="aggregate-copy"))
            continue

        callee_summary = summaries.get(callee)
        if callee in all_functions and callee_summary is not None:
            alternatives = []
            for alternative in callee_summary:
                effects = []
                for effect in alternative:
                    if isinstance(effect, ReturnEffect):
                        assigned = call.get("assigned")
                        if not assigned:
                            continue
                        destination = next((candidate for candidate in owned
                                            if sub.kind(candidate) == "variable"
                                            and sub.label(candidate) == assigned), None)
                        receiver = (_path(ap_builder, destination)
                                    if destination is not None else AccessPath(str(assigned)))
                        actual = _argument_path(
                            sub, ap_builder, call_node, effect.position)
                        if receiver is None or actual is None:
                            continue
                        effects.append(_op(
                            OpKind.COPY, anchor, target=receiver,
                            source=_compose(actual, effect.selectors), line=line,
                            ordinal=20 + len(effects), access="return-alias"))
                        continue
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

        # External sources create a fresh value at their assigned destination.
        # Keep this as an ORIGIN fact in the frozen graph; it is not an allocator
        # attempt and must remain distinct from allocation failure semantics.
        source_callees = {item.get("callee") for item in function_ir.get("source_calls", ())}
        if callee in source_callees and call.get("assigned"):
            assigned = call["assigned"]
            destination = next((candidate for candidate in owned
                                if sub.kind(candidate) == "variable" and
                                sub.label(candidate) == assigned), None)
            # `_assigned_var` is already the canonical display root.  Some
            # frontends do not retain a variable node for a call-result edge,
            # so do not require a declaration-node lookup here.
            target = _path(ap_builder, destination) if destination is not None else AccessPath(str(assigned))
            if target is not None:
                operations.append(_op(OpKind.CLOBBER, anchor, target=target, line=line,
                                      ordinal=5, access="source"))

        # Unknown callees may dereference pointer arguments. Lifecycle primitives are
        # modeled by their contracts above and allocator arguments are not pointee uses.
        if not norm.is_alloc(callee):
            for argument in call.get("args", ()):
                target = _argument_path(sub, ap_builder, call_node, argument.get("pos"))
                if target is not None:
                    operations.append(_op(OpKind.USE, anchor, target=target, line=line,
                                          ordinal=10 + int(argument.get("pos") or 0),
                                          access="pass"))

    # Returning a freed pointer is the escape form of this family. Preserve the
    # existing public pattern name by representing the observation as USE for now.
    for node in owned:
        if sub.kind(node) != "ReturnStmt":
            continue
        for child in sub.ast_children.get(node, ()):
            # Return expressions are commonly wrapped in an implicit cast or
            # parenthesized expression.  Resolve the value after peeling those
            # transparent nodes, otherwise a returned heap object is omitted
            # from the semantic RETURN_VALUE fact and is incorrectly reported
            # as a leak at the fragment exit.
            target = _path(ap_builder, _peel(sub, child))
            if target is not None:
                root_id = target.root.removeprefix("decl:")
                root_props = sub.props(root_id)
                root_kind = sub.kind(root_id)
                # A returned array decays to a pointer to its automatic
                # storage.  Explicit address-of paths cover scalar/struct
                # locals; heap-returning locals are deliberately excluded.
                stack_local = (
                    root_kind in {"variable", "VarDecl"}
                    and root_props.get("owner_function_id") == function_id
                    and ("[" in (root_props.get("type") or "")
                         or "&" in target.selectors)
                )
                operations.append(_op(OpKind.USE, _place(sub, cfg_nodes, child, node),
                                      target=target, line=_line(sub, node), ordinal=30,
                                      access="return-stack" if stack_local else "return"))
            elif _is_null(sub, _peel(sub, child)):
                # Preserve a NULL return as a path-local value.  The seam
                # composer rebases this marker onto the caller's receiver so
                # a later NONNULL guard cannot admit the failure arm.
                operations.append(_op(
                    OpKind.CLOBBER, _place(sub, cfg_nodes, child, node),
                    target=AccessPath("__return__"),
                    line=_line(sub, node), ordinal=30, access="return-null"))
            if target is not None or _is_null(sub, _peel(sub, child)):
                break

    # The same semantic event can be visible via the assignment scan and the generic
    # dereference scan. Deduplicate by meaning, not by line or source spelling.
    unique = {}
    for operation in operations:
        key = (operation.kind, operation.node, operation.target, operation.source,
               operation.is_null, operation.alternatives, operation.access)
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
    prepared = _prepare_summary(
        sub, norm, function_id, function_ir, all_functions, summaries, cfg)
    return _analyze_prepared(prepared)


@timeit
def _prepare_summary(sub, norm, function_id, function_ir, all_functions, summaries, cfg):
    operations = extract_operations(
        sub, norm, function_id, function_ir, all_functions, summaries, cfg)
    return cfg["nodes"], cfg["succ"], operations, _initial_state(cfg, operations)


def _analyze_prepared(prepared):
    """Pure, pickleable solver boundary used by process workers."""
    nodes, successors, operations, initial = prepared
    # 32 disjuncts/node (not 64): a fully-wired CFG closes every loop's def-use cycle,
    # so a looping function accumulates disjuncts across the back-edge until widening
    # fires. At 64 the widening fired so late that small pipeline-walk functions blew
    # the transfer budget and were marked capped/unsafe -- dropping ALL their leads.
    # Widening sooner makes them converge within budget; the join is an over-
    # approximation, so recall (uncapped functions) rises at a marginal precision cost,
    # which is the right trade for a finder (capping is a guaranteed false negative).
    result = ObjectStateAnalyzer(max_disjuncts=32, collect_findings=False).analyze(
        nodes, successors, operations, initial=initial)
    alternatives = {state.trace for state in result.exit_states}
    return tuple(sorted(alternatives, key=repr)), result


def _summary_worker_count(function_count, override=None):
    """Return the explicitly configured, bounded process count.

    Process execution is opt-in because ``run_pass`` is also a library API: Python's
    spawn start method requires embedding applications to protect their entrypoint.
    The production CLI satisfies that contract, while silently spawning from an
    arbitrary caller would not.  CI can set LACHESIS_LIFETIME_WORKERS to its CPU/memory
    budget; 0 or 1 keeps deterministic in-process execution.

    ``override`` (from the ``workers=`` keyword on ``run_pass``/``analyze_object_lifetimes``)
    wins over the env var so a library caller configures parallelism explicitly instead of
    mutating process-wide ``os.environ`` — which is not thread-safe and would leak into
    spawned children. ``None`` falls back to the env var, preserving the default-1 contract.
    """
    if override is not None:
        requested = int(override)
    else:
        raw = os.environ.get("LACHESIS_LIFETIME_WORKERS", "1")
        try:
            requested = int(raw)
        except ValueError as exc:
            raise ValueError("LACHESIS_LIFETIME_WORKERS must be an integer") from exc
    return max(1, min(requested, function_count, os.cpu_count() or 1))


def _schedule_levels(schedule, call_successors):
    """Group the SCC condensation DAG into independent callee-ready waves."""
    owner = {name: index for index, group in enumerate(schedule)
             for name in group["members"]}
    dependencies = {}
    for index, group in enumerate(schedule):
        dependencies[index] = {
            owner[callee]
            for caller in group["members"]
            for callee in call_successors.get(caller, ())
            if callee in owner and owner[callee] != index
        }
    callers = defaultdict(set)
    for index, deps in dependencies.items():
        for dep in deps:
            callers[dep].add(index)
    remaining = {index: len(deps) for index, deps in dependencies.items()}
    ready = deque(sorted(index for index, count in remaining.items() if count == 0))
    levels = {index: 0 for index in ready}
    visited = 0
    while ready:
        index = ready.popleft()
        visited += 1
        for caller in sorted(callers.get(index, ())):
            levels[caller] = max(levels.get(caller, 0), levels[index] + 1)
            remaining[caller] -= 1
            if remaining[caller] == 0:
                ready.append(caller)
    if visited != len(schedule):
        raise ValueError("SCC condensation schedule unexpectedly contains a cycle")
    waves = defaultdict(list)
    for index in range(len(schedule)):
        waves[levels[index]].append(schedule[index])
    return [waves[index] for index in sorted(waves)]


@dataclass(frozen=True)
class ObjectLifetimeResult:
    leads: tuple[dict, ...]
    summaries: dict[str, tuple[tuple[ParamEffect, ...], ...]]
    diagnostics: dict
    # Per-function abstract-state snapshots are retained for semantic consumers;
    # the summary API remains unchanged for callers that only need effects.
    artifacts: dict[str, object] = field(default_factory=dict)
    # Reaching-definition CFGs are also the emitter's structural input. Retain them
    # so Pass 3 does not analyze every function a second time during emission.
    cfgs: dict[str, dict] = field(default_factory=dict)


@timeit
def analyze_object_lifetimes(store, functions, call_successors, *, lang="c", graph=None,
                             workers=None, deadline=None):
    """Run object-identity lifetime analysis over all defined functions in ``functions``.

    ``workers`` overrides ``LACHESIS_LIFETIME_WORKERS`` for this call (``None`` = env).
    ``deadline`` is an optional cooperative budget: it is checked at each wave boundary
    (the dominant cost) and, on expiry, stops scheduling further waves and reports
    ``diagnostics["timed_out"]=True``. Functions already analyzed keep their summaries;
    the rest fall through to the seed-unsafe path exactly as an un-analyzable function
    does, so partial output stays sound. It never raises, and bounds scheduling rather
    than a single in-flight function."""
    started = perf_counter()
    if graph is not None and hasattr(graph, "nodes_of_kind"):
        analysis_index = graph
    elif graph is not None and graph is not store.graph:
        from lachesis.nav.graph_store import GraphStore
        analysis_index = GraphStore(graph).index
    else:
        analysis_index = store.index
    norm = normalizer(lang)
    function_node_ids = [node_id for kind in ("function", "method", "constructor")
                         for node_id in getattr(analysis_index, "by_kind", {}).get(kind, ())]
    function_node_ids = [node_id.get("id") if isinstance(node_id, dict) else node_id
                         for node_id in function_node_ids]
    sub = cached_substrate(analysis_index)
    sub.warm_nodes(function_node_ids)
    by_name = {}
    for node in analysis_index.nodes_of_kind("function", "method", "constructor"):
        if _props(node).get("declaration_only"):
            continue
        name = node.get("label")
        if name in functions and name not in by_name:
            by_name[name] = node["id"]

    cfgs = {}
    cfg_failures = {name: "no-function-node" for name in functions if name not in by_name}
    def prepare_cfg(name, function_id):
        cfg = ReachingDef(sub).analyze(function_id, reaching_defs=False)
        if cfg is None or cfg.get("bailed"):
            cfg_failures[name] = "too-large" if cfg and cfg.get("bailed") else "no-cfg"
        else:
            cfgs[name] = cfg

        # Streaming callers retain only the current owner's records. The substrate and
        # index caches are deliberately evicted after CFG preparation so a million-node
        # graph cannot become a second whole-graph Python object graph.
    stream = getattr(getattr(sub, "idx", None), "stream_nodes_by_owner", None)
    if stream is not None:
        def consume(owner_id, records):
            stream_ids = {node["id"] for node in records}
            stream_idx = sub.idx
            for node in records:
                stream_idx._node_cache[node["id"]] = node
            name = by_name.get(owner_id)
            if name is not None:
                prepare_cfg(name, owner_id)
            for node_id in stream_ids:
                stream_idx._node_cache.pop(node_id, None)
                sub._node.pop(node_id, None)
        stream(by_name.values(), consume)
    else:
        sub.warm_owned(by_name.values())
        for name, function_id in by_name.items():
            prepare_cfg(name, function_id)
    cfg_seconds = perf_counter() - started

    # Absence means "no analyzable summary", not "proven to have no effects". That
    # distinction makes callers of a CFG failure take the conservative external-call
    # path instead of silently treating the callee as pure.
    summaries = {}
    artifacts = {}
    summary_capped = set()
    summary_runs = Counter()
    summary_transfers = 0
    schedule = build_order(functions, call_successors)
    workers = _summary_worker_count(len(cfgs), override=workers)
    pool_context = (ProcessPoolExecutor(max_workers=workers)
                    if workers > 1 else nullcontext(None))
    timed_out = False
    with pool_context as executor:
        for wave in _schedule_levels(schedule, call_successors):
            # A wave boundary is the natural preemption point: the previous wave's futures
            # are already drained here, so leaving now orphans nothing. Analyzed functions
            # keep their summaries; unanalyzed ones fall through to the seed-unsafe path.
            if deadline is not None and deadline.expired():
                timed_out = True
                if executor is not None:
                    executor.shutdown(cancel_futures=True)
                break
            # Prepare graph-derived operations in the parent. Workers receive only the
            # pure CFG/state problem, never a Kuzu connection or the materialized graph.
            pending = []
            for group in wave:
                if group["cyclic"]:
                    continue
                analysable = [name for name in group["members"] if name in cfgs]
                if not analysable:
                    continue
                name = analysable[0]
                prepared = _prepare_summary(
                    sub, norm, by_name[name], functions[name], functions, summaries, cfgs[name])
                future = (executor.submit(_analyze_prepared, prepared)
                          if executor is not None else None)
                pending.append((name, prepared, future))

            # Recursive SCCs retain their dependency-driven local worklist. They are
            # few and require newly changed member summaries immediately; meanwhile,
            # independent acyclic jobs in this wave can execute in worker processes.
            for group in wave:
                if not group["cyclic"]:
                    continue
                analysable = [name for name in group["members"] if name in cfgs]
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
                        sub, norm, by_name[name], functions[name], functions,
                        summaries, cfgs[name])
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

            for name, prepared, future in pending:
                summary, result = (future.result() if future is not None
                                   else _analyze_prepared(prepared))
                summaries[name] = summary
                artifacts[name] = result
                summary_runs[name] += 1
                summary_transfers += result.transfers

    leads = []
    summary_seconds = perf_counter() - started - cfg_seconds
    diagnostics = {
        "functions": len(functions), "analyzed": 0, "cfg_failures": cfg_failures,
        "unplaced": 0, "unplaced_functions": {}, "capped": [],
        "summary_capped": sorted(summary_capped),
        "summary_analyses": sum(summary_runs.values()),
        "summary_recomputations": sum(max(0, count - 1) for count in summary_runs.values()),
        "summary_transfers": summary_transfers,
        "summary_workers": workers,
        "timed_out": timed_out,
        "cfg_seconds": round(cfg_seconds, 6),
        "summary_seconds": round(summary_seconds, 6),
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
        # Only a dropped *state-changing* op (a free/alloc/reset we could not place)
        # leaves the summary untrustworthy: it may hide a free (missed double-free in a
        # caller) or a reset (a live object we would wrongly call freed). A dropped USE
        # can only cost a read — a false negative — so it must not mark the function
        # unsafe and poison every caller that passes an object through it.
        state_changing = sum(1 for op in result.unplaced if op.kind is not OpKind.USE)
        if state_changing:
            diagnostics["unplaced_functions"][name] = state_changing
        diagnostics["widenings"] += result.widenings
        diagnostics["transfers"] += result.transfers
        if result.capped:
            diagnostics["capped"].append(name)
        # One lead per (object, pattern): a loop-carried free floods the freed state
        # around the back-edge, so the same bug otherwise surfaces at every later
        # free/use of that object (187 findings for one image double-free in a decoder
        # main). Collapse to the earliest site -- the representative, root-cause-nearest
        # occurrence -- and keep a count so the volume is visible without the noise.
        best: dict[tuple, dict] = {}
        for finding in sorted(result.findings):
            root_id = finding.path.root.removeprefix("decl:")
            root = sub.label(root_id) or root_id
            suffix = "".join(finding.path.selectors)
            key = (finding.pattern, root + suffix)
            existing = best.get(key)
            if existing is None:
                best[key] = {
                    "pattern": finding.pattern, "var": root + suffix, "root": root,
                    "entry": name, "line": finding.line, "node": finding.node,
                    "engine": "object-identity", "sites": 1,
                }
            else:
                existing["sites"] += 1
                if finding.line is not None and (
                        existing["line"] is None or finding.line < existing["line"]):
                    existing["line"], existing["node"] = finding.line, finding.node
        leads.extend(best[key] for key in sorted(best))

    # A function is *seed*-unsafe when its own analysis is untrustworthy (no CFG,
    # capped worklist, dropped ops). That set propagates UP the call graph, because a
    # caller of an unsafe function inherits its unknowns -- unless we can show the
    # unknown never touches the object a lead is about (see the object-flow map below).
    seed_unsafe = (set(cfg_failures) | summary_capped
                   | set(diagnostics["unplaced_functions"]) | set(diagnostics["capped"]))
    unsafe = set(seed_unsafe)
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

    # Object-flow refinement of the propagated-unsafe blanket. `unsafe` is transitively
    # closed up the call graph, so a propagation-only-unsafe intermediary is itself in
    # `unsafe`; therefore an object that reaches an unknown effect ALWAYS flows -- in one
    # direct hop -- into some callee already in `unsafe`. We record, per function, the
    # object roots that do so. A lead in a propagation-only-unsafe function is safe to
    # keep when its object is NOT in this set: the unknown callees never see that object.
    ap_builder = APBuilder(sub)
    unsafe_object_flow = {}
    for name, function_ir in ((n, functions[n]) for n in sorted(functions) if n in cfgs):
        if name in seed_unsafe or name not in unsafe:
            continue
        tainted = set()
        for call in function_ir.get("calls", ()):
            if call.get("callee") not in unsafe:
                continue
            call_node = call.get("node")
            if call_node is None:
                continue
            for argument in call.get("args", ()):
                path = _argument_path(sub, ap_builder, call_node, argument.get("pos"))
                if path is not None:
                    root_id = path.root.removeprefix("decl:")
                    tainted.add(sub.label(root_id) or root_id)
        if tainted:
            unsafe_object_flow[name] = sorted(tainted)

    diagnostics["unsafe_functions"] = sorted(unsafe)
    diagnostics["seed_unsafe_functions"] = sorted(seed_unsafe)
    diagnostics["unsafe_object_flow"] = unsafe_object_flow
    diagnostics["total_seconds"] = round(perf_counter() - started, 6)

    return ObjectLifetimeResult(tuple(leads), summaries, diagnostics, artifacts, cfgs)
