"""Bodies: the call sites and the control shapes the traversal tools stand on.

``callers``, ``callees``, ``hubs`` and ``call_roles`` all read the same two call
shapes. ``CALLS`` is the resolved declaration-to-declaration graph
(nav/symbol_index.py:73). ``INVOKES``/``MAY_INVOKE`` start at the call site
itself, which is why every node emitted here carries ``owner_function_id``: the
traversal climbs from a call site to the declaration that owns it, and a call
site with no owner is attributed to itself and ranks as its own hub.

``guards``, ``guards_top`` and ``siblings`` read a second set of shapes off the
same spine: ``CONDITION``, ``SHORT_CIRCUIT_LEFT``/``SHORT_CIRCUIT_RIGHT``,
``THROWS_VALUE``, ``TRY_BODY`` and ``EXCEPTION_BRANCH``, bucketed by the owning
function (nav/guards.py:78-86). Without ``CONDITION`` every function classifies
as ``passthrough``; without ``THROWS_VALUE`` the best a function can reach is
``validate``, which is exactly why the C frontend caps there
(nav/guards.py:117-122). Python emits all of them.

Body nodes are emitted for statements and for the expressions a control edge
lands on, not for every expression in the tree. That is a deliberate line: the
navigation surface reads control shape and ownership, and a node per identifier
would multiply the store without answering a question anyone asks of it.

This pass re-parses the file rather than holding pass one's AST, because
resolution needs the whole tree's binding tables and keeping every AST resident
to get them would trade a bounded second parse for unbounded memory.
"""
from __future__ import annotations

import ast
from typing import Dict, List, NamedTuple, Optional, Sequence, Set, Tuple

from .declarations import declaration_id, declaration_kind
from .emit import Graph, SourceFile, compact, stable_id
from .resolve import DYNAMIC_CALLEES, NOTHING, Resolution, Resolver
from .scopes import (
    COMPREHENSIONS, FUNCTION_NODES, SCOPE_NODES, bound_occurrences, own_regions,
    outer_regions, scope_kind, scope_span,
)
from .values import ValueWalk

# 3.11 added ``except*``; on 3.10 there is no such node and the tuple is empty.
TRY_NODES = (ast.Try,) + ((ast.TryStar,) if hasattr(ast, "TryStar") else ())

# lachesis/core/overlays/control_flow.py switches on these strings
# (control_flow.py:11-14), so the vocabulary is theirs and not ours.
CONTROL_KIND = {
    ast.If: "if",
    # Python's ``for`` is always iteration over an iterable, never a C-style
    # three-clause loop, so it is "for-each" and never "for".
    ast.For: "for-each", ast.AsyncFor: "for-each",
    ast.While: "while",
    ast.Match: "switch",
    ast.Return: "return", ast.Raise: "throw",
    ast.Break: "break", ast.Continue: "continue",
    ast.Assign: "declaration", ast.AnnAssign: "declaration",
    ast.AugAssign: "declaration",
    ast.Expr: "expression",
}
CONTROL_KIND.update({node: "try" for node in TRY_NODES})


def control_kind(node: ast.stmt) -> str:
    """The canonical control vocabulary for one statement.

    Two omissions are deliberate. ``with``/``async with`` gets a plain
    ``statement``: the branch it really introduces lives in ``__enter__`` and
    ``__exit__``, which are invisible from here, and naming it a container would
    describe a shape the graph cannot back up. ``assert`` is not reported as
    ``if`` either, because that would inject a phantom branch into the control
    flow of every function that uses one.
    """
    return CONTROL_KIND.get(type(node), "statement")


# What a caller sums across files to fill the manifest. Naming them once here
# keeps the manifest from silently missing a counter added later.
BODY_COUNTERS = (
    "call_count", "construct_count", "resolved_count", "dynamic_count",
    "statement_count", "condition_count", "short_circuit_count",
    "throw_count", "exception_branch_count",
    "definition_count", "read_count", "write_count", "allocation_count",
)


class Frame(NamedTuple):
    """One lexical scope, as much of it as call resolution needs.

    ``locals`` is derived from the AST alone rather than from symtable, on
    purpose: the only question here is whether a bare name is shadowed by
    something bound in an enclosing function, and the AST answers that without
    making this pass depend on the correlation succeeding.
    """
    kind: str
    declaration_id: Optional[str]
    owner_function_id: Optional[str]
    class_id: Optional[str]
    self_name: Optional[str]
    locals: Set[str]
    declarations: Dict[str, str]
    # The spans of this scope and every scope around it, innermost first, which
    # is how a name is resolved to the node that binds it. Spans rather than AST
    # nodes because the table they key was built during a different parse.
    scope_spans: Tuple[Tuple[int, int], ...] = ()


class BodyWalk:
    """Emits one call site per ``ast.Call``, resolved as far as the layout allows."""

    def __init__(
        self, graph: Graph, source: SourceFile, file_id: str, facts,
        resolver: Resolver,
    ) -> None:
        self.graph = graph
        self.source = source
        self.file_id = file_id
        self.facts = facts
        self.resolver = resolver
        self.call_count = 0
        self.construct_count = 0
        self.resolved_count = 0
        self.dynamic_count = 0
        self.statement_count = 0
        self.condition_count = 0
        self.short_circuit_count = 0
        self.throw_count = 0
        self.exception_branch_count = 0
        # ast node -> body node id. Keyed by identity, which is safe because the
        # tree outlives the walk; the first visit owns the parent edge, so a node
        # pre-created as a branch target is not re-parented when it is reached.
        self._bodies: Dict[int, str] = {}
        # Dataflow rides on this traversal rather than walking the tree again:
        # both need the same frame and the same body node, and two descents would
        # be two chances for the attribution to disagree with itself.
        self.values = ValueWalk(graph, source, file_id, facts)
        self.values.bodies = self._bodies

    def __getattr__(self, name: str) -> int:
        # The value counters live on the collaborator; the manifest sums them off
        # the walker, so they are readable from here under their own names.
        if name in ("definition_count", "read_count", "write_count",
                    "allocation_count"):
            return getattr(self.values, name)
        raise AttributeError(name)

    # -- the walk ------------------------------------------------------------

    def run(self, module: ast.Module) -> None:
        frame = self._frame(module, None)
        for region in own_regions(module):
            self._visit(region, frame, None)

    def _frame(self, node: ast.AST, parent: Optional[Frame]) -> Frame:
        kind = scope_kind(node)
        graph_id: Optional[str] = None
        self_name: Optional[str] = None
        if isinstance(node, FUNCTION_NODES):
            owner_kind = parent.kind if parent is not None else "module"
            graph_id = declaration_id(
                self.source, node, declaration_kind(node, owner_kind),
            )
            slots = list(getattr(node.args, "posonlyargs", [])) + list(node.args.args)
            if owner_kind == "class" and slots:
                # Whatever the first parameter is called (`self` by convention,
                # `cls` on a classmethod), it is the receiver the body reaches the
                # rest of the class through.
                self_name = slots[0].arg
        elif isinstance(node, ast.ClassDef):
            graph_id = declaration_id(self.source, node, "class")

        if parent is None:
            class_id = None
            owner_function_id = None
        else:
            class_id = (
                parent.declaration_id if parent.kind == "class" else parent.class_id
            )
            owner_function_id = (
                graph_id if kind == "function" else parent.owner_function_id
            )
        if kind == "class":
            # A class body is not a function; statements in it belong to no
            # function, exactly as the declaration pass recorded them.
            owner_function_id = parent.owner_function_id if parent else None

        locals_of_scope: Set[str] = set()
        declarations: Dict[str, str] = {}
        if kind in ("function", "lambda", "comprehension"):
            occurrences = bound_occurrences(own_regions(node))
            locals_of_scope = set(occurrences)
            if isinstance(node, (ast.Lambda,) + FUNCTION_NODES):
                locals_of_scope.update(
                    slot.arg for slot in _all_parameters(node.args)
                )
            for name, anchor in occurrences.items():
                if isinstance(anchor, FUNCTION_NODES):
                    declarations[name] = declaration_id(self.source, anchor, "function")
                elif isinstance(anchor, ast.ClassDef):
                    declarations[name] = declaration_id(self.source, anchor, "class")
            for statement in ast.walk(node):
                if isinstance(statement, ast.Global):
                    # A name declared global is not a local, whatever else the
                    # body does with it, so it must not shadow the module binding.
                    locals_of_scope.difference_update(statement.names)
        # A class body is left in the chain even though it binds nothing a nested
        # function can see: no class span is ever recorded as a binding scope, so
        # keeping it costs one miss and losing it would need a special case.
        spans = (scope_span(self.source, node),) + (
            parent.scope_spans if parent is not None else ()
        )
        return Frame(
            kind, graph_id, owner_function_id, class_id, self_name,
            locals_of_scope, declarations, spans,
        )

    def _visit(self, node: ast.AST, frame: Frame, parent: Optional[str]) -> None:
        if isinstance(node, SCOPE_NODES):
            # Decorators, defaults and base-class expressions run in the enclosing
            # scope, so a call hiding in one is attributed there and not inside.
            for region in outer_regions(node):
                self._visit(region, frame, parent)
            child = self._frame(node, frame)
            # A def or class starts a new body: its statements hang off the
            # declaration, not off whatever statement the def happened to sit in.
            # A comprehension declares nothing, so its parts stay attached to the
            # expression node standing in for it.
            inner = (
                self._comprehension(node, child, parent)
                if isinstance(node, COMPREHENSIONS) else None
            )
            # The scope node is a value in the enclosing scope (a list display
            # allocates there, a lambda is an object there), while its parameters
            # are bound inside, so the two hooks take different frames.
            self.values.visit(node, frame)
            self.values.parameters(node, child)
            for region in own_regions(node):
                self._visit(region, child, inner)
            return
        if isinstance(node, ast.stmt):
            parent = self._statement(node, frame, parent)
        elif isinstance(node, ast.Call):
            parent = self._call(node, frame, parent)
        elif isinstance(node, ast.BoolOp):
            parent = self._short_circuit(node, frame, parent)
        elif isinstance(node, ast.IfExp):
            parent = self._conditional_expression(node, frame, parent)
        elif isinstance(node, (ast.Yield, ast.YieldFrom)):
            self._yield(node, frame, parent)
        # After the body node exists, so a value can be evidenced by it, and
        # before the descent, so a definition is in place for the reads under it.
        self.values.visit(node, frame)
        for child in ast.iter_child_nodes(node):
            self._visit(child, frame, parent)

    # -- body nodes ----------------------------------------------------------

    def _body(
        self, node: ast.AST, kind: str, frame: Frame, parent: Optional[str],
        role: Optional[str] = None, **properties,
    ) -> str:
        """One body node, attached to its parent exactly once.

        The attachment follows the C frontend: ``AST_CHILD`` when there is a
        parent body node and ``CONTAINS_BODY`` from the owning declaration when
        there is not, so ``role`` survives the tier crossing for
        lachesis/core/overlays/control_flow.py to read.
        """
        existing = self._bodies.get(id(node))
        if existing is not None:
            return existing
        position = self.source.position(node)
        text = compact(self.source.excerpt(node))
        node_id = stable_id(
            kind, self.source.display, position["start_offset"],
            position["end_offset"], type(node).__name__,
        )
        self.graph.node(
            node_id, kind, text or type(node).__name__, **position,
            syntax_kind=type(node).__name__,
            owner_function_id=frame.owner_function_id,
            owner_id=frame.class_id if frame.kind == "class" else None,
            **properties,
        )
        self._bodies[id(node)] = node_id
        if parent:
            self.graph.edge("AST_CHILD", parent, node_id, role=role or "AST_CHILD")
        else:
            self.graph.edge(
                "CONTAINS_BODY", frame.owner_function_id or self.file_id, node_id,
            )
        return node_id

    def _statement(
        self, node: ast.stmt, frame: Frame, parent: Optional[str],
    ) -> Optional[str]:
        if isinstance(node, (ast.Global, ast.Nonlocal)):
            # A scope declaration executes nothing. The fact it carries is which
            # scope a name binds in, which the scope pass already recorded.
            return parent
        node_id = self._body(
            node, "statement", frame, parent, control_kind=control_kind(node),
        )
        self.statement_count += 1
        self._control(node, node_id, frame)
        return node_id

    def _first(
        self, block: Optional[Sequence[ast.stmt]], frame: Frame,
        parent: Optional[str], role: Optional[str] = None,
    ) -> Optional[str]:
        """The body node a block is entered through.

        Python has no block node: a suite is a bare list of statements. The first
        statement is where control actually arrives, so it is what a branch edge
        points at, and inventing a block node to point at instead would put a
        span in the graph that no source text backs.
        """
        if not block:
            return None
        return self._statement_target(block[0], frame, parent, role)

    def _statement_target(
        self, node: ast.stmt, frame: Frame, parent: Optional[str],
        role: Optional[str],
    ) -> Optional[str]:
        if isinstance(node, (ast.Global, ast.Nonlocal)):
            return None
        return self._body(
            node, "statement", frame, parent, role,
            control_kind=control_kind(node),
        )

    def _expression(
        self, node: ast.expr, frame: Frame, parent: Optional[str],
        role: Optional[str] = None,
    ) -> str:
        if isinstance(node, ast.Call):
            # A call that is also a condition keeps its call node; two nodes over
            # one span would double it in every count that walks either kind.
            return self._call(node, frame, parent, role)
        if isinstance(node, ast.BoolOp):
            return self._short_circuit(node, frame, parent)
        return self._body(node, "expression", frame, parent, role)

    # -- control shapes ------------------------------------------------------

    def _control(self, node: ast.stmt, node_id: str, frame: Frame) -> None:
        if isinstance(node, ast.If):
            self._branch(node.test, node.body, node.orelse, node_id, frame)
        elif isinstance(node, ast.While):
            # A while test is a branch as much as an if test is, and guards.py
            # counts CONDITION regardless of what the branch loops back to.
            test = self._expression(node.test, frame, node_id, "CONDITION")
            self.graph.edge("CONDITION", node_id, test)
            self.condition_count += 1
            entered = self._first(node.body, frame, test, "LOOP_BODY")
            if entered:
                self.graph.edge("LOOP_TRUE", test, entered)
                self.graph.edge("LOOP_BACK", entered, test)
            self._else(node.orelse, frame, test)
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            iterated = self._expression(node.iter, frame, node_id, "ITERATED")
            entered = self._first(node.body, frame, node_id, "LOOP_BODY")
            if entered:
                self.graph.edge("ITERATES", iterated, entered)
                self.graph.edge("LOOP_BACK", entered, iterated)
            self._else(node.orelse, frame, node_id)
        elif isinstance(node, TRY_NODES):
            self._try(node, node_id, frame)
        elif isinstance(node, ast.Match):
            self._match(node, node_id, frame)
        elif isinstance(node, ast.Return):
            self._return(node, node_id, frame, "return", node.value)
        elif isinstance(node, ast.Raise):
            self._return(node, node_id, frame, "throw", node.exc)

    def _branch(
        self, test: ast.expr, body: Sequence[ast.stmt],
        orelse: Sequence[ast.stmt], node_id: str, frame: Frame,
    ) -> None:
        condition = self._expression(test, frame, node_id, "CONDITION")
        self.graph.edge("CONDITION", node_id, condition)
        self.condition_count += 1
        taken = self._first(body, frame, condition, "TRUE_BRANCH")
        if taken:
            self.graph.edge("TRUE_BRANCH", condition, taken)
        skipped = self._first(orelse, frame, condition, "FALSE_BRANCH")
        if skipped:
            self.graph.edge("FALSE_BRANCH", condition, skipped)

    def _else(
        self, orelse: Sequence[ast.stmt], frame: Frame, anchor: Optional[str],
    ) -> None:
        """``for``/``while`` else: the block that runs when the loop was not broken."""
        exhausted = self._first(orelse, frame, anchor, "FALSE_BRANCH")
        if exhausted and anchor:
            self.graph.edge("FALSE_BRANCH", anchor, exhausted)

    def _try(self, node: ast.stmt, node_id: str, frame: Frame) -> None:
        attempted = self._first(node.body, frame, node_id, "TRY_BODY")
        if attempted:
            self.graph.edge("TRY_BODY", node_id, attempted)
        for handler in node.handlers:
            caught = self._first(handler.body, frame, node_id, "EXCEPTION_BRANCH")
            if caught is None:
                continue
            self.graph.edge(
                "EXCEPTION_BRANCH", attempted or node_id, caught,
                exception_type=(
                    compact(self.source.excerpt(handler.type))
                    if handler.type is not None else None
                ),
                binds=handler.name,
            )
            self.exception_branch_count += 1
        finally_id = self._first(node.finalbody, frame, node_id, "RUNS_FINALLY")
        if finally_id:
            self.graph.edge("RUNS_FINALLY", attempted or node_id, finally_id)
        self._else(node.orelse, frame, attempted or node_id)

    def _match(self, node: ast.Match, node_id: str, frame: Frame) -> None:
        subject = self._expression(node.subject, frame, node_id, "CONDITION")
        self.graph.edge("CONDITION", node_id, subject)
        self.condition_count += 1
        for case in node.cases:
            entered = self._first(case.body, frame, subject, "SWITCH_CASE")
            if entered is None:
                continue
            self.graph.edge(
                "SWITCH_CASE", subject, entered,
                label=compact(self.source.excerpt(case.pattern)),
                default=isinstance(case.pattern, ast.MatchAs)
                    and case.pattern.pattern is None,
            )
            if case.guard is not None:
                # A case guard is an ordinary condition that happens to sit in a
                # pattern: it decides whether the arm runs at all, so it hangs off
                # the subject that is being matched and not off the arm's body,
                # which is what the guard decides about rather than what tests it.
                guard = self._expression(case.guard, frame, subject, "CONDITION")
                self.graph.edge("CONDITION", subject, guard)
                self.condition_count += 1

    def _return(
        self, node: ast.stmt, node_id: str, frame: Frame, return_kind: str,
        value: Optional[ast.expr],
    ) -> None:
        """``return``/``raise``, as the value that leaves the function.

        The TypeScript frontend models both as a ``return-value`` node so the
        shared overlays see one shape, and ``THROWS_VALUE`` is what separates a
        validate-and-throw guard from a function that merely branches
        (nav/guards.py:117-122).
        """
        position = self.source.position(node)
        return_id = stable_id(
            "return-value", self.source.display, position["start_offset"],
            position["end_offset"], return_kind,
        )
        self.graph.node(
            return_id, "return-value",
            compact(self.source.excerpt(value)) if value is not None else return_kind,
            **position,
            return_kind=return_kind,
            origin="expression" if value is not None else "empty",
            owner_function_id=frame.owner_function_id,
        )
        self.graph.edge("RETURN_EVIDENCED_BY", return_id, node_id)
        if value is not None:
            self.values.returned(value, return_id, frame)
        if frame.owner_function_id:
            if return_kind == "throw":
                self.graph.edge("THROWS_VALUE", return_id, frame.owner_function_id)
                self.throw_count += 1
            else:
                self.graph.edge("RETURNS_VALUE", return_id, frame.owner_function_id)

    def _yield(
        self, node: ast.AST, frame: Frame, parent: Optional[str],
    ) -> None:
        """``yield`` folded onto the return shape.

        What is lost is the resumption point: a generator continues after the
        yield, and nothing emitted here says where. That is one of the reasons
        ``control_flow`` stays partial rather than claiming complete.
        """
        position = self.source.position(node)
        return_id = stable_id(
            "return-value", self.source.display, position["start_offset"],
            position["end_offset"], "yield",
        )
        self.graph.node(
            return_id, "return-value", compact(self.source.excerpt(node)),
            **position, return_kind="yield", origin="expression",
            owner_function_id=frame.owner_function_id,
        )
        if parent:
            self.graph.edge("RETURN_EVIDENCED_BY", return_id, parent)
        if frame.owner_function_id:
            self.graph.edge("RETURNS_VALUE", return_id, frame.owner_function_id)

    def _short_circuit(
        self, node: ast.BoolOp, frame: Frame, parent: Optional[str],
    ) -> str:
        """``a and b`` / ``a or b``: the operand that may never be evaluated.

        This is the fail-open shape ``x or raise`` and ``x and use(x)`` are built
        from, and the C frontend's lack of it is why C guard classes stop at
        ``validate`` (nav/guards.py:117-122).

        A condition reaches this twice, once through the statement that owns it and
        once through the generic descent, so the memo is checked before any edge is
        written: the edges themselves deduplicate, but the counters would not.
        """
        existing = self._bodies.get(id(node))
        if existing is not None:
            return existing
        node_id = self._body(node, "expression", frame, parent, "AST_CHILD")
        operator = "and" if isinstance(node.op, ast.And) else "or"
        previous: Optional[str] = None
        for index, operand in enumerate(node.values):
            side = self._expression(
                operand, frame, node_id,
                "LEFT_OPERAND" if index == 0 else "RIGHT_OPERAND",
            )
            if previous is None:
                self.graph.edge("SHORT_CIRCUIT_LEFT", node_id, side)
            else:
                self.graph.edge(
                    "SHORT_CIRCUIT_RIGHT", previous, side, operator=operator,
                )
            self.short_circuit_count += 1
            previous = side
        return node_id

    def _conditional_expression(
        self, node: ast.IfExp, frame: Frame, parent: Optional[str],
    ) -> str:
        existing = self._bodies.get(id(node))
        if existing is not None:
            return existing
        node_id = self._body(node, "expression", frame, parent, "AST_CHILD")
        condition = self._expression(node.test, frame, node_id, "CONDITION")
        self.graph.edge("CONDITION", node_id, condition)
        self.condition_count += 1
        self.graph.edge(
            "TRUE_BRANCH", condition,
            self._expression(node.body, frame, condition, "TRUE_VALUE"),
        )
        self.graph.edge(
            "FALSE_BRANCH", condition,
            self._expression(node.orelse, frame, condition, "FALSE_VALUE"),
        )
        return node_id

    def _comprehension(
        self, node: ast.expr, frame: Frame, parent: Optional[str],
    ) -> str:
        """A comprehension's ``if`` clauses are conditions like any other.

        No ``function`` node is emitted for the comprehension scope itself: PEP
        709 inlines comprehensions on 3.12 and later, so a declaration node here
        would be a lie on half the interpreters this runs on.
        """
        existing = self._bodies.get(id(node))
        if existing is not None:
            return existing
        node_id = self._body(node, "expression", frame, parent, "AST_CHILD")
        for generator in node.generators:
            for test in generator.ifs:
                condition = self._expression(test, frame, node_id, "CONDITION")
                self.graph.edge("CONDITION", node_id, condition)
                self.condition_count += 1
        return node_id

    # -- call sites ----------------------------------------------------------

    def _call(
        self, node: ast.Call, frame: Frame, parent: Optional[str],
        role: Optional[str] = None,
    ) -> str:
        existing = self._bodies.get(id(node))
        if existing is not None:
            return existing
        position = self.source.position(node)
        callee = node.func
        callee_text = compact(self.source.excerpt(callee))
        resolution = self._resolve(callee, frame)
        kind = "construct" if resolution.constructed_class else "call"
        node_id = stable_id(
            # Deliberately "call" and not ``kind``. Whether this is a construct is
            # decided by ``resolution``, which comes from the whole-tree Resolver:
            # ``Foo()`` with ``Foo`` imported cannot be classified from this file
            # alone. Feeding that into the identity would make the id of a call site
            # depend on code in some other file, so a change over there would silently
            # rename a node over here -- the one thing an identity may never do, and
            # what makes per-file incremental reuse possible at all. The id namespace
            # is a namespace; ``kind`` below still says what the node is, and nothing
            # reads semantics back out of an id (only segments 1 and 2, owner and
            # namespace, are ever parsed -- see core/identities.py).
            "call", self.source.display, position["start_offset"],
            position["end_offset"], callee_text,
        )
        keywords = [keyword for keyword in node.keywords if keyword.arg is not None]
        constructed = resolution.constructed_class
        self.graph.node(
            node_id, kind, callee_text, **position,
            syntax_kind="Call",
            callee_name=_callee_name(callee),
            callee_form=_callee_form(callee),
            receiver=_receiver_text(self.source, callee),
            argument_count=len(node.args),
            keyword_count=len(keywords),
            has_star_arguments=any(
                isinstance(argument, ast.Starred) for argument in node.args
            ) or any(keyword.arg is None for keyword in node.keywords),
            owner_function_id=frame.owner_function_id,
            owner_id=frame.class_id if frame.kind == "class" else None,
            # A missing edge is not an unresolved edge. This property is where the
            # misses are recorded, so that "no target" is always explained.
            resolution=resolution.resolution,
            method_candidate_count=resolution.candidate_count or None,
            constructed_type=(
                self.graph.nodes[constructed]["label"]
                if constructed and constructed in self.graph.nodes else None
            ),
        )
        self._bodies[id(node)] = node_id
        if kind == "construct":
            self.construct_count += 1
        else:
            self.call_count += 1
        if parent:
            self.graph.edge("AST_CHILD", parent, node_id, role=role or "AST_CHILD")
        else:
            self.graph.edge(
                "CONTAINS_BODY", frame.owner_function_id or self.file_id, node_id,
            )

        for target in resolution.targets:
            self.graph.edge(
                resolution.edge_kind, node_id, target,
                confidence=resolution.confidence,
                resolution=resolution.resolution,
            )
            if resolution.edge_kind == "INVOKES":
                # CALLS is the clean declaration-to-declaration graph the direct
                # half of callers/callees reads, so only a decided target enters it.
                self.graph.edge(
                    "CALLS", frame.owner_function_id, target,
                    callsite=node_id, confidence=resolution.confidence,
                )
                self.resolved_count += 1
        if constructed is not None:
            # There is no INSTANTIATES in the contract, and inventing one would put
            # a kind no reader knows into the store. REFERS_TO is the structural
            # edge that already means "this site names that declaration".
            self.graph.edge(
                "REFERS_TO", node_id, constructed,
                reason="constructed-type", confidence=resolution.confidence,
            )
        if resolution.resolution == "dynamic":
            self._dynamic_behavior(node, node_id, callee, frame, position)
        self._arguments(node, node_id, resolution, frame)
        self.values.call_result(node, node_id, frame, constructed)
        return node_id

    def _dynamic_behavior(
        self, node: ast.Call, call_id: str, callee: ast.expr, frame: Frame,
        position: dict,
    ) -> None:
        """A call whose target is chosen at run time, located but not resolved.

        ``getattr(obj, name)()`` names its callee with a string this frontend
        cannot evaluate. Emitting a call edge would be fiction; emitting nothing
        would hide a real dispatch point, so the site is marked instead.
        """
        behavior_kind = _callee_name(callee) or "dynamic"
        behavior_id = stable_id(
            "dynamic-behavior", self.source.display, position["start_offset"],
            behavior_kind,
        )
        self.graph.node(
            behavior_id, "dynamic-behavior", behavior_kind, **position,
            behavior_kind=behavior_kind,
            site_id=call_id,
            owner_function_id=frame.owner_function_id,
            resolution="dynamic",
            confidence="unresolved",
        )
        self.graph.edge("DYNAMIC_BEHAVIOR_AT", behavior_id, call_id)
        self.dynamic_count += 1

    def _arguments(
        self, node: ast.Call, call_id: str, resolution: Resolution, frame: Frame,
    ) -> None:
        slots: List[tuple] = [
            (index, None, argument) for index, argument in enumerate(node.args)
        ]
        slots.extend(
            (len(node.args) + offset, keyword.arg, keyword.value)
            for offset, keyword in enumerate(node.keywords)
        )
        parameters = self._parameters_of(resolution)
        for index, name, expression in slots:
            position = self.source.position(expression)
            argument_id = stable_id(
                "argument", self.source.display, position["start_offset"],
                position["end_offset"], call_id, index,
            )
            self.graph.node(
                argument_id, "argument", compact(self.source.excerpt(expression)),
                **position,
                syntax_kind=type(expression).__name__,
                callsite_id=call_id, position=index, index=index,
                keyword=name,
                is_starred=isinstance(expression, ast.Starred),
                owner_function_id=frame.owner_function_id,
            )
            self.graph.edge("HAS_ARGUMENT", call_id, argument_id, position=index)
            parameter = self._parameter_for(parameters, index, name)
            if parameter is not None:
                self.graph.edge(
                    "ARGUMENT_BINDS_PARAMETER", argument_id, parameter,
                    position=index, callsite=call_id,
                    confidence=resolution.confidence,
                )
            self.values.argument(
                expression, argument_id, parameter, frame, resolution.confidence,
            )

    def _parameters_of(self, resolution: Resolution) -> Optional[List[tuple]]:
        """The target's parameter slots, when exactly one target was decided."""
        if resolution.edge_kind != "INVOKES" or len(resolution.targets) != 1:
            return None
        target = resolution.targets[0]
        facts = self.resolver.declaration_file.get(target)
        if facts is None:
            return None
        slots = list((facts.parameters_by_function.get(target) or {}).items())
        if not slots:
            return None
        node = self.graph.nodes.get(target)
        if node is not None and node["kind"] in ("method", "constructor"):
            # The receiver fills the first slot and is not written at the call, so
            # every written argument is shifted by one.
            slots = slots[1:]
        return slots

    @staticmethod
    def _parameter_for(
        parameters: Optional[List[tuple]], index: int, name: Optional[str],
    ) -> Optional[str]:
        if not parameters:
            return None
        if name is not None:
            for slot_name, slot_id in parameters:
                if slot_name == name:
                    return slot_id
            return None
        return parameters[index][1] if index < len(parameters) else None

    # -- resolution ----------------------------------------------------------

    def _resolve(self, callee: ast.expr, frame: Frame) -> Resolution:
        if isinstance(callee, ast.Name):
            if callee.id in DYNAMIC_CALLEES:
                return Resolution((), "", "unresolved", "dynamic")
            local = self._local_declaration(frame, callee.id)
            if local is not None:
                return self.resolver.callable_target(local, "exact", "exact")
            if self._shadowed(frame, callee.id):
                # A local of the same name is live here; the module binding is not
                # what this call reaches, and what the local holds is dataflow.
                return Resolution((), "", "unresolved", "local-value")
            return self.resolver.resolve_name(self.facts, callee.id)
        if not isinstance(callee, ast.Attribute):
            return NOTHING

        receiver = callee.value
        if isinstance(receiver, ast.Call) and _callee_name(receiver.func) == "super":
            return self._super_method(frame, callee.attr)
        if isinstance(receiver, ast.Name):
            if frame.self_name and receiver.id == frame.self_name and frame.class_id:
                member = self.resolver.lookup_method(frame.class_id, callee.attr)
                if member is not None:
                    # The lexically nearest definition on the class. The receiver's
                    # run-time type may be a subclass, which is precisely what
                    # OVERRIDES plus the dispatch overlay fan out from here, so
                    # this is high confidence and deliberately not exact.
                    return Resolution((member,), "INVOKES", "high", "lexical-mro")
                return self.resolver.duck_typed(callee.attr)
            if not self._shadowed(frame, receiver.id):
                resolved = self.resolver.resolve_attribute(
                    self.facts, receiver.id, callee.attr,
                )
                if resolved.targets:
                    return resolved
        return self.resolver.duck_typed(callee.attr)

    def _super_method(self, frame: Frame, name: str) -> Resolution:
        if frame.class_id is None:
            return NOTHING
        registry = self.resolver.registry
        facts = registry.facts_of_class.get(frame.class_id)
        references = registry.bases.get(frame.class_id) or ()
        from .scopes import resolve_base

        for reference in references:
            base = resolve_base(facts, reference, registry, self.resolver.all_facts) \
                if facts else None
            if base is None:
                continue
            member = self.resolver.lookup_method(base, name)
            if member is not None:
                return Resolution(
                    (member,), "INVOKES",
                    "exact" if len(references) == 1 else "high", "super",
                )
        return NOTHING

    @staticmethod
    def _local_declaration(frame: Frame, name: str) -> Optional[str]:
        return frame.declarations.get(name)

    @staticmethod
    def _shadowed(frame: Frame, name: str) -> bool:
        return name in frame.locals


def _all_parameters(arguments: ast.arguments) -> List[ast.arg]:
    slots = list(getattr(arguments, "posonlyargs", [])) + list(arguments.args)
    slots += list(arguments.kwonlyargs)
    slots += [slot for slot in (arguments.vararg, arguments.kwarg) if slot is not None]
    return slots


def _callee_name(callee: ast.expr) -> Optional[str]:
    if isinstance(callee, ast.Name):
        return callee.id
    if isinstance(callee, ast.Attribute):
        return callee.attr
    return None


def _callee_form(callee: ast.expr) -> str:
    if isinstance(callee, ast.Name):
        return "name"
    if isinstance(callee, ast.Attribute):
        return "attribute"
    return "expression"


def _receiver_text(source: SourceFile, callee: ast.expr) -> Optional[str]:
    if isinstance(callee, ast.Attribute):
        return compact(source.excerpt(callee.value))
    return None
