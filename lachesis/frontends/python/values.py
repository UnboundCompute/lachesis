"""Dataflow: what a value is, where it came from, and where it goes.

``flow``, ``reaches`` and ``sources_of`` walk ``VALUE_FLOWS_TO`` between value
nodes, and ``points_to``/``aliases`` walk ``POINTS_TO``, which no frontend may
emit: lachesis/core/overlays/heap.py derives it from ``allocation`` nodes,
parameter definitions and the identity-preserving flow reasons in its
``IDENTITY_FLOW_REASONS`` set. The shapes here are therefore copied from the
TypeScript frontend rather than invented, because the overlays are tuned for
exactly those reason strings and any near miss silently produces nothing.

The vocabulary, once:

``value``           one expression's value, the node flow edges connect
``definition``      one versioned assignment to a target, with ``origin``
``read``            one use of a target, resolved to the definition it sees
``write``           one store into a target, including attribute and item stores
``property-path``   ``a.b.c`` as an addressable location under its base
``allocation``      a site that creates an object, which is what gives the heap
                    overlay something to be identical about

Versioning here is linear and offset-ordered: definitions per target in source
order, ``previous_definition_id`` and ``PREVIOUS_VERSION`` between them. No
``phi`` and no branch-sensitive reaching definitions are emitted, because ``phi``
is forbidden to frontends and the real fixpoint is
lachesis/core/overlays/branch_history.py's job.

Confidence is not decoration. A ``for`` target is bound to an element of
something this frontend never evaluates, a ``with ... as`` binding is whatever
``__enter__`` chose to return, and a starred target is a slice of unknown length,
so all three are ``conservative``. Direct assignment, parameter binding and
argument passing are ``exact``.
"""
from __future__ import annotations

import ast
from typing import Dict, List, Optional, Tuple

from .emit import Graph, SourceFile, compact, stable_id

# Literal displays that build a new object every time they are evaluated. A
# generator expression is deliberately absent: it produces an iterator whose
# elements are computed later, and calling that an allocation of the sequence
# would claim an identity the program never creates.
ALLOCATION_KIND = {
    ast.List: "array", ast.ListComp: "array",
    ast.Dict: "object", ast.DictComp: "object",
    ast.Set: "set", ast.SetComp: "set",
    ast.Tuple: "tuple",
    ast.Lambda: "function-object",
}

# The reasons lachesis/core/overlays/heap.py treats as identity-preserving. Using
# any other string for these shapes would leave points_to empty without saying so.
ASSIGNMENT = "assignment"
INITIALIZER = "initializer"


def _literal(node: ast.AST) -> Tuple[bool, Optional[str]]:
    """Whether an expression is a constant, and its value rendered as text."""
    if isinstance(node, ast.Constant):
        return True, str(node.value)
    return False, None


class ValueWalk:
    """The dataflow half of the body pass, driven by BodyWalk's traversal.

    It rides on BodyWalk rather than walking the tree a second time because the
    two need exactly the same thing: the frame a node sits in and the body node
    that stands for it. Splitting the traversal would mean rebuilding the scope
    descent and would let the two drift apart.
    """

    def __init__(
        self, graph: Graph, source: SourceFile, file_id: str, facts,
    ) -> None:
        self.graph = graph
        self.source = source
        self.file_id = file_id
        self.facts = facts
        self.definition_count = 0
        self.read_count = 0
        self.write_count = 0
        self.allocation_count = 0
        self._values: Dict[int, str] = {}
        self._paths: Dict[Tuple[str, str], str] = {}
        self._history: Dict[str, List[str]] = {}
        self._parameters_done: set = set()
        self.bodies: Dict[int, str] = {}     # shared with BodyWalk, set by it

    # -- values --------------------------------------------------------------

    def value_of(self, node: ast.expr, frame) -> str:
        """The ``value`` node for one expression, created once.

        Every flow edge in the file connects two of these, so an expression that
        is read, passed and returned has one identity through all three rather
        than a node per use.
        """
        existing = self._values.get(id(node))
        if existing is not None:
            return existing
        position = self.source.position(node)
        node_id = stable_id(
            "value", self.source.display, position["start_offset"],
            position["end_offset"], type(node).__name__,
        )
        literal, literal_value = _literal(node)
        self.graph.node(
            node_id, "value", compact(self.source.excerpt(node)), **position,
            syntax_kind=type(node).__name__,
            owner_function_id=frame.owner_function_id,
            literal=literal or None,
            literal_value=literal_value,
        )
        self._values[id(node)] = node_id
        body_id = self.bodies.get(id(node))
        if body_id:
            self.graph.edge("EVIDENCED_BY", node_id, body_id)
        return node_id

    # -- targets -------------------------------------------------------------

    def target_of(self, node: ast.expr, frame) -> Optional[str]:
        """The addressable location an expression names, or nothing.

        A bare name resolves through the binding table the scope pass built, so a
        local, a parameter and a module global all land on the one node that
        represents them. An attribute or a subscript becomes a ``property-path``
        under whatever its base resolves to; when the base resolves to nothing
        the path is not invented, because a path with no base is a location the
        rest of the graph cannot join on.
        """
        if isinstance(node, ast.Name):
            return self.binding(node.id, frame)
        if isinstance(node, (ast.Attribute, ast.Subscript)):
            return self.property_path(node, frame)
        if isinstance(node, ast.Starred):
            return self.target_of(node.value, frame)
        return None

    def binding(self, name: str, frame) -> Optional[str]:
        """The node a name binds to, looked up from the innermost scope out.

        The scope pass already pointed a parameter's binding straight at its
        ``parameter`` declaration node, which matters beyond tidiness:
        lachesis/core/overlays/heap.py:95 only gives an abstract object to a
        ``parameter`` node that owns its definition, so a separate binding node
        for a parameter would silently cost every ``points_to`` answer.
        """
        for span in frame.scope_spans:
            bindings = self.facts.bindings_by_span.get(span)
            if bindings and name in bindings:
                return bindings[name]
        if frame.kind == "class" and frame.class_id:
            member = (self.facts.class_members.get(frame.class_id) or {}).get(name)
            if member:
                return member
        bound = self.facts.module_bindings.get(name)
        # A module-level name can be bound more than once, by a def and then by a
        # reassignment. The first is the location the name means; which value it
        # holds at a given point is the question the definitions answer.
        return bound[0] if bound else None

    def property_path(self, node: ast.expr, frame) -> Optional[str]:
        pieces: List[dict] = []
        current: ast.expr = node
        while isinstance(current, (ast.Attribute, ast.Subscript)):
            if isinstance(current, ast.Attribute):
                pieces.insert(0, {"key": current.attr, "computed": False,
                                  "dynamic": False})
            else:
                index = current.slice
                if isinstance(index, ast.Constant):
                    key, dynamic = str(index.value), False
                else:
                    key, dynamic = compact(self.source.excerpt(index), 60), True
                pieces.insert(0, {"key": key, "computed": True, "dynamic": dynamic})
            current = current.value
        base = self.target_of(current, frame)
        if base is None or not pieces:
            return None
        path = ".".join(piece["key"] for piece in pieces)
        key = (base, path)
        if key in self._paths:
            return self._paths[key]
        position = self.source.position(node)
        node_id = stable_id("property-path", base, path)
        base_label = self.graph.nodes.get(base, {}).get("label", "")
        self.graph.node(
            node_id, "property-path", f"{base_label}.{path}", **position,
            base_value_id=base, path=path, path_segments=pieces,
            dynamic=any(piece["dynamic"] for piece in pieces) or None,
            owner_function_id=frame.owner_function_id,
        )
        self.graph.edge("HAS_PROPERTY_PATH", base, node_id)
        self._paths[key] = node_id
        return node_id

    # -- definitions and reads -----------------------------------------------

    def define(
        self, target_id: Optional[str], node: ast.AST, definition_kind: str,
        origin: str, frame, value: Optional[ast.expr] = None,
        confidence: str = "exact", reason: Optional[str] = None,
    ) -> Optional[str]:
        if not target_id:
            return None
        history = self._history.setdefault(target_id, [])
        position = self.source.position(node)
        node_id = stable_id(
            "definition", target_id, position["start_offset"], len(history),
            definition_kind,
        )
        value_position = self.source.position(value) if value is not None else None
        self.graph.node(
            node_id, "definition",
            self.graph.nodes.get(target_id, {}).get("label")
                or compact(self.source.excerpt(node)),
            **position,
            target_id=target_id,
            version=len(history),
            definition_kind=definition_kind,
            origin=origin,
            previous_definition_id=history[-1] if history else None,
            value_start_offset=value_position["start_offset"] if value_position else None,
            value_end_offset=value_position["end_offset"] if value_position else None,
            owner_function_id=frame.owner_function_id,
            confidence=confidence,
        )
        self.graph.edge("DEFINES", target_id, node_id, confidence=confidence)
        if history:
            self.graph.edge("PREVIOUS_VERSION", history[-1], node_id)
        if value is not None:
            self.graph.edge(
                "VALUE_FLOWS_TO", self.value_of(value, frame), node_id,
                reason=reason or definition_kind, confidence=confidence,
            )
        history.append(node_id)
        self.definition_count += 1
        return node_id

    def current_definition(self, target_id: str, node: ast.AST, frame) -> Optional[str]:
        """The definition a use at this offset sees, in linear source order.

        Linear, not branch-sensitive: this walks back to the last definition that
        starts before the use. A use that is only reachable through one arm of a
        branch is answered by lachesis/core/overlays/branch_history.py, which owns
        the fixpoint; guessing at it here would put a claim in the store that the
        overlay then has to contradict.
        """
        history = self._history.get(target_id)
        if not history:
            # A name used before anything in this file assigns it (a global
            # written elsewhere, a builtin shadow) still needs something to read
            # from, so the implicit definition stands in for the unseen write.
            return self.define(
                target_id, node, "implicit", "unknown", frame,
                confidence="conservative",
            )
        offset = self.source.position(node)["start_offset"]
        for definition_id in reversed(history):
            properties = self.graph.nodes[definition_id]["properties"]
            if properties["start_offset"] > offset:
                continue
            value_start = properties.get("value_start_offset")
            value_end = properties.get("value_end_offset")
            if (value_start is not None and value_start <= offset < value_end
                    and properties["version"] > 0):
                # `x = x + 1` reads the version before the one it is writing.
                return history[properties["version"] - 1]
            return definition_id
        return history[0]

    def read(self, node: ast.expr, frame) -> Optional[str]:
        """One use of a location, joined to the definition it sees."""
        target_id = self.target_of(node, frame)
        if target_id is None:
            return None
        definition_id = self.current_definition(target_id, node, frame)
        if definition_id is None:
            return None
        position = self.source.position(node)
        node_id = stable_id(
            "read", self.source.display, position["start_offset"],
            position["end_offset"], target_id,
        )
        self.graph.node(
            node_id, "read", compact(self.source.excerpt(node)), **position,
            target_id=target_id, definition_id=definition_id,
            owner_function_id=frame.owner_function_id,
        )
        self.graph.edge("READS_FROM", definition_id, node_id)
        self.graph.edge(
            "VALUE_FLOWS_TO", node_id, self.value_of(node, frame), reason="read-value",
        )
        body_id = self.bodies.get(id(node))
        if body_id:
            self.graph.edge("READ_EVIDENCED_BY", node_id, body_id)
        base = self.graph.nodes[target_id]["properties"].get("base_value_id")
        if base:
            # Reading `a.b` is also a read of `a`, and the overlay needs the two
            # joined to know which object the property was read off.
            base_definition = self.current_definition(base, node, frame)
            self.graph.edge(
                "PROPERTY_READ", base_definition, definition_id,
                path=self.graph.nodes[target_id]["properties"].get("path"),
            )
        self.read_count += 1
        return node_id

    def write(
        self, node: ast.AST, target: ast.expr, value: Optional[ast.expr], frame,
        write_kind: str, confidence: str = "exact",
    ) -> Optional[str]:
        target_id = self.target_of(target, frame)
        if target_id is None:
            return None
        position = self.source.position(node)
        node_id = stable_id(
            "write", self.source.display, position["start_offset"],
            position["end_offset"], target_id, write_kind,
        )
        properties = self.graph.nodes[target_id]["properties"]
        self.graph.node(
            node_id, "write", compact(self.source.excerpt(target)), **position,
            write_kind=write_kind, target_id=target_id,
            value_id=self.value_of(value, frame) if value is not None else None,
            property_path=properties.get("path"),
            owner_function_id=frame.owner_function_id,
            target_scope=(
                "property" if properties.get("base_value_id")
                else "local" if properties.get("owner_function_id") else "module"
            ),
            confidence=confidence,
        )
        self.graph.edge("WRITES_TO", node_id, target_id, confidence=confidence)
        if value is not None:
            self.graph.edge(
                "VALUE_FLOWS_TO", self.value_of(value, frame), node_id,
                reason=write_kind, confidence=confidence,
            )
        body_id = self.bodies.get(id(node))
        if body_id:
            self.graph.edge("EVIDENCED_BY", node_id, body_id)
        self.write_count += 1
        return node_id

    def release_target(self, node: ast.AST, target: ast.expr, frame, method: str) -> None:
        """Emit one catalogue release for a target (``del`` or context exit)."""
        target_id = self.target_of(target, frame)
        if target_id is None:
            return
        position = self.source.position(node)
        release_line = position.get("end_line") if method == "__exit__" else position.get("start_line")
        node_id = stable_id("release", self.source.display,
                            position["start_offset"], position["end_offset"], target_id,
                            method)
        self.graph.node(node_id, "release", compact(self.source.excerpt(target)),
                        **position, release_method=method, target_id=target_id,
                        release_line=release_line,
                        owner_function_id=frame.owner_function_id)
        body_id = self.bodies.get(id(node))
        if body_id:
            self.graph.edge("EVIDENCED_BY", node_id, body_id)

    def release(self, node: ast.Delete, frame) -> None:
        """Emit ``del`` as a structural release of its tracked target."""
        for target in node.targets:
            self.release_target(node, target, frame, "del")

    # -- allocations ---------------------------------------------------------

    def allocation(
        self, node: ast.expr, frame, allocation_kind: str,
        allocated_type: Optional[str] = None,
    ) -> str:
        """A site that creates an object, which is what heap identity is about.

        Without these, ``points_to`` and ``aliases`` answer nothing, because
        lachesis/core/overlays/heap.py does not run at all unless an ``allocation``
        node exists (heap.py:31-32).
        """
        position = self.source.position(node)
        node_id = stable_id(
            "allocation", self.source.display, position["start_offset"],
            position["end_offset"], allocation_kind,
        )
        self.graph.node(
            node_id, "allocation", compact(self.source.excerpt(node)), **position,
            allocation_kind=allocation_kind,
            allocated_type=allocated_type,
            owner_function_id=frame.owner_function_id,
            module_singleton=frame.owner_function_id is None or None,
        )
        body_id = self.bodies.get(id(node))
        if body_id:
            self.graph.edge("ALLOCATES", body_id, node_id)
        self.graph.edge(
            "VALUE_FLOWS_TO", node_id, self.value_of(node, frame), reason="allocation",
        )
        self.allocation_count += 1
        return node_id

    # -- the hooks BodyWalk calls --------------------------------------------

    def parameters(self, node: ast.AST, frame) -> None:
        """One definition per parameter, with ``origin`` spelled exactly.

        lachesis/core/overlays/branch_history.py:173 keys on the literal string
        ``"parameter"``, and heap.py gives a parameter an abstract object only
        when it finds a definition with that origin, so this is not a free-form
        label.
        """
        arguments = getattr(node, "args", None)
        if arguments is None or frame.declaration_id in self._parameters_done:
            return
        self._parameters_done.add(frame.declaration_id)
        slots = (list(getattr(arguments, "posonlyargs", [])) + list(arguments.args)
                 + ([arguments.vararg] if arguments.vararg else [])
                 + list(arguments.kwonlyargs)
                 + ([arguments.kwarg] if arguments.kwarg else []))
        for slot in slots:
            target_id = self.binding(slot.arg, frame)
            self.define(target_id, slot, "parameter", "parameter", frame)
        for default in list(arguments.defaults) + [
                value for value in arguments.kw_defaults if value is not None]:
            self.value_of(default, frame)

    def visit(self, node: ast.AST, frame) -> None:
        """Called once per AST node, in the traversal BodyWalk already performs."""
        if isinstance(node, ast.Delete):
            self.release(node, frame)
        elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign,
                             ast.NamedExpr)):
            self._assignment(node, frame)
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            self._bind(node.target, node.iter, frame, "iteration", "conservative")
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                if item.optional_vars is not None:
                    # `__enter__` may return anything at all, so the binding is a
                    # claim about the context manager and not about the object.
                    self._bind(item.optional_vars, item.context_expr, frame,
                               "context-manager", "conservative")
                if item.optional_vars is not None:
                    self.release_target(node, item.optional_vars, frame, "__exit__")
        elif isinstance(node, ast.comprehension):
            self._bind(node.target, node.iter, frame, "iteration", "conservative")
        elif isinstance(node, ast.ExceptHandler) and node.name:
            target_id = self.binding(node.name, frame)
            self.define(target_id, node, "exception", "exception", frame,
                        confidence="conservative")
        elif isinstance(node, ast.JoinedStr):
            self._formatted(node, frame)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            self.read(node, frame)
        elif isinstance(node, (ast.Attribute, ast.Subscript)) \
                and isinstance(node.ctx, ast.Load):
            self.read(node, frame)
        elif type(node) in ALLOCATION_KIND and not isinstance(
                getattr(node, "ctx", None), (ast.Store, ast.Del)):
            self.allocation(node, frame, ALLOCATION_KIND[type(node)])

    def call_result(self, node: ast.Call, call_id: str, frame, constructed) -> None:
        """What a call hands back, and the object a constructor creates.

        ``value_id`` and ``receiver_value_id`` are stamped on the call site
        because the runtime models read them from there
        (lachesis/ecosystems/common/runtime.py:146,154): without them a modelled
        call can say what it does but not flow anything through it.
        """
        value_id = self.value_of(node, frame)
        self.graph.edge("VALUE_FLOWS_TO", call_id, value_id, reason="call-result")
        receiver_value_id = (
            self.value_of(node.func.value, frame)
            if isinstance(node.func, ast.Attribute) else None
        )
        self.graph.annotate(
            call_id, value_id=value_id, receiver_value_id=receiver_value_id,
        )
        if constructed is not None:
            self.allocation(
                node, frame, "class-instance",
                self.graph.nodes.get(constructed, {}).get("label"),
            )

    def argument(
        self, expression: ast.expr, argument_id: str, parameter_id: Optional[str],
        frame, confidence: str,
    ) -> None:
        """The argument's value into the slot, and into the parameter it fills."""
        value_id = self.value_of(expression, frame)
        self.graph.edge(
            "VALUE_FLOWS_TO", value_id, argument_id, reason="argument-value",
        )
        if parameter_id:
            self.graph.edge(
                "VALUE_FLOWS_TO", argument_id, parameter_id,
                reason="call-argument", confidence=confidence,
            )

    def returned(self, value: ast.expr, return_id: str, frame) -> None:
        self.graph.edge(
            "VALUE_FLOWS_TO", self.value_of(value, frame), return_id, reason="return",
        )

    # -- assignment forms ----------------------------------------------------

    def _assignment(self, node: ast.AST, frame) -> None:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                self._bind(target, node.value, frame, ASSIGNMENT)
        elif isinstance(node, ast.AnnAssign):
            if node.value is not None:
                self._bind(node.target, node.value, frame, INITIALIZER)
        elif isinstance(node, ast.NamedExpr):
            self._bind(node.target, node.value, frame, ASSIGNMENT)
        else:                                        # AugAssign
            # `x += tainted` is both a read of the old value and a write of the
            # new one. Flowing only the operand loses everything x already held,
            # and flowing only the old value loses the taint, so both go in.
            target_id = self.target_of(node.target, frame)
            if target_id is None:
                return
            previous = self.current_definition(target_id, node, frame)
            definition_id = self.define(
                target_id, node, ASSIGNMENT, "augmented-assignment", frame,
                node.value, reason=ASSIGNMENT,
            )
            if previous and definition_id:
                self.graph.edge(
                    "VALUE_FLOWS_TO", previous, definition_id,
                    reason=ASSIGNMENT, operator=type(node.op).__name__,
                )
            self.write(node, node.target, node.value, frame, ASSIGNMENT)

    def _bind(
        self, target: ast.expr, value: Optional[ast.expr], frame,
        definition_kind: str, confidence: str = "exact",
    ) -> None:
        """One assignment target, unpacking whatever structure it has.

        A tuple target does not receive the value: it receives a piece of it,
        chosen by position, and a starred target receives a slice of unknown
        length. Neither is decidable without evaluating the right-hand side, so
        both drop to conservative and say `destructuring` rather than claiming
        the whole value flowed into each name.
        """
        if isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                self._bind(element, value, frame, "destructuring", "conservative")
            return
        if isinstance(target, ast.Starred):
            self._bind(target.value, value, frame, "destructuring", "conservative")
            return
        target_id = self.target_of(target, frame)
        if target_id is None:
            return
        origin = {
            ASSIGNMENT: "assignment", INITIALIZER: "initializer",
            "destructuring": "destructuring", "iteration": "iteration",
            "context-manager": "context-manager",
        }.get(definition_kind, definition_kind)
        self.define(
            target_id, target, definition_kind, origin, frame, value,
            confidence=confidence,
        )
        self.write(target, target, value, frame, definition_kind, confidence)
        self._parameter_property(target, value, frame)

    def _parameter_property(
        self, target: ast.expr, value: Optional[ast.expr], frame,
    ) -> None:
        """``self.x = param``: the shape a constructor stores its inputs with.

        the native Clang frontend emits the same edge, and
        lachesis/frontends/checks.py asserts on it, so a receiver-and-value pair
        that are both parameters of the owning function is reported the same way
        here rather than in a Python-shaped variant of it.
        """
        if not (isinstance(target, ast.Attribute) and isinstance(value, ast.Name)):
            return
        if not (isinstance(target.value, ast.Name) and frame.owner_function_id):
            return
        slots = list(
            (self.facts.parameters_by_function.get(frame.owner_function_id) or {})
        )
        if target.value.id not in slots or value.id not in slots:
            return
        field = self.target_of(target, frame)
        if field is None:
            return
        self.graph.edge(
            "WRITES_PARAMETER_PROPERTY", frame.owner_function_id, field,
            receiver_position=slots.index(target.value.id),
            value_position=slots.index(value.id),
        )

    def _formatted(self, node: ast.JoinedStr, frame) -> None:
        """f-string substitution, the taint edge Python code actually uses.

        SQL, shell commands and HTML are built this way, and the taint overlay is
        tuned for the reason string TypeScript template literals already use, so
        this is that string and not a Python-flavoured synonym.
        """
        target = self.value_of(node, frame)
        for piece in node.values:
            if isinstance(piece, ast.FormattedValue):
                self.graph.edge(
                    "VALUE_FLOWS_TO", self.value_of(piece.value, frame), target,
                    reason="template-substitution",
                )
