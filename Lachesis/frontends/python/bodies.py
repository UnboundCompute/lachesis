"""Call sites: the `call` and `construct` nodes the traversal tools stand on.

``callers``, ``callees``, ``hubs`` and ``call_roles`` all read the same two
shapes. ``CALLS`` is the resolved declaration-to-declaration graph
(nav/symbol_index.py:73). ``INVOKES``/``MAY_INVOKE`` start at the call site
itself, which is why every node emitted here carries ``owner_function_id``: the
traversal climbs from a call site to the declaration that owns it, and a call
site with no owner is attributed to itself and ranks as its own hub.

This pass re-parses the file rather than holding pass one's AST, because
resolution needs the whole tree's binding tables and keeping every AST resident
to get them would trade a bounded second parse for unbounded memory.
"""
from __future__ import annotations

import ast
from typing import Dict, List, NamedTuple, Optional, Set

from .declarations import declaration_id, declaration_kind
from .emit import Graph, SourceFile, compact, stable_id
from .resolve import DYNAMIC_CALLEES, NOTHING, Resolution, Resolver
from .scopes import (
    FUNCTION_NODES, SCOPE_NODES, bound_occurrences, own_regions, outer_regions,
    scope_kind,
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

    # -- the walk ------------------------------------------------------------

    def run(self, module: ast.Module) -> None:
        frame = self._frame(module, None)
        for region in own_regions(module):
            self._visit(region, frame)

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
        return Frame(
            kind, graph_id, owner_function_id, class_id, self_name,
            locals_of_scope, declarations,
        )

    def _visit(self, node: ast.AST, frame: Frame) -> None:
        if isinstance(node, SCOPE_NODES):
            # Decorators, defaults and base-class expressions run in the enclosing
            # scope, so a call hiding in one is attributed there and not inside.
            for region in outer_regions(node):
                self._visit(region, frame)
            child = self._frame(node, frame)
            for region in own_regions(node):
                self._visit(region, child)
            return
        if isinstance(node, ast.Call):
            self._call(node, frame)
        for child in ast.iter_child_nodes(node):
            self._visit(child, frame)

    # -- call sites ----------------------------------------------------------

    def _call(self, node: ast.Call, frame: Frame) -> None:
        position = self.source.position(node)
        callee = node.func
        callee_text = compact(self.source.excerpt(callee))
        resolution = self._resolve(callee, frame)
        kind = "construct" if resolution.constructed_class else "call"
        node_id = stable_id(
            kind, self.source.display, position["start_offset"],
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
        if kind == "construct":
            self.construct_count += 1
        else:
            self.call_count += 1
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
