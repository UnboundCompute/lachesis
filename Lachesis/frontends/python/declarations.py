"""Declaration extraction: the addressable surface of a Python file.

This is the layer the navigation tools enter through. ``search``, ``read_body``,
``open_file`` and ``open_folder`` resolve names to the nodes emitted here, so the
non-negotiable part is the property spine: a non-empty ``label``, a repo-relative
``file``, and character-accurate ``start_offset``/``end_offset``.
"""
from __future__ import annotations

import ast
from typing import Dict, List, Optional, Tuple

from .emit import Graph, SourceFile, compact, stable_id

# Both ``def`` forms, in one tuple, because every visitor treats them alike apart
# from the ``is_async`` flag.
FUNCTION_NODES = (ast.FunctionDef, ast.AsyncFunctionDef)

# CPython names the initializer ``__init__``; ``__new__`` is an ordinary (static)
# method that happens to allocate, so it is not promoted to `constructor`.
CONSTRUCTOR_NAME = "__init__"


def annotation_text(source: SourceFile, node: Optional[ast.AST]) -> Optional[str]:
    """An annotation as written. There is no type checker here, so an annotation
    is recorded as source text and never as a resolved type."""
    return compact(source.excerpt(node)) if node is not None else None


def decorator_texts(source: SourceFile, node: ast.AST) -> List[str]:
    return [compact(source.excerpt(item)) for item in getattr(node, "decorator_list", [])]


def _parameter_slots(arguments: ast.arguments) -> List[Tuple[ast.arg, str, bool]]:
    """Every parameter in declaration order, tagged with its binding form."""
    slots: List[Tuple[ast.arg, str, bool]] = []
    positional_only = list(getattr(arguments, "posonlyargs", []))
    positional = list(arguments.args)
    defaults = list(arguments.defaults)
    ordered = positional_only + positional
    first_defaulted = len(ordered) - len(defaults)
    for index, argument in enumerate(ordered):
        form = "positional-only" if index < len(positional_only) else "positional-or-keyword"
        slots.append((argument, form, index >= first_defaulted))
    if arguments.vararg is not None:
        slots.append((arguments.vararg, "var-positional", False))
    for argument, default in zip(arguments.kwonlyargs, arguments.kw_defaults):
        slots.append((argument, "keyword-only", default is not None))
    if arguments.kwarg is not None:
        slots.append((arguments.kwarg, "var-keyword", False))
    return slots


def signature(source: SourceFile, node: ast.AST) -> str:
    """``name(a, b=..., *rest)`` rendered from the AST, for the node's `signature`."""
    rendered = []
    for argument, form, has_default in _parameter_slots(node.args):
        prefix = {"var-positional": "*", "var-keyword": "**"}.get(form, "")
        text = prefix + argument.arg
        if has_default:
            text += "=..."
        rendered.append(text)
    return f"{node.name}({', '.join(rendered)})"


def is_stub_body(body: List[ast.stmt]) -> bool:
    """True when a body is only ``...``/``pass``/a docstring, i.e. declares no code.

    This is the Python analogue of C's bodyless prototype. Flagging it keeps a
    ``.pyi`` stub from twinning its implementation in ``search`` ranking.
    """
    for statement in body:
        if isinstance(statement, ast.Pass):
            continue
        if isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Constant):
            if statement.value.value is Ellipsis or isinstance(statement.value.value, str):
                continue
        return False
    return True


class DeclarationWalk:
    """One pass over a module that emits its declaration graph.

    ``declarations_by_node`` and ``names`` are kept for the later passes: the call
    resolver needs to map a bare name back to the declaration it binds, and the
    scope pass needs the AST-node to graph-id correspondence.
    """

    def __init__(self, graph: Graph, source: SourceFile, file_id: str, is_stub: bool) -> None:
        self.graph = graph
        self.source = source
        self.file_id = file_id
        self.is_stub = is_stub
        # ast node -> emitted graph id, for every declaration in this module.
        self.declarations_by_node: Dict[ast.AST, str] = {}
        # Module-level binding name -> [graph ids]. More than one id means the name
        # is rebound, which the call resolver must not treat as a unique target.
        self.module_bindings: Dict[str, List[str]] = {}
        # Class label -> {method name: graph id}, the lexical MRO input.
        self.class_members: Dict[str, Dict[str, str]] = {}
        # Class graph id -> its base-class expressions as written.
        self.class_bases: Dict[str, List[str]] = {}
        self.function_ids: List[str] = []

    # -- emission helpers ----------------------------------------------------

    def _declare(self, owner_id: Optional[str], owner_kind: str, node_id: str) -> None:
        if owner_kind == "class":
            self.graph.edge("DECLARES_MEMBER", owner_id, node_id)
        else:
            self.graph.edge("DECLARES", owner_id or self.file_id, node_id)

    def _bind(self, name: str, node_id: str, class_id: Optional[str], function_id: Optional[str]) -> None:
        if class_id is None and function_id is None:
            self.module_bindings.setdefault(name, []).append(node_id)

    # -- the walk ------------------------------------------------------------

    def run(self, module: ast.Module) -> None:
        self._body(module.body, owner_id=None, owner_kind="module", function_id=None)

    def _body(
        self, body: List[ast.stmt], owner_id: Optional[str], owner_kind: str,
        function_id: Optional[str],
    ) -> None:
        for statement in body:
            self._statement(statement, owner_id, owner_kind, function_id)

    def _statement(
        self, statement: ast.stmt, owner_id: Optional[str], owner_kind: str,
        function_id: Optional[str],
    ) -> None:
        if isinstance(statement, FUNCTION_NODES):
            self._function(statement, owner_id, owner_kind, function_id)
        elif isinstance(statement, ast.ClassDef):
            self._class(statement, owner_id, owner_kind, function_id)
        elif owner_kind in ("module", "class"):
            # Only module- and class-level bindings become addressable `variable`
            # nodes. Function locals are dataflow, not navigation: they are emitted
            # as `definition` nodes by the value pass, where they belong.
            self._binding(statement, owner_id, owner_kind, function_id)

    def _function(
        self, node: ast.AST, owner_id: Optional[str], owner_kind: str,
        function_id: Optional[str],
    ) -> None:
        name = node.name
        if owner_kind == "class":
            kind = "constructor" if name == CONSTRUCTOR_NAME else "method"
        else:
            kind = "function"
        position = self.source.position(node)
        node_id = stable_id(
            kind, self.source.display, position["start_offset"],
            position["end_offset"], name,
        )
        stub = self.is_stub or is_stub_body(node.body)
        self.graph.node(
            node_id, kind, name, **position,
            syntax_kind=type(node).__name__,
            form=kind,
            signature=signature(self.source, node),
            is_async=isinstance(node, ast.AsyncFunctionDef),
            is_generator=_contains_yield(node),
            decorators=decorator_texts(self.source, node),
            returns=annotation_text(self.source, node.returns),
            owner_id=owner_id,
            owner_function_id=function_id,
            declaration_only=stub,
            visibility="private" if name.startswith("_") else "public",
        )
        self.declarations_by_node[node] = node_id
        self.function_ids.append(node_id)
        self._declare(owner_id, owner_kind, node_id)
        self._bind(name, node_id, owner_id if owner_kind == "class" else None, function_id)
        if owner_kind == "class" and owner_id is not None:
            self.class_members.setdefault(owner_id, {})[name] = node_id
        self._parameters(node, node_id)
        # A nested def/class is declared by the enclosing function, and everything
        # inside it is attributed to the inner function.
        self._body(node.body, owner_id=node_id, owner_kind="function", function_id=node_id)

    def _parameters(self, node: ast.AST, function_id: str) -> None:
        for index, (argument, form, has_default) in enumerate(_parameter_slots(node.args)):
            position = self.source.position(argument)
            parameter_id = stable_id(
                "parameter", self.source.display, position["start_offset"],
                position["end_offset"], argument.arg, index,
            )
            self.graph.node(
                parameter_id, "parameter", argument.arg, **position,
                syntax_kind="arg", index=index, parameter_form=form,
                has_default=has_default,
                annotation=annotation_text(self.source, argument.annotation),
                owner_function_id=function_id,
            )
            self.graph.edge("DECLARES_VALUE", function_id, parameter_id, index=index)

    def _class(
        self, node: ast.ClassDef, owner_id: Optional[str], owner_kind: str,
        function_id: Optional[str],
    ) -> None:
        position = self.source.position(node)
        node_id = stable_id(
            "class", self.source.display, position["start_offset"],
            position["end_offset"], node.name,
        )
        self.graph.node(
            node_id, "class", node.name, **position,
            syntax_kind="ClassDef",
            bases=[compact(self.source.excerpt(base)) for base in node.bases],
            decorators=decorator_texts(self.source, node),
            owner_id=owner_id,
            owner_function_id=function_id,
            declaration_only=self.is_stub,
            visibility="private" if node.name.startswith("_") else "public",
        )
        self.declarations_by_node[node] = node_id
        self.class_bases[node_id] = [compact(self.source.excerpt(base)) for base in node.bases]
        self.class_members.setdefault(node_id, {})
        self._declare(owner_id, owner_kind, node_id)
        self._bind(
            node.name, node_id, owner_id if owner_kind == "class" else None, function_id,
        )
        if owner_kind == "class" and owner_id is not None:
            self.class_members.setdefault(owner_id, {})[node.name] = node_id
        self._body(node.body, owner_id=node_id, owner_kind="class", function_id=function_id)

    def _binding(
        self, statement: ast.stmt, owner_id: Optional[str], owner_kind: str,
        function_id: Optional[str],
    ) -> None:
        targets: List[Tuple[ast.AST, Optional[ast.AST]]] = []
        if isinstance(statement, ast.Assign):
            targets = [(target, statement.value) for target in statement.targets]
        elif isinstance(statement, ast.AnnAssign):
            targets = [(statement.target, statement.value)]
        elif isinstance(statement, ast.AugAssign):
            targets = [(statement.target, statement.value)]
        for target, value in targets:
            for name_node in _bound_names(target):
                position = self.source.position(name_node)
                node_id = stable_id(
                    "variable", self.source.display, position["start_offset"],
                    position["end_offset"], name_node.id,
                )
                self.graph.node(
                    node_id, "variable", name_node.id, **position,
                    syntax_kind=type(statement).__name__,
                    annotation=annotation_text(
                        self.source, getattr(statement, "annotation", None)
                    ),
                    initializer=compact(self.source.excerpt(value)) if value is not None else None,
                    scope_kind=owner_kind,
                    owner_id=owner_id,
                    owner_function_id=function_id,
                )
                self.graph.edge(
                    "DECLARES_VALUE", owner_id or self.file_id, node_id,
                )
                self._bind(name_node.id, node_id, owner_id if owner_kind == "class" else None, function_id)
                if owner_kind == "class" and owner_id is not None:
                    self.class_members.setdefault(owner_id, {}).setdefault(
                        name_node.id, node_id,
                    )


def _bound_names(target: ast.AST) -> List[ast.Name]:
    """Every plain ``Name`` an assignment target binds, unpacking included."""
    if isinstance(target, ast.Name):
        return [target]
    if isinstance(target, (ast.Tuple, ast.List)):
        found: List[ast.Name] = []
        for element in target.elts:
            found.extend(_bound_names(element))
        return found
    if isinstance(target, ast.Starred):
        return _bound_names(target.value)
    return []  # Attribute / Subscript targets are property writes, not declarations


def _contains_yield(node: ast.AST) -> bool:
    """True when a def is a generator: a yield in its own body, not a nested def's."""
    for statement in node.body:
        for child in ast.walk(statement):
            if isinstance(child, (ast.Yield, ast.YieldFrom)):
                return True
            if isinstance(child, (*FUNCTION_NODES, ast.ClassDef)) and child is not statement:
                break
    return False
