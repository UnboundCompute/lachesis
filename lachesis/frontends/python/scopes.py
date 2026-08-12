"""Scopes, bindings, closures and override resolution.

Two questions are answered here that ``ast`` alone cannot answer. Which scope owns
a name, and which names a nested function closes over. CPython ships the answer in
``symtable``, its own binding resolver: the same pass the compiler runs before it
emits bytecode, so ``is_free``, ``is_parameter``, ``is_declared_global`` and
``get_nonlocals`` are facts rather than heuristics.

The two trees are separate objects, so they are correlated by lockstep descent:
walk the AST's scope-introducing descendants in source order and take the first
matching block off the symtable child queue, removing only on a match so that a
miss cannot desync the rest of the queue.

**Correlation is advisory.** The scope tree comes from the AST's own nesting and
is always complete; symtable only supplies classification. When a block cannot be
matched the walk falls back to AST-derived bindings, stamps
``symtable_correlated: false``, and drops the affected facts to ``conservative``.
Nothing is dropped, only the confidence stops overclaiming.
"""
from __future__ import annotations

import ast
import symtable
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Set, Tuple

from .declarations import FUNCTION_NODES
from .emit import Graph, SourceFile, stable_id

# The block types symtable itself models. Anything else (a PEP 695 type-parameter
# block, an annotation block) is an artefact of the compiler's own bookkeeping and
# is descended through transparently, because it sits between a parent scope and
# the child scope this walk is looking for.
BLOCK_TYPES = frozenset({"module", "function", "class"})

COMPREHENSIONS = (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)
COMPREHENSION_NAMES = {
    ast.ListComp: "listcomp", ast.SetComp: "setcomp",
    ast.DictComp: "dictcomp", ast.GeneratorExp: "genexpr",
}
SCOPE_NODES = FUNCTION_NODES + (ast.Lambda, ast.ClassDef) + COMPREHENSIONS

# Scope kinds that bind names at run time. A class body executes in its own
# namespace but does not participate in closures, and module level is already
# fully described by the declaration pass, so neither emits `binding` nodes.
BINDING_SCOPE_KINDS = frozenset({"function", "lambda", "comprehension"})


def build_symbol_table(text: str, path: Path) -> Optional[symtable.SymbolTable]:
    """CPython's own binding table for a module, or None when it declines.

    ``ast.parse`` accepts a few programs the symbol pass rejects (a ``return`` at
    module level, some malformed ``global`` placements). That is a correlation gap,
    not a reason to lose the file.
    """
    try:
        return symtable.symtable(text, str(path), "exec")
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return None


def scope_span(source: SourceFile, node: ast.AST) -> Tuple[int, int]:
    """The character span of a scope, usable as a key across two parses.

    A module carries no position of its own, so it is keyed by the whole file.
    Everything else is keyed by its own span, which two parses of the same text
    agree on even though they share no AST objects.
    """
    if isinstance(node, ast.Module):
        return (0, len(source.text))
    position = source.position(node)
    return (position["start_offset"], position["end_offset"])


def scope_key(node: ast.AST) -> Tuple[str, str]:
    """The (block type, block name) symtable will have used for this AST node."""
    if isinstance(node, FUNCTION_NODES):
        return ("function", node.name)
    if isinstance(node, ast.Lambda):
        return ("function", "lambda")
    if isinstance(node, ast.ClassDef):
        return ("class", node.name)
    return ("function", COMPREHENSION_NAMES[type(node)])


def scope_kind(node: ast.AST) -> str:
    if isinstance(node, ast.Module):
        return "module"
    if isinstance(node, FUNCTION_NODES):
        return "function"
    if isinstance(node, ast.Lambda):
        return "lambda"
    if isinstance(node, ast.ClassDef):
        return "class"
    return "comprehension"


def _flatten(regions: Sequence[object]) -> List[ast.AST]:
    nodes: List[ast.AST] = []
    for region in regions:
        if region is None:
            continue
        if isinstance(region, list):
            nodes.extend(item for item in region if item is not None)
        else:
            nodes.append(region)  # type: ignore[arg-type]
    return nodes


def own_regions(node: ast.AST) -> List[ast.AST]:
    """The AST subtrees evaluated *inside* this scope's own block."""
    if isinstance(node, ast.Module):
        return _flatten([node.body])
    if isinstance(node, FUNCTION_NODES) or isinstance(node, ast.ClassDef):
        return _flatten([node.body])
    if isinstance(node, ast.Lambda):
        return _flatten([node.body])
    generators = node.generators
    parts: List[object] = [generators[0].target, generators[0].ifs]
    parts.extend(generators[1:])
    if isinstance(node, ast.DictComp):
        parts.extend([node.key, node.value])
    else:
        parts.append(node.elt)
    return _flatten(parts)


def outer_regions(node: ast.AST) -> List[ast.AST]:
    """The parts of a scope-introducing node evaluated in the *enclosing* scope.

    Defaults, decorators, annotations and base-class expressions all run before the
    new scope exists. symtable's synthetic ``.0`` parameter on a comprehension is
    exactly this split made visible: the outermost iterable is evaluated outside.
    """
    parts: List[object] = []
    if isinstance(node, FUNCTION_NODES):
        arguments = node.args
        parts.extend([
            arguments.defaults, arguments.kw_defaults, node.decorator_list,
            getattr(node, "type_params", []), node.returns,
        ])
        parts.extend(
            slot.annotation
            for slot in (
                list(getattr(arguments, "posonlyargs", []))
                + list(arguments.args) + list(arguments.kwonlyargs)
                + [arguments.vararg, arguments.kwarg]
            )
            if slot is not None
        )
    elif isinstance(node, ast.Lambda):
        parts.extend([node.args.defaults, node.args.kw_defaults])
    elif isinstance(node, ast.ClassDef):
        parts.extend([
            node.decorator_list, node.bases, [keyword.value for keyword in node.keywords],
            getattr(node, "type_params", []),
        ])
    elif isinstance(node, COMPREHENSIONS):
        parts.append(node.generators[0].iter)
    return _flatten(parts)


def _collect_scopes(regions: Sequence[ast.AST]) -> List[ast.AST]:
    """Scope-introducing nodes belonging to these regions, in compiler visit order."""
    found: List[ast.AST] = []
    for region in regions:
        _visit_for_scopes(region, found)
    return found


def _visit_for_scopes(node: ast.AST, found: List[ast.AST]) -> None:
    if isinstance(node, SCOPE_NODES):
        # symtable visits defaults, decorators and annotations before it creates
        # the block, so a lambda hiding in a default value is created first.
        found.extend(_collect_scopes(outer_regions(node)))
        found.append(node)
        return
    for child in ast.iter_child_nodes(node):
        _visit_for_scopes(child, found)


def _expand_blocks(blocks: Sequence[symtable.SymbolTable]) -> List[symtable.SymbolTable]:
    expanded: List[symtable.SymbolTable] = []
    for block in blocks:
        if block.get_type() in BLOCK_TYPES:
            expanded.append(block)
        else:
            expanded.extend(_expand_blocks(block.get_children()))
    return expanded


def _take(
    queue: List[symtable.SymbolTable], key: Tuple[str, str],
) -> Optional[symtable.SymbolTable]:
    """First block matching the key, removed from the queue; None on a miss.

    Scanning rather than popping the head is what makes a miss survivable: an
    unmatched key leaves the queue intact for the siblings that follow it.
    """
    for index, block in enumerate(queue):
        if (block.get_type(), block.get_name()) == key:
            return queue.pop(index)
    return None


def bound_occurrences(regions: Sequence[ast.AST]) -> Dict[str, ast.AST]:
    """Name -> first AST node that binds it in these regions.

    Used for two things: the position a `binding` node needs (it is source-derived,
    so it needs a real span), and the AST-only fallback when symtable could not be
    correlated.
    """
    found: Dict[str, ast.AST] = {}

    def record(name: Optional[str], node: ast.AST) -> None:
        if name and not name.startswith(".") and name not in found:
            found[name] = node

    def visit(node: ast.AST) -> None:
        if isinstance(node, SCOPE_NODES):
            if isinstance(node, (ast.ClassDef,) + FUNCTION_NODES):
                record(node.name, node)
            # The body belongs to the nested scope, but the decorators and
            # defaults still execute here and may bind through a walrus.
            for region in outer_regions(node):
                visit(region)
            return
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            record(node.id, node)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                record(alias.asname or alias.name.split(".")[0], node)
        elif isinstance(node, ast.ExceptHandler):
            record(node.name, node)
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            for name in node.names:
                record(name, node)
        elif isinstance(node, ast.MatchAs) or isinstance(node, ast.MatchStar):
            record(node.name, node)
        for child in ast.iter_child_nodes(node):
            visit(child)

    for region in regions:
        visit(region)
    return found


def binding_scope_of(symbol: symtable.Symbol) -> str:
    """symtable's own classification of a name, named the way this graph names it."""
    if symbol.is_parameter():
        return "parameter"
    if symbol.is_imported():
        return "imported"
    if symbol.is_declared_global():
        return "global"
    if getattr(symbol, "is_nonlocal", lambda: False)():
        return "nonlocal"
    if symbol.is_free():
        return "free"
    if symbol.is_global():
        return "global"
    if symbol.is_local():
        return "local"
    return "referenced"


def _binds_here(symbol: symtable.Symbol, classification: str) -> bool:
    """Whether this scope is where the name lives, rather than merely reads it.

    A plain reference to ``print`` or to a module-level constant classifies as
    global without being bound here, and emitting a node for it would put every
    builtin reference in the graph.
    """
    if classification in ("parameter", "imported", "nonlocal"):
        return True
    if classification == "local":
        return True
    if classification == "global":
        return symbol.is_declared_global() or symbol.is_assigned()
    return False


class Scope:
    """One lexical scope, whether or not symtable could be matched to it."""

    __slots__ = (
        "node", "kind", "block", "parent", "declaration_id", "owner_function_id",
        "bindings", "correlated",
    )

    def __init__(
        self, node: ast.AST, kind: str, block: Optional[symtable.SymbolTable],
        parent: Optional["Scope"], declaration_id: Optional[str],
        owner_function_id: Optional[str],
    ) -> None:
        self.node = node
        self.kind = kind
        self.block = block
        self.parent = parent
        # The graph id of the declaration this scope *is*, when it has one. A
        # lambda and a comprehension have no declaration node, on purpose: PEP 709
        # inlines comprehensions on 3.12+, so a `function` node for one would be a
        # lie on half the interpreters this frontend runs on.
        self.declaration_id = declaration_id
        self.owner_function_id = owner_function_id
        self.bindings: Dict[str, str] = {}
        self.correlated = block is not None


class ScopeWalk:
    """Builds the scope tree, emits `binding` nodes, and records closure capture."""

    def __init__(
        self, graph: Graph, source: SourceFile, file_id: str,
        declarations_by_node: Dict[ast.AST, str],
        parameters_by_function: Dict[str, Dict[str, str]],
    ) -> None:
        self.graph = graph
        self.source = source
        self.file_id = file_id
        self.declarations_by_node = declarations_by_node
        self.parameters_by_function = parameters_by_function
        self.scopes: List[Scope] = []
        self.scope_of_node: Dict[ast.AST, Scope] = {}
        # (start_offset, end_offset) of a scope -> {name: binding node id}. Keyed by
        # span rather than by AST node because the body pass re-parses the file and
        # its nodes are different objects; the span is the same in both trees.
        self.bindings_by_span: Dict[Tuple[int, int], Dict[str, str]] = {}
        self.correlated = True
        self.uncorrelated_scopes = 0
        self.binding_count = 0
        self.capture_count = 0

    # -- the walk ------------------------------------------------------------

    def run(self, module: ast.Module, table: Optional[symtable.SymbolTable]) -> None:
        if table is None:
            self.correlated = False
        root = self._descend(module, table, parent=None)
        self._emit_captures(root)
        self.graph.annotate(self.file_id, symtable_correlated=self.correlated)

    def _descend(
        self, node: ast.AST, block: Optional[symtable.SymbolTable],
        parent: Optional[Scope],
    ) -> Scope:
        kind = scope_kind(node)
        declaration_id = self.declarations_by_node.get(node)
        owner_function_id = declaration_id if kind == "function" else (
            parent.owner_function_id if parent is not None else None
        )
        scope = Scope(node, kind, block, parent, declaration_id, owner_function_id)
        self.scopes.append(scope)
        self.scope_of_node[node] = scope
        if block is None and parent is not None:
            self.uncorrelated_scopes += 1
            if declaration_id is not None:
                self.graph.annotate(declaration_id, symtable_correlated=False)

        regions = own_regions(node)
        if kind in BINDING_SCOPE_KINDS:
            self._emit_bindings(scope, regions)
            self.bindings_by_span[scope_span(self.source, node)] = scope.bindings

        queue = _expand_blocks(block.get_children()) if block is not None else []
        for child_node in _collect_scopes(regions):
            key = scope_key(child_node)
            child_block = _take(queue, key) if queue else None
            if child_block is None and block is not None:
                # PEP 709 inlines comprehensions into their enclosing scope on
                # 3.12+, so a missing comprehension block is the interpreter doing
                # its job, not a correlation failure.
                if not isinstance(child_node, COMPREHENSIONS):
                    self.correlated = False
            self._descend(child_node, child_block, scope)
        return scope

    # -- bindings ------------------------------------------------------------

    def _emit_bindings(self, scope: Scope, regions: Sequence[ast.AST]) -> None:
        occurrences = bound_occurrences(regions)
        parameters = self.parameters_by_function.get(scope.declaration_id or "", {})
        if scope.block is not None:
            entries = [
                (symbol.get_name(), binding_scope_of(symbol), symbol)
                for symbol in scope.block.get_symbols()
            ]
            entries = [
                (name, classification, symbol)
                for name, classification, symbol in entries
                if not name.startswith(".") and _binds_here(symbol, classification)
            ]
            confidence = "exact"
        else:
            # No block: fall back to what the AST alone shows is bound here, and
            # say so in the confidence rather than pretending to symtable's answer.
            entries = [(name, "local", None) for name in occurrences]
            confidence = "conservative"

        for name, classification, symbol in sorted(entries):
            if classification == "parameter" and name in parameters:
                # The declaration pass already emitted an addressable `parameter`
                # node for this name. Binding to it keeps one node per name.
                scope.bindings[name] = parameters[name]
                self.graph.annotate(parameters[name], binding_scope="parameter")
                continue
            anchor = occurrences.get(name, scope.node)
            position = self.source.position(anchor)
            node_id = stable_id(
                "binding", self.source.display, position["start_offset"],
                position["end_offset"], name, classification,
            )
            self.graph.node(
                node_id, "binding", name, **position,
                binding_scope=classification,
                scope_kind=scope.kind,
                is_parameter=classification == "parameter",
                is_assigned=bool(symbol.is_assigned()) if symbol is not None else True,
                symtable_correlated=scope.block is not None,
                owner_id=scope.declaration_id,
                owner_function_id=scope.owner_function_id,
                confidence=confidence,
                fact_origin="compiler",
            )
            self.graph.edge(
                "DECLARES_VALUE", scope.declaration_id or self.file_id, node_id,
                confidence=confidence,
            )
            scope.bindings[name] = node_id
            self.binding_count += 1

    # -- closures ------------------------------------------------------------

    def _emit_captures(self, root: Scope) -> None:
        """CAPTURES from a capturing function to the binding it closes over.

        symtable reports the free names of a block directly, which is the whole
        reason it is used here: a free name is one the compiler decided to reach
        through a cell, and no amount of AST reading reproduces that decision.
        """
        for scope in self.scopes:
            if scope.block is None or scope.kind not in BINDING_SCOPE_KINDS:
                continue
            source_id = scope.declaration_id or scope.owner_function_id
            if source_id is None:
                continue
            for name in sorted(scope.block.get_frees()):
                if name.startswith("."):
                    continue
                target_id = self._enclosing_binding(scope, name)
                if target_id is None or target_id == source_id:
                    continue
                self.graph.annotate(target_id, is_captured=True)
                self.graph.edge(
                    "CAPTURES", source_id, target_id, name=name,
                    capture_kind="closure",
                )
                self.capture_count += 1

    @staticmethod
    def _enclosing_binding(scope: Scope, name: str) -> Optional[str]:
        cursor = scope.parent
        while cursor is not None:
            # A class body does not create a closure: a method never sees the class
            # namespace as an enclosing scope, so it is skipped rather than searched.
            if cursor.kind in BINDING_SCOPE_KINDS and name in cursor.bindings:
                return cursor.bindings[name]
            cursor = cursor.parent
        return None


# -- overrides ---------------------------------------------------------------
#
# OVERRIDES is the highest-leverage edge a dynamically typed language can emit.
# lachesis/core/overlays/dispatch.py transitively closes it and fans MAY_INVOKE out
# to every implementation of a resolved target, so recording the lexical
# base-to-subclass relationship once buys the whole override fan-out without ever
# guessing at a receiver's run-time type.


class ClassRegistry:
    """Every in-tree class, keyed by graph id, with the maps needed to walk bases."""

    def __init__(self, all_facts) -> None:
        self.members: Dict[str, Dict[str, str]] = {}
        self.bases: Dict[str, List[Tuple[str, str]]] = {}
        self.facts_of_class: Dict[str, object] = {}
        self.functions: Set[str] = set()
        for facts in all_facts.values():
            self.members.update(facts.class_members)
            self.bases.update(facts.class_bases)
            self.functions.update(facts.function_ids)
            for class_id in facts.class_members:
                self.facts_of_class[class_id] = facts


def _module_binding(facts, name: str) -> Optional[str]:
    """The single graph id a module-level name binds, or None when it is rebound."""
    ids = facts.module_bindings.get(name) or []
    return ids[0] if len(ids) == 1 else None


def resolve_base(
    facts, reference: Tuple[str, str], registry: ClassRegistry, all_facts,
) -> Optional[str]:
    """A base-class reference resolved to the class node it names, or None.

    Only what the layout decides is followed: a name bound exactly once in the
    importing module, through an import whose target file is in the root set. A
    computed base (``Generic[T]``, a metaclass call) is never resolved, because
    deciding it would mean executing it.
    """
    form, text = reference
    if form == "name":
        binding = _module_binding(facts, text)
        return _class_from_binding(facts, binding, registry)
    if form != "dotted":
        return None
    head, _, rest = text.partition(".")
    binding = _module_binding(facts, head)
    if binding is None:
        return None
    current = facts
    path = current.import_modules.get(binding)
    while path is not None and "." in rest:
        next_facts = all_facts.get(path)
        if next_facts is None:
            return None
        component, _, rest = rest.partition(".")
        binding = _module_binding(next_facts, component)
        if binding is None:
            return None
        current = next_facts
        path = current.import_modules.get(binding)
    if path is None:
        return None
    target_facts = all_facts.get(path)
    if target_facts is None:
        return None
    return _class_from_binding(
        target_facts, _module_binding(target_facts, rest), registry,
    )


def _class_from_binding(
    facts, binding: Optional[str], registry: ClassRegistry,
) -> Optional[str]:
    if binding is None:
        return None
    if binding in registry.members:
        return binding
    # The name was bound by an import; follow it to the declaration it refers to.
    target = facts.import_targets.get(binding)
    if target is not None and target in registry.members:
        return target
    return None


def _lookup_member(
    class_id: str, name: str, registry: ClassRegistry, all_facts,
    seen: Set[str],
) -> Optional[Tuple[str, bool]]:
    """(member id, unambiguous) for `name` in this class's bases, depth first.

    Left-to-right depth first is a lexical approximation of the C3 linearization,
    which is computed at run time from objects this frontend never builds. It is
    exact for a single-inheritance chain and only that case is reported as exact.
    """
    if class_id in seen:
        return None
    seen.add(class_id)
    references = registry.bases.get(class_id) or []
    facts = registry.facts_of_class.get(class_id)
    unambiguous = len(references) == 1
    for reference in references:
        base_id = resolve_base(facts, reference, registry, all_facts) if facts else None
        if base_id is None:
            unambiguous = False
            continue
        member = (registry.members.get(base_id) or {}).get(name)
        if member is not None and member in registry.functions:
            return member, unambiguous
        deeper = _lookup_member(base_id, name, registry, all_facts, seen)
        if deeper is not None:
            return deeper[0], unambiguous and deeper[1]
    return None


def emit_overrides(graph: Graph, all_facts) -> int:
    """OVERRIDES from every method that redefines an inherited one to its base."""
    registry = ClassRegistry(all_facts)
    emitted = 0
    for class_id in sorted(registry.members):
        for name, member_id in sorted((registry.members.get(class_id) or {}).items()):
            if member_id not in registry.functions:
                continue
            found = _lookup_member(class_id, name, registry, all_facts, set())
            if found is None:
                continue
            base_member, unambiguous = found
            if base_member == member_id:
                continue
            graph.edge(
                "OVERRIDES", member_id, base_member, member_name=name,
                # Single inheritance through fully resolved bases is decided by
                # the layout. Anything else is a lexical guess at what the run-time
                # MRO will pick, which is high confidence and not exact.
                confidence="exact" if unambiguous else "high",
            )
            emitted += 1
    return emitted
