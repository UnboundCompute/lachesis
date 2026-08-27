"""Call-target resolution without a type checker.

Python has no compile-time answer to "what does this name call". What it does
have is a layout: a name bound exactly once at module level, an import clause
pointed at a file, a class whose bases are in the root set. Everything resolved
here is decided by that layout and nothing else, and every case that the layout
does not decide is recorded on the call node's ``resolution`` rather than guessed
at with an edge.

The distinction that matters, and that the C frontend already draws
(the native Clang frontend): ``confidence: "unresolved"`` describes an
edge emitted on a guess. A *missing* edge is not an unresolved edge, it is the
absence of a claim, and it is expressed through ``resolution``.
"""
from __future__ import annotations

from typing import Dict, List, NamedTuple, Optional, Sequence, Set, Tuple

from .scopes import ClassRegistry, resolve_base

# Builtins whose whole purpose is to reach a name the source does not spell out.
# A call edge from one of these would be fiction, so the call is located and
# marked instead. lachesis/core/overlays/dynamic_behavior.py consumes the marker.
DYNAMIC_CALLEES = frozenset({
    "getattr", "setattr", "delattr", "hasattr", "eval", "exec", "compile",
    "__import__", "globals", "locals", "vars",
})

# Above this many same-named methods, "it could be any of them" stops being a
# navigation aid and becomes noise that buries the real answer. The count is kept
# on the call node so the cap is visible rather than silent.
METHOD_CANDIDATE_CAP = 8


class Resolution(NamedTuple):
    """What a callee expression resolved to, and how much of it is decided."""
    targets: Tuple[str, ...]
    edge_kind: str          # "INVOKES" (one decided target) or "MAY_INVOKE"
    confidence: str
    resolution: str         # what goes on the call node, including the misses
    candidate_count: int = 0
    constructed_class: Optional[str] = None


NOTHING = Resolution((), "", "unresolved", "unresolved")
DYNAMIC = Resolution((), "", "unresolved", "dynamic")


class Resolver:
    """The whole-tree view a single file's call sites are resolved against."""

    def __init__(self, all_facts, registry: Optional[ClassRegistry] = None) -> None:
        self.all_facts = all_facts
        self.registry = registry if registry is not None else ClassRegistry(all_facts)
        self.declaration_file: Dict[str, object] = {}
        # Method name -> every in-tree member with that name. The duck-typing
        # fallback: with no receiver type, the name is all there is to go on.
        self.methods_named: Dict[str, List[str]] = {}
        for facts in all_facts.values():
            for declaration in facts.function_ids:
                self.declaration_file[declaration] = facts
            for members in facts.class_members.values():
                for name, member in members.items():
                    if member in self.registry.functions:
                        self.methods_named.setdefault(name, []).append(member)
        for name in self.methods_named:
            self.methods_named[name] = sorted(set(self.methods_named[name]))

    # -- names ---------------------------------------------------------------

    def module_bindings(self, facts, name: str) -> List[str]:
        return list(facts.module_bindings.get(name) or ())

    def follow(self, facts, binding: str) -> Optional[str]:
        """A module-level binding reduced to the declaration it ultimately names."""
        if binding in self.registry.functions or binding in self.registry.members:
            return binding
        target = facts.import_targets.get(binding)
        if target is not None:
            return target
        return None

    def resolve_name(self, facts, name: str) -> Resolution:
        """A bare ``name(...)`` at module scope, or one no local shadows."""
        bindings = self.module_bindings(facts, name)
        if not bindings:
            return NOTHING
        if len(bindings) == 1:
            target = self.follow(facts, bindings[0])
            if target is None:
                return NOTHING
            return self.callable_target(target, "exact", "exact")
        # The name is rebound. Any of the bindings could be live at the call, so
        # each callable one is a maybe and none of them is the answer.
        targets = tuple(
            target for target in (self.follow(facts, b) for b in bindings)
            if target is not None and target in self.registry.functions
        )
        if not targets:
            return NOTHING
        return Resolution(
            targets, "MAY_INVOKE", "conservative", "rebound", len(targets),
        )

    def resolve_attribute(self, facts, receiver: str, attribute: str) -> Resolution:
        """``receiver.attribute(...)`` where ``receiver`` is a module or a class."""
        bindings = self.module_bindings(facts, receiver)
        if len(bindings) != 1:
            return NOTHING
        binding = bindings[0]
        module_path = facts.import_modules.get(binding)
        if module_path is not None:
            target_facts = self.all_facts.get(module_path)
            if target_facts is None:
                return NOTHING
            return self.resolve_name(target_facts, attribute)
        owner = self.follow(facts, binding)
        if owner is not None and owner in self.registry.members:
            # ``Foo.bar()``: a static or class method reached through the class.
            member = self.lookup_method(owner, attribute)
            if member is not None:
                return self.callable_target(member, "exact", "exact")
        return NOTHING

    # -- classes -------------------------------------------------------------

    def lookup_method(self, class_id: str, name: str) -> Optional[str]:
        """``name`` on a class, own members first and then bases, left to right.

        Left-to-right depth first is a lexical approximation of the C3
        linearization, which is computed at run time from objects this frontend
        never builds. It is exact for a single-inheritance chain, and every caller
        of this method reports it at ``high`` rather than ``exact`` for that reason.
        """
        return self._lookup(class_id, name, set())

    def _lookup(self, class_id: str, name: str, seen: Set[str]) -> Optional[str]:
        if class_id in seen:
            return None
        seen.add(class_id)
        member = (self.registry.members.get(class_id) or {}).get(name)
        if member is not None and member in self.registry.functions:
            return member
        facts = self.registry.facts_of_class.get(class_id)
        if facts is None:
            return None
        for reference in self.registry.bases.get(class_id) or ():
            base = resolve_base(facts, reference, self.registry, self.all_facts)
            if base is None:
                continue
            found = self._lookup(base, name, seen)
            if found is not None:
                return found
        return None

    def callable_target(self, target: str, confidence: str, resolution: str) -> Resolution:
        """One decided target, split into the call and construct cases."""
        if target in self.registry.members:
            initializer = self.lookup_method(target, "__init__")
            return Resolution(
                (initializer,) if initializer else (), "INVOKES",
                confidence, resolution, constructed_class=target,
            )
        return Resolution((target,), "INVOKES", confidence, resolution)

    # -- duck typing ---------------------------------------------------------

    def duck_typed(self, attribute: str) -> Resolution:
        """``obj.m()`` with no idea what ``obj`` is: every in-tree ``m``, capped."""
        candidates = self.methods_named.get(attribute) or []
        if not candidates:
            return NOTHING
        if len(candidates) > METHOD_CANDIDATE_CAP:
            # Over the cap, "any of these forty" is not navigation. No edge is
            # emitted; the count stays on the node so the silence is explained.
            return Resolution((), "", "unresolved", "over-cap", len(candidates))
        return Resolution(
            tuple(candidates), "MAY_INVOKE", "conservative", "candidates",
            len(candidates),
        )
