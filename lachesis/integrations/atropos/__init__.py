"""Atropos integration: export the neutral callsite view Lachesis offers to the
Atropos taint-model binder. The adapter is pure Lachesis; binding lives in the
Atropos repo and is exercised by this package's tests."""
from .adapter import canonical_index

__all__ = ["canonical_index"]
