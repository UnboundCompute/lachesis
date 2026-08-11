"""PEP 420 namespace layout: no __init__.py anywhere on this path.

Its import root is therefore its own directory, so its primary dotted name is
just ``leaf``; ``inner.leaf`` and ``namespace.inner.leaf`` are namespace-style
aliases, which the module index accepts only when they are unambiguous.
"""

LEAF_MARKER = "leaf"


def identify():
    return LEAF_MARKER
