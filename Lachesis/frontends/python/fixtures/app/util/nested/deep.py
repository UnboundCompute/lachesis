"""Relative imports at level 2 and level 3, and one that names nothing real."""

from ... import PACKAGE_NAME
from ..text import normalize
from ..text import missing_symbol


def describe():
    return normalize(PACKAGE_NAME)
