"""Relative imports at level 1 and level 2, plus a deferred import."""

from . import repository
from .util.text import normalize
from .util import text as text_module


def summarize(records):
    return [normalize(record) for record in records]


def load(connection):
    # A function-level import is a real dependency, but binds no module-level name.
    from .service import build_service

    return build_service(connection)


def separator():
    return text_module.SEPARATOR


def default_limit():
    return repository.DEFAULT_LIMIT
