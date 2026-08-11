"""Every declaration form the frontend must classify, in one file."""

import asyncio
from typing import TYPE_CHECKING

MODULE_CONSTANT = 7
FIRST, SECOND = 1, 2
ANNOTATED: int = 3
ACCUMULATOR = 0
ACCUMULATOR += 1

PAIR = (lambda a: a, lambda b: b)


def full_parameter_matrix(positional, /, standard, defaulted=1, *rest, keyword, keyword_defaulted=2, **extra):
    return positional, standard, defaulted, rest, keyword, keyword_defaulted, extra


def annotated(value: int, label: str = "x") -> str:
    return f"{label}{value}"


def counter(limit):
    total = 0
    while total < limit:
        yield total
        total += 1


def outer(seed):
    def inner(step):
        return seed + step

    return inner


async def fetch_all(sources):
    results = []
    for source in sources:
        results.append(await source.read())
    await asyncio.sleep(0)
    return results


class Shapes:
    kind = "shapes"
    labelled: str = "default"

    def method(self, value):
        return value

    async def async_method(self, value):
        return value

    @staticmethod
    def static_method(value):
        return value

    @classmethod
    def class_method(cls, value):
        return cls, value

    @property
    def computed(self):
        return self.kind

    class Nested:
        def deep(self):
            return 1


if TYPE_CHECKING:
    def conditionally_declared(value):
        """A def under a compound statement is still an ordinary declaration.

        Nothing between it and the module opens a scope, so it is a module-level
        binding like any other and a walk that reads only the top level of each
        body misses it entirely.
        """
        return value


try:
    from json import dumps as serialize
except ImportError:  # pragma: no cover  the stdlib is always there
    def serialize(value):
        return str(value)


def calls_a_conditional_declaration(value):
    return conditionally_declared(value)
