"""Every declaration form the frontend must classify, in one file."""

import asyncio

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
