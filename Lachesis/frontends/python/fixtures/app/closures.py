"""Binding classification and closure capture, the cases symtable decides."""

COUNTER = 0


def make_counter(step):
    total = 0

    def advance():
        nonlocal total
        total += step
        return total

    return advance


def bump():
    global COUNTER
    COUNTER += 1
    return COUNTER


def deferred(prefix):
    def outer():
        def inner():
            return prefix
        return inner
    return outer


def scaled(factor, values):
    return [value * factor for value in values]


def shadowing(value):
    class Holder:
        # A class body is not a closure scope for its own methods, so `value`
        # reaches `read` from `shadowing` directly and never through Holder.
        label = value

        def read(self):
            return value

    return Holder
