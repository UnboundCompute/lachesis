"""Call shapes whose target the layout does not decide.

Every call in this module is a row in the resolution table: what is decided is
edged, what is not is marked on the call node and left alone.
"""

from app.repository import Repository


def reflective(target, name, payload):
    # getattr names its callee with a string this frontend cannot evaluate.
    handler = getattr(target, name)
    return handler(payload)


def evaluated(expression, environment):
    return eval(expression, environment)


def executed(script):
    exec(script)


def duck(handle_holder, key):
    # No idea what handle_holder is. The method name is all there is to go on.
    return handle_holder.fetch(key)


class RetryingRepository(Repository):
    def fetch(self, key):
        # super() reaches the base implementation by name, which the layout knows.
        first = super().fetch(key)
        if first is None:
            return super().fetch(key)
        return first

    def refresh(self, key):
        # A call through the receiver resolves to the lexically nearest definition
        # on this class, which is the override and not the base.
        return self.fetch(key)


def pick(flag):
    return flag


def pick(flag):  # noqa: F811  the same name bound twice, on purpose
    return not flag


def rebound(flag):
    return pick(flag)
