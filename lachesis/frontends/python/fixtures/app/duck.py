"""Nine classes with the same method name, to prove the candidate cap is real.

Below the cap, "it could be any of these" is a navigation aid. Above it, the
answer buries the question, so no edge is emitted and the count is recorded on
the call node instead.
"""


class Alpha:
    def dispatch(self, event):
        return ("alpha", event)


class Bravo:
    def dispatch(self, event):
        return ("bravo", event)


class Charlie:
    def dispatch(self, event):
        return ("charlie", event)


class Delta:
    def dispatch(self, event):
        return ("delta", event)


class Echo:
    def dispatch(self, event):
        return ("echo", event)


class Foxtrot:
    def dispatch(self, event):
        return ("foxtrot", event)


class Golf:
    def dispatch(self, event):
        return ("golf", event)


class Hotel:
    def dispatch(self, event):
        return ("hotel", event)


class India:
    def dispatch(self, event):
        return ("india", event)


class Pair:
    def settle(self, event):
        return event


class Peer:
    def settle(self, event):
        return event


def over_cap(handler, event):
    return handler.dispatch(event)


def under_cap(handler, event):
    return handler.settle(event)
