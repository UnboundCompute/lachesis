"""Dataflow shapes: every binding form Python has, and one taint path end to end.

`build_query` is the anchor: a parameter reaches an f-string reaches a call
argument, which is how SQL injection is actually written in Python and the one
path the flow tools have to answer. The rest of the file is one function per
binding form, so a rule that stops working stops working visibly rather than
quietly costing a confidence level somewhere.
"""


class Row:
    """A tiny object so instantiation has something to allocate."""

    def __init__(self, name, size):
        self.name = name
        self.size = size
        self.tags = []

    def label(self):
        return self.name


def execute(cursor, statement):
    return cursor.run(statement)


def build_query(cursor, table, user_input):
    query = f"select * from {table} where name = '{user_input}'"
    return execute(cursor, query)


def augmented(counter, extra):
    counter += extra
    counter += 1
    return counter


def walrus(source):
    if (item := source.read()) is not None:
        return item
    return None


def unpacked(pair, rest):
    first, second = pair
    head, *tail = rest
    return first, second, head, tail


def allocations(names):
    rows = [Row(name, len(name)) for name in names]
    index = {row.name: row for row in rows}
    seen = {name for name in names}
    pair = (rows, index)
    return rows, index, seen, pair


def aliased(row):
    same = row
    also = same
    also.size = 0
    return also


def through_context(path, payload):
    with open(path) as handle:
        handle.write(payload)
        return handle


def looped(records, default):
    latest = default
    for record in records:
        latest = record
    else:
        pass
    return latest


def caught(loader, name):
    try:
        return loader.read(name)
    except OSError as failure:
        message = str(failure)
        return message
    finally:
        loader.close()


def closes_over(prefix):
    parts = []

    def append(suffix):
        parts.append(prefix + suffix)
        return parts

    return append


def property_paths(config):
    host = config.server.host
    port = config.server.port
    config.server.host = host
    return host, port
