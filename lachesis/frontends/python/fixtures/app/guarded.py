"""Guard shapes: a family of peers where one member forgot to check.

`delete_mysql_record` and `delete_postgres_record` both validate and raise, so a
peer differential has a baseline to work from; `delete_sqlite_record` does the same
job with no check at all, which is the whole point of the fixture. The rest of the
file covers the guard edges that classification reads: short-circuit operands,
try/except/finally, and a loop with a branch inside it.
"""


class AccessError(Exception):
    """Raised when a caller is not allowed to touch a record."""


def delete_mysql_record(session, record_id):
    if not session.authenticated:
        raise AccessError("not authenticated")
    if record_id is None:
        raise AccessError("no record")
    return session.execute("delete", record_id)


def delete_postgres_record(session, record_id):
    if not session.authenticated or record_id is None:
        raise AccessError("not authenticated")
    return session.execute("delete", record_id)


def delete_sqlite_record(session, record_id):
    return session.execute("delete", record_id)


def read_config(loader, name):
    try:
        return loader.read(name)
    except KeyError:
        return None
    except OSError as failure:
        raise AccessError(str(failure))
    finally:
        loader.close()


def first_allowed(session, candidates):
    for candidate in candidates:
        if session.allows(candidate) and candidate.enabled:
            return candidate
    else:
        return None


def pick(session, primary, fallback):
    chosen = primary if session.allows(primary) else fallback
    return chosen or fallback


def enabled_names(records):
    return [record.name for record in records if record.enabled]


def classify(value):
    match value:
        case 0:
            return "zero"
        case int() as number if number > 0:
            return "positive"
        case _:
            return "other"


def drain(source, limit):
    total = 0
    while total < limit:
        item = source.next()
        if item is None:
            break
        total += 1
        continue
    return total
