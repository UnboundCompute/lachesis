"""Classes, constructors, methods and overrides."""

DEFAULT_LIMIT = 50


class Repository:
    """Base repository. ``fetch`` is overridden below."""

    table = "records"

    def __init__(self, connection, limit=DEFAULT_LIMIT):
        self.connection = connection
        self.limit = limit
        self._cache = {}

    def fetch(self, key):
        return self._cache.get(key)

    def store(self, key, value):
        self._cache[key] = value
        return value

    def _evict(self):
        self._cache.clear()


class CachingRepository(Repository):
    """Override target: dispatch.py fans MAY_INVOKE out to both implementations."""

    table = "cached_records"

    def __init__(self, connection, limit=DEFAULT_LIMIT, ttl=60):
        Repository.__init__(self, connection, limit)
        self.ttl = ttl

    def fetch(self, key):
        found = self._cache.get(key)
        if found is None:
            found = self.connection.load(key)
            self.store(key, found)
        return found


def open_repository(connection, cached=False):
    if cached:
        return CachingRepository(connection)
    return Repository(connection)
