"""Drive the nav tools against a given store, and normalize what they return.

Two suites need this. ``frontends/checks.py`` compares an in-memory graph against the
same graph in Kùzu; ``nav/checks.py`` compares today's answers against a recorded
baseline. Both are the same operation -- run the real MCP dispatch over a store the test
chose, then compare results whose element order is not meaningful -- and both are only
trustworthy if they go through the dispatch the server goes through. Reimplementing that
per suite is how a harness ends up testing a path the server does not take.

This is a test harness that lives in the package rather than beside the tests because
``checks.py`` files are collected from several directories and Python has no other place
two of them can share code from.
"""
from __future__ import annotations

import json
import types
from typing import Iterable, Sequence, Tuple


#: One call: a label to file the result under, the tool name, and its arguments.
NavCall = Tuple[str, str, dict]


def run_nav(store, calls: Iterable[NavCall]) -> dict:
    """Answer every call against ``store``, through the server's own dispatch.

    The nav dispatch reads one module-global context, so stores are driven one at a
    time. The context mirrors the real ``_Ctx``: the security tools (guards, guards_top,
    call_roles, siblings) recompute from base facts rather than reading an overlay, so
    handing them a live ``GuardProfiles`` is what makes a store with an empty overlay
    tier answer identically to one without.
    """
    from . import mcp_server
    from .call_roles import CallRoles
    from .guards import GuardProfiles
    from .hubs import Hubs
    from .reachability import Reachability
    from .siblings import SiblingDiff

    guards = GuardProfiles(store)
    mcp_server._CTX = types.SimpleNamespace(
        store=store, reach=Reachability(store), hubs=Hubs(store.gl),
        guards=guards, roles=CallRoles(store, guards=guards),
        siblings=SiblingDiff(store),
    )
    mcp_server._PROFILE = "all"
    mcp_server._DEFAULT_FORMAT = "json"
    return {
        label: mcp_server.call_tool(tool, args, format="json")
        for label, tool, args in calls
    }


def norm(payload):
    """Parse a tool's JSON and sort every nested list.

    Nearly every list a nav tool returns is a set that happened to be enumerated in
    some order -- two backends, or two builds, may walk the same set differently. Sorting
    by the canonical JSON of each element makes those compare equal while any real
    difference in content still shows.
    """
    return _walk(json.loads(payload) if isinstance(payload, str) else payload)


def _walk(value):
    if isinstance(value, list):
        return sorted((_walk(item) for item in value), key=_order)
    if isinstance(value, dict):
        return {key: _walk(item) for key, item in value.items()}
    return value


def _order(value) -> str:
    return json.dumps(value, sort_keys=True, default=str)


def rows_of(normed) -> dict:
    """Every row-bearing field of a normalized tool answer, by field name.

    The nav tools do not agree on a name -- ``callers`` returns ``callers``, ``search``
    returns ``hits``, ``flow`` returns both ``nodes`` and ``edges`` -- so a comparison
    that hardcoded one name would silently compare nothing on the other sixteen tools,
    and one that took "the first list of dicts" would compare a different field
    depending on how the dict happened to be ordered. Taking all of them, keyed by name,
    is the only version of this that cannot quietly compare nothing.
    """
    if not isinstance(normed, dict):
        return {}
    return {
        key: value for key, value in normed.items()
        if isinstance(value, list) and value
        and all(isinstance(item, dict) for item in value)
    }


def scalars_of(normed) -> dict:
    """Everything in an answer that ``rows_of`` does not take.

    Rows are the obvious half of an answer and not the whole of it. ``read_body`` returns
    a body and no rows at all; ``guards`` returns a signal; ``search`` returns a total;
    ``flow`` and ``reaches`` return the counts and manifest that say what the walk did.
    A comparison built only on rows would record those and check none of them -- forty
    eight of this harness's three hundred calls would compare zero bytes, which is the
    exact shape of a harness that passes because it is not looking.
    """
    if not isinstance(normed, dict):
        return {"": normed}
    rows = rows_of(normed)
    return {key: value for key, value in normed.items() if key not in rows}
