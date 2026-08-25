#!/usr/bin/env python3
"""Deprecation shims for the old ``lachesis-*`` console scripts.

The reader now has one entrypoint -- ``lachesis`` with pass-mirroring subcommands -- but the
standalone ``lachesis-analyze``/``-query``/``-mcp``/``-plan``/``-candidates`` scripts still exist
in shells, aliases, and CI written before the redesign. Breaking them silently would be the exact
friction this work exists to remove, so each keeps working unchanged: the shim prints one stderr
line naming the new verb, then calls the very same ``main`` the old name always called. Behaviour
and flags are identical; only a hint is added.

The notice goes to stderr (never stdout) so it can never corrupt a captured document or the
``lachesis-mcp`` stdio protocol. ``lachesis-analyze`` maps to ``lachesis build`` -- it is pass 1,
the graph builder, NOT the new pass-3 ``lachesis analyze`` -- and its notice says so, so nobody
migrates the builder onto the leads verb by mistake.
"""
from __future__ import annotations

import sys


def _notice(old: str, new: str) -> None:
    print(f"lachesis: `{old}` is deprecated -- use `{new}` (same behaviour, one front door).",
          file=sys.stderr, flush=True)


def analyze() -> int:
    """Pass 1, the structural graph builder -- now ``lachesis build`` (not the pass-3 ``analyze``)."""
    _notice("lachesis-analyze", "lachesis build")
    from lachesis.cli.analyze import main
    return main()


def query() -> int:
    _notice("lachesis-query", "lachesis query")
    from lachesis.cli.query import main
    return main()


def mcp() -> int:
    _notice("lachesis-mcp", "lachesis mcp")
    from lachesis.nav.mcp_server import main
    return main()


def plan() -> int:
    _notice("lachesis-plan", "lachesis plan")
    from lachesis.planner.cli import main
    return main() or 0


def candidates() -> int:
    _notice("lachesis-candidates", "lachesis candidates")
    from lachesis.planner.candidate_cli import main
    return main() or 0
