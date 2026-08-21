"""Minimal seed source so the container can build a graph at startup and enter
the MCP serve loop. Real projects are attached at runtime with the build_graph
tool; this exists only so the server starts in an empty working directory."""


def seed(value):
    return value
