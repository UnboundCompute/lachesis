from .build_graph import ALLOCATOR_NAMES, clang_jobs
from lachesis.flow import atropos


def test_clang_jobs_adapts_medium_and_large_trees(monkeypatch):
    monkeypatch.delenv("LACHESIS_C_JOBS", raising=False)
    assert clang_jobs(130) == 2
    assert clang_jobs(790) == 1


def test_clang_jobs_environment_override_wins(monkeypatch):
    monkeypatch.setenv("LACHESIS_C_JOBS", "3")
    assert clang_jobs(790) == 3


def test_allocator_nodes_follow_atropos_lifecycle_catalog():
    roles = atropos.detection("lifecycle-roles")
    kinds = set(roles.get("alloc_kinds") or ())
    expected = {
        name for name, entry in atropos.sink_catalog("c").items()
        if entry.get("family") in kinds
    } | set((roles.get("alloc") or {}).get("c") or ())
    assert ALLOCATOR_NAMES == expected
