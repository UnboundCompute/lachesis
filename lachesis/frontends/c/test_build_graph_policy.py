from .build_graph import clang_jobs


def test_clang_jobs_adapts_medium_and_large_trees(monkeypatch):
    monkeypatch.delenv("LACHESIS_C_JOBS", raising=False)
    assert clang_jobs(130) == 2
    assert clang_jobs(790) == 1


def test_clang_jobs_environment_override_wins(monkeypatch):
    monkeypatch.setenv("LACHESIS_C_JOBS", "3")
    assert clang_jobs(790) == 3
