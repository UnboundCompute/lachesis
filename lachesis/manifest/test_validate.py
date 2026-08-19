"""Tests for manifest graph-validation (P2). Uses a stub store exposing only
``resolve(name)`` — the sole surface :func:`validate_manifest` depends on."""
from __future__ import annotations

from lachesis.manifest import parse_manifest
from lachesis.manifest.validate import Status, validate_manifest


class FakeStore:
    """A store whose resolve() returns canned entries by exact name."""

    def __init__(self, entries: dict[str, list[dict]]):
        self._entries = entries

    def resolve(self, name: str) -> list[dict]:
        # include a fuzzy near-miss to prove _exact() filters on name equality
        out = list(self._entries.get(name, []))
        out.append({"name": name + "_similar", "kind": "function"})
        return out


def _fn(name, file="lib/x.c", line=10, decl=False):
    return {"name": name, "kind": "function", "file": file, "line": line,
            "declaration_only": decl, "node_id": f"id::{name}"}


def _parse(text):
    import tomllib
    return parse_manifest(tomllib.loads(text))


def test_validated_external_and_warning_buckets():
    store = FakeStore({
        "Curl_safefree": [_fn("Curl_safefree")],           # defined -> validated
        "talloc_free": [_fn("talloc_free", decl=True)],     # decl-only -> external
        # "typo_free" absent                                 -> warning (not found)
        "some_global": [{"name": "some_global", "kind": "variable"}],  # wrong kind
    })
    m = _parse(
        """
        [project.memory]
        free = ["Curl_safefree", "talloc_free", "typo_free", "some_global"]
        """
    )
    report = validate_manifest(m, store)
    by_sym = {c.symbol: c.status for c in report.checks}
    assert by_sym["Curl_safefree"] is Status.VALIDATED
    assert by_sym["talloc_free"] is Status.EXTERNAL
    assert by_sym["typo_free"] is Status.WARNING
    assert by_sym["some_global"] is Status.WARNING
    assert not report.ok                       # warnings present
    assert len(report.validated) == 1
    assert len(report.external) == 1
    assert len(report.warnings) == 2


def test_clean_manifest_is_ok():
    store = FakeStore({"curl_easy_perform": [_fn("curl_easy_perform")]})
    m = _parse('[project.surface]\nentrypoints = ["curl_easy_perform"]\n')
    report = validate_manifest(m, store)
    assert report.ok and len(report.validated) == 1


def test_typedef_expects_type_kind():
    store = FakeStore({
        "SessionHandle": [{"name": "SessionHandle", "kind": "struct",
                           "declaration_only": False, "file": "h.h", "line": 3}],
        "NotAType": [_fn("NotAType")],   # a function, not a type -> warning
    })
    m = _parse(
        """
        [project.typedefs]
        Curl_easy = "SessionHandle"
        Bad = "NotAType"
        """
    )
    report = validate_manifest(m, store)
    by_sym = {c.symbol: c.status for c in report.checks}
    assert by_sym["SessionHandle"] is Status.VALIDATED
    assert by_sym["NotAType"] is Status.WARNING


def test_dispatch_handler_checked_as_function():
    store = FakeStore({"ossl_disconnect": [_fn("ossl_disconnect")]})
    m = _parse('[project.dispatch]\n"Curl_handler.disconnect" = "ossl_disconnect"\n')
    report = validate_manifest(m, store)
    assert report.checks[0].status is Status.VALIDATED
    assert report.checks[0].symbol == "ossl_disconnect"


def test_empty_manifest_no_checks():
    report = validate_manifest(parse_manifest({}), FakeStore({}))
    assert report.checks == () and report.ok
    assert "no symbol facts" in report.format()


def test_format_lists_warnings_first():
    store = FakeStore({"ok_fn": [_fn("ok_fn")]})
    m = _parse('[project.memory]\nfree = ["ok_fn", "ghost"]\n')
    text = validate_manifest(m, store).format()
    assert text.index("ghost") < text.index("ok_fn")
