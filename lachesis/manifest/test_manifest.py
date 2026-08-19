"""Tests for the ``lachesis.toml`` loader (P1): parsing, defaults, strictness,
discovery.  Pure data — no graph involved."""
from __future__ import annotations

import textwrap

import pytest

from lachesis.manifest import (
    ManifestError,
    Ownership,
    discover_manifest,
    load_manifest,
    load_or_discover,
    parse_manifest,
)
from lachesis.manifest.loader import _duration_seconds

FULL = textwrap.dedent(
    """
    [project]
    name = "curl"
    language = "c"

    [project.source]
    roots = ["lib", "src"]
    exclude = ["tests", "**/vendor/**"]

    [project.build]
    config = ["USE_OPENSSL", "ENABLE_IPV6"]
    include = ["include", "lib"]
    defines = { CURL_DISABLE_FTP = 0 }

    [project.memory]
    alloc = ["curl_malloc", "Curl_saferealloc"]
    free = ["Curl_safefree"]

    [project.surface]
    entrypoints = ["curl_easy_perform"]
    [[project.surface.untrusted]]
    fn = "Curl_read"
    at = "return"
    [[project.surface.untrusted]]
    fn = "curl_easy_setopt"
    at = "arg2"

    [project.trust]
    sanitizers = ["Curl_urldecode"]

    [project.functions.Curl_close]
    frees = ["arg0.data"]
    returns = "borrowed"

    [project.functions.Curl_dup]
    returns = "owned"

    [project.alias]
    noalias = [["Curl_easy.state", "Curl_easy.set"]]

    [project.dispatch]
    "Curl_handler.disconnect" = "ossl_disconnect"

    [project.typedefs]
    Curl_easy = "SessionHandle"

    [analysis]
    engine = "object"
    graph = "~/.lachesis/graphs/curl.kuzu"
    disjunct_cap = 64
    timeout_per_fn = "30s"
    """
)


def _parse(text: str):
    import tomllib
    return parse_manifest(tomllib.loads(text), path="<test>")


def test_full_manifest_parses():
    m = _parse(FULL)
    p = m.project
    assert p.name == "curl" and p.language == "c"
    assert p.source.roots == ("lib", "src")
    assert p.source.exclude == ("tests", "**/vendor/**")
    assert p.build.config == ("USE_OPENSSL", "ENABLE_IPV6")
    assert p.build.defines == {"CURL_DISABLE_FTP": 0}
    assert p.memory.alloc == ("curl_malloc", "Curl_saferealloc")
    assert p.memory.free == ("Curl_safefree",)
    assert p.surface.entrypoints == ("curl_easy_perform",)
    assert [(u.fn, u.at) for u in p.surface.untrusted] == [
        ("Curl_read", "return"), ("curl_easy_setopt", "arg2")
    ]
    assert p.trust.sanitizers == ("Curl_urldecode",)
    by_name = {f.name: f for f in p.functions}
    assert by_name["Curl_close"].frees == ("arg0.data",)
    assert by_name["Curl_close"].returns is Ownership.BORROWED
    assert by_name["Curl_dup"].returns is Ownership.OWNED
    assert p.alias.noalias == (("Curl_easy.state", "Curl_easy.set"),)
    assert p.dispatch == {"Curl_handler.disconnect": "ossl_disconnect"}
    assert p.typedefs == {"Curl_easy": "SessionHandle"}
    assert m.analysis.engine == "object"
    assert m.analysis.disjunct_cap == 64
    assert m.analysis.timeout_per_fn == 30.0
    assert not m.is_empty


def test_empty_manifest_defaults():
    m = parse_manifest({}, path="<empty>")
    assert m.is_empty
    assert m.project.language == "c"
    assert m.project.memory.free == ()
    assert m.analysis.engine is None


def test_unknown_top_level_key_rejected():
    with pytest.raises(ManifestError, match="unknown key"):
        _parse("[projekt]\nname='x'\n")


def test_unknown_nested_key_rejected():
    # a typo that would silently drop a fact must fail loudly
    with pytest.raises(ManifestError, match=r"project\.memory.*unknown key"):
        _parse("[project.memory]\nfre = ['x']\n")


def test_wrong_type_rejected():
    with pytest.raises(ManifestError, match="list of strings"):
        _parse("[project.memory]\nfree = 'Curl_safefree'\n")


def test_bad_ownership_value_rejected():
    with pytest.raises(ManifestError, match="returns"):
        _parse("[project.functions.f]\nreturns = 'leased'\n")


def test_untrusted_requires_fn_and_at():
    with pytest.raises(ManifestError, match="requires both"):
        _parse("[[project.surface.untrusted]]\nfn = 'x'\n")


def test_duration_parsing():
    assert _duration_seconds(30, "x") == 30.0
    assert _duration_seconds("30s", "x") == 30.0
    assert _duration_seconds("5m", "x") == 300.0
    assert _duration_seconds("250ms", "x") == 0.25
    with pytest.raises(ManifestError):
        _duration_seconds(True, "x")


def test_discovery_walks_up(tmp_path):
    (tmp_path / "lachesis.toml").write_text("[project]\nname='root'\n")
    nested = tmp_path / "a" / "b"
    nested.mkdir(parents=True)
    found = discover_manifest(nested)
    assert found == tmp_path / "lachesis.toml"
    m = load_or_discover(nested)
    assert m is not None and m.project.name == "root"


def test_discovery_absent_returns_none(tmp_path):
    assert discover_manifest(tmp_path) is None
    assert load_or_discover(tmp_path) is None


def test_load_manifest_from_file(tmp_path):
    f = tmp_path / "lachesis.toml"
    f.write_text(FULL)
    m = load_manifest(f)
    assert m.project.name == "curl"
    assert m.path == str(f)


def test_invalid_toml_reports_path(tmp_path):
    f = tmp_path / "lachesis.toml"
    f.write_text("[project\nname = ")
    with pytest.raises(ManifestError, match="invalid TOML"):
        load_manifest(f)
