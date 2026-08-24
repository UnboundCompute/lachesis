#!/usr/bin/env python3
"""Loader for the REAL Atropos catalog (the models/ tree of the public atropos repo)
into the lookup tables this pass's translator and matcher consume.

This pass stops using a hand-rolled SINK_CATALOG / field-of-parameter
seed and starts speaking the catalog. Atropos is pure declarative data keyed by
(method, access_path, role); we bucket it into four tables:

    sinks       method -> {size_arg, sink_args, family, cwe, kinds}
    sources     method -> {args, kind}        (where untrusted data enters)
    sanitizers  method -> {ins, out}          (value cleaned as it crosses)
    summaries   method -> [(src_arg, dst_arg)] (library flow, taint crosses the call)

The bound axis only has an arg to watch where a '-size' kind exists (C copy/alloc);
injection sinks (python os.system, C system) have no size arg -> taint axis only.

`access_path` is decoded to a small arg id:  Argument[n]->n, Argument[*]->'*',
ReturnValue->'ret', Receiver->'recv'.  A summary path 'Argument[1] -> Argument[0]'
becomes the pair (1, 0).

The syntactic normalization + dispatch-idiom layers (items #1/#2) are a SEPARATE,
sibling catalog under profiles/ -- loaded by the parser, not here -- exactly the
two-layer split we agreed on: this file is the semantic (sink) oracle; profiles/ is
the syntactic (form) oracle.
"""
import glob
import json
import os

# The Atropos catalog is a sibling repo of `arachne` (this package lives at
# arachne/lachesis/flow/). Honor $ATROPOS_ROOT; otherwise fall back to that sibling.
_DEFAULT_ATROPOS_ROOT = os.path.normpath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "atropos"))
ATROPOS_ROOT = os.environ.get("ATROPOS_ROOT", _DEFAULT_ATROPOS_ROOT)

_EXT_LANG = {
    ".c": "c", ".h": "c", ".cc": "c", ".cpp": "c", ".cxx": "c", ".hpp": "c",
    ".py": "python", ".js": "javascript", ".jsx": "javascript",
    ".mjs": "javascript", ".ts": "typescript", ".tsx": "typescript",
}


def lang_of(path):
    return _EXT_LANG.get(os.path.splitext(path)[1], "c")


def _decode_ap(ap):
    """One access-path endpoint -> arg id.  'Argument[2]'->2, 'Argument[*]'->'*',
    'ReturnValue'->'ret', 'Receiver'->'recv'."""
    ap = ap.strip()
    if ap == "ReturnValue":
        return "ret"
    if ap == "Receiver":
        return "recv"
    if ap.startswith("Argument["):
        inner = ap[len("Argument["):-1]
        return inner if inner == "*" else int(inner)
    return None


def _entries(lang):
    """Yield every catalog entry for a language, across all model files."""
    d = os.path.join(ATROPOS_ROOT, "models", lang)
    for path in sorted(glob.glob(os.path.join(d, "*.json"))):
        try:
            with open(path, encoding="utf-8") as stream:
                doc = json.load(stream)
        except (OSError, ValueError):
            continue
        for e in doc.get("entries", []):
            yield e


def _qualname(e):
    """The lookup key a call site is matched against. C symbols carry no package, so the
    bare `method` is the name (`copy_from_user`). Python library symbols carry a package,
    so the key is the dotted `package.method` the source actually writes (`os.system`);
    `builtins` is elided because those are called bare (`eval`, not `builtins.eval`)."""
    method = e.get("method")
    if method is None:
        return None
    pkg = e.get("package")
    if pkg and pkg != "builtins":
        return f"{pkg}.{method}"
    return method


_CACHE = {}


def load(lang):
    """Build (and cache) the four lookup tables for one language."""
    if lang in _CACHE:
        return _CACHE[lang]
    sinks, sources, sanitizers, summaries = {}, {}, {}, {}
    for e in _entries(lang):
        method = _qualname(e)
        role = e.get("role")
        ap = e.get("access_path", "")
        if method is None:
            continue
        if "->" in ap:                                    # a flow: src -> dst
            lhs, rhs = (x.strip() for x in ap.split("->", 1))
            src_id, dst_id = _decode_ap(lhs), _decode_ap(rhs)
            if role == "sanitizer":                       # value cleaned crossing the call
                san = sanitizers.setdefault(method, {"ins": [], "out": "ret"})
                if src_id not in san["ins"]:
                    san["ins"].append(src_id)
                san["out"] = dst_id
            else:                                          # taint passthrough summary
                pair = (src_id, dst_id)
                if pair not in summaries.setdefault(method, []):
                    summaries[method].append(pair)
            continue
        arg = _decode_ap(ap)
        if role == "sink":
            s = sinks.setdefault(method, {"size_arg": None, "sink_args": [],
                                          "family": e.get("kind"), "cwe": [], "kinds": {}})
            # Multiple catalog rows may describe the same sink argument (for
            # example a generic role plus its language-specific refinement).
            # Preserve the merged kind/CWE information, but expose each
            # argument position once to graph builders and other consumers.
            if arg not in s["sink_args"]:
                s["sink_args"].append(arg)
            s["kinds"][arg] = e.get("kind")
            for c in e.get("cwe", []):
                if c not in s["cwe"]:
                    s["cwe"].append(c)
            # the bound-axis arg is the one carrying a length/size obligation
            if e.get("kind") in ("buffer-size", "alloc-size") and isinstance(arg, int):
                s["size_arg"] = arg
                s["family"] = e.get("kind")
        elif role == "source":
            src = sources.setdefault(method, {"args": [], "kind": e.get("kind")})
            if arg not in src["args"]:
                src["args"].append(arg)
        elif role == "sanitizer":
            san = sanitizers.setdefault(method, {"ins": [], "out": "ret"})
            if arg not in san["ins"]:
                san["ins"].append(arg)
    _CACHE[lang] = (sinks, sources, sanitizers, summaries)
    return _CACHE[lang]


def _load_profile(lang, layer):
    """Read one syntactic-layer profile (profiles/<lang>/<layer>.json) from the catalog.
    Returns {} when absent -- an unprofiled language simply has an empty known-form set,
    so every form it uses lands in the 'unnormalized' ledger (honest, not a crash)."""
    path = os.path.join(ATROPOS_ROOT, "profiles", lang, f"{layer}.json")
    try:
        with open(path, encoding="utf-8") as stream:
            return json.load(stream)
    except (OSError, ValueError):
        return {}


_PROFILE_CACHE = {}


def normalization_profile(lang):
    key = (lang, "normalization")
    if key not in _PROFILE_CACHE:
        _PROFILE_CACHE[key] = _load_profile(lang, "normalization")
    return _PROFILE_CACHE[key]


def dispatch_profile(lang):
    key = (lang, "dispatch")
    if key not in _PROFILE_CACHE:
        _PROFILE_CACHE[key] = _load_profile(lang, "dispatch")
    return _PROFILE_CACHE[key]


_DETECTION_CACHE = {}


def detection(name):
    """Read one language-agnostic detection-layer catalog (detection/<name>.json).

    These sit beside the models/ sink tree but describe DATA the engine keys on that is not a
    per-node taint role -- e.g. `lifecycle-roles` (which callee allocates / frees an object).
    Returns {} when absent, so an unshipped catalog is an empty set, never a crash."""
    if name not in _DETECTION_CACHE:
        path = os.path.join(ATROPOS_ROOT, "detection", f"{name}.json")
        try:
            with open(path, encoding="utf-8") as stream:
                _DETECTION_CACHE[name] = json.load(stream)
        except (OSError, ValueError):
            _DETECTION_CACHE[name] = {}
    return _DETECTION_CACHE[name]


def pattern_catalog():
    """Return the language-neutral declarative flow-pattern library.

    Pattern definitions belong to Atropos alongside evaluator recipes and lifecycle
    roles.  A missing catalog remains a valid empty result for older installations;
    callers can then use their compatibility defaults.
    """
    return detection("flow-patterns").get("patterns", [])


def flow_pattern_id(matcher_pattern, family=None):
    """Resolve an engine finding to Atropos's public flow-pattern identifier.

    The engine keeps its compact evaluator/lifetime names for compatibility, while
    Atropos owns the user-facing taxonomy.  Family constraints prevent a generic
    evaluator such as ``relational`` from being mislabelled across sink classes.
    """
    for entry in pattern_catalog():
        matcher = entry.get("matcher") or {}
        if matcher.get("pattern") != matcher_pattern:
            continue
        families = matcher.get("families") or []
        if families and family not in families:
            continue
        return entry.get("id")
    return None


def flow_pattern_evaluator(matcher_pattern, family=None):
    """Resolve the executable evaluator class for a graph-pattern finding."""
    for entry in pattern_catalog():
        matcher = entry.get("matcher") or {}
        if matcher.get("pattern") != matcher_pattern:
            continue
        families = matcher.get("families") or []
        if families and family not in families:
            continue
        return entry.get("evaluator")
    return None


def evaluator_catalog():
    """Return the Atropos evaluator vocabulary and kind routing table."""
    return detection("evaluators")


def event_evaluator(event_kind):
    """Return the evaluator recipe for a semantic skeleton event.

    Sink ``kind_evaluator`` routing remains for single-node observations.  Lifecycle
    events are a separate axis: their meaning depends on ordering, identity, guards,
    call/return context, and allocation generation, so the temporal graph matcher owns
    the evaluation.  Atropos still owns the vocabulary and declares which events enter
    that evaluator.
    """
    catalog = evaluator_catalog()
    return (catalog.get("event_evaluator") or {}).get(event_kind)


def sink_catalog(lang):
    return load(lang)[0]


def source_catalog(lang):
    return load(lang)[1]


def sanitizer_catalog(lang):
    return load(lang)[2]


def summary_catalog(lang):
    return load(lang)[3]


if __name__ == "__main__":
    import sys
    lg = sys.argv[1] if len(sys.argv) > 1 else "c"
    sk, so, sa, su = load(lg)
    print(f"[atropos:{lg}]  sinks={len(sk)}  sources={len(so)}  "
          f"sanitizers={len(sa)}  summaries={len(su)}")
    print("  size-arg sinks:", sorted(m for m, v in sk.items() if v["size_arg"] is not None)[:12])
    print("  sources:", sorted(so)[:12])
