"""The sink taxonomy: a broad-but-granular map the harness reasons over.

Atropos models ~30 distinct sink *kinds*. That is the right granularity for a
fact ("this call is a sql-injection sink at Argument[0]") but the wrong unit for
navigation: thirty opaque names are hard to bifurcate. This module bundles them
into a small tree so a harness can pick a broad DOMAIN, then drill to a FAMILY,
then to the exact catalog kind -- without losing any precision.

    domain            what the sink is / what must hold          (broad)
      family          the interpreter or resource in play        (mid)
        kind          the exact Atropos sink kind                (granular leaf)

A `constructor` id on a family names the enumerator that already turns those
kinds into candidates; ``None`` means "modeled in the catalog, not yet
enumerable". The map is the single source of truth for both: every catalog sink
kind belongs to exactly one family (a test pins this against the live catalog),
so adding a kind to Atropos without placing it here is a caught error, not drift.

This is a *presentation and routing* layer. It never merges or edits the catalog
facts -- each Atropos row stays one precise kind; the domain is just how we group
them for a human and a planner.
"""
from __future__ import annotations

# domain -> {title, meaning, obligation, primary, languages, families}
# family -> {kinds: (atropos sink kinds), obligation, constructor: id|None}
SINK_TAXONOMY: dict[str, dict] = {
    "memory": {
        "title": "Memory safety",
        "meaning": "an operation that takes a size or writes into a buffer",
        "obligation": "a length fits its destination and an allocation is bounded",
        "primary": True,
        "languages": ("c",),
        "families": {
            "copy": {
                "kinds": ("buffer-size", "buffer-write"),
                "obligation": "copy length must not exceed destination capacity",
                "constructor": "memory.copy.capacity",
            },
            "alloc": {
                "kinds": ("alloc-size",),
                "obligation": "allocation size must be bounded (no overflow, not attacker-huge)",
                "constructor": None,
            },
        },
    },
    "injection": {
        "title": "Injection",
        "meaning": "a string handed to an engine that executes or parses it",
        "obligation": "no untrusted input reaches the engine unescaped",
        "primary": True,
        "languages": ("c", "python", "javascript", "typescript"),
        "families": {
            "query": {
                "kinds": ("sql-injection", "nosql-injection",
                          "ldap-injection", "xpath-injection"),
                "obligation": "no untrusted text is concatenated into a query language",
                "constructor": None,
            },
            "exec": {
                "kinds": ("command-injection", "code-injection", "template-injection"),
                "obligation": "no untrusted text reaches a shell, eval, or template engine",
                "constructor": None,
            },
            "markup": {
                "kinds": ("xss",),
                "obligation": "no untrusted text reaches an HTML/JS context unescaped",
                "constructor": None,
            },
            "document": {
                "kinds": ("xxe",),
                "obligation": "an untrusted XML/document parser resolves no external entities",
                "constructor": None,
            },
            "format": {
                "kinds": ("format-string",),
                "obligation": "the format string is not attacker-controlled",
                "constructor": None,
            },
        },
    },
    "navigation": {
        "title": "Request forgery & redirection",
        "meaning": "a URL or destination the server fetches or sends the client to",
        "obligation": "the destination is not attacker-chosen",
        "primary": True,
        "languages": ("python", "javascript", "typescript"),
        "families": {
            "fetch": {
                "kinds": ("ssrf",),
                "obligation": "the server does not fetch an attacker-chosen URL",
                "constructor": None,
            },
            "redirect": {
                "kinds": ("open-redirect",),
                "obligation": "the app does not redirect to an attacker-chosen URL",
                "constructor": None,
            },
        },
    },
    "object-integrity": {
        "title": "Object integrity",
        "meaning": "untrusted bytes turned into live objects or merged into one",
        "obligation": "attacker input cannot become code or mutate shared state",
        "primary": True,
        "languages": ("python", "javascript", "typescript"),
        "families": {
            "deserialize": {
                "kinds": ("deserialization",),
                "obligation": "untrusted bytes are not deserialized into live objects",
                "constructor": None,
            },
            "prototype": {
                "kinds": ("prototype-pollution",),
                "obligation": "untrusted keys do not mutate object prototypes or shared state",
                "constructor": None,
            },
        },
    },
    "filesystem": {
        "title": "Filesystem",
        "meaning": "a file path opened or a file created",
        "obligation": "a resolved path stays within its intended directory",
        "primary": True,
        "languages": ("c", "python", "javascript", "typescript"),
        "families": {
            "path": {
                "kinds": ("path-traversal",),
                "obligation": "a resolved file path stays within the intended directory",
                "constructor": None,
            },
            "temp": {
                "kinds": ("insecure-temp-file",),
                "obligation": "a temp file is created unpredictably and exclusively",
                "constructor": None,
            },
        },
    },
    # Secondary domains: a bad setting at the call, not a taint flow. Kept in the
    # tree so nothing the catalog models is orphaned, flagged non-primary so a
    # harness can weight them behind the flow domains.
    "crypto-config": {
        "title": "Cryptography & transport config",
        "meaning": "a crypto or TLS API called with a weak setting",
        "obligation": "a strong primitive is used and transport verification is on",
        "primary": False,
        "languages": ("c", "python", "javascript", "typescript"),
        "families": {
            "primitive": {
                "kinds": ("weak-crypto",),
                "obligation": "a strong cryptographic primitive is used",
                "constructor": None,
            },
            "transport": {
                "kinds": ("insecure-tls",),
                "obligation": "TLS certificate verification is not disabled",
                "constructor": None,
            },
        },
    },
    "resource": {
        "title": "Resource exhaustion",
        "meaning": "an operation whose cost an input can blow up",
        "obligation": "input cannot drive the operation to catastrophic cost",
        "primary": False,
        "languages": ("python", "javascript", "typescript"),
        "families": {
            "regex": {
                "kinds": ("redos",),
                "obligation": "a regex cannot be driven to catastrophic backtracking",
                "constructor": None,
            },
        },
    },
}

# Not sinks -- kept as named lists so the harness knows they exist and are handled
# elsewhere: sources seed reachability, summaries are propagation edges.
SOURCE_KINDS: tuple[str, ...] = (
    "web-input", "network-input", "untrusted-input", "weak-random")
SUMMARY_KINDS: tuple[str, ...] = ("copy", "concat", "alias", "transform")


def all_sink_kinds() -> set[str]:
    """Every sink kind the taxonomy places, across all domains."""
    return {kind
            for domain in SINK_TAXONOMY.values()
            for family in domain["families"].values()
            for kind in family["kinds"]}


def locate(kind: str) -> tuple[str, str] | None:
    """The (domain, family) a sink kind belongs to, or None if unplaced."""
    for domain_id, domain in SINK_TAXONOMY.items():
        for family_id, family in domain["families"].items():
            if kind in family["kinds"]:
                return domain_id, family_id
    return None


def overview(registered_constructors: set[str] | frozenset[str] | None = None) -> list[dict]:
    """The taxonomy as a routing menu, newest coarse-to-fine.

    Each family is marked ``enumerable`` when its constructor id is among the
    registered enumerators (so the tool advertises what can be queried *now* vs
    what is modeled but planned); a domain is enumerable if any family is."""
    registered = set(registered_constructors or ())
    out: list[dict] = []
    for domain_id, domain in SINK_TAXONOMY.items():
        families = []
        for family_id, family in domain["families"].items():
            ctor = family["constructor"]
            families.append({
                "family": family_id,
                "kinds": list(family["kinds"]),
                "obligation": family["obligation"],
                "constructor": ctor,
                "enumerable": bool(ctor and ctor in registered),
            })
        out.append({
            "domain": domain_id,
            "title": domain["title"],
            "meaning": domain["meaning"],
            "obligation": domain["obligation"],
            "primary": domain["primary"],
            "languages": list(domain["languages"]),
            "enumerable": any(f["enumerable"] for f in families),
            "families": families,
        })
    return out
