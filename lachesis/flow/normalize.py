#!/usr/bin/env python3
"""Form normalizer -- canonicalize the projected IR against the Atropos form oracle.

This runs at PROJECTION time, over the already-built graph: it rewrites names in the compact
IR the pass reasons over, and never rebuilds, reloads, or mutates the graph store. The .kuzu on
disk and the in-memory graph are untouched -- a graph node still carries its surface callee
(``__builtin___memcpy_chk``); only the IR the summariser / skeleton / matcher see is canonical
(``memcpy``). So normalization changes what we MATCH over, not the graph we built.

Purely DATA-DRIVEN, by design -- the transforms come entirely from
``atropos/profiles/<lang>/normalization.json``. Extending normalization is a data edit in
Atropos, never a code change here, because this module discovers the transforms by CONVENTION
instead of hard-coding section names:

  * Any profile section whose key ends in ``_aliases`` is a callee-rewrite map
    ``{surface_name -> canonical_name}``. ``call_aliases`` (fortified ``_chk`` libc builtins ->
    their base sink) is the one shipping today; drop in a ``wrapper_aliases`` or ``macro_aliases``
    section tomorrow and it is merged automatically, with zero edits to this file.
  * Documentation fields (the conventional ``_note``) are skipped by a maintenance-free rule:
    a real callee name is a single token with no whitespace, a prose note is not. We do NOT skip
    on a leading underscore, because the fortified builtins (``__builtin___memcpy_chk``) are
    themselves underscore-prefixed -- that is exactly the surface name we must rewrite.
  * Alias chains are followed transitively (A->B->C collapses to C), with a cycle guard.

The ``opaque`` ledger (declared blind spots -- inline asm, varargs, ...) is loaded and exposed
for coverage accounting; it is not a rewrite. The ``lowered`` map (e.g. ternary -> branch-join)
is a PARSE-time desugaring the graph builder owns, so it has no effect at this layer and is
intentionally ignored here.

Beyond callee-name canonicalization, this is also where object-lifetime ROLE normalization lives
(``is_alloc`` / ``is_dealloc``): kmalloc/kzalloc/... all read as "allocates", free/kfree/kvfree/...
all read as "frees", so the typestate skeleton speaks one lifecycle vocabulary the matcher can key
on. Those name sets are DATA too -- ``atropos/detection/lifecycle-roles.json`` -- so a library
update never touches engine code. Nothing here is hard-coded.
"""
from . import atropos

_ALIAS_SUFFIX = "_aliases"


def _is_symbol(s):
    """True for a single-token callee name (no whitespace) -- the maintenance-free way to tell
    a real alias entry from a prose ``_note`` field, whichever leading characters it uses."""
    return isinstance(s, str) and bool(s) and not any(ch.isspace() for ch in s)


class Normalizer:
    """Canonicalizes IR names from one language's form profile. Cheap; build once per lang."""

    def __init__(self, lang="c", *, extra_alloc=(), extra_dealloc=()):
        self.lang = lang
        prof = atropos.normalization_profile(lang) or {}
        # Merge EVERY '*_aliases' section into one callee-rewrite table (convention, not
        # a hard-coded list) so new alias sections apply with no code change.
        self.callee_rewrites = {}
        self.alias_sections = []
        for section, body in prof.items():
            if not section.endswith(_ALIAS_SUFFIX) or not isinstance(body, dict):
                continue
            self.alias_sections.append(section)
            for surface, canon in body.items():
                if not isinstance(canon, str) or not _is_symbol(surface) or not _is_symbol(canon):
                    continue                       # skip _note docs / non-string / prose values
                self.callee_rewrites[surface] = canon
        # Declared blind spots -- exposed for coverage, never applied as a rewrite.
        self.opaque = dict(prof.get("opaque") or {})

        # --- object-lifetime roles, DATA-DRIVEN from the Atropos lifecycle catalog ---------
        # No allocator/free name list is hard-coded in the engine: a library update (a new
        # kernel allocator, a new free) is an edit in atropos/detection/lifecycle-roles.json,
        # so the reader emits the alloc/dealloc events the typestate skeleton needs with zero
        # code change. Sized allocators are NOT re-listed there -- they are derived here from
        # the sink catalog (any sink whose family is an `alloc_kinds` kind, e.g. `alloc-size`),
        # so the alloc models stay the single source of truth. The catalog's `alloc` list adds
        # only the size-LESS allocators (strdup-family), which never appear as sized sinks.
        lc = atropos.detection("lifecycle-roles")
        alloc_kinds = set(lc.get("alloc_kinds") or [])
        alloc_extra = set((lc.get("alloc") or {}).get(lang) or [])
        self.dealloc_names = set((lc.get("dealloc") or {}).get(lang) or [])
        cat = atropos.sink_catalog(lang)
        self.alloc_names = {m for m, c in cat.items()
                            if c.get("family") in alloc_kinds} | alloc_extra
        # Per-target manifest facts (project.memory.alloc/free) extend the catalog
        # vocabulary for this run only. A target's own allocator/free wrappers
        # (Curl_safefree, talloc_free, ...) are named here so the typestate skeleton
        # emits their lifecycle events -- the highest-recall lever the manifest adds.
        # They are canonical surface names, so they join the post-canonicalization sets
        # directly (canon of an unmapped name is itself).
        self.alloc_names |= {n for n in extra_alloc if _is_symbol(n)}
        self.dealloc_names |= {n for n in extra_dealloc if _is_symbol(n)}
        self.manifest_alloc = tuple(n for n in extra_alloc if _is_symbol(n))
        self.manifest_dealloc = tuple(n for n in extra_dealloc if _is_symbol(n))

    def is_alloc(self, callee):
        """True if `callee` allocates an owned object (a lifecycle alloc event source)."""
        return self.canon_callee(callee) in self.alloc_names

    def is_dealloc(self, callee):
        """True if `callee` frees its pointer argument (a lifecycle free event source)."""
        return self.canon_callee(callee) in self.dealloc_names

    def canon_callee(self, name):
        """The canonical callee/sink name for a surface name (identity if unmapped).

        Follows an alias chain transitively so a profile may point one alias at another; the
        `seen` guard makes a cyclic profile a no-op instead of a hang."""
        if not name:
            return name
        seen = set()
        while name in self.callee_rewrites and name not in seen:
            seen.add(name)
            name = self.callee_rewrites[name]
        return name

    def summary(self):
        """Small dict describing what this normalizer will apply -- for a coverage line."""
        return {"lang": self.lang, "alias_sections": sorted(self.alias_sections),
                "callee_rewrites": len(self.callee_rewrites), "opaque_kinds": len(self.opaque),
                "alloc_names": len(self.alloc_names), "dealloc_names": len(self.dealloc_names),
                "manifest_alloc": list(self.manifest_alloc),
                "manifest_dealloc": list(self.manifest_dealloc)}


_CACHE = {}


def normalizer(lang="c"):
    """Cached Normalizer for a language."""
    if lang not in _CACHE:
        _CACHE[lang] = Normalizer(lang)
    return _CACHE[lang]


def normalizer_with(lang="c", extra_alloc=(), extra_dealloc=()):
    """A Normalizer for *lang*, extended with per-target manifest alloc/free names.

    With no extras this is the shared cached instance. With extras it is a fresh,
    UNCACHED instance -- the global cache stays keyed on language only, so one run's
    manifest never leaks its custom vocabulary into another run's normalizer."""
    if not extra_alloc and not extra_dealloc:
        return normalizer(lang)
    return Normalizer(lang, extra_alloc=tuple(extra_alloc),
                      extra_dealloc=tuple(extra_dealloc))
