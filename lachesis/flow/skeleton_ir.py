#!/usr/bin/env python3
"""Universal skeleton IR -- a language-neutral, ordered event stream that any frontend can
emit and any shape pattern can match, across every language the CPG covers (C, Python, JS, TS,
and future frontends).

WHY THIS EXISTS
---------------
``flow/skeleton.py`` already stitches per-function summaries into an ordered, nesting-aware token
stream spliced at call seams. But its tokens are flat dicts with a ``t`` discriminator and a
C-flavoured lifecycle alphabet (alloc/use/free/escape). That stream is *implicitly* generic --
nothing enforces or exploits the generality. This module makes it explicit and load-bearing.

THE ONE IDEA THAT MAKES IT UNIVERSAL
------------------------------------
Every operation carries a language-neutral **role** (a small closed set), and shape patterns are
written over **roles**, not over concrete verbs. A use-after-free (C: ``free`` then deref), a
use-after-close (Python: ``close`` then read), and a use-after-dispose (C#: ``Dispose`` then use)
are all ONE universal pattern:  ``RELEASE(X) ... OBSERVE(X)`` with X co-referent and no
``ORIGIN``/``REINIT`` of X between. Only the **verb -> role** binding is per-language, and that
binding is data (see ``VERB_ROLES``; it externalises to the atropos per-language catalog).

So the structure has two layers:

  * UNIVERSAL (closed, here):   Category, Role, Proof, ObjRef, Guard, Event, Skeleton.
  * LANGUAGE-SPECIFIC (open, data):   the verb vocabulary and its verb->role / verb->family
    binding. Embedded here as a cross-language default; the real per-language tables live in
    atropos (``models/{c,python,javascript,typescript}``) and are merged in at load time.

WHAT IT IS A SUPERSET OF
------------------------
Every token ``flow/skeleton.py`` emits maps onto a Category losslessly (see ``from_flow_token``),
so the existing matcher keeps working through the adapter while new role-based patterns run over
the same stream.

Honest scope: this is a *typestate* skeleton. It represents any property expressible as ordered
role-events on identified objects along a path (use-after-release, double-release, leak,
use-before-init, ownership/escape). It deliberately does NOT represent value-range bugs (integer
overflow), pure logic/auth bugs (no verb to emit), or concurrency/interleaving (a single-path
stream cannot). Those live on other substrates.
"""
from __future__ import annotations

import argparse
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# =============================================================================
# UNIVERSAL VOCABULARY (closed sets -- the parts that never vary by language)
# =============================================================================

class Category(str, Enum):
    """The kind of event. The ONLY fixed structural axis; everything else is data."""
    SEAM = "seam"        # a call-boundary crossing (enter/exit), carries actual<->formal binding
    REGION = "region"    # a control region open/close -- the nesting structure + its guard
    BRANCH = "branch"    # non-structural control transfer: return/break/continue/goto/throw
    OP = "op"            # an operation on an object -- the verb/role-carrying event
    SINK = "sink"        # reaching a catalog sink (the spatial family surface)


class Role(str, Enum):
    """The language-neutral lifecycle role a concrete verb plays. Patterns match on these.

    This closed set is the heart of universality: a verb in any language binds to one or more
    roles (see VERB_ROLES), and a role sequence describes a bug shape once for all languages."""
    ORIGIN = "origin"          # brings an object into existence / a fresh live state
    DERIVE = "derive"          # forms an alias/handle of an existing object (copy, &x, field load)
    OBSERVE = "observe"        # reads/uses the object's memory or state (deref, read, use-as-arg)
    MUTATE = "mutate"          # writes the object's state (store, field write)
    RELEASE = "release"        # relinquishes the object (free, close, unlock, dispose)
    INVALIDATE = "invalidate"  # ends the current identity/generation (free, realloc-old, move-out)
    TRANSFER = "transfer"      # ownership/escape crosses a boundary (escape, return-of, store-global)
    REINIT = "reinit"          # rebinds the name to a FRESH object (reassign, realloc-new)


class Proof(str, Enum):
    """What a guard establishes about an object. Obligations are stated in these terms, so a
    guard discharges an obligation only if it establishes the MATCHING proof. A bare presence
    test (`if (p)`) establishes NONNULL(p) -- it says nothing about LIVE(p). That distinction
    is what stops a misleading null-guard from masking a use-after-release."""
    NONNULL = "nonnull"
    LIVE = "live"
    BOUNDED = "bounded"
    OWNED = "owned"
    INITIALIZED = "initialized"
    TYPED = "typed"


# =============================================================================
# OBJECT IDENTITY -- the co-reference key that makes temporal matching possible
# =============================================================================

@dataclass(frozen=True)
class ObjRef:
    """A canonical, seam-stable object identity. Two events act on the same object iff their
    ObjRefs canonicalise equal (after a call seam maps the actual root to the callee formal).

    * base       -- allocation-site id, or a parameter/decl root ("decl:b", "param:0").
    * path       -- access-path selectors from the base, e.g. ("*", "data") for `b->data`.
    * generation -- realloc/reassign generation. A fresh generation is a DIFFERENT object, so a
                    deref of gen N after a free of gen N is a UAF, while a deref of gen N+1 (after
                    realloc rebased the pointer) is not. This is what dissolves the
                    realloc-invalidates-interior-pointer family into the same model.
    """
    base: str
    path: tuple = ()
    generation: int = 0

    def child(self, selector: str) -> "ObjRef":
        return ObjRef(self.base, self.path + (selector,), self.generation)

    def aged(self) -> "ObjRef":
        return ObjRef(self.base, self.path, self.generation + 1)

    def key(self) -> tuple:
        return (self.base, tuple(self.path), self.generation)

    def render(self) -> str:
        sel = "".join(s if s == "*" else f".{s}" for s in self.path)
        gen = f"#{self.generation}" if self.generation else ""
        return f"{self.base}{sel}{gen}"


# =============================================================================
# GUARD-AS-PROOF -- what a dominating condition establishes, not merely that it exists
# =============================================================================

@dataclass
class Guard:
    cond: str                                   # the surface condition text (canonicalised)
    establishes: tuple = ()                     # tuple[(Proof, str)] -- proof + the obj/var it covers

    def proves(self, proof: Proof, obj_render: str) -> bool:
        return any(p == proof and o == obj_render for (p, o) in self.establishes)


# =============================================================================
# THE EVENT -- one flat, serialisable record with a Category discriminator.
# Superset of flow/skeleton.py's token dicts; grouped by category below.
# =============================================================================

@dataclass
class Event:
    category: Category
    depth: int = 0                              # call-seam / region nesting level

    # -- SEAM --
    seam: Optional[str] = None                  # "enter" | "exit"
    fn: Optional[str] = None
    binding: dict = field(default_factory=dict) # actual-root -> formal name (identity across seam)

    # -- REGION --
    region: Optional[str] = None                # "open" | "close"
    control: Optional[str] = None               # if/else/for/while/switch/case/do/...
    guard: Optional[Guard] = None

    # -- BRANCH --
    transfer: Optional[str] = None              # return/break/continue/goto/throw

    # -- OP (verb/role-carrying) --
    verb: Optional[str] = None                  # concrete, per-language ("free","close","deref",...)
    roles: tuple = ()                           # tuple[Role] this verb plays (from VERB_ROLES)
    obj: Optional[ObjRef] = None                # the object acted on (co-reference key)

    # -- SINK --
    family: Optional[str] = None                # atropos sink family ("memory.copy", "injection.query")
    callee: Optional[str] = None
    arg: Optional[int] = None
    tainted: Optional[bool] = None
    bound: Optional[str] = None                 # "bounded" | "unbounded" | None

    # -- common site facts --
    line: Optional[int] = None
    node: Optional[str] = None
    facts: dict = field(default_factory=dict)   # open, per-language extension bag

    # ---- ergonomic constructors ------------------------------------------------
    @classmethod
    def seam_enter(cls, fn, depth, binding=None):
        return cls(Category.SEAM, depth, seam="enter", fn=fn, binding=binding or {})

    @classmethod
    def seam_exit(cls, fn, depth):
        return cls(Category.SEAM, depth, seam="exit", fn=fn)

    @classmethod
    def region_open(cls, control, depth, guard=None):
        return cls(Category.REGION, depth, region="open", control=control, guard=guard)

    @classmethod
    def region_close(cls, control, depth):
        return cls(Category.REGION, depth, region="close", control=control)

    @classmethod
    def op(cls, verb, obj, depth, *, line=None, node=None, fn=None, facts=None):
        return cls(Category.OP, depth, verb=verb, roles=roles_for(verb), obj=obj,
                   line=line, node=node, fn=fn, facts=facts or {})

    @classmethod
    def sink(cls, family, callee, arg, obj, depth, *, tainted=None, bound=None, facts=None):
        return cls(Category.SINK, depth, family=family, callee=callee, arg=arg, obj=obj,
                   tainted=tainted, bound=bound, facts=facts or {})

    def has_role(self, role: Role) -> bool:
        return role in self.roles

    # ---- serialisation ---------------------------------------------------------
    def to_dict(self) -> dict:
        d = {"category": self.category.value, "depth": self.depth}
        if self.seam is not None:
            d.update(seam=self.seam, fn=self.fn)
            if self.binding:
                d["binding"] = self.binding
        if self.region is not None:
            d.update(region=self.region, control=self.control)
            if self.guard is not None:
                d["guard"] = {"cond": self.guard.cond,
                              "establishes": [[p.value, o] for (p, o) in self.guard.establishes]}
        if self.transfer is not None:
            d["transfer"] = self.transfer
        if self.verb is not None:
            d.update(verb=self.verb, roles=[r.value for r in self.roles])
        if self.family is not None:
            d.update(family=self.family, callee=self.callee, arg=self.arg,
                     tainted=self.tainted, bound=self.bound)
        if self.obj is not None:
            d["obj"] = self.obj.render()
            d["obj_key"] = [self.obj.base, list(self.obj.path), self.obj.generation]
        for k in ("line", "node", "fn"):
            v = getattr(self, k)
            if v is not None and k not in d:
                d[k] = v
        if self.facts:
            d["facts"] = self.facts
        return d


@dataclass
class Skeleton:
    """One ordered event stream: either a reach flow (value -> sink) or an object typestate."""
    kind: str                                   # "reach" | "typestate"
    entry: str
    lang: str = "c"
    events: list = field(default_factory=list)  # list[Event]
    obj: Optional[ObjRef] = None                # typestate: the tracked object
    sink: Optional[str] = None                  # reach: the sink id
    complete: bool = True
    is_source: bool = False

    def to_dict(self) -> dict:
        return {"kind": self.kind, "entry": self.entry, "lang": self.lang,
                "obj": self.obj.render() if self.obj else None, "sink": self.sink,
                "complete": self.complete, "is_source": self.is_source,
                "events": [e.to_dict() for e in self.events]}


# =============================================================================
# LANGUAGE-SPECIFIC LAYER (open data) -- verb -> role binding.
# Cross-language default; per-language tables override/extend from atropos.
# =============================================================================

# The default binding. Grouped by domain to show the universality: the manual-memory verbs and
# the resource-lifecycle verbs map onto the SAME roles, so one role-pattern covers both.
VERB_ROLES: dict[str, tuple] = {
    # --- manual memory (C, C++, Rust-unsafe) ---
    "alloc":     (Role.ORIGIN,),
    "malloc":    (Role.ORIGIN,),
    "calloc":    (Role.ORIGIN,),
    "new":       (Role.ORIGIN,),
    "realloc":   (Role.INVALIDATE, Role.REINIT),   # old generation dies; name rebinds to a new one
    "free":      (Role.RELEASE, Role.INVALIDATE),
    "delete":    (Role.RELEASE, Role.INVALIDATE),
    "deref":     (Role.OBSERVE,),
    "use":       (Role.OBSERVE,),
    "read":      (Role.OBSERVE,),
    "write":     (Role.MUTATE,),
    "store":     (Role.MUTATE,),
    "copy":      (Role.DERIVE,),
    "alias":     (Role.DERIVE,),
    "addressof": (Role.DERIVE,),
    "fieldload": (Role.DERIVE,),
    "escape":    (Role.TRANSFER,),
    "reassign":  (Role.REINIT,),
    # --- resource lifecycle (cross-language: files, sockets, locks, handles) ---
    "open":       (Role.ORIGIN,),
    "acquire":    (Role.ORIGIN,),
    "lock":       (Role.ORIGIN,),
    "connect":    (Role.ORIGIN,),
    "init":       (Role.ORIGIN,),
    "close":      (Role.RELEASE, Role.INVALIDATE),
    "release":    (Role.RELEASE, Role.INVALIDATE),
    "unlock":     (Role.RELEASE,),
    "disconnect": (Role.RELEASE, Role.INVALIDATE),
    "dispose":    (Role.RELEASE, Role.INVALIDATE),
    "shutdown":   (Role.RELEASE, Role.INVALIDATE),
}

# Per-language overrides/extensions. A frontend or the atropos catalog fills these; the value is
# merged over VERB_ROLES so a language can add verbs (e.g. Python "acquire"/"__exit__") or retarget
# an existing one without touching the universal core.
LANG_VERB_ROLES: dict[str, dict[str, tuple]] = {
    "python": {"__enter__": (Role.ORIGIN,), "__exit__": (Role.RELEASE, Role.INVALIDATE)},
    "javascript": {},
    "typescript": {},
    "c": {},
}


def roles_for(verb: Optional[str], lang: str = "c") -> tuple:
    """The role(s) a concrete verb plays, in the given language. Unknown verbs get no role -- they
    still render, they just do not participate in role patterns (honest: an unclassified verb is a
    catalog gap, not a silent drop)."""
    if verb is None:
        return ()
    lang_tbl = LANG_VERB_ROLES.get(lang, {})
    return lang_tbl.get(verb) or VERB_ROLES.get(verb) or ()


# =============================================================================
# UNIVERSAL PATTERNS -- bug shapes stated over roles, matched in ANY language.
# Data, not code: a pattern is a role sequence + co-reference + exclusion window.
# =============================================================================

# ``seq``       : ordered roles that must appear on one path, on the SAME object (co-reference).
# ``forbid``    : roles that, if they occur on that object BETWEEN two matched steps, kill the match
#                 (e.g. a REINIT/ORIGIN between two RELEASEs means the second frees a fresh object).
# ``guard_gap`` : (Proof) the obligation the final step needs; a dominating guard that establishes
#                 this proof discharges the finding. A guard that proves only NONNULL does NOT.
UNIVERSAL_PATTERNS = [
    {"name": "use-after-release", "seq": [Role.RELEASE, Role.OBSERVE],
     "forbid": [Role.REINIT, Role.ORIGIN], "guard_gap": Proof.LIVE},
    {"name": "mutate-after-release", "seq": [Role.RELEASE, Role.MUTATE],
     "forbid": [Role.REINIT, Role.ORIGIN], "guard_gap": Proof.LIVE},
    {"name": "double-release", "seq": [Role.RELEASE, Role.RELEASE],
     "forbid": [Role.REINIT, Role.ORIGIN], "guard_gap": Proof.LIVE},
    {"name": "use-after-transfer", "seq": [Role.TRANSFER, Role.OBSERVE],
     "forbid": [Role.REINIT, Role.ORIGIN], "guard_gap": Proof.OWNED},
    {"name": "leak", "seq": [Role.ORIGIN], "require_absent_after": [Role.RELEASE, Role.TRANSFER],
     "guard_gap": None},
]


def match_universal(skel: Skeleton, patterns=UNIVERSAL_PATTERNS):
    """Walk one skeleton's event stream and yield role-pattern hits. Language-agnostic: it reads
    ``roles`` and ``obj`` only, never a concrete verb or a language name.

    This is a straight-line reference matcher over the already-ordered, already-stitched stream:
    per object, track the last matched step index and the roles seen since, honouring ``forbid``
    windows and discharging on a guard that proves the ``guard_gap`` obligation. Path/branch
    joins are represented by the stream order the frontend emitted (a may-stream); a
    production matcher would consume the CFG regions explicitly."""
    hits = []
    # index the op/sink events (the ones with obj + roles)
    steps = [e for e in skel.events if e.obj is not None and (e.roles or e.category == Category.SINK)]
    # active guards keyed by (proof, obj_render), harvested from enclosing REGION opens
    live_guards: list[Guard] = [e.guard for e in skel.events
                                if e.category == Category.REGION and e.region == "open" and e.guard]

    def discharged(gap: Optional[Proof], obj: ObjRef) -> bool:
        if gap is None:
            return False
        return any(g.proves(gap, obj.render()) for g in live_guards)

    for pat in patterns:
        seq = pat.get("seq", [])
        forbid = set(pat.get("forbid", []))
        by_obj: dict[tuple, list] = {}
        for e in steps:
            by_obj.setdefault(e.obj.key(), []).append(e)
        for okey, evs in by_obj.items():
            if pat["name"] == "leak":
                origins = [e for e in evs if e.has_role(Role.ORIGIN)]
                after = set()
                for e in evs:
                    for r in e.roles:
                        after.add(r)
                if origins and not (set(pat["require_absent_after"]) & after):
                    hits.append({"pattern": "leak", "obj": origins[0].obj.render(),
                                 "at": origins[0].line, "steps": [origins[0].line]})
                continue
            i = 0                                   # next role in seq to satisfy
            anchor = None
            forbidden_since = False
            matched_lines = []
            for e in evs:
                if i > 0 and (forbid & set(e.roles)):
                    forbidden_since = True
                if e.has_role(seq[i]):
                    if i == 0:
                        anchor = e
                        matched_lines = [e.line]
                        i = 1
                        forbidden_since = False
                    elif not forbidden_since:
                        matched_lines.append(e.line)
                        i += 1
                        if i == len(seq):
                            obj = anchor.obj
                            if not discharged(pat.get("guard_gap"), obj):
                                hits.append({"pattern": pat["name"], "obj": obj.render(),
                                             "at": e.line, "steps": matched_lines})
                            # reset to catch further occurrences on the same object
                            i = 0
                            anchor = None
    return hits


# =============================================================================
# ADAPTER -- lift flow/skeleton.py's token dicts into the universal IR (lossless).
# =============================================================================

def _obj_from_var(var: Optional[str], fn: Optional[str]) -> Optional[ObjRef]:
    """Best-effort ObjRef from a flow-skeleton token's ``var`` field. The legacy stream keys
    lifecycle by variable name within a function; we root the identity at that name. (A richer
    ObjRef -- allocation-site + access path + generation -- is what a native emitter should
    produce; this adapter preserves at least name-level co-reference within a stitched flow.)"""
    if var is None:
        return None
    base = f"{fn}:{var}" if fn else var
    return ObjRef(base=base)


# legacy lifecycle token 't' -> concrete verb (so roles_for can classify it)
_LEGACY_VERB = {"alloc": "alloc", "use": "use", "free": "free", "escape": "escape",
                "realloc": "realloc", "deref": "deref", "reassign": "reassign"}


def from_flow_token(tok: dict, lang: str = "c") -> Optional[Event]:
    """Map one flow/skeleton.py token dict to a universal Event. Returns None only for an
    unrecognised token kind (forward-compatible: unknown kinds are skipped, not crashed)."""
    t = tok.get("t")
    depth = tok.get("depth", 0)
    if t == "enter":
        return Event.seam_enter(tok.get("fn"), depth)
    if t == "exit":
        return Event.seam_exit(tok.get("fn"), depth)
    if t == "guard":
        # A legacy guard carries cond + vars but not its proof content. We classify it minimally:
        # a bare identifier test establishes NONNULL of each named var (the conservative reading
        # that a name-only guard does NOT prove liveness -- the misleading-guard fix).
        cond = tok.get("cond", "")
        establishes = tuple((Proof.NONNULL, v) for v in tok.get("vars", []))
        return Event.region_open(control="if", depth=depth, guard=Guard(cond=cond, establishes=establishes))
    if t == "sink":
        obj = _obj_from_var(tok.get("var"), tok.get("fn"))
        ev = Event.sink(tok.get("family"), tok.get("callee"), tok.get("arg"), obj, depth,
                        tainted=tok.get("tainted"), bound=tok.get("bound"))
        for k in ("control", "size_expr", "dst", "guarded", "truncated"):
            if tok.get(k) is not None:
                ev.facts[k] = tok[k]
        # a reaching sink is an OBSERVE of its argument object, for role patterns
        if obj is not None:
            ev.roles = (Role.OBSERVE,)
        return ev
    if t in _LEGACY_VERB:
        obj = _obj_from_var(tok.get("var"), tok.get("fn"))
        return Event.op(_LEGACY_VERB[t], obj, depth, line=tok.get("line"),
                        node=tok.get("node"), fn=tok.get("fn"))
    return None


def from_flow_skeleton(skel: dict, lang: str = "c") -> Skeleton:
    """Lift a whole flow/skeleton.py skeleton dict into the universal Skeleton."""
    events = [e for e in (from_flow_token(t, lang) for t in skel.get("tokens", [])) if e]
    out = Skeleton(kind=skel.get("kind", "reach"), entry=skel.get("entry", "?"), lang=lang,
                   events=events, sink=skel.get("sink"),
                   complete=skel.get("complete", True), is_source=skel.get("is_source", False))
    if skel.get("kind") == "typestate":
        out.obj = _obj_from_var(skel.get("var"), skel.get("entry"))
    return out


# =============================================================================
# RENDERER -- human-readable view of a universal skeleton.
# =============================================================================

def render(skel: Skeleton) -> str:
    if skel.kind == "reach":
        head = (f"[reach] {skel.entry} -> {skel.sink}  "
                f"{'COMPLETE' if skel.complete else 'TRUNCATED'}{'  src' if skel.is_source else ''}")
    else:
        head = f"[typestate] {skel.entry}::{skel.obj.render() if skel.obj else '?'}" \
               f"{'  src' if skel.is_source else ''}"
    lines = [head]
    for e in skel.events:
        pad = "  " * (e.depth + 1)
        if e.category == Category.SEAM:
            lines.append(f"{pad}{e.seam} {e.fn}")
        elif e.category == Category.REGION:
            if e.region == "open":
                g = ""
                if e.guard and e.guard.establishes:
                    proofs = ", ".join(f"{p.value}({o})" for (p, o) in e.guard.establishes)
                    g = f"  proves[{proofs}]"
                lines.append(f"{pad}{e.control} {{{'  ' + e.guard.cond if e.guard else ''}{g}")
            else:
                lines.append(f"{pad}}}")
        elif e.category == Category.BRANCH:
            lines.append(f"{pad}{e.transfer}")
        elif e.category == Category.OP:
            roles = "/".join(r.value for r in e.roles) or "?"
            ln = f"@{e.line}" if e.line is not None else ""
            lines.append(f"{pad}{e.verb}[{roles}] {e.obj.render() if e.obj else '?'}{ln}")
        elif e.category == Category.SINK:
            tt = " tainted" if e.tainted else ""
            b = f" bound={e.bound}" if e.bound else ""
            lines.append(f"{pad}sink {e.family} {e.callee}#{e.arg} "
                         f"{e.obj.render() if e.obj else '?'}{tt}{b}")
    return "\n".join(lines)


# =============================================================================
# CLI -- lift an existing rendered-skeleton JSON dump into the universal IR and
# run the universal role-patterns over it.
# =============================================================================

def main():
    ap = argparse.ArgumentParser(description="lift flow skeletons into the universal IR + match")
    ap.add_argument("--skeletons", required=True, help="JSON produced by `python -m lachesis.flow.skeleton --out`")
    ap.add_argument("--lang", default="c")
    ap.add_argument("--emit", default=None, help="write the universal-IR JSON here")
    args = ap.parse_args()

    raw = json.load(open(args.skeletons))
    skels = [from_flow_skeleton(s, args.lang) for s in raw]

    if args.emit:
        with open(args.emit, "w") as fh:
            json.dump([s.to_dict() for s in skels], fh, indent=2)

    total = 0
    for s in skels:
        hits = match_universal(s)
        if hits:
            print(render(s))
            for h in hits:
                print(f"    >> {h['pattern']}  obj={h['obj']}  steps={h['steps']}")
            print()
            total += len(hits)
    print(f"universal-IR: {len(skels)} skeleton(s), {total} role-pattern hit(s)")


if __name__ == "__main__":
    main()
