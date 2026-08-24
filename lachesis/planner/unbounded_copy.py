"""Enumerate every observable ``memory.copy.capacity`` obligation.

This module never decides whether the obligation is satisfied.  Atropos tells us
which exact values are copy destinations and sizes; this enumerator joins those
facts at their callsite, attaches neutral evidence, and orders the resulting work.
No constant, API name, nearby check, or unwitnessed flow removes a site.
"""
from __future__ import annotations

import hashlib
import re
from collections import defaultdict

from .capabilities import absent_optional_capabilities

CONSTRUCTOR_ID = "memory.copy.capacity"
DOMAIN = "memory"

_SIZEOF = re.compile(r"sizeof\s*\([^()]*\)")
_CALL = re.compile(r"[A-Za-z_]\w*\s*\(")
_NUM = re.compile(r"\b(?:0[xX][0-9a-fA-F]+|\d+)\b")
_IDENT = re.compile(r"[A-Za-z_]\w*")
# A string or char literal span. Its inner bytes are DATA, not C syntax: the
# identifiers, calls, and operators inside a format string ("cal-%s.bin", "a-b",
# "f(%d)") must not classify the argument. Only the expression AROUND the quotes
# says whether the arg is a constant literal, a variable, or a call. Quote-aware
# with backslash escapes. Size expressions never carry a literal, so stripping is
# a no-op there and only the string-valued families (format/path/query) change.
_STRLIT = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'')


def _strip_string_literals(text: str) -> str:
    return _STRLIT.sub("", text)

# A magnitude comparison: `<`, `<=`, `>`, `>=` -- but NOT a bit shift (`<<`, `>>`)
# and NOT an equality/nullness test (`==`, `!=`). A branch imposes a *size bound* on
# a variable only when it compares that variable's magnitude; a pure presence test
# (`if (p)`, `if (p != NULL)`, `if (a && b)`) names the variable but bounds nothing.
_REL = re.compile(r"<=|>=|(?<!<)<(?![<=])|(?<!>)>(?![>=])")


def _relation_named(head: str, patterns: dict) -> list:
    """Idents that participate in a magnitude RELATION in a condition, not merely
    appear by name.

    The branch head is split into its logical clauses (on ``&&``/``||``/``,``); an
    ident counts only inside a clause that also carries a magnitude operator. So
    ``if (len < cap && ready)`` yields ``len``/``cap`` (bounded) but ``ready`` and
    every ident of ``if (z && a && b)`` are rejected -- a nullness/presence test must
    not read as a size guard, or it silently suppresses a real bug. Undecidable
    guards (a helper call like ``if (fits(n)))``) carry no operator here and read as
    unguarded: the safe direction for a recall-oriented finder is not to suppress."""
    if not head:
        return []
    named = set()
    for clause in re.split(r"&&|\|\||,", head):
        if not _REL.search(clause):
            continue
        for ident, pattern in patterns.items():
            if pattern.search(clause):
                named.add(ident)
    return sorted(named)

_ARG_INDEX = re.compile(r"Argument\[(\d+)\]")
# A leaked value-node label: either a copied-through source comment (the file's
# leading copyright banner is a frequent offender) or a bare clang AST kind name
# emitted instead of folded source text. Neither is the real size spelling.
_AST_KIND = re.compile(r"^[A-Z][A-Za-z]*(Expr|Literal|Operator|Cast|Stmt|Decl)$")


# The controlling keyword of a CFG condition node, whose label is
# "condition:if (...) { ...body... }". We match size variables against the
# controlling expression only -- the parenthesised head -- not the body, so a
# statement that merely mentions the variable is not mistaken for a guard on it.
_CTRL_KEYWORD = re.compile(r"\b(if|while|for|switch)\b")
# Tokens that are C syntax or the sizeof operator, never a size *variable*.
_NON_VARIABLE = frozenset({
    "if", "for", "while", "switch", "sizeof", "return", "int", "unsigned",
    "const", "void", "char", "long", "short", "struct", "NULL"})


def condition_head(label: str | None) -> str | None:
    """The controlling expression of a CFG-condition label, body stripped.

    ``condition:if (a > b) { ...  }`` -> ``if (a > b)``. Balanced-paren scan, so a
    call inside the condition keeps its own parens. Recovery, not evaluation."""
    if not label:
        return None
    text = label[len("condition:"):] if label.startswith("condition:") else label
    kw = _CTRL_KEYWORD.search(text)
    if not kw:
        return text.strip()
    open_paren = text.find("(", kw.end())
    if open_paren < 0:
        return text[kw.start():].strip()
    depth = 0
    for j in range(open_paren, len(text)):
        if text[j] == "(":
            depth += 1
        elif text[j] == ")":
            depth -= 1
            if depth == 0:
                return text[kw.start():j + 1].strip()
    return text[kw.start():].strip()


def size_identifiers(expression: str | None) -> set[str]:
    """The identifiers a size expression names -- the variables a guard on this
    size would compare. Syntactic; ``sizeof`` and C keywords are not variables."""
    if not expression:
        return set()
    return {tok for tok in _IDENT.findall(expression) if tok not in _NON_VARIABLE}


# The branch-region edges the control-flow overlay emits, marking a conditionally
# executed sub-region of a function. A copy inside one of these runs only when the
# region's controlling branch is taken. Same set the GraphStore-based
# ``dominance.ConditionalRegions`` consumes -- kept in sync deliberately.
_REGION_EDGE_KINDS = frozenset({
    "TRUE_BRANCH", "FALSE_BRANCH", "LOOP_TRUE", "SWITCH_CASE",
    "EXCEPTION_BRANCH", "SHORT_CIRCUIT_RIGHT"})


def _node_span(node: dict | None) -> tuple[str, int, int] | None:
    """(file, start_offset, end_offset) of a node, or None when it has no span."""
    props = (node or {}).get("properties") or {}
    path = props.get("absolute_file") or props.get("file")
    start, end = props.get("start_offset"), props.get("end_offset")
    if not path or start is None or end is None:
        return None
    return path, start, end


def _span_within(inner: tuple[str, int, int], outer: tuple[str, int, int]) -> bool:
    """True when ``inner``'s byte range sits inside ``outer``'s, same file."""
    return inner[0] == outer[0] and outer[1] <= inner[1] and inner[2] <= outer[2]


class BranchRegions:
    """Dict-native, sound region containment for the candidate enumerators.

    ``dominance.ConditionalRegions`` answers the same shape of question but needs a
    ``GraphStore``; the enumerators hold only a stamped graph dict, so this reads
    the same substrate -- cfg-condition nodes and the branch-region edges the
    control-flow overlay emits (``TRUE_BRANCH`` and friends) -- straight from the
    dict. It answers ONE sound, observable question and never an ordering verdict:
    does a copy call site lie inside a conditional region whose controlling
    condition names a size variable?

    Containment is decidable from byte offsets: a region is the branch body's span,
    and a call is inside it exactly when the call's offsets are within the body's.
    It deliberately cannot decide the early-return / negated-guard case
    (``if (n > cap) return; copy(...)``), where the copy is dominated yet sits
    *outside* the branch body -- that needs path reasoning the graph dict does not
    carry, so such a copy reads as ``fall-through``, never as guarded. An honest
    ``fall-through`` (a lead worth a human's eyes) is the point; a guessed
    ``dominates`` would violate the rule that a wrong fact is worse than an absent
    one. This is an observation the AI reads, never a filter: it neither feeds the
    rank nor removes a candidate."""

    def __init__(self, graph: dict) -> None:
        by_id = {n["id"]: n for n in graph.get("nodes", ())}
        # condition-node-id -> [region body spans], from the branch-region edges.
        self._regions_of: dict[str, list[tuple[str, int, int]]] = defaultdict(list)
        self._has_substrate = False
        for edge in graph.get("edges", ()):
            if edge.get("kind") not in _REGION_EDGE_KINDS:
                continue
            self._has_substrate = True
            span = _node_span(by_id.get(edge.get("target")))
            if span is not None:
                self._regions_of[edge.get("source")].append(span)
        # function-id -> [(condition_node_id, controlling-expression head)].
        self._conditions_of: dict[str, list[tuple[str, str | None]]] = defaultdict(list)
        for node in graph.get("nodes", ()):
            if node.get("kind") != "cfg-condition":
                continue
            props = node.get("properties") or {}
            function_id = props.get("function_id")
            if function_id:
                self._conditions_of[function_id].append(
                    (node["id"], condition_head(node.get("label"))))

    @property
    def has_substrate(self) -> bool:
        """Whether the graph carries any branch-region edges at all. When it does
        not, containment is simply unavailable and every classification is
        ``not-computed`` -- an honest absence, not a negative finding."""
        return self._has_substrate

    def classify(self, function_id: str | None, idents: set[str],
                 callsite_span: tuple[str, int, int] | None) -> dict:
        """Where a copy call site sits relative to the size-testing branches of its
        function. A neutral observation -- never a verdict, never fed to the rank.

        - ``not-computed``  : the graph has no branch-region substrate.
        - ``none-observed`` : no branch in the function tests a size variable.
        - ``undecided``     : a size-testing branch exists but the call has no span.
        - ``guarded-region``: the copy lies inside a size-testing branch's region
                              (it runs only when that branch is taken).
        - ``fall-through``  : a size-testing branch exists but the copy is outside
                              its region (reached without entering it -- the
                              missing-guard shape, not proof of a bug)."""
        if not self._has_substrate:
            return {"status": "not-computed",
                    "reason": "the graph carries no branch-region edges; region "
                              "containment is unavailable"}
        patterns = {i: re.compile(r"\b" + re.escape(i) + r"\b") for i in idents}
        testing = []  # (head, named idents, [region spans])
        for cond_id, head in self._conditions_of.get(function_id or "", ()):
            named = _relation_named(head, patterns)
            if named:
                testing.append((head, named, self._regions_of.get(cond_id, ())))
        if not testing:
            return {"status": "none-observed",
                    "basis": "no branch in the enclosing function compares a size "
                             "variable's magnitude (a nullness/presence test is not "
                             "a size guard)"}
        if callsite_span is None:
            return {"status": "undecided",
                    "reason": "the copy call site carries no source span to place "
                              "against a region"}
        containing = [
            {"condition": head, "names": named}
            for head, named, spans in testing
            for span in spans if _span_within(callsite_span, span)]
        if containing:
            return {"status": "guarded-region",
                    "basis": "the copy call site lies inside a conditional region "
                             "whose controlling branch compares a size variable's "
                             "magnitude; the copy runs only when that branch is taken",
                    "regions": containing}
        return {"status": "fall-through",
                "basis": "a branch in this function compares a size variable's "
                         "magnitude, but the copy call site lies outside that "
                         "branch's region; the copy "
                         "is reached without entering it -- a missing-guard shape "
                         "worth reading, not proof of a bug",
                "branches": [{"condition": head, "names": named}
                             for head, named, _spans in testing]}


# The value-flow edge kind and the `reason` values that mark a *definition* -- an
# edge whose target is produced/written by its source. Walking the value-flow graph
# backward from a sink argument, a def-reason edge is where a variable was last
# given its value. Kept as the frontend spells them (see c_call_dataflow /
# build_graph field-write, assignment).
_FLOW_KIND = "VALUE_FLOWS_TO"
_DEF_REASONS = frozenset({
    "initializer", "assignment", "write", "field-write", "allocation",
    "out-parameter", "call-return"})
# The reasons a backward walk may traverse: a value merely *carried along* -- read
# out of a variable, passed through a value-preserving cast, taken as an operand or
# a call argument. This is an explicit WHITELIST, not "everything that is not a
# def": the same graph also carries cross-argument taint-summary edges the Atropos
# models stamp (e.g. memcpy's src->dst copy edge, `fact_origin='atropos-model'`,
# no reason), which are copy SEMANTICS, not a reaching definition. Walking one would
# make the destination falsely appear to be defined by the source. Any edge whose
# reason is neither a def nor a known pass-through is a boundary: the walk stops
# there and records nothing, because a wrong provenance fact is worse than a missing
# one. New frontend pass-through reasons must be added here deliberately.
_PASSTHROUGH_REASONS = frozenset({
    "read", "read-value", "value-preserving-expression", "arithmetic-operand",
    "call-argument", "field-read"})
# A node that is a *source* of value with no local definition: a parameter is
# supplied by the caller, an allocation/heap-object is freshly produced. Reaching
# one means the variable is externally derived -- a fact worth surfacing, not a def.
_ORIGIN_KINDS = frozenset({"parameter", "allocation", "heap-object"})


def _context_row(node: dict | None, reason: str | None = None) -> dict:
    """One neutral 'here is an operation' row: which node, what kind, where, and
    the reason the value-flow edge carried (a def reason, or None for an origin)."""
    props = (node or {}).get("properties") or {}
    return {
        "node_id": (node or {}).get("id"),
        "kind": (node or {}).get("kind"),
        "reason": reason,
        "file": props.get("absolute_file") or props.get("file"),
        "line": props.get("start_line"),
        "offset": props.get("start_offset"),
        "text": (node or {}).get("label") or props.get("name"),
    }


class VariableContext:
    """For every variable that feeds a sink argument, the last operation(s) that
    produced it -- its reaching definitions -- recovered by walking the value-flow
    graph *backward* from the argument value node.

    This answers the question a human asks by hand at every candidate: 'where was
    this size/destination last set, and was it clamped or checked on the way in?'
    A reverse walk from the argument stops at each def-reason edge (recording the
    source as a definition) or at an origin node (a parameter or allocation with no
    local writer). For a compound argument (``block_size - CRC``) the walk fans out
    to each variable's definitions, so 'all vars present in the sink' fall out of
    one traversal.

    It is a neutral FACT, never a verdict: it states where a value was written, not
    whether that write is safe, and it neither feeds the rank nor suppresses a
    candidate. It is available only when the graph carries value-flow edges (the
    enriched dataflow tier); on the bare core graph every argument is
    ``not-computed`` -- an honest absence, not a claim of no definition."""

    _MAX_DEPTH = 32
    _MAX_ROWS = 8

    def __init__(self, graph: dict) -> None:
        self._by_id = {n["id"]: n for n in graph.get("nodes", ())}
        # target-node-id -> [incoming value-flow edges], the reverse adjacency the
        # backward walk reads. Built once.
        self._incoming: dict[str, list[dict]] = defaultdict(list)
        self._has_substrate = False
        for edge in graph.get("edges", ()):
            if edge.get("kind") != _FLOW_KIND:
                continue
            self._has_substrate = True
            self._incoming[edge.get("target")].append(edge)

    @property
    def has_substrate(self) -> bool:
        """Whether the graph carries any value-flow edges. When it does not,
        reaching definitions are simply unavailable and every argument reads
        ``not-computed`` -- never mistaken for 'no definition exists'."""
        return self._has_substrate

    def _reason(self, edge: dict) -> str | None:
        return (edge.get("properties") or {}).get("reason")

    def _walk_back(self, value_id: str,
                   sink_span: tuple[str, int, int] | None
                   ) -> tuple[list[dict], list[dict], int]:
        """Reverse-BFS from one argument value node. Returns (definitions, origins,
        unreadable): the def-reason writes reached, the parameter/allocation origins
        where a path bottoms out with no local writer, and a count of reached
        definitions whose node carried only an AST-kind/comment label instead of
        source text. Bounded in depth and de-duplicated."""
        defs: dict[str, dict] = {}
        origins: dict[str, dict] = {}
        unreadable = 0
        seen: set[str] = set()
        stack: list[tuple[str, int]] = [(value_id, 0)]
        while stack:
            nid, depth = stack.pop()
            if nid in seen or depth > self._MAX_DEPTH:
                continue
            seen.add(nid)
            incoming = self._incoming.get(nid, ())
            writers = [e for e in incoming if self._reason(e) in _DEF_REASONS]
            if writers:
                # A def-reason edge is the last operation on this value: record its
                # source and stop -- do not walk past a definition into its own inputs.
                for edge in writers:
                    src = self._by_id.get(edge.get("source"))
                    if src is None or src.get("id") in defs:
                        continue
                    row = _context_row(src, self._reason(edge))
                    # A node whose only label is an AST kind (`ImplicitCastExpr`) or
                    # a leaked comment is not readable source. Counting it keeps the
                    # tally exhaustive without presenting noise as a definition, and
                    # without letting it crowd real defs out of the capped list.
                    if looks_like_leaked_label(row.get("text")):
                        unreadable += 1
                        defs.setdefault(src["id"], None)  # reserve id, drop from output
                    else:
                        defs[src["id"]] = row
                continue
            # Only follow known pass-through edges -- never an unrecognised or
            # taint-summary edge, which would fabricate provenance (see the reason
            # whitelist above). A node reached only by such boundary edges is a dead
            # end, not a definition.
            passthrough = [e for e in incoming
                           if self._reason(e) in _PASSTHROUGH_REASONS]
            if passthrough:
                for edge in passthrough:
                    stack.append((edge.get("source"), depth + 1))
                continue
            # No pass-through predecessor: a value source. Surface parameters and
            # allocations (externally derived / freshly produced); ignore bare
            # literals and operators, which are not variables.
            node = self._by_id.get(nid)
            if node is not None and node.get("kind") in _ORIGIN_KINDS and nid != value_id:
                origins[nid] = _context_row(node)
        readable_defs = [row for row in defs.values() if row is not None]
        return (self._finish(readable_defs, sink_span),
                list(origins.values())[:self._MAX_ROWS], unreadable)

    def _finish(self, rows: list[dict],
                sink_span: tuple[str, int, int] | None) -> list[dict]:
        """Order definitions by source position and flag the one nearest *before*
        the sink -- the most recent write, the one that actually governs the copy."""
        rows.sort(key=lambda r: (r.get("file") or "", r.get("offset") or 0))
        if sink_span is not None:
            sink_file, sink_start = sink_span[0], sink_span[1]
            preceding = [r for r in rows
                         if r.get("file") == sink_file
                         and (r.get("offset") or 0) <= sink_start]
            if preceding:
                nearest = max(preceding, key=lambda r: r.get("offset") or 0)
                nearest["nearest_to_sink"] = True
        return rows[:self._MAX_ROWS]

    def describe(self, arguments: list[tuple[str, str | None]],
                 sink_span: tuple[str, int, int] | None = None) -> dict:
        """The reaching-definition context for a sink's arguments. ``arguments`` is
        a list of (role, value_id) -- e.g. ``[("size", sz), ("destination", d)]``.
        A neutral evidence block: where each argument was last written, never a
        judgement about whether the write is adequate."""
        if not self._has_substrate:
            return {
                "status": "not-computed",
                "reason": "the graph carries no value-flow edges; reaching "
                          "definitions are unavailable",
                "needs_capability": "value-flow"}
        rows = []
        for role, value_id in arguments:
            if not value_id or value_id not in self._by_id:
                continue
            defs, origins, unreadable = self._walk_back(value_id, sink_span)
            argument = self._by_id[value_id].get("label") \
                or (self._by_id[value_id].get("properties") or {}).get("name")
            if looks_like_leaked_label(argument):
                argument = None  # an AST-kind label is not the argument's source text
            entry = {
                "role": role,
                "value_id": value_id,
                "argument": argument,
                "last_definitions": defs,
                "origins": origins}
            if unreadable:
                # Transparent, never silent: N reaching definitions exist but their
                # nodes carried no readable source label, so they are counted here
                # rather than shown as noise. A reader can widen via the graph.
                entry["unreadable_definition_count"] = unreadable
            rows.append(entry)
        return {"status": "computed" if rows else "none-observed",
                "basis": "reaching definitions recovered by walking value-flow edges "
                         "backward from each sink argument; the definition nearest "
                         "before the sink is flagged. Neutral: where a value was "
                         "written, not whether the write is safe.",
                "arguments": rows}


def looks_like_leaked_label(label: str | None) -> bool:
    """True when a value-node label is comment/AST-kind noise, not source text."""
    if not label:
        return False
    text = label.strip()
    return text.startswith(("/*", "//")) or bool(_AST_KIND.match(text))


# A fixed-size C array type as clang spells it: `char[64]`, `unsigned char[16]`,
# `int[8]`. The element type is everything before the bracket; the count is the
# integer inside. A pointer (`char *`), a flexible array (`char[]`), or a VLA
# (`char[n]`) does not match -- their capacity is not a compile-time constant and
# must stay unknown, never guessed.
_ARRAY_TYPE = re.compile(r"^(?P<elem>[A-Za-z_][\w ]*?)\s*\[(?P<count>\d+)\]$")
# The element types whose size is exactly one byte by the C standard, independent
# of platform ABI. Only for these can an element count be turned into a BYTE
# capacity soundly; every other element type needs sizeof(T), which depends on the
# target ABI and is therefore left unresolved rather than assumed.
_ONE_BYTE_ELEMENTS = frozenset({"char", "signed char", "unsigned char"})
_INT_LITERAL = re.compile(r"^\s*(?:0[xX][0-9a-fA-F]+|\d+)\s*$")


def array_capacity(type_str: str | None) -> tuple[str, int, int | None] | None:
    """``(element_type, element_count, byte_capacity)`` for a fixed C array type,
    else None. ``byte_capacity`` is filled only when the element is a one-byte type
    (``char`` and its signed/unsigned spellings); for every other element the count
    is exact but the byte size needs ``sizeof(T)`` -- an ABI fact this analyzer does
    not assume -- so it is left None. A compile-time constant, never an estimate."""
    if not type_str:
        return None
    match = _ARRAY_TYPE.match(type_str.strip())
    if not match:
        return None
    element = " ".join(match.group("elem").split())
    count = int(match.group("count"))
    byte_capacity = count if element in _ONE_BYTE_ELEMENTS else None
    return element, count, byte_capacity


def _literal_bytes(expression: str | None) -> int | None:
    """The integer value of a copy size that is spelled as a bare integer literal,
    else None. Only a literal is a constant here -- a named length or an arithmetic
    expression is not evaluated, so its relation to a capacity stays unproven."""
    if not expression or not _INT_LITERAL.match(expression):
        return None
    text = expression.strip()
    return int(text, 16) if text[:2].lower() == "0x" else int(text)


def object_size_capacity(dest_nodes: list[dict], size_expression: str | None) -> dict:
    """The destination-capacity fact for a copy, from fixed-array object sizes.

    Sound and observable only: a capacity is reported exactly when a destination is
    a fixed-size array whose element size is known (a one-byte ``char`` family), and
    a comparison against the copy size is made exactly when that size is an integer
    literal. Everything else -- a pointer destination, a non-char array (byte size
    needs the ABI's ``sizeof``), a named or arithmetic size -- stays ``unknown`` or
    ``capacity-known-size-unknown`` rather than guessed. A wrong capacity would be
    worse than an absent one, so this never estimates.

    Never suppresses and never feeds the rank: an ``exceeds-capacity`` result is a
    neutral, high-value observation for a human to confirm, not a verdict."""
    resolved = []
    for node in dest_nodes:
        type_str = (node.get("properties") or {}).get("type")
        capacity = array_capacity(type_str)
        if capacity is None:
            continue
        element, count, byte_capacity = capacity
        resolved.append({
            "destination": node.get("label"), "declared_type": type_str,
            "element_type": element, "element_count": count,
            "capacity_bytes": byte_capacity})
    if not resolved:
        return {
            "status": "unknown",
            "reason": "no destination resolves to a fixed-size array object; the "
                      "exact-capacity match cannot be proven here",
            "needs_capability": "object-size"}
    literal = _literal_bytes(size_expression)
    byte_sized = [d for d in resolved if d["capacity_bytes"] is not None]
    if literal is not None and byte_sized:
        # The tightest capacity is the one the copy can actually overflow.
        smallest = min(d["capacity_bytes"] for d in byte_sized)
        if literal > smallest:
            return {
                "status": "exceeds-capacity",
                "basis": f"the copy writes {literal} bytes into a destination whose "
                         f"fixed capacity is {smallest} bytes",
                "copy_size_bytes": literal, "capacity_bytes": smallest,
                "destinations": resolved}
        return {
            "status": "within-capacity",
            "basis": f"the copy writes {literal} bytes into a destination whose "
                     f"fixed capacity is {smallest} bytes",
            "copy_size_bytes": literal, "capacity_bytes": smallest,
            "destinations": resolved}
    if byte_sized:
        return {
            "status": "capacity-known-size-unknown",
            "basis": "the destination's fixed byte capacity is known, but the copy "
                     "size is not an integer literal, so the relation is unproven",
            "capacity_bytes": min(d["capacity_bytes"] for d in byte_sized),
            "destinations": resolved}
    return {
        "status": "capacity-known-in-elements",
        "basis": "the destination is a fixed-size array of a known element count, "
                 "but its byte size needs sizeof(element) (an ABI fact not assumed "
                 "here), so no byte comparison is made",
        "destinations": resolved}


def arg_from_callsite(call_label: str | None, access_path: str | None) -> str | None:
    """Recover the exact argument spelling from the reliable callsite label.

    Value sub-nodes sometimes carry a wrong ``label`` (see A12), but the call
    node's own label is faithful and ``access_path`` names the argument index.
    Splitting the top-level argument list is source recovery, not evaluation."""
    if not call_label or not access_path:
        return None
    match = _ARG_INDEX.search(access_path)
    if not match:
        return None
    index, start = int(match.group(1)), call_label.find("(")
    if start < 0:
        return None
    depth, current, args = 0, [], []
    quote, escaped = None, False
    for ch in call_label[start:]:
        if quote:
            # Inside a string/char literal a comma or paren is data, not syntax.
            current.append(ch)
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = None
            continue
        if ch in "\"'":
            quote = ch
            current.append(ch)
            continue
        if ch in "([{":
            depth += 1
            if depth == 1 and ch == "(":
                continue
        elif ch in ")]}":
            depth -= 1
            if depth == 0:
                args.append("".join(current).strip())
                break
            current.append(ch)
            continue
        if ch == "," and depth == 1:
            args.append("".join(current).strip())
            current = []
            continue
        current.append(ch)
    if 0 <= index < len(args):
        return args[index] or None
    return None


def syntactic_shape(label: str | None) -> str:
    """Classify source spelling only; this is not constant evaluation."""
    if not label:
        return "unknown"
    if looks_like_leaked_label(label):
        return "unknown"
    rest = _SIZEOF.sub("", _strip_string_literals(label))
    if _CALL.search(rest):
        return "call-expression"
    rest = _NUM.sub("", rest)
    if _IDENT.search(rest):
        return "identifier-expression"
    return "literal-or-sizeof"


# A binary minus that is not the `->` member operator: a subtraction, which is
# the underflow-prone size arithmetic worth ranking to the top.
_SUBTRACT = re.compile(r"-(?!>)")
_ARITHMETIC = re.compile(r"[+*/%]|<<|>>")
# A destination written at base+offset (``buf->buffer + buf->len``): a copy into a
# pre-existing buffer where an unchecked running length is the classic overflow.
_OFFSET_WRITE = re.compile(r"\+")


def size_semantics(expression: str | None, shape: str) -> tuple[float, str]:
    """Rank the size expression by *risk shape*, not spelling. Cheap and syntactic:
    a dynamic length (arithmetic, variable) is worth a human's eyes; a constant
    (literal/sizeof) rarely is. This orders, it never suppresses."""
    if shape == "no-length-argument":
        # A write-only copy (strcpy/strcat/gets) carries no length bound at all;
        # the amount written is whatever the source holds. Nothing here is more
        # deserving of a human's eyes, so it ranks at the ceiling.
        return 1.0, "unbounded-no-length"
    if not expression or shape == "unknown":
        return 0.4, "opaque"
    # Strip literal spans first: a format string "a-b" or "f(%d)" must not be
    # read as subtraction or arithmetic. What remains is the real size/arg math.
    stripped = _SIZEOF.sub("", _strip_string_literals(expression))
    if _SUBTRACT.search(stripped):
        return 1.0, "arithmetic-subtraction"
    if _ARITHMETIC.search(stripped):
        return 0.9, "arithmetic"
    if shape == "identifier-expression":
        return 0.75, "dynamic-identifier"
    if shape == "call-expression":
        return 0.7, "dynamic-call"
    return 0.2, "constant"


def destination_kind(expression: str | None) -> str:
    """A neutral syntactic class for one destination spelling. Finer than the
    rank's three buckets, and provable from the spelling alone: it says what
    KIND of write target this is, never whether it is safe. Distinguishing an
    exact-sized allocation from an opaque fixed buffer is NOT possible here --
    both spell as a bare identifier or a deref -- so that lives on the frontier
    as an object-size obligation, not in this guess."""
    if not expression:
        return "unknown"
    text = expression.strip()
    if _OFFSET_WRITE.search(text):
        return "offset-write"       # base + running offset into an existing buffer
    if "[" in text:
        return "indexed-write"      # buf[i]: a write at a computed index
    if text.startswith("*") or text.startswith("&"):
        return "indirect-write"     # *p: through a pointer; capacity is not local
    if "->" in text or "." in text:
        return "field-write"        # a struct/union field buffer
    return "named-buffer"           # a bare identifier: local/param/global buffer


def dest_semantics(dest_expressions: list[str | None]) -> tuple[float, str]:
    """Rank the destination by how easily it overflows. An offset write into an
    existing buffer is the pattern to inspect; a bare buffer is next; an unknown
    destination is least informative."""
    present = [d for d in dest_expressions if d]
    if any(_OFFSET_WRITE.search(d) for d in present):
        return 1.0, "offset-write"
    if present:
        return 0.6, "whole-buffer"
    return 0.3, "unknown"


def _candidate_id(model_id: str, callsite_id: str, value_id: str) -> str:
    raw = f"{CONSTRUCTOR_ID}\0{model_id}\0{callsite_id}\0{value_id}"
    return "obl_" + hashlib.sha256(raw.encode()).hexdigest()[:20]


class MemoryCopyCapacity:
    metadata = {
        "id": CONSTRUCTOR_ID,
        "domain": DOMAIN,
        "family": "copy",
        "languages": ("c",),
        "required_capabilities": ("calls", "argument-binding"),
        "optional_capabilities": ("value-flow", "points-to", "object-size", "dominance"),
        "enumeration_basis": "atropos:sink:buffer-size + atropos:sink:buffer-write(write-only)",
        "completeness_contract": "every bound Atropos buffer-size attachment, plus "
                                 "every write-only buffer-write with no length argument",
        # The failure mode this obligation actually points at: writing past the
        # destination's capacity. A copy model may carry broader tags (a source
        # over-read, an ambient "dangerous function" class); those are real but
        # out of THIS constructor's scope, so we scope what we surface rather
        # than let a read-side CWE ride along as if the pointer had checked it.
        "obligation_cwe": ("CWE-787", "CWE-120"),
    }

    # Cap the referencing-condition list so the capsule stays bounded even in a
    # function dense with branches; the count is reported in full regardless.
    _MAX_CONDITIONS = 8

    def __init__(self, stamped_graph: dict, bind_summary: dict | None = None) -> None:
        self.graph = stamped_graph
        self.bind_summary = bind_summary or {}
        self.by_id = {n["id"]: n for n in stamped_graph.get("nodes", ())}
        # Region containment for the `dominance` observation: does a copy sit inside
        # a size-testing branch's region, or is it reached on the fall-through? Built
        # once from the branch-region edges the control-flow overlay emits.
        self._regions = BranchRegions(stamped_graph)
        # Reaching definitions for each sink argument -- the last operation(s) that
        # produced a size or destination -- recovered by walking value-flow edges
        # backward. Neutral context; not-computed until the graph carries them.
        self._variables = VariableContext(stamped_graph)
        # function_id -> [(control_kind, condition_head)], built once. A condition
        # node carries the id of the function it controls, in the same id space as
        # a call's owner_function_id, so a candidate can ask "does any branch in my
        # function test my size variable?" without a graph walk per candidate.
        self._conditions_by_function: dict[str, list[tuple[str, str]]] = defaultdict(list)
        for node in stamped_graph.get("nodes", ()):
            if node.get("kind") != "cfg-condition":
                continue
            props = node.get("properties") or {}
            fn = props.get("function_id")
            head = condition_head(node.get("label"))
            if fn and head:
                self._conditions_by_function[fn].append(
                    (props.get("control_kind") or "if", head))

    def _referencing_conditions(self, function_id: str | None,
                                idents: set[str]) -> tuple[list[dict], int]:
        """Branch conditions in this function whose controlling expression names a
        size variable. A neutral fact -- presence, not proof the guard dominates or
        is even correct. Returns (capped rows, total count)."""
        if not function_id or not idents:
            return [], 0
        patterns = {i: re.compile(r"\b" + re.escape(i) + r"\b") for i in idents}
        hits = []
        for control, head in self._conditions_by_function.get(function_id, ()):
            named = sorted(i for i, p in patterns.items() if p.search(head))
            if named:
                hits.append({"control": control, "condition": head, "names": named})
        return hits[:self._MAX_CONDITIONS], len(hits)

    def _label(self, node_id: str | None) -> str | None:
        node = self.by_id.get(node_id or "", {})
        return node.get("label") or (node.get("properties") or {}).get("name")

    def _call(self, callsite_id: str | None) -> dict:
        return self.by_id.get(callsite_id or "", {})

    def _capacity(self, dest_value_ids: list[str | None], size_expression: str | None,
                  computed: set[str]) -> dict:
        """The destination-capacity fact for a copy, resolved from the fixed-array
        object sizes of its destination value nodes. Records that object-size was
        actually computed (so the capability manifest can report it present) exactly
        when a capacity was resolved -- an `unknown` result computes nothing."""
        dest_nodes = [self.by_id[v] for v in dest_value_ids
                      if v and v in self.by_id]
        result = object_size_capacity(dest_nodes, size_expression)
        if result["status"] != "unknown":
            computed.add("object-size")
        return result

    def _rank(self, expression: str | None, shape: str,
              dest_expressions: list[str | None], confidence: str
              ) -> tuple[float, list[dict]]:
        size_value, size_tag = size_semantics(expression, shape)
        dest_value, dest_tag = dest_semantics(dest_expressions)
        confidence_value = {"high": 1.0, "medium": 0.7, "low": 0.4}.get(
            confidence, 0.5)
        reasons = [
            {"term": "size_semantics", "value": size_value,
             "why": f"size is {size_tag}"},
            {"term": "destination_semantics", "value": dest_value,
             "why": f"destination is {dest_tag}"},
            {"term": "model_confidence", "value": confidence_value,
             "why": f"Atropos attachment confidence is {confidence}"},
        ]
        rank = round(0.6 * size_value + 0.2 * dest_value
                     + 0.2 * confidence_value, 4)
        return rank, reasons

    def enumerate(self) -> dict:
        role_nodes = [
            n for n in self.graph.get("nodes", ())
            if n.get("kind") == "sink"
            and (n.get("properties") or {}).get("fact_origin") == "atropos-model"
        ]
        destinations: dict[str, list[dict]] = defaultdict(list)
        sizes = []
        for node in role_nodes:
            props = node.get("properties") or {}
            if props.get("sink_kind") == "buffer-write":
                destinations[props.get("callsite_id")].append(node)
            elif props.get("sink_kind") == "buffer-size":
                sizes.append(node)

        # Optional inferences this run actually computed (no raw edge witnesses
        # them), so the capability manifest can report object-size present exactly
        # when a destination capacity was resolved -- never merely advertised.
        computed: set[str] = set()
        candidates = []
        for sink in sizes:
            props = sink["properties"]
            callsite_id, value_id = props.get("callsite_id"), props.get("value_id")
            call = self._call(callsite_id)
            call_props = call.get("properties") or {}
            owner_id = call_props.get("owner_function_id")
            # Prefer the argument recovered from the faithful callsite label; the
            # value node's own label is sometimes comment/AST-kind noise (A12).
            # A callsite whose own label is comment/AST noise -- a sink mislocated
            # onto a file-header comment (start_line 1, label `/* Copyright ... */`)
            # -- cannot yield a faithful argument spelling. Recovering from it only
            # fabricates expressions from stray comment fragments ("the \"License\"")
            # and, worse, invents a destination the rank then trusts. Treat such a
            # callsite as unresolved rather than emitting that noise as real source.
            call_label = call.get("label")
            faithful = bool(call_label) and not looks_like_leaked_label(call_label)
            recovered = (arg_from_callsite(call_label, props.get("access_path"))
                         if faithful else None)
            value_label = self._label(value_id)
            if recovered:
                expression, expression_origin = recovered, "callsite-argument"
            elif faithful:
                # Faithful callsite but the argument index did not resolve: fall
                # back to the value node's own label. It may still be AST/comment
                # noise, which syntactic_shape flags "unknown" -- recorded, not
                # fabricated away.
                expression, expression_origin = value_label, "value-node-label"
            else:
                # The callsite itself is comment/AST noise (a sink mislocated onto
                # a file-header comment): nothing here is faithful source, so it is
                # unresolved rather than a "the \"License\"" fragment posing as one.
                expression, expression_origin = None, "unresolved-callsite"
            shape = syntactic_shape(expression)
            dests = destinations.get(callsite_id, ())
            dest_values = [d["properties"].get("value_id") for d in dests]
            # Recover destinations from the callsite too, so a leaked value-node
            # label can't corrupt the destination or the rank it feeds. An
            # unfaithful callsite recovers no destination at all -- an empty list is
            # honest where a fabricated buffer name would mislead the judge.
            dest_expressions = [
                arg_from_callsite(call_label, d["properties"].get("access_path"))
                or self._label(d["properties"].get("value_id"))
                for d in dests] if faithful else []
            confidence = props.get("confidence", "medium")
            model_cwe = props.get("cwe", [])
            obligation_cwe = set(self.metadata.get("obligation_cwe", ()))
            idents = size_identifiers(expression)
            referencing, referencing_total = self._referencing_conditions(owner_id, idents)
            rank, reasons = self._rank(expression, shape, dest_expressions, confidence)
            loc_file = call_props.get("absolute_file") or call_props.get("file")
            candidate = {
                "candidate_id": _candidate_id(props.get("model_id", ""), callsite_id or "", value_id or ""),
                "constructor": CONSTRUCTOR_ID, "domain": DOMAIN, "language": "c",
                "obligation": "copy length must not exceed destination capacity",
                "handles": {"site_node_id": callsite_id,
                            "enclosing_function_id": owner_id,
                            "obligation_value_ids": [value_id, *dest_values]},
                "observations": {
                    "callee": call_props.get("callee") or call_props.get("method_name"),
                    "site": call.get("label"), "file": loc_file,
                    "line": call_props.get("start_line"),
                    "size_expression": expression, "syntactic_shape": shape,
                    "size_expression_origin": expression_origin,
                    "destination_expressions": dest_expressions,
                    "destination_kinds": [
                        {"expression": d, "kind": destination_kind(d)}
                        for d in dest_expressions],
                    "atropos_model_id": props.get("model_id"),
                    "access_path": props.get("access_path"),
                    # `cwe` is the model's full tag set, verbatim; `obligation_cwe`
                    # is the subset this capacity pointer actually concerns (a
                    # destination over-write). Anything the model tags but this
                    # obligation does not check (e.g. a source over-read) stays
                    # visible in `cwe` but is absent from `obligation_cwe`.
                    "cwe": model_cwe,
                    "obligation_cwe": [c for c in model_cwe if c in obligation_cwe],
                    "model_confidence": confidence,
                },
                "inferences": {
                    "input_reachability": {
                        "status": "not-queried", "source_kind": None,
                        "witness_ids": [],
                        "reason": "the AI may call sources_of/reaches when investigating",
                    },
                    # Whether the copy size fits the destination's real capacity.
                    # Sound object-size only: resolved when a destination is a
                    # fixed-size char array (byte capacity known) and compared only
                    # when the size is an integer literal -- so `memcpy(buf, .., 128)`
                    # into `char buf[64]` reads as exceeds-capacity. A pointer
                    # destination, a non-char array, or a named/arithmetic size stays
                    # unknown/unproven rather than guessed.
                    "destination_capacity": self._capacity(
                        dest_values, expression, computed),
                    # A neutral observation, never a verdict and never fed to the
                    # rank: does a branch in this function test a size variable, and
                    # does the copy sit inside that branch's region or on the
                    # fall-through past it? `dominance` is sound region containment,
                    # not proof the guard is correct -- only a lead worth reading.
                    "conditions": {
                        "status": "observed" if referencing_total else "none-observed",
                        "basis": "syntactic: a control condition in the enclosing "
                                 "function names a size variable",
                        "size_identifiers": sorted(idents),
                        "referencing_conditions": referencing,
                        "referencing_condition_count": referencing_total,
                        "dominance": self._regions.classify(
                            owner_id, idents, _node_span(call)),
                    },
                    # Where each sink argument was last written -- the reaching
                    # definition of the size and of every destination -- so guard
                    # ADEQUACY can be read: the bound a branch tests can be compared
                    # against the value the size was actually clamped to. Neutral
                    # fact, not a verdict; not-computed without value-flow edges.
                    "variable_context": self._variables.describe(
                        [("size", value_id),
                         *[("destination", d) for d in dest_values]],
                        _node_span(call)),
                },
                "rank": rank, "rank_reasons": reasons,
                # Enumeration can be complete while the evidence capsule is still
                # partial: v1 deliberately has no object-size or dominance proof.
                "completeness": "PARTIAL",
                "next_op": {"tool": "sources_of", "args": {"sink": value_id},
                            "why": "let the AI inspect provenance before judging the obligation"},
            }
            candidates.append(candidate)

        # Write-only copies -- strcpy/strcat/gets and friends -- carry NO length
        # argument, so they never produce a buffer-size sink and the loop above
        # never reaches them. They are the purest unbounded-copy obligation (the
        # amount written is whatever the source holds), so a callsite whose only
        # attachment is a buffer-write MUST still be enumerated. Inclusion is
        # exhaustive: a missing length bound is a reason to surface a site, never
        # to drop it.
        sized_callsites = {s["properties"].get("callsite_id") for s in sizes}
        for callsite_id, dests in destinations.items():
            if callsite_id in sized_callsites:
                continue  # already enumerated through its buffer-size sink
            primary = dests[0]
            dprops = primary["properties"]
            value_id = dprops.get("value_id")
            call = self._call(callsite_id)
            call_props = call.get("properties") or {}
            owner_id = call_props.get("owner_function_id")
            dest_values = [d["properties"].get("value_id") for d in dests]
            dest_expressions = [
                arg_from_callsite(call.get("label"), d["properties"].get("access_path"))
                or self._label(d["properties"].get("value_id"))
                for d in dests]
            confidence = dprops.get("confidence", "medium")
            model_cwe = dprops.get("cwe", [])
            obligation_cwe = set(self.metadata.get("obligation_cwe", ()))
            shape = "no-length-argument"
            rank, reasons = self._rank(None, shape, dest_expressions, confidence)
            loc_file = call_props.get("absolute_file") or call_props.get("file")
            candidate = {
                "candidate_id": _candidate_id(
                    dprops.get("model_id", ""), callsite_id or "", value_id or ""),
                "constructor": CONSTRUCTOR_ID, "domain": DOMAIN, "language": "c",
                "obligation": "copy length must not exceed destination capacity",
                "handles": {"site_node_id": callsite_id,
                            "enclosing_function_id": owner_id,
                            "obligation_value_ids": dest_values},
                "observations": {
                    "callee": call_props.get("callee") or call_props.get("method_name"),
                    "site": call.get("label"), "file": loc_file,
                    "line": call_props.get("start_line"),
                    "size_expression": None, "syntactic_shape": shape,
                    "size_expression_origin": "implicit-length",
                    # The length is not spelled anywhere at the callsite: it is
                    # whatever the source string holds (an implicit strlen). This
                    # is recorded, not guessed away.
                    "length_bound": "none: write-only copy has no length argument",
                    "destination_expressions": dest_expressions,
                    "destination_kinds": [
                        {"expression": d, "kind": destination_kind(d)}
                        for d in dest_expressions],
                    "atropos_model_id": dprops.get("model_id"),
                    "access_path": dprops.get("access_path"),
                    "cwe": model_cwe,
                    "obligation_cwe": [c for c in model_cwe if c in obligation_cwe],
                    "model_confidence": confidence,
                },
                "inferences": {
                    "input_reachability": {
                        "status": "not-queried", "source_kind": None,
                        "witness_ids": [],
                        "reason": "the AI may call sources_of/reaches when investigating",
                    },
                    # A write-only copy has no length argument, so the size is never
                    # an integer literal; object-size can still name a fixed-array
                    # destination's capacity (capacity-known-size-unknown), which is
                    # a real lead -- the amount written is bounded only by the source.
                    "destination_capacity": self._capacity(
                        dest_values, None, computed),
                    # No size variable exists to test, so no branch can reference
                    # one; this is stated as fact, not treated as a clean bill.
                    "conditions": {
                        "status": "not-applicable",
                        "basis": "a write-only copy has no length argument to guard",
                        "size_identifiers": [],
                        "referencing_conditions": [],
                        "referencing_condition_count": 0,
                        "dominance": {
                            "status": "not-applicable",
                            "reason": "a write-only copy has no length argument, so "
                                      "no branch can guard one"},
                    },
                    # No size argument exists, but the destination still has a last
                    # operation -- where the buffer was allocated or last written --
                    # which bounds how much the implicit-length copy may overrun.
                    "variable_context": self._variables.describe(
                        [("destination", d) for d in dest_values],
                        _node_span(call)),
                },
                "rank": rank, "rank_reasons": reasons,
                "completeness": "PARTIAL",
                "next_op": {"tool": "sources_of", "args": {"sink": value_id},
                            "why": "trace what reaches the write target; a write-only "
                                   "copy is bounded only by its source length"},
            }
            candidates.append(candidate)
        candidates.sort(key=lambda c: (-c["rank"], c["candidate_id"]))

        c_summary = self.bind_summary.get("per_language", {}).get("c", {})
        bind = c_summary.get("bind", {})
        # Every sink model the catalog carries that did NOT attach to a callsite.
        # Surfaced in full (not just counted) so no sink is silently dropped: the
        # AI sees exactly which copy/size sinks are missing and why. Sources are
        # excluded here because this constructor's obligation is a copy sink.
        unbound_sinks = [
            row for row in c_summary.get("unbound", ())
            if row.get("role") == "sink"]
        frontiers = {
            "unresolved_calls": 0,
            "unbound_models": sum(v for k, v in bind.items() if k != "bound"),
            "unbound_sinks": unbound_sinks,
            "truncated_walks": 0,
            "missing_optional_capabilities": absent_optional_capabilities(
                self.graph, self.metadata["optional_capabilities"], computed),
            "unselected_configs": [],
        }
        return {
            "constructor": CONSTRUCTOR_ID, "domain": DOMAIN,
            "metadata": dict(self.metadata), "candidates": candidates,
            "census": {"enumerated": len(candidates),
                       "by_status": {"not-queried": len(candidates)}},
            "frontiers": frontiers,
            "complete_for_observable_graph": True,
        }
