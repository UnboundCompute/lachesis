"""Export a loaded graph as a lachesis-explorer ``bundle.json`` (schema 1.0).

This is pure reader glue. It projects the reader's own evidence -- guard-differential
capsules and the candidate registry's sink leads -- into the versioned finding
envelope the stack already publishes (``docs/OSS_FINDING_SCHEMA.json`` /
``OSS_EVIDENCE_SCHEMA.json``), packaged for the explorer:

    {format, bundle_version, finding_schema_version, evidence_manifest,
     findings: [envelope, ...], graph: {nodes, edges}, meta, display_hints}

Two evidence sources feed the findings, and the split is deliberate:

  * the **candidate registry** is the exhaustive spine -- every enumerated sink
    family, never scoped to one -- so coverage is over the whole taxonomy;
  * **guard-differential capsules** enrich the subset of sinks they also reach,
    contributing real ``witness`` and ``guards`` and an honest ``completeness``.

Identity is content-derived (``finding_id`` = sha256 over the sink's semantic
location), so a capsule and a candidate about the same sink collapse to one
finding -- the capsule wins, the candidate-only families remain. No adjudication,
ranking, or tuning happens here; a finding is a ``lead``, never a verdict, and the
envelope's ``status``/``completeness``/``limitations`` carry that honesty intact.

The public MCP surface (``mcp_server.call_tool``) drives the graph operations so
this module shares the one proven load/census/candidates/sources_of path; capsules
come from the public planner constructor.
"""
from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import subprocess
from datetime import datetime, timezone
from typing import Any, Optional

from lachesis.nav import mcp_server as M

try:
    from lachesis.config import is_nonproduct as _is_nonproduct
except Exception:  # config is pure-stdlib and same-package, so this should not fail;
    _is_nonproduct = None  # if it ever does, the gate fails open (keeps everything).

BUNDLE_VERSION = "1.0"
FINDING_SCHEMA_VERSION = "0.1"
_HEX64 = 64


def _call(name: str, args: dict) -> Any:
    return json.loads(M.call_tool(name, args, "json"))


def _is_nonproduct_path(path: Optional[str]) -> bool:
    """True when a source path is test/example/docs/benchmark scaffolding.

    The featured comprehension surfaces (entrypoints, request roots, the core spine)
    describe what the *product* does, so scaffolding must never seed them. Build-time
    exclusion normally keeps such files out of the graph entirely, but the exporter
    must not rely on that -- run against a graph built without exclusion, an uncalled
    ``test_*`` function is an in-degree-0 callable and would otherwise rank as a
    top-of-stack driver, refeaturing exactly the tests the classifier is meant to
    drop. Reuses the same classifier the build filter uses, so the two agree; fails
    open (keeps the node) only if the classifier is somehow unavailable.
    """
    if not path or _is_nonproduct is None:
        return False
    try:
        return bool(_is_nonproduct(path))
    except Exception:
        return False


# --------------------------------------------------------------------- identity

def _basename(path: Optional[str]) -> str:
    return os.path.basename(path) if isinstance(path, str) and path else ""


def _finding_primary_file(finding: dict, node_map: dict) -> Optional[str]:
    """Repo-relative path of a finding's featured surface (its sink), or None.

    Used to keep the trust view a *product* security surface (H12): the exhaustive
    envelope carries findings located anywhere the graph reaches, including
    type-test and test scaffolding (`test-d/…`, `test_*.py`, `*.spec.*`), which are
    not a surface a maintainer ships. We resolve the file from the witness sink node
    (walking from the last step back to the first node that carries a path) rather
    than ``finding['locations']``, because ``locations`` records only a basename
    while the graph node carries the repo-relative path ``_is_nonproduct_path``
    classifies over. Returns None when no step resolves, so the caller fails open.
    """
    steps = (finding.get("witness") or {}).get("steps") or []
    for step in reversed(steps):
        node = node_map.get(step.get("node_id"))
        if node:
            path = node.get("file") or node.get("absolute_file")
            if path:
                return path
    return None


def _finding_id(sink_kind: Optional[str], file: Optional[str],
                symbol: Optional[str]) -> str:
    """Content-derived, line-independent identity for a sink.

    Deliberately excludes the line and the analysis source: the same semantic sink
    must fingerprint the same across runs (line shifts, renames) and across the two
    evidence sources (candidate vs capsule), so overlapping findings dedupe.
    """
    payload = "\0".join([
        str(sink_kind or ""), _basename(file), str(symbol or ""),
    ])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------- helpers

def _nonempty_constructors(census: dict) -> list[str]:
    """Every enumerated sink family, in census order -- no family is privileged."""
    out: list[str] = []
    for c in census.get("constructors", []) or []:
        meta = c.get("metadata") or {}
        cid = meta.get("id")
        if cid and (c.get("census") or {}).get("enumerated", 0):
            out.append(cid)
    return out


def _leads(constructor_id: str, per_family: int) -> list[dict]:
    try:
        r = _call("candidates", {"constructor_id": constructor_id,
                                 "detail": "full", "limit": per_family})
    except Exception:
        return []
    return [l for l in (r.get("leads") or []) if isinstance(l, dict)]


def _edge_flags(edge: dict) -> tuple[bool, bool]:
    """(alias, dynamic) for one reachability edge."""
    alias = edge.get("reason") == "alias-via-heap"
    dynamic = edge.get("kind") == "DYNAMIC_INPUT"
    return alias, dynamic


def _edge_src_tgt(edge: dict) -> tuple[Optional[str], Optional[str]]:
    """Edges arrive as ``src/tgt`` (sources_of) or ``source/target`` (path_shape)."""
    return (edge.get("src") or edge.get("source"),
            edge.get("tgt") or edge.get("target"))


def _order_path(nodes: list[dict], edges: list[dict], sink_id: str) -> list[str]:
    """Order a reverse cone into an origin->...->sink chain.

    The cone is a reverse tree rooted at the sink. We walk forward (source->sink)
    from each origin (a node that is never an edge target within the cone) and keep
    the longest chain that actually lands on the sink. If nothing connects, the
    flow is the sink alone -- an honest single-step flow, never invented ordering.
    """
    ids = {n["id"] for n in nodes}
    if sink_id not in ids and nodes:
        sink_id = nodes[0]["id"]
    fwd: dict[str, list[str]] = {}
    targets: set[str] = set()
    for e in edges:
        s, t = _edge_src_tgt(e)
        if s in ids and t in ids:
            fwd.setdefault(s, []).append(t)
            targets.add(t)
    origins = sorted(nid for nid in ids if nid not in targets)

    def walk(start: str) -> list[str]:
        path = [start]
        cur = start
        seen = {start}
        while cur != sink_id:
            nxt = [x for x in fwd.get(cur, []) if x not in seen]
            if not nxt:
                break
            cur = nxt[0]
            seen.add(cur)
            path.append(cur)
        return path

    best: list[str] = []
    for o in origins:
        p = walk(o)
        if p and p[-1] == sink_id and len(p) > len(best):
            best = p
    return best or [sink_id]


def _edge_into(edges: list[dict], prev: str, cur: str) -> Optional[dict]:
    for e in edges:
        s, t = _edge_src_tgt(e)
        if s == prev and t == cur:
            return e
    return None


# ------------------------------------------------------------------ snippets

def _snippet_lookup(graph_path: str):
    """Best-effort node -> source text, walking EVIDENCED_BY to a source-span.

    Mirrors the reasoning layer's excerpt walk but against the already-loaded
    store index, so it costs one adjacency hop per node and never rebuilds a
    layered graph. Returns a callable; on any trouble it yields None and callers
    fall back to the node label.
    """
    try:
        ctx = M.ctx()
        idx = ctx.store.index
        from lachesis.nav.graph_store import GraphIndex
    except Exception:
        return lambda _nid: None

    cache: dict[str, Optional[str]] = {}

    def excerpt(node_id: str) -> Optional[str]:
        if node_id in cache:
            return cache[node_id]
        text: Optional[str] = None
        try:
            frontier, visited = [node_id], {node_id}
            spans = []
            for _ in range(2):
                nxt = []
                for cur in frontier:
                    for edge in [*idx.outgoing.get(cur, []), *idx.incoming.get(cur, [])]:
                        if GraphIndex.semantic_edge_kind(edge) != "EVIDENCED_BY":
                            continue
                        other = edge["target"] if edge["source"] == cur else edge["source"]
                        if other in visited:
                            continue
                        visited.add(other)
                        node = idx.nodes.get(other)
                        if not node:
                            continue
                        if node.get("kind") == "source-span":
                            spans.append(node)
                        else:
                            nxt.append(other)
                frontier = nxt
            if spans:
                proof = sorted(spans, key=lambda n: n["id"])[0]
                text = str(proof.get("properties", {}).get("text") or proof.get("label") or "")
        except Exception:
            text = None
        cache[node_id] = text or None
        return cache[node_id]

    return excerpt


# ------------------------------------------------------------------- provenance

def _git(cwd: str, *args: str) -> Optional[str]:
    try:
        out = subprocess.run(["git", "-C", cwd, *args], capture_output=True,
                             text=True, timeout=10)
        if out.returncode == 0:
            return out.stdout.strip() or None
    except Exception:
        return None
    return None


def _sha_of(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _repo_roots() -> tuple[Optional[str], Optional[str]]:
    """(arachne root, atropos root) inferred from the installed package layout."""
    try:
        import lachesis
        arachne = os.path.dirname(os.path.dirname(os.path.abspath(lachesis.__file__)))
    except Exception:
        return None, None
    atropos = os.path.join(os.path.dirname(arachne), "atropos")
    return arachne, (atropos if os.path.isdir(atropos) else None)


def _provenance(source_dir: Optional[str], census: dict) -> dict:
    """Honest engine/catalog/toolchain/tree digests; required fields never empty."""
    import platform
    arachne, atropos = _repo_roots()

    engine_sha = (arachne and _git(arachne, "rev-parse", "HEAD")) or None
    if not engine_sha:
        try:
            import lachesis
            engine_sha = _sha_of(getattr(lachesis, "__version__", "") or lachesis.__file__)
        except Exception:
            engine_sha = _sha_of("lachesis")

    catalog_sha = (atropos and _git(atropos, "rev-parse", "HEAD")) or None
    if not catalog_sha:
        atropos_meta = (census.get("atropos") or {})
        catalog_sha = _sha_of(json.dumps(atropos_meta, sort_keys=True) or "atropos")

    try:
        from lachesis.kuzu_store import STORE_FORMAT_VERSION
        store_ver = str(STORE_FORMAT_VERSION)
    except Exception:
        store_ver = "?"
    toolchain_fingerprint = _sha_of(
        f"py={platform.python_version()}|store={store_ver}|engine={engine_sha[:12]}")

    commit_sha = (source_dir and _git(source_dir, "rev-parse", "HEAD")) or ""
    tree_digest = (source_dir and _git(source_dir, "rev-parse", "HEAD^{tree}")) or ""
    return {
        "engine_sha": engine_sha,
        "catalog_sha": catalog_sha,
        "toolchain_fingerprint": toolchain_fingerprint,
        "commit_sha": commit_sha,
        "tree_digest": tree_digest,
    }


# ------------------------------------------------------------------- assembly

class _Assembler:
    """Accumulates the graph node/edge pool shared across every finding."""

    def __init__(self, snippet_of):
        self.nodes: dict[str, dict] = {}
        self.edges: dict[tuple, dict] = {}
        self._snippet_of = snippet_of

    def add_node(self, node: dict, *, default_kind: str = "value") -> Optional[str]:
        nid = node.get("id")
        if not nid:
            return None
        if nid in self.nodes:
            return nid
        label = node.get("name") or node.get("label") or nid
        snip = self._snippet_of(nid) or label
        self.nodes[nid] = {
            "id": nid,
            "kind": node.get("kind") or default_kind,
            "file": node.get("file"),
            "line": node.get("line"),
            "label": label,
            "snippet": snip,
        }
        return nid

    def add_edge(self, edge: dict, among: set[str]) -> None:
        s, t = _edge_src_tgt(edge)
        if s in among and t in among:
            a, d = _edge_flags(edge)
            self.edges[(s, t)] = {"source": s, "target": t,
                                  "kind": edge.get("kind") or "VALUE_FLOWS_TO",
                                  "alias": a, "dynamic": d}


def _steps_from_path(path: list[str], node_pool: set[str],
                     edges: list[dict]) -> list[dict]:
    """An ordered value-flow path -> explorer steps (origin/transform/sink)."""
    steps: list[dict] = []
    present = [nid for nid in path if nid in node_pool]
    last = len(present) - 1
    for i, nid in enumerate(present):
        role = "sink" if i == last else ("origin" if i == 0 else "transform")
        step = {"node_id": nid, "role": role}
        if i > 0:
            e = _edge_into(edges, present[i - 1], nid)
            if e:
                a, d = _edge_flags(e)
                if a or d:
                    step["edge"] = {"alias": a, "dynamic": d}
        steps.append(step)
    return steps


def _candidate_findings(census: dict, asm: _Assembler, *, per_family: int,
                        max_flows: int, cone_limit: int) -> dict[str, dict]:
    """The exhaustive spine: one finding per sink, over every enumerated family."""
    findings: dict[str, dict] = {}
    for cid in _nonempty_constructors(census):
        if len(findings) >= max_flows:
            break
        for lead in _leads(cid, per_family):
            if len(findings) >= max_flows:
                break
            handles = lead.get("handles") or {}
            val_ids = handles.get("obligation_value_ids") or []
            sink_id = val_ids[0] if val_ids else handles.get("site_node_id")
            if not sink_id:
                continue
            obs = lead.get("observations") or {}
            fid = _finding_id(obs.get("sink_kind"), obs.get("file"),
                              obs.get("callee") or obs.get("site"))
            if fid in findings:
                continue

            env = _call("sources_of", {"sink": sink_id, "limit": cone_limit})
            env_nodes = env.get("nodes") or []
            env_edges = env.get("edges") or []
            if not env_nodes:
                continue
            node_by_id = {n["id"]: n for n in env_nodes}
            path = _order_path(env_nodes, env_edges, sink_id)
            for nid in path:
                if nid in node_by_id:
                    asm.add_node(node_by_id[nid])
            pool = set(asm.nodes)
            for e in env_edges:
                asm.add_edge(e, pool)
            steps = _steps_from_path(path, pool, env_edges)
            if not steps:
                continue

            inf = lead.get("inferences") or {}
            reach = (inf.get("input_reachability") or {}).get("status")
            limitations = ["candidate lead; no guard-differential capsule"]
            if reach and reach != "confirmed":
                limitations.append(f"input reachability {reach}")
            findings[fid] = {
                "schema_version": FINDING_SCHEMA_VERSION,
                "finding_id": fid,
                "status": "lead",
                "lifecycle_state": "new",
                "constructor": cid,
                "analysis": {
                    "projection": "candidate-reachability",
                    "confidence": str(obs.get("model_confidence") or "conservative"),
                    "limitations": limitations,
                },
                "locations": [{
                    "file": obs.get("file"), "line": obs.get("line"),
                    "symbol": obs.get("callee") or obs.get("site"), "role": "sink",
                }],
                "witness": {"steps": steps, "guards": {}},
                "display_name": str(obs.get("callee") or obs.get("site")
                                    or asm.nodes[path[-1]]["label"])[:80],
                "result_summary": f"{len(env_nodes)} nodes, {len(env_edges)} edges "
                                  f"reach {obs.get('sink_kind') or cid}",
            }
    return findings


def _capsule_findings(source_graph_path: str, asm: _Assembler, *,
                      depth: int, limit_entrypoints: int) -> dict[str, dict]:
    """Guard-differential capsules -> findings with real witness + guards.

    Runs the public planner constructor over the same store. Returns {} on any
    trouble (the candidate spine still stands), so a graph the planner cannot walk
    degrades to candidate-only rather than failing the export.
    """
    try:
        from lachesis.nav.graph_store import GraphStore
        from lachesis.planner.constructors import GuardDifferential
        store = GraphStore.load(source_graph_path)
        store.ensure_dataflow_tier()
        result = GuardDifferential(store, depth=depth).run(
            limit_entrypoints=limit_entrypoints)
    except Exception:
        return {}

    findings: dict[str, dict] = {}
    for cap in result.get("queue") or []:
        effect = cap.get("sensitive_effect") or {}
        fid = _finding_id(effect.get("kind"), effect.get("file"),
                          effect.get("symbol"))
        if fid in findings:
            continue

        witness = cap.get("witness") or {}
        wnodes = witness.get("nodes") or []
        wedges = witness.get("edges") or []
        chain_ids: list[str] = []
        for n in wnodes:
            nid = asm.add_node(n, default_kind="function")
            if nid:
                chain_ids.append(nid)
        # The sensitive effect is the sink; append it as the terminal node.
        sink_id = effect.get("node_id")
        if sink_id:
            asm.add_node({"id": sink_id, "name": effect.get("symbol"),
                          "file": effect.get("file"), "line": effect.get("line"),
                          "kind": "sink"}, default_kind="sink")
            path = chain_ids + [sink_id]
        else:
            path = chain_ids
        pool = set(asm.nodes)
        for e in wedges:
            asm.add_edge(e, pool)
        steps = _steps_from_path(path, pool, wedges)
        if not steps:
            continue

        guards_present = cap.get("guards_present") or []
        guards = {
            "present": guards_present,
            "dominating": any(g.get("dominates") for g in guards_present),
            "missing": cap.get("missing_guard"),
        }
        findings[fid] = {
            "schema_version": FINDING_SCHEMA_VERSION,
            "finding_id": fid,
            "status": "lead",
            "lifecycle_state": "new",
            "constructor": cap.get("constructor"),
            "provenance": cap.get("provenance"),
            "completeness": cap.get("completeness"),
            "analysis": {
                "projection": "guard-differential",
                "confidence": str(cap.get("completeness") or "PARTIAL"),
                "limitations": list(cap.get("uncertainty") or []),
            },
            "locations": [
                {"file": effect.get("file"), "line": effect.get("line"),
                 "symbol": effect.get("symbol"), "role": "sink"},
                {"file": (cap.get("entrypoint") or {}).get("file"),
                 "line": (cap.get("entrypoint") or {}).get("line"),
                 "symbol": (cap.get("entrypoint") or {}).get("symbol"),
                 "role": "entrypoint"},
            ],
            "witness": {"steps": steps, "guards": guards},
            "display_name": str(effect.get("symbol")
                                or (cap.get("claim") or {}).get("object")
                                or asm.nodes[path[-1]]["label"])[:80],
            "result_summary": cap.get("objective") or "guard-differential lead",
        }
    return findings


# ----------------------------------------------------------- comprehension layer
#
# The graph-first 2.0 bundle is a *reading* aid first and a finding envelope second.
# A developer opening a repository they do not know needs three things the security
# projection never surfaced: where control legitimately enters (`graph.entrypoints`),
# a few honest walks *through* the code from those entries (`paths.requests`), and the
# file/module scaffolding to place any node (`graph.files`, `graph.modules`).
#
# Everything here is derived from the same loaded store the rest of the export uses,
# and everything it references is a real node it also adds to the shared pool, so the
# graph-first invariant (every id resolves) holds. Nothing is invented: entrypoints
# come from the public entrypoint-anchoring recognitions (route / callback / exported),
# a guided path is the real CALLS chain out of an entry, and the modules are the
# comprehension layer's own call/dependency communities. If any of it cannot be built
# the whole projection degrades to empty lists -- the security bundle still stands.

_ENTRY_KIND = {
    "route": "http-handler",
    "callback-registration": "callback",
    "object-literal-registration": "callback",
    "exported-entry": "exported-entry",
}


def _slug(text: str) -> str:
    """A stable, id-safe slug from a symbol label (never empty).

    The underscore is preserved, not folded to the dot separator. It is an
    id-safe character and it is semantically load-bearing: a Python private
    module ``click._utils`` and its public twin ``click.utils`` must not collapse
    onto the same slug. When they did, the derived ``id`` was no longer injective
    and the duplicate-id guard in both apps rejected the *entire* bundle for any
    package carrying a ``foo``/``_foo`` pair (``utils``/``_utils``,
    ``compat``/``_compat``) -- a ubiquitous convention. Folding also stripped a
    leading underscore, so ``_termui_impl`` mangled into ``termui.impl`` (a
    phantom ``termui.impl`` child). Keeping the underscore fixes both: the map is
    now injective over inputs differing in alphanumerics or underscores, and it
    stops rewriting the module hierarchy. Only genuinely unsafe characters (path
    separators, punctuation, spaces) become dot separators.
    """
    keep = [c.lower() if (c.isalnum() or c in "._") else "." for c in str(text or "")]
    s = "".join(keep).strip(".")
    while ".." in s:
        s = s.replace("..", ".")
    return s or "anon"


def _norm_node(gl, node: dict) -> dict:
    """Project a graph-library node into the flat shape ``_Assembler.add_node`` reads."""
    file, line = None, None
    try:
        loc = gl.loc(node)
        file, line = loc[0], loc[1]
    except Exception:
        pass
    if not (isinstance(file, str) and file.strip()):
        afile, aline = _anchor_location(gl, node)
        if afile:
            file = afile
            if not (isinstance(line, int) and line > 0):
                line = aline
    return {"id": node.get("id"), "name": gl.label(node),
            "kind": gl.kind(node.get("id")), "file": file, "line": line}


# Synthetic dataflow nodes (heap objects/locations, interprocedural-context bindings)
# carry no source location of their own -- gl.loc() returns (None, None). They do,
# however, reference the real site they derive from through their properties: a heap
# object names the function that owns its allocation, a context binding names the
# call-site it flows through, a heap location names the object it is a field/index of.
# Following those references to a located node gives every synthetic node a real
# file:line -- better for a reader than a blank, and required by the bundle contract,
# which rejects a node with an empty file.
# Structural references first (the owning function, the call-site, the parent
# object), then evidence -- the concrete frontend nodes the inference was drawn from,
# which always carry a location. Evidence is a list; the rest are scalar ids.
_ANCHOR_PROPERTY_KEYS = (
    "owner_function_id", "function_id", "callsite_id", "call_id",
    "object_id", "parameter_id", "argument_id", "context_id", "evidence_ids",
)


def _anchor_ids(value: Any) -> list[str]:
    """Node ids a property references. A reference may be a scalar id or a list of
    them; kuzu stores some list properties as their ``repr`` string, so parse that."""
    if isinstance(value, (list, tuple)):
        return [item for item in value if isinstance(item, str) and item]
    if isinstance(value, str) and value.strip():
        text = value.strip()
        if text.startswith("[") or text.startswith("("):
            try:
                parsed = ast.literal_eval(text)
            except (ValueError, SyntaxError):
                return []
            if isinstance(parsed, (list, tuple)):
                return [item for item in parsed if isinstance(item, str) and item]
            return []
        return [text]
    return []


def _anchor_location(gl, node: dict) -> tuple[Optional[str], Optional[int]]:
    """Best-effort (repo-relative file, line) for a location-less synthetic node,
    resolved from the real site it references. (None, None) when nothing resolves."""
    seen: set[str] = set()

    def resolve(node_id: str, depth: int) -> tuple[Optional[str], Optional[int]]:
        if not node_id or node_id in seen or depth > 6:
            return (None, None)
        seen.add(node_id)
        target = gl.nodes.get(node_id)
        if target is None:
            return (None, None)
        try:
            file, line, _end = gl.loc(target)
        except Exception:
            file, line = None, None
        if isinstance(file, str) and file.strip():
            return (file, line)
        props = target.get("properties", {}) or {}
        for key in _ANCHOR_PROPERTY_KEYS:
            for ref in _anchor_ids(props.get(key)):
                resolved = resolve(ref, depth + 1)
                if resolved[0]:
                    return resolved
        return (None, None)

    props = node.get("properties", {}) or {}
    for key in _ANCHOR_PROPERTY_KEYS:
        for ref in _anchor_ids(props.get(key)):
            resolved = resolve(ref, 0)
            if resolved[0]:
                return resolved
    return (None, None)


# The request lifecycle a reader wants is the *success* path; error, teardown and
# logging branches are real but secondary, so we only derank them when choosing the
# primary hop -- never drop them. Word-token match (not raw substring) over the
# identifier keeps this generic and framework-agnostic: it is a vocabulary of
# English failure/teardown verbs, never a hardcoded symbol from one library.
_LIFECYCLE_ERROR_TOKENS = frozenset({
    "exception", "error", "err", "teardown", "cleanup", "abort", "raise",
    "rollback", "fail", "reject", "panic", "warn", "log", "logging",
})
_CALL_EDGE_KINDS = ("CALLS", "INVOKES", "MAY_INVOKE")

# A special-case/fallback branch is real but is not the lifecycle a reader opens the
# bundle to follow: an auto-generated default reply, a not-found placeholder, an
# unsupported-method stub. Deranked (never dropped) below error branches when picking
# the primary hop, so the spine stays on the ordinary request rather than diving into
# a corner case. Generic English morphology -- matches ``make_default_options_response``
# or ``handle_not_found`` in any codebase, not a symbol from one framework.
_LIFECYCLE_FALLBACK_TOKENS = frozenset({
    "default", "fallback", "options", "notfound", "missing", "unsupported",
    "unavailable", "placeholder", "noop", "stub", "unknown",
})

# A request lifecycle culminates in *constructing the thing it returns* -- a response,
# a rendered page, a serialized result. We recognise that terminus by morphology so the
# spine ends there rather than in a routing corner: a construction verb applied to a
# result noun. Generic across codebases (``make_response``, ``build_result``,
# ``render_page``, ``serialize_output``), never a hardcoded framework symbol.
_RESULT_CONSTRUCTION_VERBS = frozenset({
    "make", "build", "create", "construct", "render", "format", "compose",
    "produce", "generate", "new", "serialize", "encode", "write", "emit",
})
_RESULT_NOUNS = frozenset({
    "response", "reply", "result", "output", "answer", "payload", "body",
    "page", "document", "content", "view", "html", "json", "template",
})


def _identifier_tokens(name: Optional[str]) -> list[str]:
    """Lowercased word tokens of an identifier, splitting snake_case and camelCase.

    ``full_dispatch_request`` -> ``[full, dispatch, request]``; ``makeResponse`` ->
    ``[make, response]``; ``__call__`` -> ``[call]``; ``HTTPServer`` -> ``[http,
    server]``. The atom every generic morphology check below reasons over, so a rule
    keys off whole words rather than raw substrings (no ``err`` inside ``inherit``).
    """
    return [t.lower() for t in re.findall(r"[A-Z]+(?![a-z])|[A-Z][a-z]+|[a-z]+|\d+",
                                          str(name or ""))]


def _is_fallback_name(name: Optional[str]) -> bool:
    return bool(_LIFECYCLE_FALLBACK_TOKENS.intersection(_identifier_tokens(name)))


def _is_result_construction(name: Optional[str]) -> bool:
    """True when an identifier reads as 'construct the returned result'.

    Requires both a construction verb and a result noun as whole tokens, and is not a
    fallback/error name -- so ``make_response`` and ``render_page`` qualify while a
    special-case ``make_default_options_response`` (fallback) and a plain
    ``process_response`` (no construction verb) do not.
    """
    toks = set(_identifier_tokens(name))
    if _LIFECYCLE_ERROR_TOKENS.intersection(toks) or _LIFECYCLE_FALLBACK_TOKENS.intersection(toks):
        return False
    return bool(_RESULT_CONSTRUCTION_VERBS.intersection(toks) and _RESULT_NOUNS.intersection(toks))


# Generic leading-verb -> third-person phrase, so a hop caption reads as what the
# step *does* rather than as a bare symbol. Keyed off the identifier's action token,
# it renders any codebase's ``make_*``/``parse_*``/``dispatch_*`` the same way -- a
# vocabulary of English verbs, never a per-framework symbol table.
_VERB_READS_AS = {
    "make": "builds", "build": "builds", "create": "creates", "construct": "constructs",
    "new": "creates", "render": "renders", "format": "formats", "compose": "assembles",
    "produce": "produces", "generate": "generates", "prepare": "prepares", "wrap": "wraps",
    "get": "reads", "fetch": "fetches", "load": "loads", "read": "reads", "find": "finds",
    "lookup": "looks up", "resolve": "resolves", "select": "selects", "match": "matches",
    "search": "searches", "query": "queries", "collect": "collects", "gather": "gathers",
    "dispatch": "dispatches", "route": "routes", "handle": "handles", "process": "processes",
    "run": "runs", "execute": "runs", "exec": "runs", "invoke": "invokes", "call": "calls",
    "apply": "applies", "perform": "performs", "iter": "iterates over",
    "parse": "parses", "decode": "decodes", "deserialize": "deserializes", "unpack": "unpacks",
    "encode": "encodes", "serialize": "serializes", "dump": "serializes", "pack": "packs",
    "write": "writes", "save": "saves", "store": "stores", "persist": "persists",
    "send": "sends", "emit": "emits", "flush": "flushes", "commit": "commits",
    "validate": "validates", "check": "checks", "verify": "verifies", "ensure": "ensures",
    "sign": "signs", "unsign": "verifies the signature on", "hash": "hashes",
    "init": "initializes", "initialize": "initializes", "setup": "sets up",
    "configure": "configures", "register": "registers", "bind": "binds", "connect": "connects",
    "open": "opens", "close": "closes", "push": "pushes", "pop": "pops",
    "add": "adds", "append": "appends", "remove": "removes", "delete": "deletes",
    "update": "updates", "set": "sets", "reset": "resets", "clear": "clears",
    "preprocess": "preprocesses", "postprocess": "post-processes", "finalize": "finalizes",
    "convert": "converts", "transform": "transforms", "normalize": "normalizes",
}
# Modifier/adjective tokens that decorate an identifier without naming its action or
# object; dropped from a caption so ``full_dispatch_request`` reads "dispatches the
# request", not "dispatches the full request".
_CAPTION_FILLER = frozenset({
    "full", "do", "self", "the", "internal", "impl", "inner", "raw", "safe",
    "unsafe", "sync", "async", "maybe", "try", "helper", "default", "real",
})


def _readable_caption(name: Optional[str], *, is_entry: bool = False) -> str:
    """A short human phrase for a hop: what the step does, from its name's morphology.

    Finds the leading action verb (past any modifier like ``full``/``do``) and renders
    it in the third person over the remaining object tokens: ``make_response`` ->
    "builds the response", ``full_dispatch_request`` -> "dispatches the request",
    ``parse_args`` -> "parses the args". A name with no recognised verb reads as its
    humanized noun phrase (an entry as the place to "start"). Never a framework table --
    the same rule renders any codebase, and it degrades to the bare symbol on anything
    it cannot parse, so it only ever adds a hint, never hides the identifier.
    """
    toks = _identifier_tokens(name)
    if not toks:
        return str(name or "step")
    verb_i = None
    for i, tok in enumerate(toks):
        if tok in _VERB_READS_AS:
            verb_i = i
            break
        if tok not in _CAPTION_FILLER:
            break  # a leading noun-style token: not a verb-first name
    if verb_i is not None:
        phrase = _VERB_READS_AS[toks[verb_i]]
        obj = [t for t in toks[verb_i + 1:] if t not in _CAPTION_FILLER]
        return f"{phrase} the {' '.join(obj)}" if obj else phrase
    human = " ".join(t for t in toks if t not in _CAPTION_FILLER) or " ".join(toks)
    return f"starts at {human}" if is_entry else human

# Modules that are real product code but *peripheral* to the request lifecycle a
# reader wants first: the command-line front door, generic string/util helpers, the
# in-tree test harness (``testing.py`` -- kept in the graph, but never the headline
# lifecycle). A framework's CLI command has a long, valid execution story, so pure
# spine length floats it above the web path; demoting these modules as lifecycle
# *roots* keeps them in the bundle while letting the dispatch spine lead. Matched on
# the file's basename stem so it stays language-agnostic (cli.py, cli.js, cli.ts).
_PERIPHERAL_MODULE_STEMS = frozenset({
    "cli", "__main__", "__main", "cmd", "cmdline", "commands", "command",
    "utils", "util", "helpers", "helper", "testing", "compat", "_compat",
})


def _is_peripheral_module_path(path: Optional[str]) -> bool:
    """True when a file is product code but off the primary request lifecycle.

    A soft signal for *ranking* only -- never for inclusion. The stem set is generic
    (a CLI front-door, string/util helpers, the test harness); a segment named
    ``commands`` catches a management-command package regardless of file name.
    """
    if not path:
        return False
    p = str(path).replace("\\", "/")
    stem = p.rsplit("/", 1)[-1].rsplit(".", 1)[0].lower()
    if stem in _PERIPHERAL_MODULE_STEMS:
        return True
    segments = p.lower().split("/")
    return "commands" in segments[:-1]


def _is_error_name(name: Optional[str]) -> bool:
    return bool(_LIFECYCLE_ERROR_TOKENS.intersection(_identifier_tokens(name)))


# How many module areas the concept list surfaces. Concepts are the "areas" a reader
# would name (the request lifecycle, templates, sessions, the CLI); we bound them so a
# large tree stays legible while a small one is not padded.
_MAX_CONCEPTS = 12


def _module_stem(path: Optional[str]) -> str:
    """The bare module name of a source path: ``pkg/sessions.py`` -> ``sessions``."""
    base = str(path or "").replace("\\", "/").rsplit("/", 1)[-1]
    return base.rsplit(".", 1)[0] or base


def _concept_label(path: Optional[str], stem_counts) -> str:
    """A concept's display label from its module path.

    The module stem alone (``sessions``, ``templating``, ``cli``) is the area name a
    reader recognises. Widen to ``parent · stem`` only to break a genuine collision --
    ``app.py`` and ``sansio/app.py`` both stem to ``app`` -- so labels stay short but
    never ambiguous. Generic over any layout; never a per-framework name table.
    """
    p = str(path or "").replace("\\", "/")
    if p.startswith("src/"):
        p = p[4:]
    stem = _module_stem(p)
    if stem_counts.get(stem, 0) > 1 and "/" in p:
        parent = p.rsplit("/", 2)[-2]
        if parent:
            return f"{parent} · {stem}"
    return stem


def _story_fn_openable(fn: dict) -> bool:
    """A story step a reader can open: a real product file and a positive line.

    ``execution_story`` reports unresolved/external callees with a null file; those
    are honest frontier markers, never places to root or continue a lifecycle spine.
    """
    line = fn.get("line")
    return bool(fn.get("file")) and isinstance(line, int) and line > 0


def _reach2(index, node_id: str) -> int:
    """Distinct callees within two CALLS hops -- a cheap 'does this drive control?'.

    An orchestration root (a WSGI ``__call__``, a CLI ``main``) fans out into a
    broad two-hop cone; a leaf utility barely moves. Ranking candidate roots by this
    before paying for a full execution story elevates the real lifecycles without
    naming any framework. Bounded by the graph's own fan-out, so it stays cheap.
    """
    try:
        one = {t.get("id") for t in index.targets(node_id, *_CALL_EDGE_KINDS)
               if t.get("id")}
    except Exception:
        return 0
    total = set(one)
    for mid in one:
        try:
            total.update(t.get("id") for t in index.targets(mid, *_CALL_EDGE_KINDS)
                         if t.get("id"))
        except Exception:
            continue
    total.discard(node_id)
    return len(total)


# Source-extension -> coarse language family. JavaScript and TypeScript are one
# family (the same web frontend, the same event/handler surface); the C headers
# and sources are one family. Used only to answer "what language is this repo
# primarily", so the grouping is deliberately coarse.
_LANG_BY_EXT = {
    "py": "python", "pyi": "python", "pyx": "python",
    "js": "web", "jsx": "web", "mjs": "web", "cjs": "web",
    "ts": "web", "tsx": "web", "mts": "web", "cts": "web",
    "c": "c", "h": "c", "cc": "c", "cpp": "c", "cxx": "c",
    "hpp": "c", "hh": "c", "hxx": "c",
}


def _language_family(path: Optional[str]) -> Optional[str]:
    """The coarse language family of a source path, or None if unrecognised."""
    if not isinstance(path, str):
        return None
    base = path.replace("\\", "/").rsplit("/", 1)[-1]
    if "." not in base:
        return None
    return _LANG_BY_EXT.get(base.rsplit(".", 1)[-1].lower())


def _primary_language_family(index, gl) -> Optional[str]:
    """The dominant product-source language family of the graph, or None.

    Counts product (non-scaffolding) source files by family and returns the family
    that is a strict majority. A repo with no clear majority — a genuinely polyglot
    tree — returns None, which disables the language gate so nothing is dropped.

    This is the notion the entrypoint and request-lifecycle selection was missing:
    on a multi-language repository (a Python framework that ships bundled JavaScript
    admin widgets under ``static/``) the JS event handlers otherwise fill every
    featured slot, so a newcomer sees a JS widget toolkit instead of the Python
    request path. The gate keeps the projection in the language the repo actually is.
    """
    counts: dict[str, int] = {}
    try:
        for node in index.nodes_of_kind("file"):
            f = gl.loc(node)[0] or gl.prop(node, "file")
            if not f or _is_nonproduct_path(f):
                continue
            fam = _language_family(f)
            if fam:
                counts[fam] = counts.get(fam, 0) + 1
    except Exception:
        return None
    if not counts:
        return None
    top = max(counts, key=lambda k: counts[k])
    if counts[top] * 2 <= sum(counts.values()):
        return None  # no strict majority -> polyglot -> do not gate
    return top


# Source-extension -> the *specific* display language a reader recognises. Unlike
# ``_LANG_BY_EXT`` (which coarsens js and ts into one "web" family for projection
# gating), this keeps javascript and typescript distinct because it answers a
# different question: the single word shown as ``meta.language``.
_LANG_NAME_BY_EXT = {
    "py": "python", "pyi": "python", "pyx": "python",
    "js": "javascript", "jsx": "javascript", "mjs": "javascript", "cjs": "javascript",
    "ts": "typescript", "tsx": "typescript", "mts": "typescript", "cts": "typescript",
    "c": "c", "h": "c", "cc": "c++", "cpp": "c++", "cxx": "c++",
    "hpp": "c++", "hh": "c++", "hxx": "c++",
    "go": "go", "rs": "rust", "rb": "ruby", "java": "java", "kt": "kotlin",
    "php": "php", "cs": "c#", "swift": "swift",
}


def _language_name(path: Optional[str]) -> Optional[str]:
    """The specific display language of a source path, or None if unrecognised."""
    if not isinstance(path, str):
        return None
    base = path.replace("\\", "/").rsplit("/", 1)[-1]
    if "." not in base:
        return None
    return _LANG_NAME_BY_EXT.get(base.rsplit(".", 1)[-1].lower())


def _primary_language_name(index, gl) -> Optional[str]:
    """The repo's dominant *product* language as a display word, or None.

    Counts product (non-scaffolding) source files by specific language and returns
    the plurality. This is the honest answer to ``meta.language``: it is read off
    the repo's own files, so a repository that ships only JavaScript is labelled
    ``javascript`` even when a handful of the toolchain's own ``.d.ts`` stubs leak
    into the graph (they are ``_is_nonproduct_path`` scaffolding and never counted).
    The earlier ``census.atropos.languages[0]`` was an aggregate over *all* indexed
    files, so a single ``.d.ts`` flipped express from javascript to typescript --
    the reported defect. Returns None (caller keeps its fallback) only when no
    product source file has a recognised extension.
    """
    counts: dict[str, int] = {}
    try:
        for node in index.nodes_of_kind("file"):
            f = gl.loc(node)[0] or gl.prop(node, "file")
            if not f or _is_nonproduct_path(f):
                continue
            name = _language_name(f)
            if name:
                counts[name] = counts.get(name, 0) + 1
    except Exception:
        return None
    if not counts:
        return None
    return max(counts, key=lambda k: (counts[k], k))


# Featured "start here / read next" surfaces and the trust evidence list must name
# something a reader can act on -- a function, a method, a real sink. A def-use
# artifact instead names a single-letter local (``f``, ``e``), a traceback-walking
# internal (``tb``, ``tb.tb_frame``, ``tb.tb_next``), a bare file handle (``f.read``),
# an interpreter-internal attribute (``self.__dict__[name]``, ``__code__``), or an
# anonymous callback (``<anonymous@571>``). Surfacing these as "places to start" or as
# security "evidence" is the reported noise (B4/D7): they are real nodes in a flow but
# meaningless as a heading. This predicate flags them so the featured surfaces can
# demote them while the exhaustive ``security.findings`` envelope keeps every node.
_NOISE_LOCALS = {
    "tb", "f", "e", "ex", "exc", "err", "cb", "fn", "fp", "fh", "fd",
    "config_file", "traceback", "frame",
}


def _is_noise_surface(label: Optional[str]) -> bool:
    """True when a node label is an internal/local artifact, not a nameable surface."""
    if not isinstance(label, str):
        return False
    name = label.strip()
    if not name:
        return False
    # Anonymous callbacks/lambdas the frontend names positionally.
    if name.startswith("<anonymous") or name.startswith("<lambda") or name.startswith("("):
        return True
    lowered = name.lower()
    # Traceback-walking chains and file-handle reads (``tb``, ``tb.tb_frame``,
    # ``f.read``): the root of the attribute chain is a noise local.
    root = lowered.split("[", 1)[0].split("(", 1)[0].split(".", 1)[0].strip()
    if root in _NOISE_LOCALS:
        return True
    # ``self.__dict__[...]`` / dunder-internal access surfaced as a symbol.
    if "__dict__" in lowered or "__code__" in lowered or "f_code" in lowered or "f_globals" in lowered:
        return True
    # A single non-dunder character (``f``, ``e``) is a local, never a public surface.
    if len(name) == 1 and name.isalpha():
        return True
    return False


def _descend_trampoline(index, gl, nid: str, *,
                        primary_family: Optional[str] = None, limit: int = 4) -> str:
    """Skip thin forwarders so a lifecycle root is the real orchestrator.

    A WSGI ``Flask.__call__`` is a one-line trampoline: ``return self.wsgi_app(...)``.
    Rooting the story at it prepends a meaningless hop and, worse, makes the *entry*
    of the request the trampoline rather than the dispatcher a reader wants named.
    While the current node forwards to exactly one product callee of the repo's
    dominant language (a single direct CALLS target), descend to it. Bounded by
    ``limit`` and a ``seen`` set so a mutually-recursive pair can never loop.
    """
    seen = {nid}
    for _ in range(limit):
        try:
            callees = [t.get("id") for t in index.targets(nid, "CALLS") if t.get("id")]
        except Exception:
            return nid
        openable = []
        for cid in callees:
            if cid in seen:
                continue
            node = gl.nodes.get(cid)
            if node is None:
                continue
            f, l = gl.loc(node)[0], gl.loc(node)[1]
            if not f or not isinstance(l, int) or l <= 0 or _is_nonproduct_path(f):
                continue
            if primary_family is not None:
                fam = _language_family(f)
                if fam is not None and fam != primary_family:
                    continue
            openable.append(cid)
        if len(openable) != 1:
            return nid
        nid = openable[0]
        seen.add(nid)
    return nid


def _lifecycle_roots(index, gl, handler_ids: list[str], *, cap: int,
                     primary_family: Optional[str] = None) -> list[str]:
    """Candidate roots for request-lifecycle stories, best driver first.

    Two sources, deduped in priority order: the planner's entry handlers (already
    ranked upstream), then every product callable that nothing else in the product
    calls -- an in-degree-0 top-of-stack (a WSGI ``__call__``, an event loop, a
    public API orchestrator). The in-degree-0 set is ordered by two-hop reach so the
    orchestration roots precede the many leaf helpers that also happen to be
    uncalled once tests are excluded. Truncated to ``cap`` so the story pass is
    bounded regardless of codebase size.
    """
    # Both sources feed one ranked candidate pool. A planner handler is *not* an
    # automatic front-of-line: a framework like Click emits dozens of thin decorator
    # handlers (``version_option``, ``argument``) that each spin a valid but peripheral
    # story, and if they were kept ahead of the drivers they would fill ``cap`` and
    # starve the real dispatcher (``Command.main``, in-degree-0, widest cone) out of the
    # pass entirely. Ranking every candidate by two-hop reach means the widest-cone
    # lifecycle always survives the cap; the downstream story pass re-ranks the
    # survivors, so this ordering governs only *which* candidates it gets to see.
    candidates: list[tuple[int, str]] = []
    seen: set[str] = set()

    def _consider(nid: str, node: Optional[dict]) -> None:
        if not nid or nid in seen:
            return
        f = gl.loc(node)[0] if node is not None else None
        if node is None or _is_nonproduct_path(f):
            return  # a test/example handler is not a product lifecycle root
        if primary_family is not None:
            fam = _language_family(f)
            if fam is not None and fam != primary_family:
                return  # a non-primary-language handler (bundled JS in a Python repo)
        seen.add(nid)
        candidates.append((_reach2(index, nid), nid))

    for hid in handler_ids:
        _consider(hid, gl.nodes.get(hid) if hid else None)

    try:
        callable_nodes = list(index.nodes_of_kind("function", "method", "constructor"))
    except Exception:
        callable_nodes = []
    for node in callable_nodes:
        nid = node.get("id")
        if not nid or nid in seen:
            continue
        f, l = gl.loc(node)[0], gl.loc(node)[1]
        if not f or not isinstance(l, int) or l <= 0:
            continue
        # An uncalled test_* function is in-degree-0; exclude scaffolding so it never
        # ranks as a top-of-stack driver on a graph built without build-time exclusion.
        if _is_nonproduct_path(f):
            continue
        # ...and never a non-primary-language driver: a bundled JS handler in a
        # Python repo is in-degree-0 too, but it is not this repo's request path.
        if primary_family is not None:
            fam = _language_family(f)
            if fam is not None and fam != primary_family:
                continue
        try:
            out = sum(1 for _ in index.targets(nid, *_CALL_EDGE_KINDS))
            if out < 1:
                continue
            inn = sum(1 for _ in index.sources(nid, *_CALL_EDGE_KINDS))
        except Exception:
            continue
        if inn == 0:
            # An in-degree-0 root is often a thin WSGI/entry trampoline (Flask.__call__,
            # Click's BaseCommand.__call__); descend to the real orchestrator it forwards
            # to *before* ranking, so the driver is ordered by the dispatcher's own
            # control cone (Click's main reaches far more than its one-line __call__) and
            # the lifecycle is named at the dispatcher rather than the forwarder.
            driver = _descend_trampoline(index, gl, nid, primary_family=primary_family)
            _consider(driver, gl.nodes.get(driver))

    candidates.sort(key=lambda pair: (-pair[0], pair[1]))
    return [nid for _, nid in candidates][:cap]


def _hop_semantics(via: str, branch: dict) -> dict:
    """Per-hop reader facts from an execution-story step: how it is reached and
    whether it decides. ``reached_via`` names the call-seam boundary (a direct call
    vs a dynamic dispatch the graph resolved), and the branch summary flags a hop
    that forks control -- the decision points a newcomer traces. All derived from
    real story structure; absent facts are simply omitted so hops stay compact.
    """
    out: dict = {}
    v = via or ""
    if v == "entry":
        out["reached_via"] = "entry"
    elif v == "direct":
        out["reached_via"] = "direct call"
    elif v.startswith("indirect:"):
        out["reached_via"] = f"dynamic dispatch ({v.split(':', 1)[1] or 'resolved'})"
    elif v:
        out["reached_via"] = v
    count = branch.get("count") or 0
    if count:
        out["decides"] = True
        out["branch_count"] = count
        kinds = branch.get("kinds") or []
        if kinds:
            out["decision_kinds"] = kinds
    return out


def _story_spine(story: dict, index, gl, *, max_hops: int) -> tuple[list[str], list[str], dict]:
    """Linearize an execution story into (primary success spine, all functions, meta).

    The story is a call tree keyed by (caller -> function). The spine walks from the
    entry always choosing the direct-edge, deepest-subtree callee, deranking obvious
    error/teardown branches, so it follows the happy path (a WSGI entry down through
    dispatch to the response) rather than wandering into a handler. Every consecutive
    pair on the spine is a real edge the story observed; cycles are cut by ``seen``.
    Returns the ordered spine node ids, the flat set of every function id the story
    touched (the raw material for the architecture core), and a per-spine-node
    semantics map (how each hop is reached, whether it branches).

    ``index``/``gl`` let the walk recover call edges the story *tree* attached to a
    different parent (see ``_candidate_children``): the story visits each function
    once, so a genuine callee can hang off an earlier caller than the one whose body
    actually makes the call, and a tree-only walk could never reach it.
    """
    steps = story.get("steps") or []
    entry = (story.get("entry") or {}).get("node_id")
    if not entry:
        return [], [], {}
    children: dict[str, list[tuple[int, dict, str]]] = {}
    functions: dict[str, dict] = {}
    branches: dict[str, dict] = {}
    for step in steps:
        fn = step.get("function") or {}
        fid = fn.get("node_id")
        if not fid:
            continue
        functions[fid] = fn
        # Per-function control facts: how many decision points the body has and which
        # control kinds -- surfaced on the hop as its decision signal.
        rows = step.get("branches") or []
        kinds = sorted({r.get("control") for r in rows if r.get("control")})
        branches[fid] = {"count": step.get("branch_count") or 0, "kinds": kinds}
        caller = (step.get("caller") or {}).get("node_id")
        if caller:
            children.setdefault(caller, []).append(
                (step.get("sequence", 0), fn, step.get("via") or ""))

    def _candidate_children(node_id: str) -> list[tuple[dict, str]]:
        """Callees to consider when extending the spine from ``node_id``.

        The execution story is a *tree*: each function is attached under its
        first-discovered caller, so a real callee can hang off a different parent
        than the one whose body makes the call. Flask's ``finalize_request`` (which
        builds the response) lands under ``handle_exception`` in the tree, not under
        ``full_dispatch_request`` whose call actually reaches it -- so a walk over
        story-children alone can never route the spine to the response terminus.
        Recover the missing edges from the graph: every genuine callee of
        ``node_id`` that the story itself visited becomes a candidate, carrying its
        story fn record and a via classified from the edge kind. This invents no
        nodes (only functions already in the story are admitted) and no edges the
        graph does not hold; it merely lets the spine follow the real call an
        earlier caller happened to be credited with in the tree.
        """
        out: list[tuple[dict, str]] = []
        story_ids: set[str] = set()
        for _seq, fn, via in sorted(children.get(node_id, []), key=lambda t: t[0]):
            cid = fn.get("node_id")
            if cid:
                story_ids.add(cid)
            out.append((fn, via))
        try:
            direct = {t.get("id") for t in index.targets(node_id, _CALL_EDGE_KINDS[0])
                      if t.get("id")}
            callees = [t.get("id") for t in index.targets(node_id, *_CALL_EDGE_KINDS)
                       if t.get("id")]
        except Exception:
            return out
        added: set[str] = set()
        for t in callees:
            if t in story_ids or t in added or t not in functions:
                continue
            added.add(t)
            out.append((functions[t],
                        "direct" if t in direct else "indirect:may_invoke"))
        return out

    memo: dict[str, int] = {}

    def subtree(nid: str, guard: frozenset) -> int:
        if nid in memo:
            return memo[nid]
        if nid in guard:
            return 0
        deeper = guard | {nid}
        total = 0
        for _, fn, _via in children.get(nid, []):
            cid = fn.get("node_id")
            if cid:
                total += 1 + subtree(cid, deeper)
        # Only cache when no guard cycle influenced the count (guard was the path
        # to nid); good enough as a heuristic ranker and keeps the walk bounded.
        memo[nid] = total
        return total

    reach_memo: dict[str, bool] = {}

    def reaches_result(nid: str, guard: frozenset) -> bool:
        """Does this subtree build the value the request returns? A response, a
        rendered page, a serialized result -- recognised by morphology (see
        ``_is_result_construction``), so the spine can end at the response terminus
        rather than in a routing corner. Bounded and cycle-guarded like ``subtree``.
        """
        if nid in reach_memo:
            return reach_memo[nid]
        if nid in guard:
            return False
        if _is_result_construction((functions.get(nid) or {}).get("name")):
            reach_memo[nid] = True
            return True
        deeper = guard | {nid}
        found = any(cid and reaches_result(cid, deeper)
                    for _, fn, _via in children.get(nid, [])
                    for cid in (fn.get("node_id"),))
        reach_memo[nid] = found
        return found

    spine = [entry]
    seen = {entry}
    cur = entry
    meta: dict[str, dict] = {entry: _hop_semantics("entry", branches.get(entry) or {})}
    while len(spine) < max_hops:
        kids = [(fn, via)
                for fn, via in _candidate_children(cur)
                if fn.get("node_id") not in seen and _story_fn_openable(fn)]
        if not kids:
            break
        # Rank each candidate hop, best first, by five generic signals:
        #  1. a direct CALLS edge is the real control flow; ``indirect:may_invoke``
        #     hops are duck-typed over-approximations (a session deserialize, a JSON
        #     dump that *might* run), so direct wins;
        #  2. error/teardown branches derank (real, but not the success path);
        #  3. special-case/fallback branches derank next (an auto OPTIONS reply, a
        #     not-found stub -- a corner, not the ordinary request);
        #  4. a branch that reaches the response/result construction is preferred, so
        #     the spine ends where the request builds what it returns
        #     (full_dispatch_request -> finalize_request -> make_response) rather than
        #     tunnelling into the widest routing subtree and stopping at a corner;
        #  5. the deepest subtree breaks any remaining tie.
        # Every signal is morphology over the identifier, never a framework symbol.
        pick = max(kids, key=lambda kv: (
            1 if kv[1] == "direct" else 0,
            0 if _is_error_name(kv[0].get("name")) else 1,
            0 if _is_fallback_name(kv[0].get("name")) else 1,
            1 if reaches_result(kv[0].get("node_id"), frozenset()) else 0,
            subtree(kv[0].get("node_id"), frozenset())))
        nid = pick[0].get("node_id")
        meta[nid] = _hop_semantics(pick[1], branches.get(nid) or {})
        cur = nid
        seen.add(nid)
        spine.append(nid)
    ordered_functions = [fid for fid in functions if _story_fn_openable(functions[fid])]
    return spine, ordered_functions, meta


def _lifecycle_projection(asm: "_Assembler", index, gl, handler_ids: list[str], *,
                          max_requests: int, max_core: int,
                          max_hops: int,
                          primary_family: Optional[str] = None) -> tuple[list[dict], list[dict]]:
    """Request lifecycles and the architecture core, from bounded execution stories.

    Runs a bounded forward execution story from each candidate driver (see
    ``_lifecycle_roots``), ranks them by how much real control each covers (spine
    length, then breadth), and keeps the deepest few as guided request paths -- each
    the success spine of one story, every consecutive hop a real observed edge. A
    shallower story whose root already sits inside a kept spine is skipped, so we do
    not emit both ``__call__ -> wsgi_app -> ...`` and its ``wsgi_app -> ...`` suffix.
    The union of every kept story's functions, bounded, becomes the core spine a
    newcomer reads first. Best-effort: any failure yields empty lists, never raises.
    """
    requests: list[dict] = []
    core: list[dict] = []
    try:
        roots = _lifecycle_roots(index, gl, handler_ids, cap=30,
                                 primary_family=primary_family)
    except Exception:
        return requests, core

    ranked: list[tuple[int, int, int, int, str, list[str], list[str], dict]] = []
    for root in roots:
        try:
            story = _call("execution_story",
                          {"entry": root, "max_depth": max_hops + 2,
                           "max_steps": 120, "format": "json"})
        except Exception:
            continue
        if not isinstance(story, dict):
            continue
        spine, functions, meta = _story_spine(story, index, gl, max_hops=max_hops)
        if len(spine) < 2:
            continue
        # A peripheral root (a CLI command, a util helper) still yields a long, valid
        # story, so ranking on spine length alone floats it above the web request path
        # a reader opened the bundle to see. Demote by the root's module so the primary
        # dispatch lifecycle leads; the peripheral path is kept, just not first.
        root_file = gl.loc(gl.nodes.get(root))[0] if gl.nodes.get(root) else None
        demote = 1 if _is_peripheral_module_path(root_file) else 0
        # The dispatcher a reader wants first is the top-of-stack that drives the most
        # code, not whichever helper happens to keep the longest in-library spine. The
        # true lifecycle (Flask.wsgi_app, Click's Command.main -> invoke) exits to
        # external user code quickly, so its openable spine is *short* even though its
        # control cone is the widest; a string helper (secho -> echo -> isatty) stays
        # in-library and spins a longer spine. Ranking by 2-hop reach first puts the
        # real driver on top; spine length only breaks ties between comparable drivers.
        reach = _reach2(index, root)
        ranked.append((demote, -reach, len(spine), len(functions), root, spine, functions, meta))

    # Primary lifecycles first (widest control cone), then deepest, then broadest.
    ranked.sort(key=lambda row: (row[0], row[1], -row[2], -row[3], row[4]))

    node_ids = set(asm.nodes)
    covered: set[str] = set()
    core_ids: set[str] = set()
    used_ids: set[str] = set()
    for _, _, _, _, root, spine, functions, meta in ranked:
        if len(requests) >= max_requests:
            break
        if root in covered:  # a redundant suffix of a spine already shown
            continue
        hops: list[dict] = []
        chain_ids: list[str] = []
        for nid in spine:
            node = gl.nodes.get(nid)
            if node is None:
                continue
            asm.add_node(_norm_node(gl, node), default_kind="function")
            node_ids.add(nid)
            label = gl.label(node)
            # ``caption`` stays the exact symbol (a reader can grep it); ``reads_as``
            # adds a human phrase derived from the symbol's morphology, so the hop
            # says what the step does ("dispatches the request") without hiding the
            # identifier. First hop on the spine is the entry -- phrased as a start.
            hop = {"node_id": nid, "caption": label,
                   "reads_as": _readable_caption(label, is_entry=not hops)}
            hop.update(meta.get(nid) or {})
            hops.append(hop)
            chain_ids.append(nid)
        if len(hops) < 2:
            continue
        for a, b in zip(chain_ids, chain_ids[1:]):
            asm.add_edge({"src": a, "tgt": b, "kind": "CALLS"}, node_ids)
        covered.update(chain_ids)
        root_label = gl.label(gl.nodes.get(root)) or "entry"
        rid = f"request.{_slug(root_label)}"
        if rid in used_ids:
            rid = f"{rid}.{_slug(root)}"
        used_ids.add(rid)
        requests.append({
            "id": rid,
            "kind": "call-path",
            "description": f"Request lifecycle from {root_label} through "
                           f"{len(hops) - 1} call(s).",
            "entry_node": root,
            "hops": hops,
        })
        # The architecture core draws from every kept story's functions, spine first.
        for nid in [*chain_ids, *(f for f in functions if f not in chain_ids)]:
            if len(core_ids) >= max_core:
                break
            if nid in core_ids:
                continue
            node = gl.nodes.get(nid)
            if node is None:
                continue
            f, l = gl.loc(node)[0], gl.loc(node)[1]
            if not f or not isinstance(l, int) or l <= 0:
                continue
            if _is_nonproduct_path(f):
                continue  # keep scaffolding off the architecture core
            asm.add_node(_norm_node(gl, node), default_kind="function")
            node_ids.add(nid)
            try:
                degree = sum(1 for _ in index.targets(nid, *_CALL_EDGE_KINDS))
            except Exception:
                degree = 0
            core.append({"node_id": nid, "label": gl.label(node),
                         "file": f, "line": l, "degree": degree})
            core_ids.add(nid)
    return requests, core


def _api_rank(anchor: dict) -> tuple:
    """Public-API preference used to break ties *within* an anchor tier (H7).

    ``_anchor_strength`` already orders the tiers (route > callback > exported), so a
    route-anchored framework (flask, express) never reaches this and cannot regress.
    It matters inside the ``exported-entry`` tier, where "exported callable nothing
    calls" is a coarse net: a getattr-dispatched visitor family -- jinja's
    ``CodeGenerator.visit_CallBlock`` / ``visit_For`` and its ~48 siblings -- is
    exported and never statically called, so it otherwise floods "a useful place to
    start" ahead of the real public surface (``Environment``, ``Template``). A
    newcomer starts from a class/decorator/factory, not one dispatch method, so we
    prefer, in order: a class/interface, then a plain function, then a constructor,
    then a method; and within any kind, demote dunder and dispatch-prefixed names
    (``visit_*``/``_*``) below ordinary public names. Ordering only -- which
    entrypoints exist is unchanged.
    """
    kind = (anchor.get("anchor_kind") or "").lower()
    kind_rank = {"class": 0, "interface": 0, "enum": 0, "type": 0,
                 "function": 1, "constructor": 2, "method": 3}.get(kind, 4)
    label = (anchor.get("anchor_label") or "")
    leaf = label.rsplit(".", 1)[-1] if "." in label else label
    dispatchy = 1 if (leaf.startswith("visit_") or leaf.startswith("_")) else 0
    return (dispatchy, kind_rank)


def _comprehension_projection(asm: "_Assembler", *, max_entrypoints: int,
                              chain_depth: int, max_files: int) -> dict:
    """Entrypoints, guided request paths, files and modules for the 2.0 bundle.

    Adds every node it references (entry handlers and each request hop) to ``asm``
    and, for each request path, the real ``CALLS`` edges between consecutive hops --
    so the graph-first validator finds all of them resolvable. Returns empty lists,
    never raises: a graph the comprehension layer cannot walk simply reads as a bare
    graph rather than failing the whole export.
    """
    empty = {"entrypoints": [], "requests": [], "files": [], "modules": [], "concepts": [], "core": []}
    try:
        from lachesis.planner.entrypoints import EntryPoints, _anchor_strength
        ctx = M.ctx()
        store, gl, index = ctx.store, ctx.store.gl, ctx.store.index
        comp = ctx.comprehension
    except Exception:
        return empty

    # The repo's dominant product language. A multi-language tree (a Python framework
    # that bundles JavaScript admin widgets) otherwise features the wrong language:
    # its JS event handlers rank as entrypoints and fill every request flow. Gating to
    # the primary family keeps the projection in the language the repo actually is.
    primary_family = _primary_language_family(index, gl)

    entrypoints: list[dict] = []
    requests: list[dict] = []
    used_ids: set[str] = set()
    try:
        by_handler = EntryPoints(store).by_handler()
        # Strongest anchor per handler, then a stable global order over handlers.
        best = {hid: sorted(rows, key=_anchor_strength)[0]
                for hid, rows in by_handler.items() if rows}
        ordered = sorted(best.items(),
                         key=lambda kv: (_anchor_strength(kv[1]), _api_rank(kv[1]),
                                         kv[1].get("file") or "", kv[1].get("anchor_label") or "",
                                         kv[0]))
        for handler_id, anchor in ordered:
            if len(entrypoints) >= max_entrypoints:
                break
            node = gl.nodes.get(handler_id)
            if node is None:
                continue
            nfile, nline = gl.loc(node)[0], gl.loc(node)[1]
            # A code-understanding entrypoint must be openable: it needs a real
            # file and line, or it is not a place a developer can actually begin.
            if not nfile or not isinstance(nline, int) or nline <= 0:
                continue
            # ...and it must be product code -- never a test/example handler.
            if _is_nonproduct_path(nfile):
                continue
            # ...and in the repo's primary language -- never a bundled JS admin
            # widget standing in for the request path of a Python framework.
            if primary_family is not None:
                fam = _language_family(nfile)
                if fam is not None and fam != primary_family:
                    continue
            asm.add_node(_norm_node(gl, node), default_kind="function")
            how = anchor.get("how")
            label = gl.label(node)
            eid = f"entry.{_slug(label)}"
            if eid in used_ids:
                eid = f"{eid}.{_slug(handler_id)}"
            used_ids.add(eid)
            try:
                efile = comp._relative_path(nfile) or anchor.get("file") or nfile
            except Exception:
                efile = anchor.get("file") or nfile
            entrypoints.append({
                "id": eid,
                "label": label,
                "kind": _ENTRY_KIND.get(how, "entrypoint"),
                "node_id": handler_id,
                "file": efile,
                "line": nline,
            })
    except Exception:
        pass

    # Guided request paths are no longer a greedy CALLS walk out of each exported
    # symbol -- that surfaced leaf utilities (render_template) and never the request
    # lifecycle. Instead root them at the real top-of-stack drivers and follow the
    # success spine of each one's bounded execution story (wsgi __call__ -> wsgi_app
    # -> full_dispatch_request -> dispatch_request -> ...). The same stories yield the
    # architecture core, so both are built together below.
    handler_ids = [entry["node_id"] for entry in entrypoints]
    requests, core = _lifecycle_projection(
        asm, index, gl, handler_ids,
        max_requests=8, max_core=32, max_hops=max(2, chain_depth),
        primary_family=primary_family)

    # Promote each lifecycle root to an entrypoint. ``by_handler`` only recognises
    # module-level public helpers, so a framework's real request driver -- a WSGI
    # ``Flask.wsgi_app``, an event loop -- is *never* an anchored handler and would
    # otherwise be a request whose entry is nowhere in the entrypoint set. These
    # drivers are the truest "begin reading here" nodes, so they lead the list. This
    # also gives a library with no anchored handler at all (itsdangerous) a real,
    # source-backed entrypoint, which the code-understanding contract requires.
    entry_node_ids = {entry["node_id"] for entry in entrypoints}
    promoted: list[dict] = []
    for req in requests:
        root = req.get("entry_node")
        if not root or root in entry_node_ids:
            continue
        node = gl.nodes.get(root)
        if node is None:
            continue
        nfile, nline = gl.loc(node)[0], gl.loc(node)[1]
        if not nfile or not isinstance(nline, int) or nline <= 0:
            continue
        if _is_nonproduct_path(nfile):
            continue
        if primary_family is not None:
            fam = _language_family(nfile)
            if fam is not None and fam != primary_family:
                continue
        entry_node_ids.add(root)
        label = gl.label(node)
        eid = f"entry.{_slug(label)}"
        if eid in used_ids:
            eid = f"{eid}.{_slug(root)}"
        used_ids.add(eid)
        try:
            efile = comp._relative_path(nfile) or nfile
        except Exception:
            efile = nfile
        promoted.append({
            "id": eid,
            "label": label,
            "kind": "request-lifecycle",
            "node_id": root,
            "file": efile,
            "line": nline,
        })
    entrypoints = promoted + entrypoints

    files: list[dict] = []
    try:
        seen_paths: set[str] = set()
        for node in index.nodes_of_kind("file"):
            raw = gl.loc(node)[0] or gl.prop(node, "file")
            # Scaffolding and vendored/toolchain files (the compiler's own
            # ``node_modules/typescript/lib/*.d.ts`` stubs) must not appear in the
            # file inventory a reader browses -- test the raw path before
            # relativization strips the ``node_modules`` marker that identifies them.
            if _is_nonproduct_path(raw):
                continue
            path = comp._relative_path(raw)
            if not path or path in seen_paths or _is_nonproduct_path(path):
                continue
            seen_paths.add(path)
            files.append({"id": node.get("id"), "path": path})
        files.sort(key=lambda f: f["path"])
        if len(files) > max_files:
            files = files[:max_files]
    except Exception:
        files = []

    # Concepts are the module *areas* a newcomer would name: the request lifecycle,
    # routing, request context, templates, sessions, the CLI. Call-community
    # clustering is too coarse here -- a flat single-package framework (every file in
    # one directory) collapses into one giant community, so the whole request path,
    # templating and session code read as a single undifferentiated blob. Derive areas
    # from the *modules* instead: one concept per product file, ranked by how much it
    # defines (definition count, then path for a stable order), capped at
    # ``_MAX_CONCEPTS``. Fully generic -- the busiest modules of any codebase are its
    # areas, named by their own path, never a framework symbol table -- and it degrades
    # to an empty list, never raises. Ranking on the definition count alone keeps this a
    # single cheap node scan (no per-node graph query), so it stays bounded on a large
    # tree where an edge lookup per function would dominate the export.
    concepts: list[dict] = []
    try:
        import collections as _collections
        defs: "_collections.Counter" = _collections.Counter()
        for node in index.nodes_of_kind("function", "method", "constructor"):
            f = gl.loc(node)[0]
            if not f or _is_nonproduct_path(f):
                continue
            if primary_family is not None:
                fam = _language_family(f)
                if fam is not None and fam != primary_family:
                    continue  # keep the concept list in the repo's own language
            try:
                rel = comp._relative_path(f) or f
            except Exception:
                rel = f
            defs[rel] += 1
        ranked_modules = sorted(defs.items(), key=lambda kv: (-kv[1], kv[0]))
        top = ranked_modules[:_MAX_CONCEPTS]
        stem_counts = _collections.Counter(_module_stem(rel) for rel, _ in top)
        for rel, n in top:
            concepts.append({
                "id": f"concept.{_slug(rel)}",
                "label": _concept_label(rel, stem_counts),
                "description": f"The {_module_stem(rel)} module ({n} definition(s)).",
                "file_paths": [rel],
            })
    except Exception:
        concepts = []

    # Module anchors (B7): guarantee the architecture map shows *every* product
    # module, not only those the request-lifecycle spine happens to traverse.
    # ``_partition_modules`` builds one module per file that owns an *included* node,
    # so a core module a newcomer expects (flask.globals -> request/session/g,
    # flask.views -> View/MethodView, flask.wrappers -> Request/Response) silently
    # vanished from the map whenever no featured path passed through it -- 10 of
    # flask's 24 modules were dropped. The fix is to seed one representative, openable
    # definition from each otherwise-unrepresented product module into the shared
    # pool, so the module surfaces with a real "begin reading here" node. The module
    # validator requires every module node to be an included node, so the map can only
    # be completed by adding these anchors, not by inventing empty modules.
    try:
        import collections as _collections2
        # A file is already represented when any pool node (candidate, capsule, entry,
        # request hop) lives in it. Pool files are still absolute here (relativization
        # runs later), matching ``gl.loc``'s absolute paths.
        represented = {n.get("file") for n in asm.nodes.values() if n.get("file")}
        # Best openable definition per product file: prefer a type/class, then the
        # earliest top-of-file definition, so the anchor is the module's most
        # recognisable name. Interface/type/enum are included so a *type-only*
        # TypeScript module -- a ``types/options.ts`` that declares the public
        # ``Options`` config object but no runtime code -- is seeded and surfaces as a
        # module, instead of being dropped for owning no function/class node.
        _KIND_RANK = {"class": 0, "interface": 1, "constructor": 2,
                      "type": 3, "enum": 3, "function": 4, "method": 5}
        best_anchor: dict[str, dict] = {}
        best_rank: dict[str, tuple] = {}
        for node in index.nodes_of_kind("class", "constructor", "function", "method",
                                        "interface", "type", "enum"):
            f, l = gl.loc(node)[0], gl.loc(node)[1]
            if not f or not isinstance(l, int) or l <= 0 or _is_nonproduct_path(f):
                continue
            if f in represented:
                continue  # module already has an included node -- no anchor needed
            if primary_family is not None:
                fam = _language_family(f)
                if fam is not None and fam != primary_family:
                    continue  # keep the map in the repo's own language
            rank = (_KIND_RANK.get(gl.kind(node.get("id")), 6), l)
            if f not in best_rank or rank < best_rank[f]:
                best_rank[f] = rank
                best_anchor[f] = node
        for node in best_anchor.values():
            asm.add_node(_norm_node(gl, node), default_kind="function")
    except Exception:
        pass

    # Modules are not built here: they must partition the *final* included node
    # pool (one unambiguous module per node, keyed by that node's file), which is
    # only settled after candidate/capsule/entry nodes are all in and relativized.
    return {"entrypoints": entrypoints, "requests": requests, "files": files,
            "concepts": concepts, "core": core}


# ------------------------------------------------------- source / node enrichment

_EDGE_KIND_CANON = {
    "CALLS": "calls",
    "VALUE_FLOWS_TO": "flows to",
    "DYNAMIC_INPUT": "dynamic input",
    "REACHING_DEF": "reaching def",
    "ALIAS": "aliases",
}
_SOURCE_WINDOW_CONTEXT = 2
_SOURCE_WINDOW_MAX_LINES = 60


def _canon_edge_kind(kind: Optional[str]) -> str:
    if not kind:
        return "relates to"
    return _EDGE_KIND_CANON.get(kind, str(kind).lower().replace("_", " "))


def _dotted_module(path: Optional[str]) -> Optional[str]:
    """A dotted module name from a repo-relative source path (best effort)."""
    if not isinstance(path, str) or not path:
        return None
    p = path.replace("\\", "/")
    for prefix in ("src/", "lib/", "./"):
        if p.startswith(prefix):
            p = p[len(prefix):]
    # Drop the extension. A TypeScript declaration file carries a *double*
    # extension (``index.d.ts``); splitting on the last dot alone leaves ``index.d``
    # and names the module after a stray ``d``. Treat ``.d.ts`` as one unit so the
    # module reads as ``index``, not ``index.d``.
    if p[-5:].lower() == ".d.ts":
        p = p[:-5]
    else:
        p = p.rsplit(".", 1)[0]
    if p.endswith("/__init__"):
        p = p[: -len("/__init__")]
    return p.strip("/").replace("/", ".") or None


def _source_window(gl, node: dict) -> Optional[dict]:
    """A small, highlighted source window around a node, read from disk.

    Returns ``{start_line, lines, highlight_start, highlight_end}`` with 1-based
    highlight offsets into ``lines``, or None when the file or span is unavailable.
    Bounded to ``_SOURCE_WINDOW_MAX_LINES`` so a huge function body cannot bloat the
    bundle; the highlight is clamped into whatever window survives that bound.
    """
    props = node.get("properties") or {}
    abs_path = props.get("absolute_file") or props.get("file")
    start = props.get("start_line")
    end = props.get("end_line") or start
    if not abs_path or not isinstance(start, int) or start <= 0:
        return None
    try:
        text = gl._read_file(abs_path)
    except Exception:
        text = None
    if not text:
        return None
    lines = text.splitlines()
    if not lines:
        return None
    win_start = max(1, start - _SOURCE_WINDOW_CONTEXT)
    win_end = min(len(lines), max(start, int(end or start)))
    if win_end - win_start + 1 > _SOURCE_WINDOW_MAX_LINES:
        win_end = win_start + _SOURCE_WINDOW_MAX_LINES - 1
    window = lines[win_start - 1:win_end]
    if not window:
        return None
    return {
        "start_line": win_start,
        "lines": window,
        "highlight_start": start - win_start + 1,
        "highlight_end": min(int(end or start), win_end) - win_start + 1,
    }


def _count_source_lines(index, gl) -> int:
    """Physical source lines across the indexed files, for ``meta.loc``/``lines``.

    Counts each distinct file once. The count is the file's real line count read
    off disk (via the graph library's cached reader, so it shares reads with the
    source windows and adds no second pass); when a file cannot be read we fall
    back to its file-node span end, which the frontends record as the last line.
    Returns 0 when the graph carries no readable file nodes -- honest, not a guess.
    """
    total = 0
    seen: set[str] = set()
    for node in index.nodes_of_kind("file"):
        props = node.get("properties") or {}
        abs_path = props.get("absolute_file") or props.get("file")
        key = abs_path or props.get("file")
        if not key or key in seen:
            continue
        seen.add(key)
        # Scaffolding and vendored/toolchain files must not inflate the repo's line
        # count -- the compiler's own ``typescript/lib/*.d.ts`` stubs added ~45k lines
        # to express's real 2,773 (a 17x overcount). Test both the display and
        # absolute path so the ``node_modules`` marker and the ``.d.ts`` suffix are
        # each caught.
        if _is_nonproduct_path(props.get("file")) or _is_nonproduct_path(abs_path):
            continue
        count = 0
        if abs_path:
            try:
                text = gl._read_file(abs_path)
            except Exception:
                text = None
            if text:
                count = len(text.splitlines())
        if count == 0:
            end = props.get("end_line")
            if isinstance(end, int) and end > 0:
                count = end
        total += count
    return total


def _enrich_graph_nodes(nodes: list[dict], gl) -> None:
    """Attach comprehension detail (end_line, qualified_name, module, source window).

    Mutates each bundle node in place from its graph-library twin. A node with no
    twin (a synthetic value with no declaration) is left as-is -- it simply carries
    no source, which the featured-path gate then accounts for honestly.
    """
    for node in nodes:
        twin = gl.nodes.get(node.get("id"))
        if twin is None:
            continue
        _file, _start, end_line = gl.loc(twin)
        if isinstance(end_line, int) and end_line > 0:
            node["end_line"] = end_line
        module = _dotted_module(node.get("file"))
        if module:
            node["qualified_name"] = f"{module}.{node.get('label')}"
        # Scope: the enclosing callable every node lives in (problem #6 -- scope was
        # absent on most nodes). owner_function returns the node itself when it is
        # already a callable, so a function/method reports the module it belongs to,
        # while an operand or a value reports the function that contains it. This is
        # the container a frontend groups by, never an empty field.
        try:
            owner = gl.owner_function(twin)
        except Exception:
            owner = None
        scope = None
        if owner is not None and owner.get("id") != twin.get("id"):
            owner_file, _os, _oe = gl.loc(owner)
            owner_module = _dotted_module(owner_file)
            owner_label = gl.label(owner)
            scope = f"{owner_module}.{owner_label}" if owner_module else owner_label
        if not scope:
            scope = module
        if scope:
            node["scope"] = scope
        # A synthetic node (heap object/location, interprocedural-context binding)
        # reaches this projection with no file of its own. Anchor it to the real site
        # it derives from so it opens at a real location instead of a blank the bundle
        # contract would reject.
        if not (isinstance(node.get("file"), str) and node["file"].strip()):
            anchor_file, anchor_line = _anchor_location(gl, twin)
            if anchor_file:
                node["file"] = anchor_file
                if not (isinstance(node.get("line"), int) and node["line"] > 0):
                    node["line"] = anchor_line
        for key in ("documentation", "docstring", "comment"):
            try:
                documentation = gl.prop(twin, key)
            except Exception:
                documentation = None
            if isinstance(documentation, str) and documentation.strip():
                node["documentation"] = documentation.strip()
                break
        try:
            excerpt = gl.source_excerpt(twin)
        except Exception:
            excerpt = ""
        if excerpt:
            node["snippet"] = excerpt
        window = _source_window(gl, twin)
        if window:
            node["source_window"] = window


def _has_source(node: dict) -> bool:
    """A node a code-understanding path may feature: openable and with real text."""
    if not node:
        return False
    if not isinstance(node.get("file"), str) or not node["file"].strip():
        return False
    line = node.get("line")
    if not isinstance(line, int) or line <= 0:
        return False
    window = node.get("source_window") or {}
    return bool(window.get("lines") or (node.get("snippet") or "").strip())


def _canonical_edges(raw_edges: list[dict], node_ids: set[str]) -> list[dict]:
    """Raw assembler edges -> first-class explorer edges (kind canonical + relation)."""
    out: list[dict] = []
    seen: set[str] = set()
    for e in raw_edges:
        s, t = e.get("source"), e.get("target")
        if s not in node_ids or t not in node_ids:
            continue
        kind = _canon_edge_kind(e.get("kind"))
        eid = "edge." + hashlib.sha1(
            f"{s}\0{t}\0{kind}".encode("utf-8")).hexdigest()[:16]
        if eid in seen:
            continue
        seen.add(eid)
        dynamic = bool(e.get("dynamic"))
        limitations = ["target resolved by dynamic dispatch"] if dynamic else []
        out.append({
            "id": eid,
            "source": s,
            "target": t,
            "kind": kind,
            "relation": kind,  # compatibility alias; `kind` is canonical
            "confidence": "conservative" if dynamic else "high",
            "dynamic": dynamic,
            "alias": bool(e.get("alias")),
            "limitations": limitations,
        })
    return out


def _edge_label(edges_by_pair: dict, a: str, b: str) -> str:
    e = edges_by_pair.get((a, b))
    return e["kind"] if e else "calls"


def _finalize_requests(raw_requests: list[dict], node_map: dict,
                       edges_by_pair: dict) -> list[dict]:
    """Gate + decorate guided request paths.

    A path survives only when every hop is a source-backed node; then each hop gets
    a stable id and the label of the edge that reached it, and the path gets the
    ``source_node``/``sink_node`` endpoints (guaranteed to occur in the hops) plus an
    honest confidence and limitation. A path with a node we cannot open is dropped
    rather than shown without source -- the code-understanding contract is strict.
    """
    out: list[dict] = []
    for req in raw_requests:
        hops = req.get("hops") or []
        if len(hops) < 2:
            continue
        if any(not _has_source(node_map.get(h.get("node_id"))) for h in hops):
            continue
        rid = req.get("id")
        decorated = []
        for i, hop in enumerate(hops, start=1):
            nid = hop.get("node_id")
            entry = {"id": f"{rid}:{i:02d}", "node_id": nid,
                     "caption": hop.get("caption")}
            if hop.get("reads_as"):
                entry["reads_as"] = hop["reads_as"]
            # Carry the story-derived hop semantics (how this hop is reached, whether
            # it forks control) through decoration so a reader sees the call-seam and
            # decision points, not just an ordered list of names.
            for key in ("reached_via", "decides", "branch_count", "decision_kinds"):
                if hop.get(key) is not None:
                    entry[key] = hop[key]
            if i > 1:
                entry["edge_label"] = _edge_label(
                    edges_by_pair, hops[i - 2].get("node_id"), nid)
            decorated.append(entry)
        out.append({
            "id": rid,
            "kind": req.get("kind") or "call-path",
            "description": req.get("description"),
            "entry_node": req.get("entry_node"),
            "source_node": hops[0].get("node_id"),
            "sink_node": hops[-1].get("node_id"),
            "confidence": "high",
            "limitations": ["Callees reached only by dynamic dispatch may be omitted."],
            "hops": decorated,
        })
    return out


# The node kinds that are genuine *declarations* a reader would count as a module's
# API surface -- a definition they can open and read -- across the languages the
# frontends cover (Python/C: class/function/method/enum; TypeScript adds the pure
# type surface interface/type). Everything else a module owns (heap objects, value
# nodes, interprocedural-context bindings) is dataflow projection, not a definition.
_DEFINITION_KINDS = frozenset({
    "class", "constructor", "function", "method", "interface", "type", "enum",
})


def _partition_modules(nodes: list[dict], entrypoints: list[dict]) -> list[dict]:
    """One unambiguous module per included node, keyed by that node's file.

    Every concrete (file-bearing) node lands in exactly one module -- the module of
    its file -- so no node is ever repeated across modules. A module anchored by an
    entrypoint carries that entry's node id, giving a reader a place to start.

    Each module reports both a ``definition_count`` (declarations it owns) and a
    ``symbol_count`` (all projected nodes), and the list is ordered by declarations
    first. The two counts must stay distinct: a module's total projected-node count
    mixes declarations with dataflow/heap nodes, so a tiny but dataflow-heavy file
    (jinja2.bccache: 6 real definitions, ~47 value/heap nodes) otherwise outweighs a
    large one (jinja2.compiler: 34 definitions) on every "start here" surface. Ranking
    by declarations puts the module a newcomer should read first at the top.
    """
    anchor_by_file: dict[str, str] = {}
    for ep in entrypoints:
        f = ep.get("file")
        if isinstance(f, str) and f not in anchor_by_file:
            anchor_by_file[f] = ep.get("node_id")

    kind_by_id = {n.get("id"): (n.get("kind") or "") for n in nodes}
    groups: dict[str, list[str]] = {}
    for node in nodes:
        f = node.get("file")
        if not isinstance(f, str) or not f.strip():
            continue
        # Non-product files (tests, docs, examples, vendored deps, generated output)
        # must not surface as modules a reader is invited to explore. The same gate the
        # entrypoint/request selection uses, applied to the module partition.
        if _is_nonproduct_path(f):
            continue
        module_name = _dotted_module(f) or f
        node["module"] = module_name
        groups.setdefault(f, []).append(node["id"])

    modules: list[dict] = []
    for path in sorted(groups):
        module_name = _dotted_module(path) or path
        node_ids = groups[path]
        definition_count = sum(1 for nid in node_ids
                               if kind_by_id.get(nid) in _DEFINITION_KINDS)
        module = {
            "id": f"module.{_slug(module_name)}",
            "name": module_name,
            "path": path,
            "node_ids": node_ids,
            "definition_count": definition_count,
            "symbol_count": len(node_ids),
        }
        anchor = anchor_by_file.get(path)
        if anchor:
            module["anchor_node_id"] = anchor
        modules.append(module)
    # Declarations first (the reader's "how big / where to start" signal), then a
    # stable dotted-name order so equal-sized modules keep a deterministic layout.
    modules.sort(key=lambda m: (-m["definition_count"], m["name"]))
    return modules


def _project_concepts(raw_concepts: list[dict], nodes: list[dict]) -> list[dict]:
    """Keep architecture concepts honest to the final included node pool.

    A concept is dropped entirely when every file it spans is non-product, and its
    node set is restricted to product files, so a vendored dependency
    (``node_modules · typescript · lib``), a build config (``rollup.config.js``), or a
    docs/scripts tree never surfaces as an architecture concept — even on a graph
    built without build-time exclusion.
    """
    out: list[dict] = []
    for concept in raw_concepts or []:
        paths = {str(path) for path in concept.get("file_paths") or [] if path
                 and not _is_nonproduct_path(str(path))}
        if not paths:
            continue
        node_ids = [node["id"] for node in nodes
                    if isinstance(node.get("file"), str) and node.get("file") in paths
                    and not _is_nonproduct_path(node.get("file"))]
        if not node_ids:
            continue
        out.append({
            "id": str(concept.get("id") or f"concept.{len(out)}"),
            "label": str(concept.get("label") or "Code area"),
            "description": str(concept.get("description") or "Connected code area."),
            "node_ids": node_ids[:20],
        })
    return out


def _project_curated_tour(raw: Optional[dict], values: list[dict], requests: list[dict]) -> Optional[dict]:
    """Keep only tour steps that resolve in this exact exported projection.

    Tour files are user-authored convenience metadata, not evidence. A changed
    repository can make an old flow or anchor disappear, so stale steps are
    omitted instead of making the entire export fail. Maintainer identity is
    deliberately not accepted from this unauthenticated file path.
    """
    if not isinstance(raw, dict):
        return None
    title = str(raw.get("title") or "Start here").strip()
    tour_id = str(raw.get("id") or "tour.start-here").strip()
    if not title or not tour_id:
        return None
    paths = {str(path.get("id")): path for path in [*values, *requests]
             if isinstance(path, dict) and path.get("id")}
    steps: list[dict] = []
    for item in raw.get("steps") or []:
        if not isinstance(item, dict):
            continue
        flow_id = str(item.get("flow_id") or item.get("flowId") or "").strip()
        path = paths.get(flow_id)
        if not path:
            continue
        raw_steps = path.get("steps") if isinstance(path.get("steps"), list) else path.get("hops")
        node_ids = {str(step.get("node_id")) for step in raw_steps or []
                    if isinstance(step, dict) and step.get("node_id")}
        node_id = item.get("node_id") or item.get("nodeId")
        if node_id is not None and str(node_id) not in node_ids:
            continue
        step = {"flow_id": flow_id}
        if node_id is not None:
            step["node_id"] = str(node_id)
        for key in ("label", "note"):
            if item.get(key) is not None and str(item[key]).strip():
                step[key] = str(item[key]).strip()
        steps.append(step)
    if not steps:
        return None
    result = {"id": tour_id, "title": title, "steps": steps}
    description = str(raw.get("description") or "").strip()
    if description:
        result["description"] = description[:500]
    overview = raw.get("overview")
    if isinstance(overview, dict):
        overview_description = str(overview.get("description") or "").strip()
        overview_result = {"description": overview_description[:1000]} if overview_description else {}
        concepts = overview.get("concepts")
        if isinstance(concepts, list):
            selected_concepts = []
            for item in concepts[:8]:
                if not isinstance(item, dict) or not str(item.get("id") or "").strip() or not str(item.get("label") or "").strip():
                    continue
                concept = {"id": str(item["id"]).strip(), "label": str(item["label"]).strip()}
                if str(item.get("description") or "").strip():
                    concept["description"] = str(item["description"]).strip()[:300]
                related = item.get("related_ids")
                if isinstance(related, list) and related:
                    concept["related_ids"] = [str(value) for value in related if str(value).strip()][:8]
                selected_concepts.append(concept)
            if selected_concepts:
                overview_result["concepts"] = selected_concepts
        if overview_result:
            result["overview"] = overview_result
    selection = raw.get("selection")
    if isinstance(selection, dict):
        allowed = ("include_tests", "include_examples", "include_generated")
        selected = {key: value for key, value in selection.items() if key in allowed and isinstance(value, bool) and value}
        if selected:
            result["selection"] = selected
    return result


def _normalize_node_location(node: dict) -> None:
    """Coerce a node's ``file``/``line``/``end_line`` to their 2.0 field types in place.

    Synthetic nodes (heap locations, summary objects) have no source and were
    emitting ``file: null, line: null``; the 2.0 contract is ``file: ""`` and
    ``line: 0`` -- a real absence, not a missing key of unknown type -- so a reader
    can uniformly test ``line > 0`` for openability. ``end_line`` is made mandatory
    and never less than ``line`` (a single-line span when no wider extent is known,
    ``0`` for synthetics). Normalizing null to ""/0 does not change which nodes count
    as source-backed: ``_has_source`` already rejects an empty file and a non-positive
    line, so featured-path and entrypoint selection are unaffected.
    """
    file = node.get("file")
    node["file"] = file if isinstance(file, str) and file.strip() else ""
    line = node.get("line")
    line = line if isinstance(line, int) and not isinstance(line, bool) and line > 0 else 0
    node["line"] = line
    end = node.get("end_line")
    node["end_line"] = end if (isinstance(end, int) and not isinstance(end, bool)
                               and end >= line) else line


def _graph_first_bundle(bundle: dict, *, repo: Optional[str], commit: Optional[str],
                        lang: Optional[str], indexed_nodes: int,
                        source_url_template: Optional[str] = None,
                        comprehension: Optional[dict] = None,
                        description: Optional[str] = None,
                        purpose: Optional[str] = None,
                        curated_tour: Optional[dict] = None) -> dict:
    """Adapt the assembled evidence into Explorer's graph-first 2.0 contract.

    The security envelope remains available under ``security.findings``.  The
    navigable witness steps are also exposed as ordinary value paths so Explorer
    can serve code comprehension without presenting every path as a verdict.
    """
    meta = bundle.get("meta") or {}
    repository = str(repo or meta.get("repo") or "unknown")
    # meta.language must name the repo's *own* dominant language (B1). The passed
    # ``lang``/``meta.lang`` derives from ``census.atropos.languages[0]``, an aggregate
    # over every indexed file, so a single leaked ``.d.ts`` stub flipped express from
    # javascript to typescript. Prefer the plurality language of the product source
    # files read straight off the graph; fall back to the caller's value only when the
    # graph cannot decide (unrecognised extensions).
    language = str(lang or meta.get("lang") or "unknown")
    try:
        ctx = M.ctx()
        graph_lang = _primary_language_name(ctx.store.index, ctx.store.gl)
        if graph_lang:
            language = graph_lang
    except Exception:
        pass
    revision = str(commit or meta.get("commit") or "unknown")

    graph = bundle.get("graph") or {}
    nodes = graph.get("nodes") or []
    for node in nodes:
        _normalize_node_location(node)
    node_map = {n.get("id"): n for n in nodes}
    node_ids = set(node_map)

    findings = bundle.get("findings") or []
    # H12: drop findings whose featured surface (the sink) lives in test/non-product
    # scaffolding before anything else looks at them. The exhaustive envelope reaches
    # wherever the graph does -- a graph built without the non-product filter carries
    # `test-d/…` type-tests and `test_*` sinks -- but a *security* surface a maintainer
    # is asked to trust must describe the product, not its tests. `_is_nonproduct_path`
    # fails open (unknown file -> keep), so a finding is dropped only when its sink is
    # positively classified scaffolding.
    findings = [f for f in findings
                if not _is_nonproduct_path(_finding_primary_file(f, node_map))]
    # `security.findings` stays exhaustive, but each finding whose featured surface is
    # an internal/local artifact (a traceback local `tb`, a file handle `f`, an
    # anonymous callback) is marked `low_signal` so the trust view can demote it from
    # "what evidence needs a closer read" without losing it from the envelope (D7). The
    # real surfaces (`send_file`, `Markup`, `hashlib.sha1`, `re.split`) are left
    # unflagged and lead the list.
    for finding in findings:
        if _is_noise_surface(finding.get("display_name")):
            finding["low_signal"] = True
    # Only the *featured* value paths are cleaned. Two hygiene rules (problems #7 and #8):
    #   #7  A value path that visits fewer than two distinct nodes has not moved --
    #       it is a bare def-use artifact (a traceback local `tb`, a file handle `f`,
    #       `config_file`, `tb.tb_frame`), not a behavior. Featuring it as one is the
    #       reported defect. Genuine flows (`hashlib.sha1`, `send_file`, `re.split`,
    #       `Markup`) always traverse a source and a distinct sink, so the two-distinct
    #       -node floor drops exactly the artifacts and keeps every real flow, including
    #       the minimal two-step call-argument flows.
    #   #8  Identical paths (same endpoints and same ordered node ids) are collapsed to
    #       one; the graph often yields the same def-use twice from different findings.
    #   #9  A path whose featured surface is an internal/local artifact -- a traceback
    #       walk (`tb`, `tb.tb_frame`), a bare file handle (`f`, `f.read`), an anonymous
    #       callback (`<anonymous@571>`) -- is not a place to start reading (B4/D7). It
    #       is flagged `low_signal` on the exhaustive finding (below) and dropped from
    #       the featured value paths here, so "places to start / read next" name real
    #       surfaces (`res.download`, `hashlib.sha1`, `send_file`) instead of locals.
    values = []
    seen_paths: set[tuple] = set()
    for finding in findings:
        witness = finding.get("witness") or {}
        steps = witness.get("steps") or []
        if not steps:
            continue
        finding_id = str(finding.get("finding_id") or "")
        if not finding_id:
            continue
        step_ids = tuple(step.get("node_id") for step in steps)
        if len({sid for sid in step_ids if sid}) < 2:
            continue  # #7: a path that never leaves one node is not a behavior
        if _is_noise_surface(finding.get("display_name")):
            continue  # #9: internal/local artifact, not a featurable surface
        source_node = steps[0].get("node_id")
        sink_node = steps[-1].get("node_id")
        dedupe_key = (source_node, sink_node, step_ids)
        if dedupe_key in seen_paths:
            continue  # #8: same endpoints and same ordered hops -- one is enough
        seen_paths.add(dedupe_key)
        path_id = f"value:{finding_id}"
        values.append({
            "id": path_id,
            "kind": "value-flow",
            "name": finding.get("display_name") or "value path",
            "description": finding.get("result_summary") or "Exporter-provided value path",
            "source_node": source_node,
            "sink_node": sink_node,
            "confidence": (finding.get("analysis") or {}).get("confidence"),
            "limitations": list((finding.get("analysis") or {}).get("limitations") or []),
            "steps": steps,
        })

    edges = _canonical_edges(graph.get("edges") or [], node_ids)
    edges_by_pair = {(e["source"], e["target"]): e for e in edges}

    comp = comprehension or {}
    entrypoints = [e for e in (comp.get("entrypoints") or [])
                   if e.get("node_id") in node_ids]
    requests = _finalize_requests(comp.get("requests") or [], node_map, edges_by_pair)
    modules = _partition_modules(nodes, entrypoints)
    concepts = _project_concepts(comp.get("concepts") or [], nodes)
    core = [item for item in (comp.get("core") or [])
            if item.get("node_id") in node_ids]
    tour = _project_curated_tour(curated_tour, values, requests)

    coverage = {
        "scope": "repository-projection",
        "included_nodes": len(nodes),
        "indexed_nodes": int(indexed_nodes),
        "limitations": [
            "Third-party dependencies are omitted.",
            "Dynamic dispatch targets may be incomplete.",
            "Only representative request and value paths are included.",
        ],
    }

    meta_out = {
        "repository": repository,
        "language": language,
        "revision": revision,
        "description": description or (
            f"Representative request and value paths through {repository}."),
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "lines": int(meta.get("loc") or 0),
        "indexed_nodes": int(indexed_nodes),
    }
    # The repo's own one-line purpose ("what is this?"), read from its package
    # manifest or README. Distinct from ``description`` (which names what this
    # *projection* contains): this answers what the repository is, the first thing a
    # newcomer or a README badge needs. Omitted entirely when the tree declares none,
    # so the field's presence always means a real, source-derived summary.
    if purpose:
        meta_out["purpose"] = purpose
    if source_url_template:
        meta_out["source_url_template"] = source_url_template

    v2 = {
        "format": "lachesis-explorer-bundle",
        "schema_version": "2.0",
        "analysis_projection": "code-understanding",
        "meta": meta_out,
        "graph": {
            "nodes": nodes,
            "edges": edges,
            "files": comp.get("files") or [],
            "modules": modules,
            "concepts": concepts,
            "entrypoints": entrypoints,
            "core": core,
            "coverage": coverage,
        },
        "paths": {"requests": requests, "values": values},
        "security": {"findings": findings},
    }
    if tour is not None:
        v2["meta"]["curated_tour"] = tour
    _validate_graph_first(v2)
    return v2


def _validate_graph_first(bundle: dict) -> None:
    """Validate the invariants needed before publishing a 2.0 artifact.

    Beyond structural integrity (every referenced id resolves), this enforces the
    two contracts a comprehension consumer relies on: coverage is exact
    (``included_nodes`` is literally the node count), and every node a
    code-understanding path or entrypoint *features* is openable and carries real
    source -- the reader is never pointed at a location it cannot show.
    """
    if bundle.get("format") != "lachesis-explorer-bundle" or bundle.get("schema_version") != "2.0":
        raise ValueError("graph-first bundle must use Explorer schema 2.0")
    meta = bundle.get("meta") or {}
    for key in ("repository", "language", "revision"):
        if not isinstance(meta.get(key), str) or not meta[key].strip():
            raise ValueError(f"graph-first meta missing {key}")
    graph = bundle.get("graph") or {}
    nodes = graph.get("nodes") or []
    node_map = {node.get("id"): node for node in nodes}
    node_ids = set(node_map)
    if not nodes or None in node_ids:
        raise ValueError("graph-first bundle has invalid nodes")

    # Every node carries the concrete 2.0 location types -- ``file`` a string
    # (``""`` when absent), ``line`` and ``end_line`` non-negative ints with the
    # span never inverted. Synthetic nodes (heap locations) legitimately report
    # ``""``/``0``; what is rejected is the earlier ``null`` leak, which left the
    # field's type undefined for consumers.
    for node in nodes:
        nid = node.get("id")
        if not isinstance(node.get("file"), str):
            raise ValueError(f"node {nid} file must be a string")
        line = node.get("line")
        if not isinstance(line, int) or isinstance(line, bool) or line < 0:
            raise ValueError(f"node {nid} line must be an int >= 0")
        end = node.get("end_line")
        if not isinstance(end, int) or isinstance(end, bool) or end < line:
            raise ValueError(f"node {nid} end_line must be an int >= line")

    coverage = graph.get("coverage") or {}
    if coverage and coverage.get("included_nodes") != len(nodes):
        raise ValueError("graph-first coverage.included_nodes must equal node count")

    for edge in graph.get("edges") or []:
        if edge.get("source") not in node_ids or edge.get("target") not in node_ids:
            raise ValueError("graph-first edge references unknown node")

    for entry in graph.get("entrypoints") or []:
        nid = entry.get("node_id")
        if nid not in node_ids:
            raise ValueError(f"entrypoint {entry.get('id')} references unknown node")
        if not _has_source(node_map.get(nid)):
            raise ValueError(f"entrypoint {entry.get('id')} node has no openable source")

    # A comprehension-first projection is meaningless without a boundary to enter
    # from and a path with enough hops to be a story. An empty entrypoint set (the
    # ItsDangerous case) or paths that never exceed a bare def-use pair defeat the
    # whole projection, so they are rejected here rather than shipped as a hollow
    # bundle. Request hops are already proven source-backed above, so a >=3-hop
    # request is a source-backed path of three or more hops by construction.
    if bundle.get("analysis_projection") == "code-understanding":
        if not (graph.get("entrypoints") or []):
            raise ValueError(
                "code-understanding projection requires at least one production entrypoint")
        requests = (bundle.get("paths") or {}).get("requests") or []
        if not any(len(req.get("hops") or []) >= 3 for req in requests):
            raise ValueError(
                "code-understanding projection requires a source-backed path of >= 3 hops")

    seen_module_nodes: set[str] = set()
    for module in graph.get("modules") or []:
        for nid in module.get("node_ids") or []:
            if nid not in node_ids:
                raise ValueError(f"module {module.get('id')} references unknown node")
            if nid in seen_module_nodes:
                raise ValueError(f"node {nid} appears in more than one module")
            seen_module_nodes.add(nid)

    for req in (bundle.get("paths") or {}).get("requests") or []:
        hops = req.get("hops") or []
        hop_ids = [h.get("node_id") for h in hops]
        if len(hops) < 2 or any(nid not in node_ids for nid in hop_ids):
            raise ValueError(f"request {req.get('id')} references invalid nodes")
        if req.get("source_node") not in hop_ids or req.get("sink_node") not in hop_ids:
            raise ValueError(f"request {req.get('id')} endpoints must occur in hops")
        for nid in hop_ids:
            if not _has_source(node_map.get(nid)):
                raise ValueError(f"request {req.get('id')} hop node {nid} has no source")

    for path in ((bundle.get("paths") or {}).get("values") or []):
        steps = path.get("steps") or []
        if not steps or any(step.get("node_id") not in node_ids for step in steps):
            raise ValueError("graph-first path references invalid nodes")


def _clean_purpose(text: Optional[str]) -> Optional[str]:
    """Collapse a candidate purpose to one bounded, human line, or None.

    Strips markup noise that would read badly as a headline: leading Markdown
    heading/quote/list markers, inline emphasis and code ticks, and image/badge
    lines. Whitespace is collapsed to single spaces and the result is capped so a
    stray long paragraph cannot bloat the bundle or the landing view.
    """
    if not isinstance(text, str):
        return None
    s = text.strip()
    if not s:
        return None
    s = re.sub(r"[`*_]+", "", s)                    # inline emphasis / code ticks
    s = re.sub(r"^\s*[#>\-*+]+\s*", "", s)          # heading / quote / list markers
    s = re.sub(r"\s+", " ", s).strip()
    if len(s) > 240:
        s = s[:237].rstrip() + "…"
    return s or None


def _project_purpose(source_dir: Optional[str]) -> Optional[str]:
    """A real one-line "what is this repo" from the source tree, best effort.

    Neither app could answer "what is this?" for a newcomer because the bundle
    never carried the project's own description -- only a generic per-projection
    boilerplate. This reads the repo's own declared purpose from the places a repo
    states it: the package manifest's ``description`` (npm/PyPI/Cargo/Composer)
    first, since it is authored to be exactly a one-line summary, then the README's
    first real paragraph as a fallback. Returns None (not a guess) when the tree
    declares nothing, so the caller keeps the honest boilerplate.
    """
    if not source_dir or not os.path.isdir(source_dir):
        return None

    def _read(name: str) -> Optional[str]:
        try:
            with open(os.path.join(source_dir, name), encoding="utf-8") as fh:
                return fh.read()
        except Exception:
            return None

    # 1) Package manifests -- authored to be a one-line summary.
    raw = _read("package.json") or _read("composer.json")
    if raw:
        try:
            desc = (json.loads(raw) or {}).get("description")
            cleaned = _clean_purpose(desc)
            if cleaned:
                return cleaned
        except Exception:
            pass
    for toml_name, tables in (("pyproject.toml", (("project",), ("tool", "poetry"))),
                              ("Cargo.toml", (("package",),))):
        raw = _read(toml_name)
        if not raw:
            continue
        try:
            import tomllib
            data = tomllib.loads(raw)
        except Exception:
            continue
        for path in tables:
            node = data
            for key in path:
                node = node.get(key) if isinstance(node, dict) else None
            if isinstance(node, dict):
                cleaned = _clean_purpose(node.get("description"))
                if cleaned:
                    return cleaned
    raw = _read("setup.cfg")
    if raw:
        try:
            import configparser
            cp = configparser.ConfigParser()
            cp.read_string(raw)
            if cp.has_section("metadata"):
                cleaned = _clean_purpose(cp["metadata"].get("description")
                                         or cp["metadata"].get("summary"))
                if cleaned:
                    return cleaned
        except Exception:
            pass

    # 2) README first real paragraph -- skip headings, badges, images, and blanks.
    for readme in ("README.md", "README.rst", "README.txt", "README",
                   "readme.md", "Readme.md"):
        text = _read(readme)
        if not text:
            continue
        for block in re.split(r"\n\s*\n", text):
            line = block.strip()
            if not line:
                continue
            low = line.lower()
            if line.startswith("#") or line.startswith("==") or line.startswith("--"):
                continue  # a heading (the project name), not the description
            if low.startswith("![") or low.startswith("[![") or "shields.io" in low:
                continue  # a badge / image row
            if line.startswith("<") and line.endswith(">"):
                continue  # a bare HTML tag line (e.g. a centered logo block)
            cleaned = _clean_purpose(line.splitlines()[0])
            if cleaned and len(cleaned) >= 12:
                return cleaned
        break  # only the first README that exists is authoritative
    return None


def build_bundle(graph_path: str, *, repo: Optional[str] = None,
                 commit: Optional[str] = None, lang: Optional[str] = None,
                 loc: Optional[int] = None, source_dir: Optional[str] = None,
                 per_family: int = 6, max_flows: int = 40, cone_limit: int = 80,
                 planner_depth: int = 6, planner_entrypoints: int = 0,
                 schema_version: str = "1.0",
                 source_url_template: Optional[str] = None,
                 description: Optional[str] = None,
                 curated_tour: Optional[dict] = None,
                 max_entrypoints: int = 40, chain_depth: int = 6,
                 max_files: int = 2000) -> dict:
    """Build an explorer bundle (schema 1.0) from a built+enriched graph."""
    load = _call("load_graph", {"path": graph_path, "profile": "all"})
    census = _call("candidate_census", {})
    snippet_of = _snippet_lookup(graph_path)
    asm = _Assembler(snippet_of)

    # Line count: derive it from the loaded graph's files when the caller did not
    # pass one, so meta.loc/lines is a real figure rather than 0. Independent of
    # indexed_nodes (a node count), which it must never be conflated with.
    if loc is None:
        try:
            _ctx = M.ctx()
            loc = _count_source_lines(_ctx.store.index, _ctx.store.gl)
        except Exception:
            loc = None

    manifest_lang = None
    langs = ((census.get("atropos") or {}).get("languages")) or []
    if langs:
        manifest_lang = langs[0]

    # Capsules first: they own overlapping sinks (richer witness + guards); the
    # candidate spine then fills every family the capsules did not reach.
    capsules = _capsule_findings(graph_path, asm, depth=planner_depth,
                                 limit_entrypoints=planner_entrypoints)
    candidates = _candidate_findings(census, asm, per_family=per_family,
                                     max_flows=max_flows, cone_limit=cone_limit)
    merged = dict(capsules)
    for fid, finding in candidates.items():
        if fid not in merged:
            merged[fid] = finding
    findings = list(merged.values())

    # The comprehension projection (entrypoints, guided request paths, files) adds
    # its own real nodes/edges to the shared pool -- do it before relativizing so
    # those files are normalized alongside the finding nodes.
    projection: Optional[dict] = None
    if schema_version == "2.0":
        projection = _comprehension_projection(
            asm, max_entrypoints=max_entrypoints, chain_depth=chain_depth,
            max_files=max_files)

    _relativize_files(asm.nodes)
    _relativize_locations(findings)

    if projection is not None:
        try:
            gl = M.ctx().store.gl
            _enrich_graph_nodes(list(asm.nodes.values()), gl)
        except Exception:
            pass
        # Keep each entrypoint's displayed file identical to its node's (post-
        # relativization) file, so module partitioning can anchor by that file.
        for entry in projection.get("entrypoints") or []:
            node = asm.nodes.get(entry.get("node_id"))
            if node and node.get("file"):
                entry["file"] = node["file"]

    prov = _provenance(source_dir, census)
    finding_ids = sorted(f["finding_id"] for f in findings)
    evidence_manifest = {
        "format": "lachesis-evidence",
        "schema_version": 1,
        "finding_schema_version": FINDING_SCHEMA_VERSION,
        "analysis_projection": "security-paths",
        "repository": repo or "",
        "commit_sha": commit or prov["commit_sha"],
        "tree_digest": prov["tree_digest"],
        "engine_sha": prov["engine_sha"],
        "catalog_sha": prov["catalog_sha"],
        "toolchain_fingerprint": prov["toolchain_fingerprint"],
        "capsule_findings": len(capsules),
        "candidate_findings": len(findings) - len(capsules),
        "finding_lifecycle": {
            "state": "initial",
            "observed_finding_ids": finding_ids,
            "new_finding_ids": finding_ids,
            "active_finding_ids": [],
            "resolved_finding_ids": [],
        },
    }

    bundle = {
        "format": "lachesis-explorer-bundle",
        "bundle_version": BUNDLE_VERSION,
        "finding_schema_version": FINDING_SCHEMA_VERSION,
        "meta": {k: v for k, v in {
            "repo": repo, "lang": lang or manifest_lang, "commit": commit,
            "loc": loc, "nodes_total": load.get("nodes"),
        }.items() if v is not None},
        "evidence_manifest": evidence_manifest,
        "findings": findings,
        "graph": {
            "nodes": list(asm.nodes.values()),
            "edges": list(asm.edges.values()),
        },
        "display_hints": {},
    }
    validate(bundle)
    if schema_version == "2.0":
        return _graph_first_bundle(bundle, repo=repo,
                                   commit=commit or prov.get("commit_sha"), lang=lang,
                                   indexed_nodes=int(load.get("nodes") or 0),
                                   source_url_template=source_url_template,
                                   comprehension=projection, description=description,
                                   purpose=_project_purpose(source_dir),
                                   curated_tour=curated_tour)
    if schema_version != "1.0":
        raise ValueError(f"unsupported Explorer schema version: {schema_version}")
    return bundle


def _relativize_files(nodes: dict[str, dict]) -> None:
    """Strip the shared source-root prefix so bundle paths are repo-relative.

    Graphs built from an absolute source directory carry absolute file paths;
    those both read poorly in the explorer and leak a local filesystem path into
    a bundle that is meant to be shared. Reduce every node's ``file`` to a path
    relative to the deepest directory common to all of them.
    """
    files = [n["file"] for n in nodes.values()
             if isinstance(n.get("file"), str) and os.path.isabs(n["file"])]
    if not files:
        return
    try:
        root = os.path.commonpath(files)
    except ValueError:
        return  # mixed drives / relative -- leave as-is
    # With a single file, commonpath returns that file itself; step up to its
    # directory. With several, it is already their shared directory.
    if root in set(files):
        root = os.path.dirname(root)
    if not root or root == os.sep:
        return
    for n in nodes.values():
        f = n.get("file")
        if isinstance(f, str) and f.startswith(root):
            n["file"] = os.path.relpath(f, root)


def _relativize_locations(findings: list[dict]) -> None:
    """Mirror _relativize_files over the finding envelopes' location files."""
    files = []
    for f in findings:
        for loc in f.get("locations") or []:
            v = loc.get("file")
            if isinstance(v, str) and os.path.isabs(v):
                files.append(v)
    if not files:
        return
    try:
        root = os.path.commonpath(files)
    except ValueError:
        return
    if root in set(files):
        root = os.path.dirname(root)
    if not root or root == os.sep:
        return
    for f in findings:
        for loc in f.get("locations") or []:
            v = loc.get("file")
            if isinstance(v, str) and v.startswith(root):
                loc["file"] = os.path.relpath(v, root)


def validate(bundle: dict) -> None:
    """Fail loudly if the bundle would not import: graph + finding integrity."""
    graph = bundle.get("graph") or {}
    nodes = graph.get("nodes")
    findings = bundle.get("findings")
    if not isinstance(nodes, list) or not nodes:
        raise ValueError("bundle has no nodes")
    if not isinstance(findings, list) or not findings:
        raise ValueError("bundle has no findings")
    ids = set()
    for n in nodes:
        nid = n.get("id")
        if not nid:
            raise ValueError("node without id")
        if nid in ids:
            raise ValueError(f"duplicate node id: {nid}")
        ids.add(nid)
    seen_findings = set()
    for f in findings:
        fid = f.get("finding_id")
        if not isinstance(fid, str) or len(fid) != _HEX64:
            raise ValueError(f"finding_id must be 64 hex chars: {fid!r}")
        if fid in seen_findings:
            raise ValueError(f"duplicate finding_id: {fid}")
        seen_findings.add(fid)
        analysis = f.get("analysis") or {}
        if not analysis.get("projection"):
            raise ValueError(f"finding {fid} has no analysis.projection")
        if not isinstance(analysis.get("limitations"), list):
            raise ValueError(f"finding {fid} limitations must be a list")
        witness = f.get("witness") or {}
        steps = witness.get("steps")
        if not isinstance(steps, list) or not steps:
            raise ValueError(f"finding {fid} has no witness steps")
        if not isinstance(witness.get("guards"), dict):
            raise ValueError(f"finding {fid} guards must be an object")
        for s in steps:
            if s.get("node_id") not in ids:
                raise ValueError(f"finding {fid} step references unknown node "
                                 f"{s.get('node_id')}")
    manifest = bundle.get("evidence_manifest") or {}
    for req in ("engine_sha", "catalog_sha", "toolchain_fingerprint"):
        if not manifest.get(req):
            raise ValueError(f"evidence_manifest missing required {req}")
    for e in graph.get("edges") or []:
        if e.get("source") not in ids or e.get("target") not in ids:
            raise ValueError("edge references unknown node")
