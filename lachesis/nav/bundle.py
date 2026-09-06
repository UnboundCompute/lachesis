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
    """A stable, id-safe slug from a symbol label (never empty)."""
    keep = [c.lower() if (c.isalnum() or c == ".") else "." for c in str(text or "")]
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
    return {"id": node.get("id"), "name": gl.label(node),
            "kind": gl.kind(node.get("id")), "file": file, "line": line}


# The request lifecycle a reader wants is the *success* path; error, teardown and
# logging branches are real but secondary, so we only derank them when choosing the
# primary hop -- never drop them. Substring match keeps this language-agnostic.
_LIFECYCLE_ERROR_TOKENS = (
    "exception", "error", "teardown", "cleanup", "abort", "log_",
    "handle_http", "raise_", "rollback", "finalize_request",
)
_CALL_EDGE_KINDS = ("CALLS", "INVOKES", "MAY_INVOKE")


def _is_error_name(name: Optional[str]) -> bool:
    n = str(name or "").lower()
    return any(tok in n for tok in _LIFECYCLE_ERROR_TOKENS)


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


def _lifecycle_roots(index, gl, handler_ids: list[str], *, cap: int) -> list[str]:
    """Candidate roots for request-lifecycle stories, best driver first.

    Two sources, deduped in priority order: the planner's entry handlers (already
    ranked upstream), then every product callable that nothing else in the product
    calls -- an in-degree-0 top-of-stack (a WSGI ``__call__``, an event loop, a
    public API orchestrator). The in-degree-0 set is ordered by two-hop reach so the
    orchestration roots precede the many leaf helpers that also happen to be
    uncalled once tests are excluded. Truncated to ``cap`` so the story pass is
    bounded regardless of codebase size.
    """
    roots: list[str] = []
    seen: set[str] = set()
    for hid in handler_ids:
        if hid and hid not in seen:
            seen.add(hid)
            node = gl.nodes.get(hid)
            if node is not None and _is_nonproduct_path(gl.loc(node)[0]):
                continue  # a test/example handler is not a product lifecycle root
            roots.append(hid)

    drivers: list[tuple[int, str]] = []
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
        try:
            out = sum(1 for _ in index.targets(nid, *_CALL_EDGE_KINDS))
            if out < 1:
                continue
            inn = sum(1 for _ in index.sources(nid, *_CALL_EDGE_KINDS))
        except Exception:
            continue
        if inn == 0:
            drivers.append((_reach2(index, nid), nid))
    drivers.sort(key=lambda pair: (-pair[0], pair[1]))
    for _, nid in drivers:
        if nid not in seen:
            seen.add(nid)
            roots.append(nid)
    return roots[:cap]


def _story_spine(story: dict, *, max_hops: int) -> tuple[list[str], list[str]]:
    """Linearize an execution story into (primary success spine, all functions).

    The story is a call tree keyed by (caller -> function). The spine walks from the
    entry always choosing the deepest-subtree callee, deranking obvious error/
    teardown branches, so it follows the happy path (a WSGI entry down through
    dispatch to the response) rather than wandering into a handler. Every consecutive
    pair on the spine is a real edge the story observed; cycles are cut by ``seen``.
    Returns the ordered spine node ids and the flat set of every function id the
    story touched (the raw material for the architecture core).
    """
    steps = story.get("steps") or []
    entry = (story.get("entry") or {}).get("node_id")
    if not entry:
        return [], []
    children: dict[str, list[tuple[int, dict]]] = {}
    functions: dict[str, dict] = {}
    for step in steps:
        fn = step.get("function") or {}
        fid = fn.get("node_id")
        if not fid:
            continue
        functions[fid] = fn
        caller = (step.get("caller") or {}).get("node_id")
        if caller:
            children.setdefault(caller, []).append((step.get("sequence", 0), fn))

    memo: dict[str, int] = {}

    def subtree(nid: str, guard: frozenset) -> int:
        if nid in memo:
            return memo[nid]
        if nid in guard:
            return 0
        deeper = guard | {nid}
        total = 0
        for _, fn in children.get(nid, []):
            cid = fn.get("node_id")
            if cid:
                total += 1 + subtree(cid, deeper)
        # Only cache when no guard cycle influenced the count (guard was the path
        # to nid); good enough as a heuristic ranker and keeps the walk bounded.
        memo[nid] = total
        return total

    spine = [entry]
    seen = {entry}
    cur = entry
    while len(spine) < max_hops:
        kids = [fn for _, fn in sorted(children.get(cur, []), key=lambda pair: pair[0])
                if fn.get("node_id") not in seen and _story_fn_openable(fn)]
        if not kids:
            break
        pick = max(kids, key=lambda fn: (
            0 if _is_error_name(fn.get("name")) else 1,
            subtree(fn.get("node_id"), frozenset())))
        nid = pick.get("node_id")
        cur = nid
        seen.add(nid)
        spine.append(nid)
    ordered_functions = [fid for fid in functions if _story_fn_openable(functions[fid])]
    return spine, ordered_functions


def _lifecycle_projection(asm: "_Assembler", index, gl, handler_ids: list[str], *,
                          max_requests: int, max_core: int,
                          max_hops: int) -> tuple[list[dict], list[dict]]:
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
        roots = _lifecycle_roots(index, gl, handler_ids, cap=30)
    except Exception:
        return requests, core

    ranked: list[tuple[int, int, str, list[str], list[str]]] = []
    for root in roots:
        try:
            story = _call("execution_story",
                          {"entry": root, "max_depth": max_hops + 2,
                           "max_steps": 120, "format": "json"})
        except Exception:
            continue
        if not isinstance(story, dict):
            continue
        spine, functions = _story_spine(story, max_hops=max_hops)
        if len(spine) < 2:
            continue
        ranked.append((len(spine), len(functions), root, spine, functions))

    # Deepest, then broadest, wins attention; stable by root id for reproducibility.
    ranked.sort(key=lambda row: (-row[0], -row[1], row[2]))

    node_ids = set(asm.nodes)
    covered: set[str] = set()
    core_ids: set[str] = set()
    used_ids: set[str] = set()
    for _, _, root, spine, functions in ranked:
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
            hops.append({"node_id": nid, "caption": gl.label(node)})
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

    entrypoints: list[dict] = []
    requests: list[dict] = []
    try:
        by_handler = EntryPoints(store).by_handler()
        # Strongest anchor per handler, then a stable global order over handlers.
        best = {hid: sorted(rows, key=_anchor_strength)[0]
                for hid, rows in by_handler.items() if rows}
        ordered = sorted(best.items(),
                         key=lambda kv: (_anchor_strength(kv[1]),
                                         kv[1].get("file") or "", kv[1].get("anchor_label") or "",
                                         kv[0]))
        used_ids: set[str] = set()
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
        max_requests=8, max_core=32, max_hops=max(2, chain_depth))

    files: list[dict] = []
    try:
        seen_paths: set[str] = set()
        for node in index.nodes_of_kind("file"):
            path = comp._relative_path(gl.loc(node)[0] or gl.prop(node, "file"))
            if not path or path in seen_paths:
                continue
            seen_paths.add(path)
            files.append({"id": node.get("id"), "path": path})
        files.sort(key=lambda f: f["path"])
        if len(files) > max_files:
            files = files[:max_files]
    except Exception:
        files = []

    concepts: list[dict] = []
    try:
        architecture = comp.architecture_map(max_communities=8, max_files_per_community=20)
        for idx, community in enumerate(architecture.get("communities") or []):
            paths = [str(path) for path in community.get("files") or [] if path]
            if not paths:
                continue
            first = paths[0]
            directory = first.rsplit("/", 1)[0] if "/" in first else first
            if directory.startswith("src/"):
                directory = directory[4:]
            label = directory.replace("/", " · ") or first
            concepts.append({
                "id": f"concept.{_slug(community.get('id') or idx)}",
                "label": label,
                "description": f"Connected code area spanning {len(paths)} file(s).",
                "file_paths": paths,
            })
    except Exception:
        concepts = []

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
    p = p.rsplit(".", 1)[0]  # drop the extension
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


def _partition_modules(nodes: list[dict], entrypoints: list[dict]) -> list[dict]:
    """One unambiguous module per included node, keyed by that node's file.

    Every concrete (file-bearing) node lands in exactly one module -- the module of
    its file -- so no node is ever repeated across modules. A module anchored by an
    entrypoint carries that entry's node id, giving a reader a place to start.
    """
    anchor_by_file: dict[str, str] = {}
    for ep in entrypoints:
        f = ep.get("file")
        if isinstance(f, str) and f not in anchor_by_file:
            anchor_by_file[f] = ep.get("node_id")

    groups: dict[str, list[str]] = {}
    for node in nodes:
        f = node.get("file")
        if not isinstance(f, str) or not f.strip():
            continue
        module_name = _dotted_module(f) or f
        node["module"] = module_name
        groups.setdefault(f, []).append(node["id"])

    modules: list[dict] = []
    for path in sorted(groups):
        module_name = _dotted_module(path) or path
        module = {
            "id": f"module.{_slug(module_name)}",
            "name": module_name,
            "path": path,
            "node_ids": groups[path],
        }
        anchor = anchor_by_file.get(path)
        if anchor:
            module["anchor_node_id"] = anchor
        modules.append(module)
    return modules


def _project_concepts(raw_concepts: list[dict], nodes: list[dict]) -> list[dict]:
    """Keep architecture concepts honest to the final included node pool."""
    out: list[dict] = []
    for concept in raw_concepts or []:
        paths = {str(path) for path in concept.get("file_paths") or [] if path}
        node_ids = [node["id"] for node in nodes
                    if isinstance(node.get("file"), str) and node.get("file") in paths]
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


def _graph_first_bundle(bundle: dict, *, repo: Optional[str], commit: Optional[str],
                        lang: Optional[str], indexed_nodes: int,
                        source_url_template: Optional[str] = None,
                        comprehension: Optional[dict] = None,
                        description: Optional[str] = None,
                        curated_tour: Optional[dict] = None) -> dict:
    """Adapt the assembled evidence into Explorer's graph-first 2.0 contract.

    The security envelope remains available under ``security.findings``.  The
    navigable witness steps are also exposed as ordinary value paths so Explorer
    can serve code comprehension without presenting every path as a verdict.
    """
    meta = bundle.get("meta") or {}
    repository = str(repo or meta.get("repo") or "unknown")
    language = str(lang or meta.get("lang") or "unknown")
    revision = str(commit or meta.get("commit") or "unknown")
    findings = bundle.get("findings") or []
    # `security.findings` stays exhaustive (passed through untouched below); only the
    # *featured* value paths are cleaned. Two hygiene rules (problems #7 and #8):
    #   #7  A value path that visits fewer than two distinct nodes has not moved --
    #       it is a bare def-use artifact (a traceback local `tb`, a file handle `f`,
    #       `config_file`, `tb.tb_frame`), not a behavior. Featuring it as one is the
    #       reported defect. Genuine flows (`hashlib.sha1`, `send_file`, `re.split`,
    #       `Markup`) always traverse a source and a distinct sink, so the two-distinct
    #       -node floor drops exactly the artifacts and keeps every real flow, including
    #       the minimal two-step call-argument flows.
    #   #8  Identical paths (same endpoints and same ordered node ids) are collapsed to
    #       one; the graph often yields the same def-use twice from different findings.
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

    graph = bundle.get("graph") or {}
    nodes = graph.get("nodes") or []
    node_map = {n.get("id"): n for n in nodes}
    node_ids = set(node_map)
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
