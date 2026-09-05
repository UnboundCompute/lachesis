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
import subprocess
from datetime import datetime, timezone
from typing import Any, Optional

from lachesis.nav import mcp_server as M

BUNDLE_VERSION = "1.0"
FINDING_SCHEMA_VERSION = "0.1"
_HEX64 = 64


def _call(name: str, args: dict) -> Any:
    return json.loads(M.call_tool(name, args, "json"))


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


def _call_chain(index, gl, start_id: str, depth: int) -> list[str]:
    """A single deterministic CALLS chain out of ``start_id`` (source order).

    At each hop we descend into the callee that itself calls the most -- the branch
    most likely to keep telling the request's story -- breaking ties by label so the
    walk is reproducible. Cycles are cut by the visited set; a leaf ends the chain.
    This invents no ordering: every consecutive pair is a real ``CALLS`` edge.
    """
    chain = [start_id]
    seen = {start_id}
    cur = start_id
    for _ in range(max(0, depth - 1)):
        nxt: list[dict] = []
        try:
            nxt = [n for n in index.targets(cur, "CALLS")
                   if n.get("id") and n["id"] not in seen]
        except Exception:
            break
        if not nxt:
            break

        def out_degree(node: dict) -> int:
            try:
                return len(index.targets(node["id"], "CALLS"))
            except Exception:
                return 0

        pick = min(nxt, key=lambda n: (-out_degree(n), gl.label(n), n["id"]))
        cur = pick["id"]
        seen.add(cur)
        chain.append(cur)
    return chain


def _comprehension_projection(asm: "_Assembler", *, max_entrypoints: int,
                              chain_depth: int, max_files: int) -> dict:
    """Entrypoints, guided request paths, files and modules for the 2.0 bundle.

    Adds every node it references (entry handlers and each request hop) to ``asm``
    and, for each request path, the real ``CALLS`` edges between consecutive hops --
    so the graph-first validator finds all of them resolvable. Returns empty lists,
    never raises: a graph the comprehension layer cannot walk simply reads as a bare
    graph rather than failing the whole export.
    """
    empty = {"entrypoints": [], "requests": [], "files": [], "modules": []}
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

            # A guided path is only worth showing when it actually goes somewhere:
            # the real CALLS chain out of the entry must have more than the entry.
            chain = _call_chain(index, gl, handler_id, chain_depth)
            if len(chain) < 2:
                continue
            hops = []
            for nid in chain:
                cnode = gl.nodes.get(nid)
                if cnode is None:
                    continue
                asm.add_node(_norm_node(gl, cnode), default_kind="function")
                hops.append({"node_id": nid, "caption": gl.label(cnode)})
            for a, b in zip(chain, chain[1:]):
                asm.add_edge({"src": a, "tgt": b, "kind": "CALLS"}, set(asm.nodes))
            if len(hops) >= 2:
                requests.append({
                    "id": f"request.{_slug(label)}",
                    "kind": "call-path",
                    "description": f"Follow control from {label} through "
                                   f"{len(hops) - 1} call(s).",
                    "entry_node": handler_id,
                    "hops": hops,
                })
    except Exception:
        pass

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

    # Modules are not built here: they must partition the *final* included node
    # pool (one unambiguous module per node, keyed by that node's file), which is
    # only settled after candidate/capsule/entry nodes are all in and relativized.
    return {"entrypoints": entrypoints, "requests": requests, "files": files}


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


def _graph_first_bundle(bundle: dict, *, repo: Optional[str], commit: Optional[str],
                        lang: Optional[str], indexed_nodes: int,
                        source_url_template: Optional[str] = None,
                        comprehension: Optional[dict] = None,
                        description: Optional[str] = None) -> dict:
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
    values = []
    for finding in findings:
        witness = finding.get("witness") or {}
        steps = witness.get("steps") or []
        if not steps:
            continue
        finding_id = str(finding.get("finding_id") or "")
        if not finding_id:
            continue
        path_id = f"value:{finding_id}"
        values.append({
            "id": path_id,
            "kind": "value-flow",
            "name": finding.get("display_name") or "value path",
            "description": finding.get("result_summary") or "Exporter-provided value path",
            "source_node": steps[0].get("node_id"),
            "sink_node": steps[-1].get("node_id"),
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
            "entrypoints": entrypoints,
            "coverage": coverage,
        },
        "paths": {"requests": requests, "values": values},
        "security": {"findings": findings},
    }
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
                                   comprehension=projection, description=description)
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
