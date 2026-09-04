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
        ctx = M._get_ctx()
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


def _graph_first_bundle(bundle: dict, *, repo: Optional[str], commit: Optional[str],
                        lang: Optional[str], indexed_nodes: int) -> dict:
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
    v2 = {
        "format": "lachesis-explorer-bundle",
        "schema_version": "2.0",
        "analysis_projection": "code-understanding",
        "meta": {
            "repository": repository,
            "language": language,
            "revision": revision,
            "lines": int(meta.get("loc") or 0),
            "indexed_nodes": int(indexed_nodes),
        },
        "graph": {
            "nodes": graph.get("nodes") or [],
            "edges": graph.get("edges") or [],
        },
        "paths": {"values": values},
        "security": {"findings": findings},
    }
    if repository.count("/") == 1:
        v2["meta"]["source_url_template"] = (
            f"https://github.com/{repository}/blob/{{revision}}/{{file}}#L{{line}}-L{{end_line}}"
        )
    _validate_graph_first(v2)
    return v2


def _validate_graph_first(bundle: dict) -> None:
    """Validate the invariants needed before publishing a 2.0 artifact."""
    if bundle.get("format") != "lachesis-explorer-bundle" or bundle.get("schema_version") != "2.0":
        raise ValueError("graph-first bundle must use Explorer schema 2.0")
    meta = bundle.get("meta") or {}
    for key in ("repository", "language", "revision"):
        if not isinstance(meta.get(key), str) or not meta[key].strip():
            raise ValueError(f"graph-first meta missing {key}")
    nodes = (bundle.get("graph") or {}).get("nodes") or []
    node_ids = {node.get("id") for node in nodes}
    if not nodes or None in node_ids:
        raise ValueError("graph-first bundle has invalid nodes")
    for edge in (bundle.get("graph") or {}).get("edges") or []:
        if edge.get("source") not in node_ids or edge.get("target") not in node_ids:
            raise ValueError("graph-first edge references unknown node")
    for path in ((bundle.get("paths") or {}).get("values") or []):
        steps = path.get("steps") or []
        if not steps or any(step.get("node_id") not in node_ids for step in steps):
            raise ValueError("graph-first path references invalid nodes")


def build_bundle(graph_path: str, *, repo: Optional[str] = None,
                 commit: Optional[str] = None, lang: Optional[str] = None,
                 loc: Optional[int] = None, source_dir: Optional[str] = None,
                 per_family: int = 6, max_flows: int = 40, cone_limit: int = 80,
                 planner_depth: int = 6, planner_entrypoints: int = 0,
                 schema_version: str = "1.0") -> dict:
    """Build an explorer bundle (schema 1.0) from a built+enriched graph."""
    load = _call("load_graph", {"path": graph_path, "profile": "all"})
    census = _call("candidate_census", {})
    snippet_of = _snippet_lookup(graph_path)
    asm = _Assembler(snippet_of)

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

    _relativize_files(asm.nodes)
    _relativize_locations(findings)

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
                                   indexed_nodes=int(load.get("nodes") or 0))
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
