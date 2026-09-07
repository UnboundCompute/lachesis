"""Offline semantic enrichment of the comprehension bundle.

A precompute pass that decorates an already-built graph-first bundle with
meaning-based structure derived from the same card vectors the concept-search
index persists. Everything here is *additive* and *advisory*: it annotates and
arranges the compiler-precise structure the projection already produced -- it
never redefines that structure, and it never feeds the judge. When no local
embedding model is present the pass is a silent no-op and the bundle ships
exactly as the structural projection built it.

What it adds (all optional, absent without a model):

* per node   -- ``related`` (nearest behavioural neighbours), ``xy`` (a 2-D
               semantic layout coordinate), ``tags`` (behavioural facets).
* per module -- ``semantic_label`` + ``exemplars`` (centroid representatives),
               ``coherence`` + ``outliers`` (how tightly the members cohere and
               which ones do not), ``affinity`` (conceptually related modules),
               ``tags`` and a templated ``summary``.
* per concept-- ``coherence`` + ``outliers`` + ``suggested`` (nearby members).
* top level  -- ``enrichment`` = model/meta, ``near_duplicates`` (copy-paste
               smells), ``cross_cutting`` (a facet whose members span many
               modules -- a horizontal concern the call graph cannot show) and
               ``reading_order`` (a greedy semantic tour of the modules).

numpy is imported lazily inside the guarded path: the pass only runs when the
concept-search embedder is present, which means FastEmbed -- and therefore
numpy -- is installed.
"""
from __future__ import annotations

import re
from collections import defaultdict

from .concept import ConceptSearch, DEFAULT_MODEL

# Arrow functions, callbacks and object-literal methods often reach the graph
# without a source name; the frontend (TS compiler) labels them ``<anonymous@42>``
# or a bare ``anonymous``. Such a name makes a poor module label, so we skip it in
# favour of the next-best *named* exemplar (and fall back to the structural name).
_ANON = re.compile(r"^\s*(<?anonymous)", re.IGNORECASE)


def _named(text) -> bool:
    """True when ``text`` is a usable human label (not empty, not anonymous)."""
    return bool(text) and not _ANON.match(str(text))


# A small, language-neutral vocabulary of behavioural facets. Each card is tagged
# with the facet(s) its vector sits closest to, giving the map a "what this code
# *does*" axis orthogonal to the module ("where it lives") axis. Purely advisory.
_FACETS = {
    "validation": "validate and check input arguments preconditions and constraints",
    "io": "read and write files streams sockets and network input output",
    "parsing": "parse tokenize lex and decode text or structured input",
    "serialization": "serialize deserialize encode marshal data to json bytes or wire format",
    "http": "handle http requests responses headers cookies and web endpoints",
    "routing": "route dispatch and map urls or commands to handlers",
    "database": "database query sql orm transactions persistence and storage",
    "auth": "authentication authorization login credentials tokens sessions and permissions",
    "crypto": "cryptography hashing encryption signing certificates and secure randomness",
    "config": "configuration settings options flags and environment variables",
    "logging": "logging tracing diagnostics metrics and telemetry",
    "error-handling": "error handling exceptions failures retries and recovery",
    "concurrency": "concurrency threads processes async await locks and scheduling",
    "caching": "cache memoize store and invalidate computed results",
    "templating": "render templates html markup and text output",
    "data-model": "data model class struct fields records schema and types",
    "cli": "command line argument parsing options and terminal interface",
    "collection": "collections lists maps sets iteration and containers",
    "lifecycle": "initialize construct set up tear down dispose and clean up resources",
    "math": "mathematical numeric arithmetic geometry and algorithmic computation",
}


def enrich(store, nodes, modules, concepts, entrypoints, *,
           model: str = DEFAULT_MODEL, neighbors: int = 6,
           tag_floor: float = 0.30, tag_margin: float = 0.05,
           related_floor: float = 0.30, dup_threshold: float = 0.90,
           outlier_gap: float = 0.12, suggest_floor: float = 0.62,
           max_duplicates: int = 60, max_cross_cutting: int = 12) -> dict | None:
    """Decorate ``nodes``/``modules``/``concepts`` in place; return the top-level
    ``enrichment`` dict, or None when there is no model (caller ships unchanged).

    The dicts passed in are the very objects the bundle references, so mutating
    them here is what threads the overlay into the artifact. Nothing raises on a
    missing model or a degenerate corpus -- the pass simply returns None.
    """
    searcher = ConceptSearch(store, model)
    matrix = searcher.vector_matrix()
    if matrix is None:
        return None
    try:
        import numpy as np
    except Exception:
        return None

    cards, vectors = matrix
    node_by_id = {n.get("id"): n for n in nodes}
    module_by_id = {m.get("id"): m for m in modules}
    card_by_id = {c["node_id"]: c for c in cards}

    # Only enrich nodes that are both in the bundle pool and carry a vector; a
    # value/heap node or a test/vendor card has no vector and simply gets nothing.
    ids = [c["node_id"] for c in cards
           if c["node_id"] in vectors and c["node_id"] in node_by_id]
    if len(ids) < 2:
        return None
    index_of = {nid: i for i, nid in enumerate(ids)}
    V = np.asarray([vectors[i] for i in ids], dtype="float32")
    n = V.shape[0]

    # --- per-node related + top-level near-duplicates (one blocked pass) --------
    # V is row-normalised (concept.py normalises every stored vector), so V @ V.T
    # is the cosine matrix. Block the rows so peak memory is block*n, not n*n --
    # a 16k-node C graph would otherwise want a 1 GB dense matrix.
    k = min(neighbors, n - 1)
    dup_pairs: list[tuple] = []
    block = 512
    for start in range(0, n, block):
        sims = V[start:start + block] @ V.T
        for r in range(sims.shape[0]):
            gi = start + r
            row = sims[r]
            row[gi] = -2.0  # never a neighbour of itself
            top = np.argpartition(-row, k - 1)[:k] if k < n else np.arange(n)
            top = top[np.argsort(-row[top])]
            related = [{"id": ids[int(j)], "score": round(float(row[int(j)]), 4)}
                       for j in top if float(row[int(j)]) >= related_floor]
            if related:
                node_by_id[ids[gi]]["related"] = related
            # near-duplicates: only the upper triangle, above the copy-paste bar
            for j in np.where(row >= dup_threshold)[0]:
                j = int(j)
                if j > gi:
                    dup_pairs.append((float(row[j]), ids[gi], ids[j]))
    dup_pairs.sort(reverse=True)
    near_duplicates = [{"a": a, "b": b, "score": round(s, 4)}
                       for s, a, b in dup_pairs[:max_duplicates]]

    # --- behavioural tags (cards vs facet prototypes) ---------------------------
    facet_keys = list(_FACETS)
    facet_vecs = searcher.embed_queries([_FACETS[key] for key in facet_keys])
    F = np.asarray(facet_vecs, dtype="float32") if facet_vecs else None
    if F is not None:
        tag_sims = V @ F.T
        for i, nid in enumerate(ids):
            row = tag_sims[i]
            best = float(row.max())
            if best < tag_floor:
                continue
            picks = [facet_keys[int(t)] for t in np.argsort(-row)[:2]
                     if float(row[int(t)]) >= max(tag_floor, best - tag_margin)]
            if picks:
                node_by_id[nid]["tags"] = picks

    # --- 2-D semantic layout (PCA to the top two components) --------------------
    try:
        centered = V - V.mean(axis=0, keepdims=True)
        _u, _s, vt = np.linalg.svd(centered, full_matrices=False)
        coords = centered @ vt[:2].T
        span = np.abs(coords).max(axis=0)
        span[span == 0] = 1.0
        coords = coords / span  # each axis into [-1, 1] for the frontend
        for i, nid in enumerate(ids):
            node_by_id[nid]["xy"] = [round(float(coords[i, 0]), 4),
                                     round(float(coords[i, 1]), 4)]
    except Exception:
        pass  # layout is a nicety; never fail enrichment over a linear-algebra edge

    # --- per-module label / exemplars / coherence / outliers / tags / summary ---
    module_centroids: dict[str, "np.ndarray"] = {}
    for module in modules:
        members = [index_of[nid] for nid in module.get("node_ids") or []
                   if nid in index_of]
        if not members:
            continue
        sub = V[members]
        centroid = sub.mean(axis=0)
        norm = float(np.linalg.norm(centroid))
        if norm == 0:
            continue
        centroid = centroid / norm
        module_centroids[module["id"]] = centroid
        cos = sub @ centroid
        mean_cos = float(cos.mean())
        module["coherence"] = round(mean_cos, 4)
        order = np.argsort(-cos)
        exemplars = []
        for j in order[:3]:
            j = int(j)
            card = card_by_id.get(ids[members[j]], {})
            exemplars.append({"node_id": ids[members[j]], "name": card.get("name"),
                              "kind": card.get("kind"), "file": card.get("file"),
                              "line": card.get("line"),
                              "score": round(float(cos[j]), 4)})
        module["exemplars"] = exemplars
        # Prefer the highest-scoring *named* exemplar; fall back to the structural
        # module name so a module of arrow-fns still reads as something meaningful.
        label = next((e["name"] for e in exemplars if _named(e.get("name"))), None)
        module["semantic_label"] = label or module.get("name")
        outliers = [ids[members[int(j)]] for j in order[::-1]
                    if float(cos[int(j)]) < mean_cos - outlier_gap][:5]
        if outliers:
            module["outliers"] = outliers
        if F is not None:
            mtag = (sub @ F.T).mean(axis=0)
            tags = [facet_keys[int(t)] for t in np.argsort(-mtag)[:3]
                    if float(mtag[int(t)]) >= tag_floor]
            if tags:
                module["tags"] = tags
        blurb_tags = ", ".join(module.get("tags", [])[:2])
        blurb_ex = ", ".join(e["name"] for e in exemplars[:2] if e.get("name"))
        if blurb_tags and blurb_ex:
            module["summary"] = f"{blurb_tags} — e.g. {blurb_ex}"
        elif blurb_ex:
            module["summary"] = f"e.g. {blurb_ex}"

    # --- module <-> module affinity (centroid cosine) ---------------------------
    mids = list(module_centroids)
    if len(mids) >= 2:
        centroids = np.asarray([module_centroids[mid] for mid in mids], dtype="float32")
        msims = centroids @ centroids.T
        for r, mid in enumerate(mids):
            row = msims[r].copy()
            row[r] = -2.0
            kk = min(4, len(mids) - 1)
            picks = np.argpartition(-row, kk - 1)[:kk] if kk < len(mids) else \
                np.arange(len(mids))
            picks = picks[np.argsort(-row[picks])]
            affinity = [{"id": mids[int(j)], "score": round(float(row[int(j)]), 4)}
                        for j in picks if float(row[int(j)]) >= 0.2]
            if affinity:
                module_by_id[mid]["affinity"] = affinity

    # --- per-concept coherence / outliers / suggested members -------------------
    for concept in concepts:
        members = [index_of[nid] for nid in concept.get("node_ids") or []
                   if nid in index_of]
        if len(members) < 2:
            continue
        sub = V[members]
        centroid = sub.mean(axis=0)
        norm = float(np.linalg.norm(centroid))
        if norm == 0:
            continue
        centroid = centroid / norm
        cos = sub @ centroid
        mean_cos = float(cos.mean())
        concept["coherence"] = round(mean_cos, 4)
        outliers = [ids[members[int(j)]] for j in np.argsort(cos)
                    if float(cos[int(j)]) < mean_cos - outlier_gap][:5]
        if outliers:
            concept["outliers"] = outliers
        member_set = set(members)
        all_cos = V @ centroid
        suggested = [ids[int(i)] for i in np.argsort(-all_cos)
                     if int(i) not in member_set
                     and float(all_cos[int(i)]) >= suggest_floor][:5]
        if suggested:
            concept["suggested"] = suggested

    # --- cross-cutting concerns (a facet whose members span many modules) -------
    tag_nodes: dict[str, list[str]] = defaultdict(list)
    for nid in ids:
        for tag in node_by_id[nid].get("tags", []):
            tag_nodes[tag].append(nid)
    cross_cutting = []
    for tag, nlist in tag_nodes.items():
        spread = {node_by_id[nid].get("module") for nid in nlist
                  if node_by_id[nid].get("module")}
        if len(spread) >= 3 and len(nlist) >= 4:
            cross_cutting.append({"tag": tag, "count": len(nlist),
                                  "module_spread": len(spread),
                                  "node_ids": nlist[:20]})
    cross_cutting.sort(key=lambda item: (-item["module_spread"], -item["count"]))
    cross_cutting = cross_cutting[:max_cross_cutting]

    # --- reading order: a greedy semantic tour over the modules -----------------
    reading_order: list[str] = []
    if module_centroids:
        remaining = set(module_centroids)
        anchored = [m for m in modules
                    if m.get("anchor_node_id") and m["id"] in remaining]
        seed = (anchored or [m for m in modules if m["id"] in remaining])[0]["id"]
        current = seed
        while current is not None:
            reading_order.append(current)
            remaining.discard(current)
            if not remaining:
                break
            here = module_centroids[current]
            current = max(remaining,
                          key=lambda mid: float(here @ module_centroids[mid]))

    return {
        "model": model,
        "dimensions": int(V.shape[1]),
        "method": {"similarity": "cosine", "layout": "pca-2d",
                   "tags": "facet-prototype-cosine"},
        "coverage": {"vector_nodes": n, "bundle_nodes": len(nodes),
                     "modules_labeled": len(module_centroids)},
        "facets": facet_keys,
        "near_duplicates": near_duplicates,
        "cross_cutting": cross_cutting,
        "reading_order": reading_order,
    }
