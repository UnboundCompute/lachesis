"""Optional, local semantic retrieval for code-comprehension queries.

The core wheel contains this adapter but neither its runtime nor model weights.
Installing ``lachesis-cpg[concept-search]`` adds FastEmbed; running the explicit
``lachesis concept-model download`` command downloads the model into a user cache.
Search itself is offline-only and will never initiate a network request.
"""
from __future__ import annotations

import gzip
import hashlib
from importlib.metadata import PackageNotFoundError, version as package_version
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import uuid

from .graphlib import CALLABLE_KINDS, camel_tokens


DEFAULT_MODEL = "BAAI/bge-small-en-v1.5"
INDEX_VERSION = 9
EMBED_BATCH_SIZE = 32
CARD_KINDS = frozenset((*CALLABLE_KINDS, "class", "interface", "type", "record", "enum"))
_NON_APPLICATION_PATH = re.compile(
    r"(^|/)(node_modules|vendor|vendors|third_party|third-party|tests?|__tests__|js_tests)(/|$)"
    r"|[._-](test|spec)(?:[._-]|$)",
    re.IGNORECASE,
)


def cache_root() -> Path:
    configured = os.environ.get("LACHESIS_CONCEPT_CACHE")
    if configured:
        return Path(configured).expanduser().resolve()
    xdg = os.environ.get("XDG_CACHE_HOME")
    base = Path(xdg).expanduser() if xdg else Path.home() / ".cache"
    return base / "lachesis" / "concept-search"


def model_cache() -> Path:
    return cache_root() / "models"


def _slug(model: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "--", model)


def model_marker(model: str = DEFAULT_MODEL) -> Path:
    return model_cache() / f"{_slug(model)}.ready.json"


def runtime_available() -> bool:
    return importlib.util.find_spec("fastembed") is not None


def model_status(model: str = DEFAULT_MODEL) -> dict:
    marker = model_marker(model)
    metadata = {}
    if marker.is_file():
        try:
            metadata = json.loads(marker.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            metadata = {}
    return {
        "runtime": "installed" if runtime_available() else "missing",
        "model": model,
        "model_ready": bool(metadata.get("model") == model),
        "cache": str(model_cache()),
        "install": "python -m pip install 'lachesis-cpg[concept-search]'",
        "download": f"lachesis concept-model download --model {model}",
        **{key: metadata[key] for key in ("dimensions", "runtime_version", "generation")
           if key in metadata},
    }


def download_model(model: str = DEFAULT_MODEL) -> dict:
    if not runtime_available():
        raise RuntimeError("FastEmbed is not installed; run: "
                           "python -m pip install 'lachesis-cpg[concept-search]'")
    from fastembed import TextEmbedding

    directory = model_cache()
    directory.mkdir(parents=True, exist_ok=True)
    embedder = TextEmbedding(model_name=model, cache_dir=str(directory),
                             local_files_only=False)
    # Force lazy runtimes to load and validate the downloaded files before marking ready.
    vector = next(iter(embedder.embed(["passage: local model readiness check"])))
    marker = model_marker(model)
    try:
        runtime_version = package_version("fastembed")
    except PackageNotFoundError:
        runtime_version = "unknown"
    marker.write_text(json.dumps({
        "model": model, "dimensions": len(vector), "runtime_version": runtime_version,
        # An explicit re-download may refresh a mutable upstream model ID. Changing
        # this generation makes every graph-vector cache rebuild against those weights.
        "generation": uuid.uuid4().hex,
    }, indent=2) + "\n", encoding="utf-8")
    return {**model_status(model), "dimensions": len(vector)}


def _location(gl, node: dict) -> dict:
    file, line, _ = gl.loc(node)
    return {"node_id": node["id"], "name": gl.label(node), "kind": node.get("kind"),
            "file": file, "line": line}


def _application_card(gl, node: dict) -> bool:
    file, _line, _end = gl.loc(node)
    provenance = str((node.get("properties") or {}).get("provenance") or "").casefold()
    return provenance not in {"external", "dependency", "vendor"} and not (
        file and _NON_APPLICATION_PATH.search(file.replace("\\", "/"))
    )


def semantic_cards(store) -> list[dict]:
    """Compact graph-grounded documents; no whole raw body is embedded."""
    gl, index = store.gl, store.index
    cards = []
    seen_text = set()
    # Build the two relational summaries in bulk. Asking ``calls_from`` and
    # ``DECLARES_MEMBER`` once per card turns a 16k-card C graph into tens of thousands
    # of Kuzu round trips; the edge families are small enough to scan once and group.
    label_by_id = {
        (item["id"] if isinstance(item, dict) else item): label
        for label, items in index.by_label.items() if label for item in items
    }
    calls_by_source = {}
    for edge in index.edges_of_kind("CALLS"):
        name = label_by_id.get(edge["target"])
        if name:
            calls_by_source.setdefault(edge["source"], set()).add(name)
    members_by_type = {}
    for edge in index.edges_of_kind("DECLARES_MEMBER"):
        name = label_by_id.get(edge["target"])
        if name:
            members_by_type.setdefault(edge["source"], set()).add(name)

    for node in index.nodes_of_kind(*CARD_KINDS):
        if not _application_card(gl, node):
            continue
        name = gl.label(node)
        if not name:
            continue
        props = node.get("properties", {})
        parts = [f"{node.get('kind')} {name}"]
        signature = props.get("signature") or props.get("type")
        if signature:
            parts.append(f"signature {signature}")
        if node.get("kind") in CALLABLE_KINDS:
            callees = sorted(calls_by_source.get(node["id"], ()))
            if callees:
                parts.append("calls " + ", ".join(callees[:20]))
            source = gl.source_text(node)
            if source:
                # Rich source behavior is retained for the full semantic index. The
                # interactive path will use a coarse structural pass before embedding
                # only a shortlist of these richer cards.
                parts.append("code " + " ".join(source.split())[:1000])
        else:
            members = sorted(members_by_type.get(node["id"], ()))
            if members:
                parts.append("members " + ", ".join(members[:40]))
        text = "\n".join(parts)
        # C graphs commonly contain the same record declaration once per translation
        # unit. Embedding identical cards repeatedly spends minutes and adds no search
        # signal; keep the first stable location as the representative result.
        if text in seen_text:
            continue
        seen_text.add(text)
        cards.append({**_location(gl, node), "text": text})
    cards.sort(key=lambda card: (card.get("file") or "", card.get("line") or 0,
                                 card["name"], card["node_id"]))
    return cards


def _fingerprint(store, cards: list[dict], model: str) -> str:
    graph_hash = store.graph_hash()
    digest = hashlib.sha256()
    digest.update(f"concept-v{INDEX_VERSION}\0{model}\0{graph_hash}".encode())
    try:
        digest.update(model_marker(model).read_bytes())
    except OSError:
        pass
    if not graph_hash:
        for card in cards:
            digest.update(card["node_id"].encode())
            digest.update(b"\0")
            digest.update(card["text"].encode())
    return digest.hexdigest()


def _index_path(fingerprint: str, model: str) -> Path:
    return cache_root() / "indexes" / f"{fingerprint}-{_slug(model)}.json.gz"


def _load_embedder(model: str):
    status = model_status(model)
    if status["runtime"] != "installed":
        return None, {"error": "concept-runtime-missing", **status}
    if not status["model_ready"]:
        return None, {"error": "concept-model-not-downloaded", **status}
    from fastembed import TextEmbedding
    try:
        # Search is strictly offline. Only the explicit download command may fetch.
        return TextEmbedding(model_name=model, cache_dir=str(model_cache()),
                             local_files_only=True), None
    except Exception as error:  # the cache marker can outlive manually removed weights
        return None, {"error": "concept-model-cache-invalid", "detail": str(error), **status}


def _norm(vector) -> list[float]:
    values = [float(value) for value in vector]
    length = math.sqrt(sum(value * value for value in values))
    return [value / length for value in values] if length else values


def _embed_documents(embedder, documents: list[str]) -> list[list[float]]:
    """Embed in explicit small batches so ONNX never retains a corpus-sized tensor."""
    vectors = []
    for start in range(0, len(documents), EMBED_BATCH_SIZE):
        batch = documents[start:start + EMBED_BATCH_SIZE]
        try:
            generated = embedder.embed(batch, batch_size=EMBED_BATCH_SIZE)
        except TypeError:  # lightweight test/fallback adapters may omit batch_size
            generated = embedder.embed(batch)
        vectors.extend(_norm(vector) for vector in generated)
    return vectors


_LEXICAL_STOP = frozenset({
    "a", "an", "and", "are", "as", "at", "be", "by", "does", "for", "from",
    "how", "in", "is", "it", "of", "on", "or", "the", "this", "to", "what",
    "when", "where", "which", "with",
})


def _search_tokens(text: str) -> frozenset[str]:
    tokens = set()
    for word in re.findall(r"[A-Za-z_$][A-Za-z0-9_$]*", text):
        tokens.add(word.casefold())
        tokens.update(token.casefold() for token in camel_tokens(word))
    return frozenset(token for token in tokens if token and token not in _LEXICAL_STOP)


def _write_index(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + f".tmp.{os.getpid()}")
    with gzip.open(temporary, "wt", encoding="utf-8") as handle:
        json.dump(payload, handle, separators=(",", ":"))
    temporary.replace(path)


class ConceptSearch:
    def __init__(self, store, model: str = DEFAULT_MODEL) -> None:
        self.store = store
        self.model = model
        self._index = None
        self._embedder = None
        self._index_file: Path | None = None
        self._card_tokens: list[frozenset[str]] | None = None
        # None when the model is ready; otherwise the runtime/download status that
        # explains why search fell back to lexical ranking.
        self._embed_status: dict | None = None

    def _ensure_index(self):
        if self._index is not None:
            return self._index, None
        cards = semantic_cards(self.store)
        # The embedder is optional. When it is missing the index still serves the
        # lexical fallback, so a missing model degrades search rather than failing it.
        embedder, self._embed_status = _load_embedder(self.model)
        fingerprint = _fingerprint(self.store, cards, self.model)
        path = _index_path(fingerprint, self.model)
        payload = None
        if path.is_file():
            try:
                with gzip.open(path, "rt", encoding="utf-8") as handle:
                    loaded = json.load(handle)
                if loaded.get("fingerprint") == fingerprint:
                    payload = loaded
            except (OSError, ValueError):
                payload = None
        if payload is None:
            payload = {"version": INDEX_VERSION, "model": self.model,
                       "fingerprint": fingerprint, "cards": cards, "vectors": {}}
            _write_index(path, payload)
        self._embedder, self._index, self._index_file = embedder, payload, path
        # With the model present, embed every card once and persist the vectors. Ranking
        # is then a cosine over the whole corpus, so the lexical pass never caps recall --
        # the fix for intent queries whose answer sits outside any lexical shortlist. The
        # embed is a one-time, fingerprint-keyed cost; later searches only embed the query.
        if embedder is not None:
            vectors = payload.setdefault("vectors", {})
            missing = [card for card in cards if card["node_id"] not in vectors]
            if missing:
                generated = _embed_documents(
                    embedder, ["passage: " + card["text"] for card in missing])
                vectors.update({card["node_id"]: vector
                                for card, vector in zip(missing, generated)})
                _write_index(path, payload)
        return payload, None

    def _lexical_relevance(self, cards: list[dict], query: str) -> list[float]:
        """IDF-weighted query-token overlap per card, normalised to [0, 1].

        Always computed: it is the whole ranking when the model is absent, and a small
        exact-identifier bonus when it is present so a typed symbol name stays pinned.
        """
        if self._card_tokens is None:
            self._card_tokens = [_search_tokens(card["text"]) for card in cards]
        query_tokens = _search_tokens(query)
        document_count = max(1, len(self._card_tokens))
        frequencies = {token: sum(token in tokens for tokens in self._card_tokens)
                       for token in query_tokens}
        weights = {token: math.log((document_count + 1) / (frequencies[token] + 1)) + 1
                   for token in query_tokens}
        denominator = sum(weights.values()) or 1.0
        return [sum(weight for token, weight in weights.items() if token in tokens)
                / denominator for tokens in self._card_tokens]

    def search(self, query: str, limit: int = 20, min_score: float = 0.0,
               offset: int = 0) -> dict:
        payload, error = self._ensure_index()
        if error:
            return {"move": "concept_search", "query": query, **error}
        cards = payload["cards"]
        lexical = self._lexical_relevance(cards, query)
        vectors = payload.get("vectors") or {}

        if self._embedder is not None and vectors:
            query_vector = _norm(next(iter(self._embedder.embed(["query: " + query]))))
            query_tokens = _search_tokens(query)
            typed = query.strip().casefold()
            strategy = "embedding-global"
            scored = []
            for card in cards:
                vector = vectors.get(card["node_id"])
                cosine = (sum(left * right for left, right in zip(query_vector, vector))
                          if vector else 0.0)
                # A small lexical bonus keeps an exactly- or prefix-typed identifier at the
                # top; it never outweighs a strong semantic match on an intent query.
                name = (card.get("name") or "").casefold()
                bonus = (0.15 if name and typed == name else
                         0.05 if name and any(name == token or name.startswith(token)
                                              for token in query_tokens) else 0.0)
                scored.append((cosine + bonus, card, "embedding"))
        else:
            strategy = "lexical-fallback"
            scored = [(score, card, "lexical") for score, card in zip(lexical, cards)]

        scored.sort(key=lambda item: (-item[0], item[1].get("file") or "",
                                      item[1].get("line") or 0, item[1]["node_id"]))
        ranked = [item for item in scored if item[0] >= min_score]
        start, size = max(0, offset), max(1, limit)
        page = ranked[start:start + size]
        results = [{k: v for k, v in card.items() if k != "text"} |
                   {"score": round(score, 6), "ranking_tier": tier,
                    "summary": card["text"][:500]}
                   for score, card, tier in page]
        next_offset = start + len(results)
        has_more = next_offset < len(ranked)
        index = {"documents": len(cards), "fingerprint": payload["fingerprint"],
                 "strategy": strategy, "vectors_cached": len(vectors)}
        if self._embed_status:
            # Keep the fallback actionable: name why meaning-based search is off *and*
            # how to turn it on, so a lexical-fallback answer still points the way.
            index["semantic"] = self._embed_status.get("error", "unavailable")
            for hint in ("download", "install"):
                if self._embed_status.get(hint):
                    index[hint] = self._embed_status[hint]
        return {"move": "concept_search", "query": query, "model": self.model,
                "index": index,
                "count": len(results), "total": len(ranked), "results": results,
                "page": {"total": len(ranked), "offset": start,
                         "returned": len(results), "has_more": has_more,
                         "next_offset": next_offset if has_more else None}}

    def find_similar(self, anchor: str, limit: int = 15,
                     min_score: float = 0.0) -> dict:
        """Cards nearest an anchor node by cosine over the cached card vectors.

        Purely a reuse of the vectors `search` already persisted -- nothing is re-embedded.
        The anchor is matched as a node id first, then by exact card name, so both
        `find_similar("flask.helpers.make_response")` and `find_similar("make_response")`
        work. This is strictly a retrieval lead (a "what else looks like this"): it never
        resolves a seed for the judge path. Without a model there are no vectors and hence
        no notion of similarity, so it returns an explanatory note rather than guessing.
        """
        payload, error = self._ensure_index()
        if error:
            return {"move": "find_similar", "anchor": anchor, **error}
        cards = payload["cards"]
        vectors = payload.get("vectors") or {}
        if self._embedder is None or not vectors:
            note = (self._embed_status or {}).get("error") if self._embed_status else \
                "no cached vectors; run `lachesis concept-model download` to enable"
            return {"move": "find_similar", "anchor": anchor, "model": self.model,
                    "index": {"documents": len(cards), "strategy": "unavailable",
                              "vectors_cached": len(vectors), "semantic": note},
                    "count": 0, "total": 0, "results": []}

        by_id = {card["node_id"]: card for card in cards}
        anchor_card = by_id.get(anchor)
        if anchor_card is None:
            folded = anchor.strip().casefold()
            anchor_card = next((card for card in cards
                                if (card.get("name") or "").casefold() == folded), None)
        anchor_vector = vectors.get(anchor_card["node_id"]) if anchor_card else None
        if anchor_vector is None:
            return {"move": "find_similar", "anchor": anchor, "model": self.model,
                    "error": f"no indexed node matches {anchor!r} "
                             "(pass a node id or an exact declaration name)",
                    "index": {"documents": len(cards), "strategy": "embedding-global",
                              "vectors_cached": len(vectors)},
                    "count": 0, "total": 0, "results": []}

        anchor_id = anchor_card["node_id"]
        scored = []
        for card in cards:
            if card["node_id"] == anchor_id:
                continue
            vector = vectors.get(card["node_id"])
            if not vector:
                continue
            cosine = sum(left * right for left, right in zip(anchor_vector, vector))
            scored.append((cosine, card))
        scored.sort(key=lambda item: (-item[0], item[1].get("file") or "",
                                      item[1].get("line") or 0, item[1]["node_id"]))
        ranked = [item for item in scored if item[0] >= min_score]
        page = ranked[:max(1, limit)]
        results = [{k: v for k, v in card.items() if k != "text"} |
                   {"score": round(score, 6), "ranking_tier": "embedding",
                    "summary": card["text"][:500]}
                   for score, card in page]
        return {"move": "find_similar", "anchor": anchor, "model": self.model,
                "anchor_node": {"node_id": anchor_id, "name": anchor_card.get("name"),
                                "kind": anchor_card.get("kind"),
                                "file": anchor_card.get("file"),
                                "line": anchor_card.get("line")},
                "index": {"documents": len(cards), "fingerprint": payload["fingerprint"],
                          "strategy": "embedding-global", "vectors_cached": len(vectors)},
                "count": len(results), "total": len(ranked), "results": results}

    def representatives(self, node_ids, k: int = 3) -> list[dict] | None:
        """The members nearest the vector centroid of a set of nodes -- its exemplars.

        Given the members of a community (or any node set), average their cached card
        vectors and return the k members closest to that mean. That closest member reads
        as 'what this cluster is mostly about', a semantic complement to the structural
        highest-degree label. Reuses cached vectors only; embeds nothing. Returns None
        when there is no model (so a caller keeps its structural label untouched) rather
        than an error -- this is a labelling nicety, never a load-bearing result.
        """
        payload, error = self._ensure_index()
        if error or self._embedder is None:
            return None
        vectors = payload.get("vectors") or {}
        present = [(nid, vectors[nid]) for nid in dict.fromkeys(node_ids)
                   if nid in vectors]
        if not present:
            return None
        dimensions = len(present[0][1])
        centroid = [0.0] * dimensions
        for _, vector in present:
            for i, value in enumerate(vector):
                centroid[i] += value
        centroid = _norm([value / len(present) for value in centroid])
        by_id = {card["node_id"]: card for card in payload["cards"]}
        scored = sorted(((sum(a * b for a, b in zip(centroid, vector)), nid)
                         for nid, vector in present), reverse=True)
        exemplars = []
        for score, nid in scored[:max(1, k)]:
            card = by_id.get(nid, {})
            exemplars.append({"node_id": nid, "name": card.get("name"),
                              "kind": card.get("kind"), "file": card.get("file"),
                              "line": card.get("line"), "score": round(score, 6)})
        return exemplars

    def vector_matrix(self):
        """(cards, {node_id: vector}) from the cached index, or None without a model.

        A read-only accessor over the vectors ``search`` already persisted, for a
        caller that builds a comprehension overlay (the offline bundle enrichment)
        rather than running a single query. It reuses the fingerprint-keyed cache and
        embeds nothing beyond the one-time card indexing. Returns None when there is no
        local model or no cached vectors, so the caller degrades to a structure-only
        artifact rather than forcing a download. The vectors are already L2-normalised,
        so a dot product between any two is their cosine similarity.
        """
        payload, error = self._ensure_index()
        if error or self._embedder is None:
            return None
        vectors = payload.get("vectors") or {}
        if not vectors:
            return None
        return payload["cards"], vectors

    def embed_queries(self, texts) -> list[list[float]] | None:
        """Embed short intent phrases with search's ``query:`` prefix; None without a model.

        Used to place cards against a small fixed vocabulary of behavioural facets (a
        tagging pass), following the same asymmetric query/passage convention ``search``
        uses so a facet phrase and a card are compared the way a query and a passage are.
        Returns None when there is no model so the caller simply omits tags.
        """
        payload, error = self._ensure_index()
        if error or self._embedder is None:
            return None
        texts = list(texts)
        if not texts:
            return []
        return _embed_documents(self._embedder, ["query: " + text for text in texts])
