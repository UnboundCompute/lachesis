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
INDEX_VERSION = 8
EMBED_BATCH_SIZE = 32
RICH_RERANK_CANDIDATES = 32
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
        "install": "pip install 'lachesis-cpg[concept-search]'",
        "download": f"lachesis concept-model download --model {model}",
        **{key: metadata[key] for key in ("dimensions", "runtime_version", "generation")
           if key in metadata},
    }


def download_model(model: str = DEFAULT_MODEL) -> dict:
    if not runtime_available():
        raise RuntimeError("FastEmbed is not installed; run: "
                           "pip install 'lachesis-cpg[concept-search]'")
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

    def _ensure_index(self):
        if self._index is not None:
            return self._index, None
        embedder, error = _load_embedder(self.model)
        if error:
            return None, error
        cards = semantic_cards(self.store)
        fingerprint = _fingerprint(self.store, cards, self.model)
        path = _index_path(fingerprint, self.model)
        if path.is_file():
            try:
                with gzip.open(path, "rt", encoding="utf-8") as handle:
                    payload = json.load(handle)
                if payload.get("fingerprint") == fingerprint:
                    self._embedder, self._index, self._index_file = embedder, payload, path
                    return payload, None
            except (OSError, ValueError):
                pass
        payload = {"version": INDEX_VERSION, "model": self.model,
                   "fingerprint": fingerprint, "cards": cards, "rich_vectors": {}}
        _write_index(path, payload)
        self._embedder, self._index, self._index_file = embedder, payload, path
        return payload, None

    def search(self, query: str, limit: int = 20, min_score: float = 0.0,
               offset: int = 0) -> dict:
        payload, error = self._ensure_index()
        if error:
            return {"move": "concept_search", "query": query, **error}
        query_vector = _norm(next(iter(self._embedder.embed(["query: " + query]))))
        if self._card_tokens is None:
            self._card_tokens = [_search_tokens(card["text"]) for card in payload["cards"]]
        query_tokens = _search_tokens(query)
        document_count = max(1, len(self._card_tokens))
        frequencies = {token: sum(token in tokens for tokens in self._card_tokens)
                       for token in query_tokens}
        weights = {token: math.log((document_count + 1) / (frequencies[token] + 1)) + 1
                   for token in query_tokens}
        denominator = sum(weights.values()) or 1.0
        coarse = []
        for card, tokens in zip(payload["cards"], self._card_tokens):
            score = sum(weight for token, weight in weights.items() if token in tokens)
            coarse.append((score / denominator, card))
        coarse.sort(key=lambda item: (-item[0], item[1].get("file") or "",
                                      item[1].get("line") or 0, item[1]["node_id"]))

        # Richly rerank a stable prefix, then append the remaining lexical order.
        # Pagination therefore reaches the whole corpus without changing earlier pages,
        # while no query embeds more than this fixed, inspectable amount of source.
        shortlist = coarse[:RICH_RERANK_CANDIDATES]
        rich_vectors = payload.setdefault("rich_vectors", {})
        missing = [card for _score, card in shortlist if card["node_id"] not in rich_vectors]
        if missing:
            generated = _embed_documents(
                self._embedder, ["passage: " + card["text"] for card in missing],
            )
            rich_vectors.update({card["node_id"]: vector
                                 for card, vector in zip(missing, generated)})
            if self._index_file is not None:
                _write_index(self._index_file, payload)
        reranked = []
        for coarse_score, card in shortlist:
            vector = rich_vectors.get(card["node_id"])
            rich_score = (sum(left * right for left, right in zip(query_vector, vector))
                          if vector else coarse_score)
            score = 0.35 * coarse_score + 0.65 * rich_score
            reranked.append((score, card, "rich"))
        reranked.sort(key=lambda item: (-item[0], item[1].get("file") or "",
                                        item[1].get("line") or 0, item[1]["node_id"]))
        ranked = reranked + [(score, card, "structural")
                             for score, card in coarse[RICH_RERANK_CANDIDATES:]]
        ranked = [item for item in ranked if item[0] >= min_score]
        start, size = max(0, offset), max(1, limit)
        page = ranked[start:start + size]
        results = [{k: v for k, v in card.items() if k != "text"} |
                   {"score": round(score, 6), "ranking_tier": tier,
                    "summary": card["text"][:500]}
                   for score, card, tier in page]
        next_offset = start + len(results)
        has_more = next_offset < len(ranked)
        return {"move": "concept_search", "query": query, "model": self.model,
                "index": {"documents": len(payload["cards"]),
                          "fingerprint": payload["fingerprint"],
                          "strategy": "lexical-structural-global-plus-rich-rerank",
                          "rich_rerank_candidates": min(
                              RICH_RERANK_CANDIDATES, len(payload["cards"])),
                          "rich_vectors_cached": len(rich_vectors)},
                "count": len(results), "total": len(ranked), "results": results,
                "page": {"total": len(ranked), "offset": start,
                         "returned": len(results), "has_more": has_more,
                         "next_offset": next_offset if has_more else None}}
