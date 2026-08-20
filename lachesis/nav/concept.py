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

from .graphlib import CALLABLE_KINDS


DEFAULT_MODEL = "BAAI/bge-small-en-v1.5"
INDEX_VERSION = 1
CARD_KINDS = frozenset((*CALLABLE_KINDS, "class", "interface", "type", "record", "enum"))


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


def semantic_cards(store) -> list[dict]:
    """Compact graph-grounded documents; no whole raw body is embedded."""
    gl, index = store.gl, store.index
    cards = []
    for node in index.nodes_of_kind(*CARD_KINDS):
        name = gl.label(node)
        if not name:
            continue
        props = node.get("properties", {})
        parts = [f"{node.get('kind')} {name}"]
        signature = props.get("signature") or props.get("type")
        if signature:
            parts.append(f"signature {signature}")
        if node.get("kind") in CALLABLE_KINDS:
            callees = sorted({gl.label(target) for target in gl.calls_from(node["id"])
                              if gl.label(target)})
            if callees:
                parts.append("calls " + ", ".join(callees[:40]))
            controls = sorted({body.get("properties", {}).get("control_kind")
                               for body in index.nodes_owned_by(node["id"])
                               if body.get("properties", {}).get("control_kind")})
            if controls:
                parts.append("control " + ", ".join(controls))
            source = gl.source_text(node)
            if source:
                # Enough lexical behavior for semantic retrieval, bounded below the
                # model's 512-token context rather than embedding an arbitrary body.
                compact = " ".join(source.split())[:2200]
                parts.append("code " + compact)
        else:
            members = sorted({gl.label(member)
                              for member in index.targets(node["id"], "DECLARES_MEMBER")
                              if gl.label(member)})
            if members:
                parts.append("members " + ", ".join(members[:80]))
        cards.append({**_location(gl, node), "text": "\n".join(parts)})
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


class ConceptSearch:
    def __init__(self, store, model: str = DEFAULT_MODEL) -> None:
        self.store = store
        self.model = model
        self._index = None
        self._embedder = None

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
                    self._embedder, self._index = embedder, payload
                    return payload, None
            except (OSError, ValueError):
                pass
        documents = ["passage: " + card["text"] for card in cards]
        vectors = [_norm(vector) for vector in embedder.embed(documents)] if documents else []
        payload = {"version": INDEX_VERSION, "model": self.model,
                   "fingerprint": fingerprint, "cards": cards, "vectors": vectors}
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(path.suffix + f".tmp.{os.getpid()}")
        with gzip.open(temporary, "wt", encoding="utf-8") as handle:
            json.dump(payload, handle, separators=(",", ":"))
        temporary.replace(path)
        self._embedder, self._index = embedder, payload
        return payload, None

    def search(self, query: str, limit: int = 20, min_score: float = 0.0) -> dict:
        payload, error = self._ensure_index()
        if error:
            return {"move": "concept_search", "query": query, **error}
        query_vector = _norm(next(iter(self._embedder.embed(["query: " + query]))))
        ranked = []
        for card, vector in zip(payload["cards"], payload["vectors"]):
            score = sum(left * right for left, right in zip(query_vector, vector))
            if score >= min_score:
                ranked.append((score, card))
        ranked.sort(key=lambda item: (-item[0], item[1].get("file") or "",
                                      item[1].get("line") or 0))
        results = [{k: v for k, v in card.items() if k != "text"} |
                   {"score": round(score, 6), "summary": card["text"][:500]}
                   for score, card in ranked[:max(1, limit)]]
        return {"move": "concept_search", "query": query, "model": self.model,
                "index": {"documents": len(payload["cards"]),
                          "fingerprint": payload["fingerprint"]},
                "count": len(results), "results": results}
