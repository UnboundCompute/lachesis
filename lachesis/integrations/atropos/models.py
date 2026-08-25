"""Load Atropos catalog entries without importing its Python binder."""
from __future__ import annotations

import json
from pathlib import Path


class CatalogError(ValueError):
    """A catalog file that cannot be safely loaded."""


def load_models(root: Path) -> list[dict]:
    """Load model entries; matching is performed exclusively by the Rust binder."""
    out: list[dict] = []
    for path in sorted(root.rglob("*.json")):
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except OSError as error:
            raise CatalogError(f"cannot read model file {path}: {error}") from error
        except json.JSONDecodeError as error:
            raise CatalogError(f"invalid JSON in model file {path}: {error}") from error
        if not isinstance(document, dict) or not isinstance(document.get("entries"), list):
            raise CatalogError(f"invalid model document shape: {path}")
        for entry in document["entries"]:
            if not isinstance(entry, dict):
                raise CatalogError(f"invalid model entry in {path}")
            out.append(entry)
    return out
