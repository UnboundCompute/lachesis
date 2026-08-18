"""Load the detection recipe tables from the atropos catalog.

The `kind -> evaluator` recipe and the front-end sink-role bridges are pure DATA that
live in the atropos checkout (``detection/*.json``), not in this engine. This module is
the single seam that reads them: it locates atropos exactly as the enrichment path does,
loads atropos's own stdlib loader by file path -- atropos is neither vendored nor
pip-installable, so it is imported by path, never as a package -- and returns the tables.
Every other module in this package is handed the tables and never touches atropos.

A `Detector` bundles the recipe with one selected front-end bridge so the adapter carries
a single object: `detector.bridge(role)` translates a graph's sink role to a catalog kind,
and `detector.evaluate(kind, fact)` / `detector.is_call_level(kind)` run the recipe.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Optional

from lachesis.integrations.atropos.enrich import locate_atropos
from lachesis.detect import substrate


class DetectionCatalogUnavailable(RuntimeError):
    """No atropos checkout carrying the detection layer could be found or loaded."""


def _load_detection_module(atropos_root: Path):
    """Import atropos's ``tools/detection.py`` by file path (it self-checks the data)."""
    path = atropos_root / "tools" / "detection.py"
    if not path.exists():
        raise DetectionCatalogUnavailable(
            f"atropos at {atropos_root} has no detection layer (missing tools/detection.py)"
        )
    spec = importlib.util.spec_from_file_location("atropos_detection", str(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_detection(explicit: Optional[str] = None) -> dict:
    """Return {evaluators, kind_evaluator, role_bridges} from the atropos detection layer.

    Raises DetectionCatalogUnavailable if no atropos checkout is present. Set ATROPOS_ROOT
    or pass ``explicit`` to point at a checkout in a non-standard location.
    """
    root = locate_atropos(explicit)
    if root is None:
        raise DetectionCatalogUnavailable(
            "no atropos checkout found (set ATROPOS_ROOT or place it beside the lachesis repo)"
        )
    return _load_detection_module(root).load_detection()


class Detector:
    """The recipe plus one selected front-end sink-role bridge, ready to route facts."""

    def __init__(self, kind_evaluator: dict, role_bridge: dict, vocabulary: str):
        self.kind_evaluator = kind_evaluator
        self.role_bridge = role_bridge
        self.vocabulary = vocabulary

    def bridge(self, sink_role):
        """Translate a front-end sink role into the catalog kind its evaluator runs, or None."""
        return self.role_bridge.get(sink_role)

    def evaluate(self, kind, fact):
        return substrate.evaluate(kind, fact, self.kind_evaluator)

    def is_call_level(self, kind):
        return substrate.is_call_level(kind, self.kind_evaluator)


def load_detector(vocabulary: str = "generic-security-roles",
                  explicit: Optional[str] = None) -> Detector:
    """Load the recipe and the bridge for one front-end vocabulary as a single Detector.

    ``vocabulary`` selects which sink-role bridge to bind (the enriched Lachesis graphs
    stamp ``generic-security-roles``). An unknown vocabulary binds an empty bridge -- the
    recipe still runs for any kind resolved another way.
    """
    d = load_detection(explicit)
    bridge = d["role_bridges"].get(vocabulary, {})
    return Detector(d["kind_evaluator"], bridge, vocabulary)
