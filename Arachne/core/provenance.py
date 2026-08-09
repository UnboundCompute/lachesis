"""Source and inference provenance rules for canonical graph facts."""
from __future__ import annotations

from typing import Iterable, Mapping

from .schema import CONFIDENCE_LEVELS, FACT_ORIGINS


SOURCE_PROVENANCE_FIELDS = (
    "frontend_id", "language", "absolute_file", "content_hash",
    "start_offset", "end_offset", "start_line", "start_column",
    "end_line", "end_column", "compiler_node_id",
)


def source_provenance_errors(properties: Mapping[str, object]) -> list[str]:
    errors = [name for name in SOURCE_PROVENANCE_FIELDS if properties.get(name) is None]
    start = properties.get("start_offset")
    end = properties.get("end_offset")
    if isinstance(start, int) and isinstance(end, int) and end < start:
        errors.append("end_offset_before_start_offset")
    return errors


def inference_provenance_errors(properties: Mapping[str, object]) -> list[str]:
    errors = []
    origin = properties.get("origin")
    confidence = properties.get("confidence")
    evidence = properties.get("evidence_ids")
    if origin not in FACT_ORIGINS:
        errors.append("origin")
    if confidence not in CONFIDENCE_LEVELS:
        errors.append("confidence")
    if origin != "compiler" and (not isinstance(evidence, list) or not evidence):
        errors.append("evidence_ids")
    return errors

