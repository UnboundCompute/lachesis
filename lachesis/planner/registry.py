"""Registry and query surface for obligation-candidate enumerators."""
from __future__ import annotations

from dataclasses import dataclass

from .unbounded_copy import MemoryCopyCapacity


@dataclass(frozen=True)
class ConstructorSpec:
    implementation: type

    @property
    def metadata(self) -> dict:
        return dict(self.implementation.metadata)


class CandidateRegistry:
    def __init__(self, graph: dict, bind_summary: dict | None = None) -> None:
        self.graph, self.bind_summary = graph, bind_summary or {}
        self._specs: dict[str, ConstructorSpec] = {}
        self._results: dict[str, dict] = {}

    def register(self, implementation: type) -> None:
        constructor_id = implementation.metadata["id"]
        if constructor_id in self._specs:
            raise ValueError(f"candidate constructor already registered: {constructor_id}")
        self._specs[constructor_id] = ConstructorSpec(implementation)

    @property
    def constructors(self) -> tuple[dict, ...]:
        return tuple(self._specs[key].metadata for key in sorted(self._specs))

    def _result(self, constructor: str) -> dict:
        if constructor not in self._specs:
            raise KeyError(f"unknown candidate constructor: {constructor}")
        if constructor not in self._results:
            impl = self._specs[constructor].implementation(self.graph, self.bind_summary)
            self._results[constructor] = impl.enumerate()
        return self._results[constructor]

    def selected(self, *, constructor: str | None = None,
                 domain: str | None = None, language: str | None = None) -> list[str]:
        if constructor:
            metadata = self._specs.get(constructor)
            if metadata is None:
                raise KeyError(f"unknown candidate constructor: {constructor}")
            keys = [constructor]
        else:
            keys = sorted(self._specs)
        return [key for key in keys
                if (domain is None or self._specs[key].metadata["domain"] == domain)
                and (language is None or language in self._specs[key].metadata["languages"])]

    @staticmethod
    def _offset(cursor: str | None) -> int:
        if not cursor:
            return 0
        if not cursor.startswith("v1:"):
            raise ValueError("invalid candidate cursor")
        return max(0, int(cursor.split(":", 1)[1]))

    def candidates(self, *, constructor: str | None = None, domain: str | None = None,
                   language: str | None = None, limit: int = 40,
                   cursor: str | None = None, detail: str = "compact") -> dict:
        keys = self.selected(constructor=constructor, domain=domain, language=language)
        if len(keys) != 1:
            return {"move": "candidates", "groups": [
                self.candidates(constructor=key, limit=limit, cursor=cursor, detail=detail)
                for key in keys], "constructors": keys}
        result = self._result(keys[0])
        offset, limit = self._offset(cursor), max(1, min(int(limit), 200))
        all_rows = result["candidates"]
        rows = all_rows[offset:offset + limit]
        if detail == "compact":
            rows = [{k: row[k] for k in (
                "candidate_id", "constructor", "domain", "language", "obligation",
                "handles", "observations", "rank", "rank_reasons", "completeness", "next_op")}
                    for row in rows]
        next_cursor = f"v1:{offset + len(rows)}" if offset + len(rows) < len(all_rows) else None
        return {"move": "candidates", "constructor": keys[0], "returned": len(rows),
                "total": len(all_rows), "cursor": cursor, "next_cursor": next_cursor,
                "candidates": rows, "census": result["census"],
                "frontiers": result["frontiers"],
                "complete_for_observable_graph": result["complete_for_observable_graph"]}

    def detail(self, candidate_id: str) -> dict:
        for key in sorted(self._specs):
            for row in self._result(key)["candidates"]:
                if row["candidate_id"] == candidate_id:
                    return {"move": "candidate_detail", "candidate": row}
        return {"move": "candidate_detail", "error": f"unknown candidate: {candidate_id}"}

    def census(self, constructor: str | None = None) -> dict:
        keys = self.selected(constructor=constructor)
        return {"move": "candidate_census", "constructors": [{
            "metadata": self._result(key)["metadata"],
            "census": self._result(key)["census"],
            "frontiers": self._result(key)["frontiers"],
            "complete_for_observable_graph": self._result(key)["complete_for_observable_graph"],
        } for key in keys]}


def default_candidate_registry(graph: dict, bind_summary: dict | None = None) -> CandidateRegistry:
    registry = CandidateRegistry(graph, bind_summary)
    registry.register(MemoryCopyCapacity)
    return registry
