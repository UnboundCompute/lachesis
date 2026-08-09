"""Language-neutral registry contract for runtime and framework models."""
from __future__ import annotations

from typing import Iterable, Protocol, Tuple

from ..core.composition import GraphDelta
from ..core.contract import ContractError


class EcosystemModel(Protocol):
    model_id: str
    supported_languages: Tuple[str, ...]
    required_capabilities: Tuple[str, ...]

    def applies(self, graph: dict, package_inventory: frozenset[str]) -> bool: ...

    def enrich(self, graph: dict) -> GraphDelta: ...


class EcosystemRegistry:
    def __init__(self) -> None:
        self._models: dict[str, EcosystemModel] = {}

    def register(self, model: EcosystemModel) -> None:
        if model.model_id in self._models:
            raise ContractError(f"ecosystem model already registered: {model.model_id}")
        self._models[model.model_id] = model

    @property
    def models(self) -> Tuple[EcosystemModel, ...]:
        return tuple(self._models[key] for key in sorted(self._models))

    def applicable(
        self,
        graph: dict,
        package_inventory: Iterable[str],
        languages: Iterable[str],
        capabilities: dict[str, str],
    ) -> Tuple[EcosystemModel, ...]:
        packages = frozenset(package_inventory)
        available_languages = frozenset(languages)
        return tuple(
            model for model in self.models
            if available_languages.intersection(model.supported_languages)
            and all(capabilities.get(name) in {"partial", "complete"}
                    for name in model.required_capabilities)
            and model.applies(graph, packages)
        )

