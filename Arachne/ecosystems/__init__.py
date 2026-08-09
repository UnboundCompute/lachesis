"""Runtime and framework models registered independently of language frontends."""

from .registry import EcosystemModel, EcosystemRegistry
from .common import GenericRouteModel


def default_ecosystem_registry() -> EcosystemRegistry:
    registry = EcosystemRegistry()
    registry.register(GenericRouteModel())
    return registry

__all__ = [
    "EcosystemModel", "EcosystemRegistry", "default_ecosystem_registry",
]
