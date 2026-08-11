"""Runtime and framework models registered independently of language frontends."""

from .registry import EcosystemModel, EcosystemRegistry
from .common import (
    GenericRouteModel, GenericRuntimeModel, GenericSecurityRoleModel,
    PythonRuntimeModel,
)


def default_ecosystem_registry() -> EcosystemRegistry:
    registry = EcosystemRegistry()
    registry.register(GenericRuntimeModel())
    registry.register(PythonRuntimeModel())
    registry.register(GenericSecurityRoleModel())
    registry.register(GenericRouteModel())
    return registry

__all__ = [
    "EcosystemModel", "EcosystemRegistry", "GenericRuntimeModel", "PythonRuntimeModel",
    "GenericSecurityRoleModel",
    "default_ecosystem_registry",
]
