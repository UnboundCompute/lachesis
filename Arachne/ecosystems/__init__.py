"""Runtime and framework models registered independently of language frontends."""

from .registry import EcosystemModel, EcosystemRegistry
from .common import GenericRouteModel, GenericSecurityRoleModel


def default_ecosystem_registry() -> EcosystemRegistry:
    registry = EcosystemRegistry()
    registry.register(GenericSecurityRoleModel())
    registry.register(GenericRouteModel())
    return registry

__all__ = [
    "EcosystemModel", "EcosystemRegistry", "GenericSecurityRoleModel",
    "default_ecosystem_registry",
]
