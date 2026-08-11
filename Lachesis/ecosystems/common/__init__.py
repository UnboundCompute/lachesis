"""Framework-neutral models for recurring runtime registration shapes."""

from .routes import GenericRouteModel
from .runtime import GenericRuntimeModel
from .security_roles import GenericSecurityRoleModel

__all__ = ["GenericRouteModel", "GenericRuntimeModel", "GenericSecurityRoleModel"]
