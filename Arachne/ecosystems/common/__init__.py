"""Framework-neutral models for recurring runtime registration shapes."""

from .routes import GenericRouteModel
from .security_roles import GenericSecurityRoleModel

__all__ = ["GenericRouteModel", "GenericSecurityRoleModel"]
