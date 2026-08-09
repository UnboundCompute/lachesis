"""Registered language-neutral analyses over canonical compiler facts."""

from .effects import ParameterPropertyEffects, apply_parameter_property_effects
from .branch_history import BranchHistory
from .control_flow import ControlFlow
from .interprocedural import InterproceduralContexts
from .module_initialization import ModuleInitialization
from .registry import CanonicalOverlay, OverlayRegistry
from .taint import TaintPropagation


def default_overlay_registry() -> OverlayRegistry:
    registry = OverlayRegistry()
    registry.register(ControlFlow())
    registry.register(BranchHistory())
    registry.register(InterproceduralContexts())
    registry.register(ModuleInitialization())
    registry.register(ParameterPropertyEffects())
    return registry


def default_security_overlay_registry() -> OverlayRegistry:
    registry = OverlayRegistry()
    registry.register(TaintPropagation())
    return registry


__all__ = [
    "CanonicalOverlay",
    "BranchHistory",
    "ControlFlow",
    "InterproceduralContexts",
    "ModuleInitialization",
    "OverlayRegistry",
    "ParameterPropertyEffects",
    "TaintPropagation",
    "apply_parameter_property_effects",
    "default_overlay_registry",
    "default_security_overlay_registry",
]
