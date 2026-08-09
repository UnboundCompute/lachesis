"""Registered language-neutral analyses over canonical compiler facts."""

from .effects import ParameterPropertyEffects, apply_parameter_property_effects
from .interprocedural import InterproceduralContexts
from .module_initialization import ModuleInitialization
from .registry import CanonicalOverlay, OverlayRegistry


def default_overlay_registry() -> OverlayRegistry:
    registry = OverlayRegistry()
    registry.register(InterproceduralContexts())
    registry.register(ModuleInitialization())
    registry.register(ParameterPropertyEffects())
    return registry


__all__ = [
    "CanonicalOverlay",
    "InterproceduralContexts",
    "ModuleInitialization",
    "OverlayRegistry",
    "ParameterPropertyEffects",
    "apply_parameter_property_effects",
    "default_overlay_registry",
]
