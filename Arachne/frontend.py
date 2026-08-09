"""Compatibility imports for the canonical core and frontend registry.

New code should import contract/runner/snapshot APIs from ``Arachne.core`` and
registry APIs from ``Arachne.frontends``. This module remains until legacy
callers have migrated.
"""

from .core.capabilities import (
    CAPABILITY_COMPLETE,
    CAPABILITY_NONE,
    CAPABILITY_PARTIAL,
    FRONTEND_OWNED_CAPABILITIES,
    OVERLAY_OWNED_CAPABILITIES,
    VALID_CAPABILITY_LEVELS,
)
from .core.contract import (
    ContractError as FrontendError,
    FrontendSnapshot,
    FrontendSpec,
)
from .core.runner import run_frontend
from .core.schema import CURRENT_CONTRACT_VERSION as FRONTEND_CONTRACT_VERSION
from .core.snapshot import load_snapshot
from .core.validation import validate_snapshot
from .frontends.registry import (
    FrontendRegistry,
    clang_c_frontend,
    default_registry,
    typescript_compiler_frontend,
)

__all__ = [
    "CAPABILITY_COMPLETE", "CAPABILITY_NONE", "CAPABILITY_PARTIAL",
    "FRONTEND_CONTRACT_VERSION", "FRONTEND_OWNED_CAPABILITIES",
    "OVERLAY_OWNED_CAPABILITIES", "VALID_CAPABILITY_LEVELS",
    "FrontendError", "FrontendRegistry", "FrontendSnapshot", "FrontendSpec",
    "clang_c_frontend", "default_registry", "load_snapshot", "run_frontend",
    "typescript_compiler_frontend", "validate_snapshot",
]
