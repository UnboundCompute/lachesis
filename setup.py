"""Setuptools hooks for a platform-specific, Python-agnostic wheel.

Lachesis ships prebuilt native artifacts under ``lachesis/_native`` (a Rust
lifetime kernel and clang frontend). They are loaded at runtime through
``ctypes``/``subprocess``, never imported as CPython extension modules, so the
wheel must be:

* platform-specific  -- a macOS build must not install on Linux, and vice
  versa (otherwise ``pip`` would serve one platform's binaries everywhere); and
* Python-agnostic     -- the same binary works on every supported interpreter,
  so one ``py3-none-<platform>`` wheel covers all of CPython 3.10+ rather than
  emitting a separate ``cp310``/``cp311``/``cp312`` wheel that pins an ABI the
  package does not actually use.

``NativeDistribution.has_ext_modules`` forces a platform tag; the ``bdist_wheel``
override then relaxes the interpreter/ABI tags back to ``py3``/``none``.
"""
from setuptools import Distribution, setup

try:  # setuptools >= 70.1 vendors the command; older trees use the wheel package.
    from setuptools.command.bdist_wheel import bdist_wheel as _BdistWheel
except ImportError:  # pragma: no cover - depends on the build environment
    from wheel.bdist_wheel import bdist_wheel as _BdistWheel


class NativeDistribution(Distribution):
    """Mark the distribution impure so the wheel carries a platform tag."""

    def has_ext_modules(self) -> bool:  # noqa: D401 - setuptools hook
        return True


class PlatformWheel(_BdistWheel):
    """Emit ``py3-none-<platform>``: platform-specific, interpreter-agnostic."""

    def finalize_options(self) -> None:
        super().finalize_options()
        # Keep the platform tag (root is not pure) ...
        self.root_is_pure = False

    def get_tag(self) -> tuple[str, str, str]:
        _python, _abi, platform = super().get_tag()
        # ... but do not pin a CPython ABI we never link against.
        return "py3", "none", platform


setup(distclass=NativeDistribution, cmdclass={"bdist_wheel": PlatformWheel})
