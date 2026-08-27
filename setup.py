"""Setuptools hook marking distributions with bundled native binaries as non-pure."""
from setuptools import Distribution, setup


class NativeDistribution(Distribution):
    """Tell wheel that package data includes platform-specific native artifacts."""

    def has_ext_modules(self):
        return True


setup(distclass=NativeDistribution)
