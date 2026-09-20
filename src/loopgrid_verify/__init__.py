"""Standalone offline verification for LoopGrid evidence bundles."""

from .verifier import verify_bundle
from .version import __version__

__all__ = ["verify_bundle", "__version__"]
