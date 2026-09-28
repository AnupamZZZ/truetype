"""truetype - detect what a file really is, regardless of its name."""
from .scanner import analyze, verdict, identify

__version__ = "0.1.0"
__all__ = ["analyze", "verdict", "identify", "__version__"]
