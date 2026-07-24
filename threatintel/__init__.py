"""Threat Intel Toolkit -- phishing-URL heuristics + VirusTotal reputation lookups."""

from . import phishing, vt_check

__version__ = "1.0.0"
__all__ = ["phishing", "vt_check"]
