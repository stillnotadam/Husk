"""
Husk - a static security scanner for AI agent skill packages.

Built and adversarially self-tested against documented 2026 bypass
techniques, then validated against real confirmed-malicious samples.
See README.md and BENCHMARK.md for the full story, including honest
limitations.
"""

from .package_scanner import scan_package
from .pickle_scanner import scan_file as scan_pickle_file
from .skill_scanner import scan_skill_file

__version__ = "0.1.0"
__all__ = ["scan_skill_file", "scan_package", "scan_pickle_file"]
