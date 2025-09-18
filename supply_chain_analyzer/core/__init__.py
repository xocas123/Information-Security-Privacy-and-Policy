"""
Core modules for dependency graph management and analysis.
"""

from .dependency_graph import DependencyGraph, SoftwareComponent, SoftwareType, Vulnerability, VulnerabilityLevel
from .output_manager import OutputManager

__all__ = [
    'DependencyGraph',
    'SoftwareComponent',
    'SoftwareType',
    'Vulnerability',
    'VulnerabilityLevel',
    'OutputManager'
]