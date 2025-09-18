"""
Supply Chain Risk Analyzer

A professional tool for analyzing software dependency graphs and
simulating vulnerability propagation through supply chains.

Author: Claude Code Assistant
Version: 1.0.0
"""

__version__ = "1.0.0"
__author__ = "Claude Code Assistant"

from .core.dependency_graph import DependencyGraph, SoftwareComponent, SoftwareType, Vulnerability, VulnerabilityLevel
from .analyzers.risk_analyzer import RiskAnalyzer
from .analyzers.github_analyzer import GitHubDependencyAnalyzer

__all__ = [
    'DependencyGraph',
    'SoftwareComponent',
    'SoftwareType',
    'Vulnerability',
    'VulnerabilityLevel',
    'RiskAnalyzer',
    'GitHubDependencyAnalyzer'
]