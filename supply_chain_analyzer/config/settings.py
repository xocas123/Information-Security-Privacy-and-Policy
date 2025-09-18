"""
Configuration settings for Supply Chain Analyzer.

This module provides centralized configuration management with defaults
and user customization support.
"""

import json
import os
from pathlib import Path
from typing import Dict, Any, Optional
from dataclasses import dataclass, asdict


@dataclass
class AnalysisSettings:
    """Settings for dependency analysis"""
    max_depth: int = 2
    max_components: int = 30
    include_dev_dependencies: bool = True
    vulnerability_check: bool = True


@dataclass
class OutputSettings:
    """Settings for output management"""
    base_directory: str = "outputs"
    include_timestamps: bool = True
    auto_cleanup_days: int = 30
    export_formats: list = None

    def __post_init__(self):
        if self.export_formats is None:
            self.export_formats = ["json", "csv"]


@dataclass
class VisualizationSettings:
    """Settings for visualizations"""
    default_layout: str = "spring"
    figure_size: tuple = (12, 8)
    dpi: int = 300
    highlight_compromised: bool = True
    show_criticality: bool = True


@dataclass
class GitHubSettings:
    """Settings for GitHub repository analysis"""
    default_branch_order: list = None
    timeout_seconds: int = 30
    rate_limit_delay: float = 1.0

    def __post_init__(self):
        if self.default_branch_order is None:
            self.default_branch_order = ["main", "dev", "master", "develop"]


@dataclass
class Settings:
    """Main configuration settings"""
    analysis: AnalysisSettings = None
    output: OutputSettings = None
    visualization: VisualizationSettings = None
    github: GitHubSettings = None

    def __post_init__(self):
        if self.analysis is None:
            self.analysis = AnalysisSettings()
        if self.output is None:
            self.output = OutputSettings()
        if self.visualization is None:
            self.visualization = VisualizationSettings()
        if self.github is None:
            self.github = GitHubSettings()

    def to_dict(self) -> Dict[str, Any]:
        """Convert settings to dictionary"""
        return {
            "analysis": asdict(self.analysis),
            "output": asdict(self.output),
            "visualization": asdict(self.visualization),
            "github": asdict(self.github)
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Settings':
        """Create settings from dictionary"""
        return cls(
            analysis=AnalysisSettings(**data.get("analysis", {})),
            output=OutputSettings(**data.get("output", {})),
            visualization=VisualizationSettings(**data.get("visualization", {})),
            github=GitHubSettings(**data.get("github", {}))
        )

    def save_to_file(self, filepath: str) -> None:
        """Save settings to JSON file"""
        with open(filepath, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)

    @classmethod
    def load_from_file(cls, filepath: str) -> 'Settings':
        """Load settings from JSON file"""
        with open(filepath, 'r') as f:
            data = json.load(f)
        return cls.from_dict(data)


def get_config_directory() -> Path:
    """Get the configuration directory path"""
    # Check for user config directory
    if os.name == 'nt':  # Windows
        config_dir = Path(os.environ.get('APPDATA', '')) / 'SupplyChainAnalyzer'
    else:  # Unix-like
        config_dir = Path.home() / '.config' / 'supply_chain_analyzer'

    config_dir.mkdir(parents=True, exist_ok=True)
    return config_dir


def get_default_config_file() -> Path:
    """Get the default configuration file path"""
    return get_config_directory() / 'config.json'


def load_config(config_file: Optional[str] = None) -> Settings:
    """Load configuration from file or use defaults"""
    if config_file is None:
        config_file = get_default_config_file()

    config_path = Path(config_file)

    if config_path.exists():
        try:
            return Settings.load_from_file(str(config_path))
        except Exception as e:
            print(f"Warning: Failed to load config from {config_path}: {e}")
            print("Using default settings.")

    # Return default settings
    return Settings()


def save_default_config() -> str:
    """Save default configuration to file"""
    config_file = get_default_config_file()
    settings = Settings()
    settings.save_to_file(str(config_file))
    return str(config_file)


def create_sample_config() -> str:
    """Create a sample configuration file with comments"""
    config_content = """{
  "analysis": {
    "max_depth": 2,
    "max_components": 30,
    "include_dev_dependencies": true,
    "vulnerability_check": true
  },
  "output": {
    "base_directory": "outputs",
    "include_timestamps": true,
    "auto_cleanup_days": 30,
    "export_formats": ["json", "csv"]
  },
  "visualization": {
    "default_layout": "spring",
    "figure_size": [12, 8],
    "dpi": 300,
    "highlight_compromised": true,
    "show_criticality": true
  },
  "github": {
    "default_branch_order": ["main", "dev", "master", "develop"],
    "timeout_seconds": 30,
    "rate_limit_delay": 1.0
  }
}"""

    sample_file = get_config_directory() / 'config_sample.json'
    with open(sample_file, 'w') as f:
        f.write(config_content)

    return str(sample_file)