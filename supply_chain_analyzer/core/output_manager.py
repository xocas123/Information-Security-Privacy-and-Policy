"""
Output Manager for organizing and managing analysis results.

This module handles all file output operations, ensuring results are organized
in a clean folder structure with proper naming conventions.
"""

import os
import json
import pandas as pd
from datetime import datetime
from typing import Dict, Any, Optional
from pathlib import Path


class OutputManager:
    """Manages organized output of analysis results"""

    def __init__(self, base_output_dir: str = "outputs"):
        """Initialize output manager with base directory"""
        self.base_dir = Path(base_output_dir)
        self.setup_directories()

    def setup_directories(self):
        """Create organized directory structure"""
        directories = [
            self.base_dir / "graphs",
            self.base_dir / "reports",
            self.base_dir / "metrics",
            self.base_dir / "visualizations"
        ]

        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)

    def get_timestamped_filename(self, base_name: str, extension: str = "json") -> str:
        """Generate timestamped filename"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return f"{base_name}_{timestamp}.{extension}"

    def save_dependency_graph(self, graph_data: Dict[str, Any],
                             project_name: str,
                             include_timestamp: bool = True) -> str:
        """Save dependency graph data to organized location"""
        if include_timestamp:
            filename = self.get_timestamped_filename(f"{project_name}_dependencies")
        else:
            filename = f"{project_name}_dependencies.json"

        filepath = self.base_dir / "graphs" / filename

        with open(filepath, 'w') as f:
            json.dump(graph_data, f, indent=2)

        return str(filepath)

    def save_risk_metrics(self, metrics_data: pd.DataFrame,
                         project_name: str,
                         include_timestamp: bool = True) -> str:
        """Save risk metrics to CSV file"""
        if include_timestamp:
            filename = self.get_timestamped_filename(f"{project_name}_risk_metrics", "csv")
        else:
            filename = f"{project_name}_risk_metrics.csv"

        filepath = self.base_dir / "metrics" / filename
        metrics_data.to_csv(filepath, index=False)

        return str(filepath)

    def save_analysis_report(self, report_data: Dict[str, Any],
                           project_name: str,
                           include_timestamp: bool = True) -> str:
        """Save comprehensive analysis report"""
        if include_timestamp:
            filename = self.get_timestamped_filename(f"{project_name}_analysis_report")
        else:
            filename = f"{project_name}_analysis_report.json"

        filepath = self.base_dir / "reports" / filename

        with open(filepath, 'w') as f:
            json.dump(report_data, f, indent=2)

        return str(filepath)

    def save_visualization(self, project_name: str, viz_type: str,
                         include_timestamp: bool = True) -> str:
        """Generate filepath for visualization saves"""
        if include_timestamp:
            filename = self.get_timestamped_filename(f"{project_name}_{viz_type}", "png")
        else:
            filename = f"{project_name}_{viz_type}.png"

        filepath = self.base_dir / "visualizations" / filename
        return str(filepath)

    def create_project_summary(self, project_name: str,
                             analysis_results: Dict[str, Any]) -> str:
        """Create a summary file with all output locations"""
        summary = {
            "project_name": project_name,
            "analysis_date": datetime.now().isoformat(),
            "outputs": analysis_results,
            "file_locations": {
                "graphs_dir": str(self.base_dir / "graphs"),
                "reports_dir": str(self.base_dir / "reports"),
                "metrics_dir": str(self.base_dir / "metrics"),
                "visualizations_dir": str(self.base_dir / "visualizations")
            }
        }

        filename = f"{project_name}_summary.json"
        filepath = self.base_dir / filename

        with open(filepath, 'w') as f:
            json.dump(summary, f, indent=2)

        return str(filepath)

    def cleanup_old_files(self, days_old: int = 30):
        """Clean up files older than specified days"""
        cutoff_time = datetime.now().timestamp() - (days_old * 24 * 60 * 60)

        for root, dirs, files in os.walk(self.base_dir):
            for file in files:
                filepath = Path(root) / file
                if filepath.stat().st_mtime < cutoff_time:
                    filepath.unlink()
                    print(f"Cleaned up old file: {filepath}")

    def get_project_files(self, project_name: str) -> Dict[str, list]:
        """Get all files for a specific project"""
        project_files = {
            "graphs": [],
            "reports": [],
            "metrics": [],
            "visualizations": []
        }

        for category in project_files.keys():
            dir_path = self.base_dir / category
            if dir_path.exists():
                for file in dir_path.glob(f"{project_name}*"):
                    project_files[category].append(str(file))

        return project_files

    def list_all_projects(self) -> list:
        """List all analyzed projects"""
        projects = set()

        for root, dirs, files in os.walk(self.base_dir):
            for file in files:
                if file.endswith(('_dependencies.json', '_risk_metrics.csv')):
                    # Extract project name from filename
                    project_name = file.split('_')[0]
                    projects.add(project_name)

        return sorted(list(projects))

    def get_output_summary(self) -> Dict[str, Any]:
        """Get summary of all outputs"""
        summary = {
            "total_projects": len(self.list_all_projects()),
            "output_directories": {
                "graphs": len(list((self.base_dir / "graphs").glob("*"))),
                "reports": len(list((self.base_dir / "reports").glob("*"))),
                "metrics": len(list((self.base_dir / "metrics").glob("*"))),
                "visualizations": len(list((self.base_dir / "visualizations").glob("*")))
            },
            "recent_projects": self.list_all_projects()[-5:],  # Last 5 projects
            "base_directory": str(self.base_dir)
        }

        return summary

    def __str__(self) -> str:
        """String representation of output manager"""
        summary = self.get_output_summary()
        return f"OutputManager(base_dir={self.base_dir}, projects={summary['total_projects']})"