"""
Professional CLI interface for the Supply Chain Risk Analyzer.

This module provides a command-line interface for analyzing software
dependencies and assessing supply chain risks.
"""

import argparse
import sys
from pathlib import Path
from typing import Optional

from .core.output_manager import OutputManager
from .analyzers.github_analyzer import GitHubDependencyAnalyzer
from .analyzers.risk_analyzer import RiskAnalyzer


class SupplyChainCLI:
    """Professional CLI for Supply Chain Risk Analysis"""

    def __init__(self):
        self.output_manager = OutputManager()

    def setup_parser(self) -> argparse.ArgumentParser:
        """Setup command line argument parser"""
        parser = argparse.ArgumentParser(
            description="Supply Chain Risk Analyzer - Analyze software dependencies and assess security risks",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  # Analyze a GitHub repository
  python -m supply_chain_analyzer analyze-github https://github.com/requests/requests

  # Analyze with custom depth and component limits
  python -m supply_chain_analyzer analyze-github https://github.com/django/django --max-depth 3 --max-components 50

  # List all analyzed projects
  python -m supply_chain_analyzer list-projects

  # Clean up old output files
  python -m supply_chain_analyzer cleanup --days 30
            """
        )

        parser.add_argument(
            '--version',
            action='version',
            version='Supply Chain Analyzer v1.0.0'
        )

        parser.add_argument(
            '--output-dir',
            type=str,
            default='outputs',
            help='Base directory for output files (default: outputs)'
        )

        parser.add_argument(
            '--verbose',
            '-v',
            action='store_true',
            help='Enable verbose output'
        )

        # Create subparsers for different commands
        subparsers = parser.add_subparsers(dest='command', help='Available commands')

        # GitHub analysis command
        github_parser = subparsers.add_parser(
            'analyze-github',
            help='Analyze a GitHub repository for supply chain risks'
        )
        github_parser.add_argument(
            'repository_url',
            help='GitHub repository URL to analyze'
        )
        github_parser.add_argument(
            '--max-depth',
            type=int,
            default=2,
            help='Maximum dependency depth to analyze (default: 2)'
        )
        github_parser.add_argument(
            '--max-components',
            type=int,
            default=30,
            help='Maximum number of components to include (default: 30)'
        )
        github_parser.add_argument(
            '--project-name',
            type=str,
            help='Custom project name (default: extracted from URL)'
        )
        github_parser.add_argument(
            '--no-timestamp',
            action='store_true',
            help='Disable timestamps in output filenames'
        )

        # Analysis management commands
        list_parser = subparsers.add_parser(
            'list-projects',
            help='List all analyzed projects'
        )

        status_parser = subparsers.add_parser(
            'status',
            help='Show output directory status and summary'
        )

        cleanup_parser = subparsers.add_parser(
            'cleanup',
            help='Clean up old output files'
        )
        cleanup_parser.add_argument(
            '--days',
            type=int,
            default=30,
            help='Remove files older than this many days (default: 30)'
        )

        # Project-specific commands
        project_parser = subparsers.add_parser(
            'project-files',
            help='List files for a specific project'
        )
        project_parser.add_argument(
            'project_name',
            help='Name of the project to list files for'
        )

        return parser

    def analyze_github_repository(self, args) -> int:
        """Analyze a GitHub repository"""
        try:
            if args.verbose:
                print(f"Analyzing repository: {args.repository_url}")
                print(f"Max depth: {args.max_depth}")
                print(f"Max components: {args.max_components}")
                print(f"Output directory: {args.output_dir}")

            # Initialize output manager with custom directory if specified
            if args.output_dir != 'outputs':
                self.output_manager = OutputManager(args.output_dir)

            # Determine project name
            if args.project_name:
                project_name = args.project_name
            else:
                project_name = args.repository_url.split('/')[-1].replace('.git', '')

            # Analyze the repository
            analyzer = GitHubDependencyAnalyzer(args.repository_url)
            graph, risk_analyzer, results = analyzer.analyze_repository(
                max_components=args.max_components,
                max_depth=args.max_depth
            )

            if not graph or not results:
                print("ERROR: Failed to analyze repository")
                return 1

            # Save organized outputs
            include_timestamp = not args.no_timestamp

            # Save dependency graph
            graph_path = graph.export_to_json(
                output_manager=self.output_manager,
                project_name=project_name
            )

            # Save risk metrics
            metrics_path = risk_analyzer.export_metrics_to_csv(
                output_manager=self.output_manager,
                project_name=project_name
            )

            # Save comprehensive analysis report
            report_data = {
                "project_info": {
                    "name": project_name,
                    "repository_url": args.repository_url,
                    "analysis_parameters": {
                        "max_depth": args.max_depth,
                        "max_components": args.max_components
                    }
                },
                "analysis_results": results,
                "file_outputs": {
                    "dependency_graph": graph_path,
                    "risk_metrics": metrics_path
                }
            }

            report_path = self.output_manager.save_analysis_report(
                report_data, project_name, include_timestamp
            )

            # Create project summary
            summary_path = self.output_manager.create_project_summary(
                project_name, report_data
            )

            # Display results
            print(f"\n=== ANALYSIS COMPLETE ===")
            print(f"Project: {project_name}")
            print(f"Components analyzed: {results['stats']['total_components']}")
            print(f"Risk level: {results['risk_assessment']['overall_risk_score']:.1f}/10")

            print(f"\n=== OUTPUT FILES ===")
            print(f"Dependency graph: {graph_path}")
            print(f"Risk metrics: {metrics_path}")
            print(f"Analysis report: {report_path}")
            print(f"Project summary: {summary_path}")

            if args.verbose:
                self._display_detailed_results(results)

            return 0

        except Exception as e:
            print(f"ERROR: Analysis failed - {str(e)}")
            if args.verbose:
                import traceback
                traceback.print_exc()
            return 1

    def list_projects(self, args) -> int:
        """List all analyzed projects"""
        projects = self.output_manager.list_all_projects()

        if not projects:
            print("No analyzed projects found.")
            return 0

        print(f"=== ANALYZED PROJECTS ===")
        print(f"Total projects: {len(projects)}")
        print(f"Output directory: {self.output_manager.base_dir}")
        print()

        for i, project in enumerate(projects, 1):
            print(f"{i:2d}. {project}")
            if args.verbose:
                files = self.output_manager.get_project_files(project)
                for category, file_list in files.items():
                    if file_list:
                        print(f"    {category}: {len(file_list)} files")

        return 0

    def show_status(self, args) -> int:
        """Show output directory status"""
        summary = self.output_manager.get_output_summary()

        print(f"=== OUTPUT DIRECTORY STATUS ===")
        print(f"Base directory: {summary['base_directory']}")
        print(f"Total projects: {summary['total_projects']}")
        print()

        print(f"File counts by category:")
        for category, count in summary['output_directories'].items():
            print(f"  {category}: {count} files")

        if summary['recent_projects']:
            print(f"\nRecent projects:")
            for project in summary['recent_projects']:
                print(f"  - {project}")

        return 0

    def cleanup_files(self, args) -> int:
        """Clean up old output files"""
        print(f"Cleaning up files older than {args.days} days...")
        self.output_manager.cleanup_old_files(args.days)
        print("Cleanup completed.")
        return 0

    def show_project_files(self, args) -> int:
        """Show files for a specific project"""
        files = self.output_manager.get_project_files(args.project_name)

        if not any(files.values()):
            print(f"No files found for project: {args.project_name}")
            return 1

        print(f"=== FILES FOR PROJECT: {args.project_name} ===")
        for category, file_list in files.items():
            if file_list:
                print(f"\n{category.title()}:")
                for file_path in file_list:
                    print(f"  {file_path}")

        return 0

    def _display_detailed_results(self, results):
        """Display detailed analysis results"""
        stats = results.get('stats', {})
        risk = results.get('risk_assessment', {})
        critical = results.get('critical_components', [])

        print(f"\n=== DETAILED RESULTS ===")
        print(f"Dependencies: {stats.get('total_dependencies', 0)}")
        print(f"Libraries: {stats.get('libraries', 0)}")
        print(f"Applications: {stats.get('applications', 0)}")
        print(f"High-risk components: {risk.get('high_risk_components', 0)}")

        if critical:
            print(f"\nTop critical components:")
            for comp_id, dependents in critical[:3]:
                print(f"  {comp_id}: {dependents} dependents")

    def run(self, args=None) -> int:
        """Main CLI entry point"""
        parser = self.setup_parser()
        parsed_args = parser.parse_args(args)

        if not parsed_args.command:
            parser.print_help()
            return 1

        # Route to appropriate command handler
        if parsed_args.command == 'analyze-github':
            return self.analyze_github_repository(parsed_args)
        elif parsed_args.command == 'list-projects':
            return self.list_projects(parsed_args)
        elif parsed_args.command == 'status':
            return self.show_status(parsed_args)
        elif parsed_args.command == 'cleanup':
            return self.cleanup_files(parsed_args)
        elif parsed_args.command == 'project-files':
            return self.show_project_files(parsed_args)
        else:
            print(f"Unknown command: {parsed_args.command}")
            return 1


def main():
    """Entry point for the CLI"""
    cli = SupplyChainCLI()
    return cli.run()


if __name__ == '__main__':
    sys.exit(main())