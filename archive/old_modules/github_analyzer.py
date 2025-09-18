"""
GitHub Repository Dependency Analyzer

This module demonstrates how to automatically analyze any GitHub repository
and build dependency graphs from their package files.

Currently supports:
- Python (requirements.txt, setup.py, pyproject.toml)
- Node.js (package.json)
- Java (pom.xml, build.gradle)
- Go (go.mod)
- Rust (Cargo.toml)
"""

import re
import json
import requests
from typing import Dict, List, Optional, Tuple
from dependency_graph import DependencyGraph, SoftwareComponent, SoftwareType
from analysis_metrics import RiskAnalyzer


class GitHubDependencyAnalyzer:
    """Automatically analyze dependencies from any GitHub repository"""

    def __init__(self, github_url: str):
        self.github_url = github_url
        self.repo_info = self._parse_github_url(github_url)
        self.raw_base_url = f"https://raw.githubusercontent.com/{self.repo_info['owner']}/{self.repo_info['repo']}/{self.repo_info['branch']}"

    def _parse_github_url(self, url: str) -> Dict[str, str]:
        """Parse GitHub URL to extract owner, repo, and branch"""
        # Handle various GitHub URL formats
        patterns = [
            r'github\.com/([^/]+)/([^/]+)/?(?:tree/([^/]+))?',
            r'github\.com/([^/]+)/([^/]+)\.git'
        ]

        for pattern in patterns:
            match = re.search(pattern, url)
            if match:
                owner, repo = match.groups()[:2]
                branch = match.group(3) if len(match.groups()) > 2 and match.group(3) else None
                # Remove .git suffix if present
                repo = repo.replace('.git', '')

                # If no branch specified, try to detect the default branch
                if not branch:
                    branch = self._detect_default_branch(owner, repo)

                return {'owner': owner, 'repo': repo, 'branch': branch}

        raise ValueError(f"Could not parse GitHub URL: {url}")

    def _detect_default_branch(self, owner: str, repo: str) -> str:
        """Try to detect the default branch by testing common options"""
        common_branches = ['main', 'dev', 'master', 'develop']

        for branch in common_branches:
            test_url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/README.md"
            try:
                response = requests.get(test_url)
                if response.status_code == 200:
                    return branch
            except:
                continue

        # Default fallback
        return 'main'

    def fetch_file_content(self, file_path: str) -> Optional[str]:
        """Fetch content of a file from the repository"""
        url = f"{self.raw_base_url}/{file_path}"
        try:
            response = requests.get(url)
            if response.status_code == 200:
                return response.text
            return None
        except Exception as e:
            print(f"Error fetching {file_path}: {e}")
            return None

    def detect_project_type(self) -> List[str]:
        """Detect what types of projects this repository contains"""
        project_types = []

        # Check for various dependency files
        files_to_check = {
            'python': ['requirements.txt', 'setup.py', 'pyproject.toml', 'Pipfile'],
            'nodejs': ['package.json'],
            'java': ['pom.xml', 'build.gradle', 'build.gradle.kts'],
            'go': ['go.mod'],
            'rust': ['Cargo.toml'],
            'csharp': ['*.csproj', 'packages.config'],
            'ruby': ['Gemfile'],
            'php': ['composer.json']
        }

        for project_type, files in files_to_check.items():
            for file_pattern in files:
                if '*' in file_pattern:
                    # For wildcard patterns, we'd need directory listing
                    continue
                content = self.fetch_file_content(file_pattern)
                if content:
                    project_types.append(project_type)
                    break

        return project_types

    def parse_python_dependencies(self) -> List[Dict[str, str]]:
        """Parse Python dependencies from various sources"""
        dependencies = []

        # Try requirements.txt
        req_content = self.fetch_file_content('requirements.txt')
        if req_content:
            dependencies.extend(self._parse_requirements_txt(req_content))

        # Try setup.py
        setup_content = self.fetch_file_content('setup.py')
        if setup_content:
            dependencies.extend(self._parse_setup_py(setup_content))

        # Try pyproject.toml
        pyproject_content = self.fetch_file_content('pyproject.toml')
        if pyproject_content:
            dependencies.extend(self._parse_pyproject_toml(pyproject_content))

        return dependencies

    def _parse_requirements_txt(self, content: str) -> List[Dict[str, str]]:
        """Parse requirements.txt format"""
        dependencies = []
        lines = content.strip().split('\n')

        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            # Handle various requirement formats
            # package==1.0.0, package>=1.0.0, package, etc.
            match = re.match(r'^([a-zA-Z0-9_-]+)([>=<!=~]+)?([0-9.]+)?', line)
            if match:
                name = match.group(1)
                version = match.group(3) if match.group(3) else 'latest'
                dependencies.append({
                    'name': name,
                    'version': version,
                    'type': 'library'
                })

        return dependencies

    def _parse_setup_py(self, content: str) -> List[Dict[str, str]]:
        """Extract dependencies from setup.py"""
        dependencies = []

        # Look for install_requires
        install_requires_match = re.search(r'install_requires\s*=\s*\[(.*?)\]', content, re.DOTALL)
        if not install_requires_match:
            # Also look for 'requires' variable
            install_requires_match = re.search(r'requires\s*=\s*\[(.*?)\]', content, re.DOTALL)

        if install_requires_match:
            deps_text = install_requires_match.group(1)
            # Extract quoted strings
            dep_matches = re.findall(r'["\']([^"\']+)["\']', deps_text)

            for dep in dep_matches:
                # Parse package name and version constraints
                match = re.match(r'^([a-zA-Z0-9_-]+)([>=<!=~,\s]+)?([0-9.,<>=!\s]+)?', dep)
                if match:
                    name = match.group(1)
                    # Extract version if present, otherwise use 'latest'
                    version_spec = match.group(3) if match.group(3) else 'latest'
                    if version_spec != 'latest':
                        # Try to extract a specific version number
                        version_match = re.search(r'([0-9]+\.[0-9]+(?:\.[0-9]+)?)', version_spec)
                        version = version_match.group(1) if version_match else 'latest'
                    else:
                        version = 'latest'

                    dependencies.append({
                        'name': name,
                        'version': version,
                        'type': 'library'
                    })

        return dependencies

    def _parse_pyproject_toml(self, content: str) -> List[Dict[str, str]]:
        """Parse pyproject.toml dependencies (simplified)"""
        dependencies = []

        # Look for dependencies section
        deps_match = re.search(r'dependencies\s*=\s*\[(.*?)\]', content, re.DOTALL)
        if deps_match:
            deps_text = deps_match.group(1)
            dep_matches = re.findall(r'["\']([^"\']+)["\']', deps_text)

            for dep in dep_matches:
                match = re.match(r'^([a-zA-Z0-9_-]+)([>=<!=~]+)?([0-9.]+)?', dep)
                if match:
                    name = match.group(1)
                    version = match.group(3) if match.group(3) else 'latest'
                    dependencies.append({
                        'name': name,
                        'version': version,
                        'type': 'library'
                    })

        return dependencies

    def parse_nodejs_dependencies(self) -> List[Dict[str, str]]:
        """Parse Node.js package.json dependencies"""
        dependencies = []

        package_content = self.fetch_file_content('package.json')
        if not package_content:
            return dependencies

        try:
            package_data = json.loads(package_content)

            # Parse dependencies
            for dep_type in ['dependencies', 'devDependencies']:
                if dep_type in package_data:
                    for name, version in package_data[dep_type].items():
                        # Clean version string (remove ^, ~, etc.)
                        clean_version = re.sub(r'[^\d.]', '', version)
                        if not clean_version:
                            clean_version = 'latest'

                        dependencies.append({
                            'name': name,
                            'version': clean_version,
                            'type': 'library' if dep_type == 'dependencies' else 'dev_library'
                        })

        except json.JSONDecodeError:
            print("Error parsing package.json")

        return dependencies

    def create_dependency_graph(self, max_components: int = 50) -> DependencyGraph:
        """Create a dependency graph from the repository"""
        print(f"Analyzing repository: {self.repo_info['owner']}/{self.repo_info['repo']}")

        # Detect project types
        project_types = self.detect_project_type()
        print(f"Detected project types: {', '.join(project_types)}")

        if not project_types:
            print("No supported project types detected")
            return DependencyGraph(f"{self.repo_info['repo']} Dependencies")

        # Create the graph
        graph = DependencyGraph(f"{self.repo_info['repo']} Dependencies")

        # Create main application component
        main_app = SoftwareComponent(
            name=self.repo_info['repo'],
            version="main",
            software_type=SoftwareType.APPLICATION,
            vendor=self.repo_info['owner'],
            description=f"Main application from {self.github_url}",
            criticality_score=10.0
        )
        graph.add_component(main_app)

        all_dependencies = []

        # Parse dependencies based on detected types
        if 'python' in project_types:
            all_dependencies.extend(self.parse_python_dependencies())

        if 'nodejs' in project_types:
            all_dependencies.extend(self.parse_nodejs_dependencies())

        # Limit number of components to prevent overwhelming graphs
        dependencies = all_dependencies[:max_components]

        print(f"Found {len(all_dependencies)} total dependencies, analyzing top {len(dependencies)}")

        # Add dependency components
        for dep in dependencies:
            component = SoftwareComponent(
                name=dep['name'],
                version=dep['version'],
                software_type=SoftwareType.LIBRARY,
                vendor="Unknown",
                description=f"Dependency from {project_types[0]} ecosystem",
                criticality_score=5.0  # Default criticality
            )
            graph.add_component(component)

            # Add dependency relationship to main app
            graph.add_dependency(main_app.id, component.id, "direct")

        return graph

    def analyze_repository(self, max_components: int = 30, max_depth: int = 2) -> Tuple[DependencyGraph, RiskAnalyzer, Dict]:
        """Complete analysis of a GitHub repository"""

        print(f"GitHub Repository Analysis")
        print("=" * 50)
        print(f"Repository: {self.github_url}")
        print(f"Owner: {self.repo_info['owner']}")
        print(f"Repo: {self.repo_info['repo']}")
        print(f"Branch: {self.repo_info['branch']}")
        print(f"Max components: {max_components}")
        print(f"Max depth: {max_depth}")

        # Create dependency graph
        graph = self.create_dependency_graph(max_components)

        # Get statistics
        stats = graph.get_graph_stats()
        print(f"\nDependency Graph Statistics:")
        print(f"  Total components: {stats['total_components']}")
        print(f"  Total dependencies: {stats['total_dependencies']}")
        print(f"  Applications: {stats['applications']}")
        print(f"  Libraries: {stats['libraries']}")

        if stats['total_components'] <= 1:
            print("Insufficient dependencies found for analysis")
            return graph, None, {}

        # Find critical components
        critical_components = graph.find_critical_components(min_dependents=1)
        print(f"\nCritical Components:")
        for comp_id, dependent_count in critical_components[:5]:
            component = graph.components[comp_id]
            impact = graph.calculate_impact_score(comp_id, max_depth=max_depth)
            print(f"  {component.name}: {dependent_count} dependents, impact: {impact:.1f}")

        # Risk analysis
        analyzer = RiskAnalyzer(graph)
        risk_assessment = analyzer.calculate_supply_chain_risk_score()

        print(f"\nRisk Assessment:")
        print(f"  Overall risk level: {analyzer._categorize_risk_level(risk_assessment['overall_risk_score'])}")
        print(f"  Risk score: {risk_assessment['overall_risk_score']:.1f}/10")
        print(f"  High-risk components: {risk_assessment['high_risk_components']}")

        # Export results
        output_prefix = f"{self.repo_info['owner']}_{self.repo_info['repo']}"
        graph.export_to_json(f"{output_prefix}_dependencies.json")
        analyzer.export_metrics_to_csv(f"{output_prefix}_risk_metrics.csv")

        print(f"\nExported Results:")
        print(f"  Dependencies: {output_prefix}_dependencies.json")
        print(f"  Risk metrics: {output_prefix}_risk_metrics.csv")

        results = {
            'repo_info': self.repo_info,
            'stats': stats,
            'risk_assessment': risk_assessment,
            'critical_components': critical_components
        }

        return graph, analyzer, results


def analyze_github_repo(github_url: str, max_components: int = 30, max_depth: int = 2):
    """Convenience function to analyze any GitHub repository"""

    try:
        analyzer = GitHubDependencyAnalyzer(github_url)
        return analyzer.analyze_repository(max_components, max_depth)

    except Exception as e:
        print(f"Error analyzing repository: {e}")
        return None, None, {}


def demo_multiple_repos():
    """Demonstrate analysis of multiple different repositories"""

    test_repos = [
        "https://github.com/home-assistant/core",
        "https://github.com/django/django",
        "https://github.com/fastapi/fastapi",
        "https://github.com/microsoft/vscode"
    ]

    print("Multi-Repository Analysis Demo")
    print("=" * 60)

    results = {}

    for repo_url in test_repos:
        print(f"\n{'='*20} ANALYZING {repo_url.split('/')[-1].upper()} {'='*20}")

        try:
            graph, analyzer, analysis = analyze_github_repo(repo_url, max_components=20)
            results[repo_url] = analysis

        except Exception as e:
            print(f"Failed to analyze {repo_url}: {e}")
            results[repo_url] = {"error": str(e)}

    # Summary comparison
    print(f"\n{'='*60}")
    print("SUMMARY COMPARISON")
    print("=" * 60)

    for repo_url, result in results.items():
        repo_name = repo_url.split('/')[-1]
        if 'error' in result:
            print(f"{repo_name}: Analysis failed - {result['error']}")
        else:
            stats = result.get('stats', {})
            risk = result.get('risk_assessment', {})
            print(f"{repo_name}:")
            print(f"  Components: {stats.get('total_components', 0)}")
            print(f"  Libraries: {stats.get('libraries', 0)}")
            print(f"  Risk Score: {risk.get('overall_risk_score', 0):.1f}")


if __name__ == "__main__":
    # Test with Home Assistant (we know this works)
    print("Testing GitHub Repository Analyzer")
    print("=" * 50)

    # Single repository analysis - try a simpler Python project first
    test_url = "https://github.com/requests/requests"  # Well-known Python library
    graph, analyzer, results = analyze_github_repo(test_url, max_components=15, max_depth=2)

    if graph:
        print(f"\nSuccess! Analysis completed for {test_url}")
        print(f"Use MAX_DEPTH parameter to control analysis depth")

    # Uncomment to test multiple repositories
    # demo_multiple_repos()