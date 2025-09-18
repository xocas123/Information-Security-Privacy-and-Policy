"""
Basic usage examples for the Supply Chain Analyzer.

This script demonstrates how to use the organized, professional version
of the dependency graph analyzer with proper output management.
"""

import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from supply_chain_analyzer import DependencyGraph, SoftwareComponent, SoftwareType, RiskAnalyzer
from supply_chain_analyzer.core.output_manager import OutputManager
from supply_chain_analyzer.analyzers.github_analyzer import GitHubDependencyAnalyzer


def example_manual_dependency_graph():
    """Example: Create a dependency graph manually"""
    print("=== MANUAL DEPENDENCY GRAPH EXAMPLE ===")

    # Initialize output manager
    output_manager = OutputManager("example_outputs")

    # Create a dependency graph
    graph = DependencyGraph("Example Application Dependencies")

    # Add main application
    main_app = SoftwareComponent(
        name="example_app",
        version="1.0.0",
        software_type=SoftwareType.APPLICATION,
        vendor="Example Corp",
        description="Example web application",
        criticality_score=10.0
    )
    graph.add_component(main_app)

    # Add dependencies
    flask = SoftwareComponent(
        name="flask",
        version="2.3.0",
        software_type=SoftwareType.FRAMEWORK,
        vendor="Pallets",
        description="Web framework",
        criticality_score=8.0
    )

    requests = SoftwareComponent(
        name="requests",
        version="2.31.0",
        software_type=SoftwareType.LIBRARY,
        vendor="PSF",
        description="HTTP library",
        criticality_score=7.0
    )

    graph.add_component(flask)
    graph.add_component(requests)

    # Add dependency relationships
    graph.add_dependency(main_app.id, flask.id, "direct")
    graph.add_dependency(main_app.id, requests.id, "direct")

    # Analyze with configurable depth
    MAX_DEPTH = 2  # Easy to change!

    print(f"Analysis depth: {MAX_DEPTH}")
    print(f"Total components: {len(graph.components)}")

    # Calculate impact scores with depth control
    for comp_id, component in graph.components.items():
        impact = graph.calculate_impact_score(comp_id, max_depth=MAX_DEPTH)
        dependents = len(graph.get_dependents(comp_id, max_depth=MAX_DEPTH))
        print(f"  {component.name}: impact={impact:.1f}, dependents={dependents}")

    # Save organized outputs
    project_name = "example_manual"

    graph_path = graph.export_to_json(
        output_manager=output_manager,
        project_name=project_name
    )

    # Risk analysis
    analyzer = RiskAnalyzer(graph)
    metrics_path = analyzer.export_metrics_to_csv(
        output_manager=output_manager,
        project_name=project_name
    )

    print(f"\nOutputs saved:")
    print(f"  Graph: {graph_path}")
    print(f"  Metrics: {metrics_path}")

    return graph, analyzer


def example_github_analysis():
    """Example: Analyze a GitHub repository"""
    print("\n=== GITHUB REPOSITORY ANALYSIS EXAMPLE ===")

    # Easy configuration
    REPOSITORY_URL = "https://github.com/requests/requests"
    MAX_DEPTH = 2
    MAX_COMPONENTS = 15

    print(f"Repository: {REPOSITORY_URL}")
    print(f"Max depth: {MAX_DEPTH}")
    print(f"Max components: {MAX_COMPONENTS}")

    try:
        # Analyze repository
        analyzer = GitHubDependencyAnalyzer(REPOSITORY_URL)
        graph, risk_analyzer, results = analyzer.analyze_repository(
            max_components=MAX_COMPONENTS,
            max_depth=MAX_DEPTH
        )

        if results:
            stats = results['stats']
            risk = results['risk_assessment']

            print(f"\nResults:")
            print(f"  Components found: {stats['total_components']}")
            print(f"  Libraries: {stats['libraries']}")
            print(f"  Risk score: {risk['overall_risk_score']:.1f}/10")

            # Files are automatically saved in organized structure
            print(f"\nOutputs automatically saved to organized folders:")
            print(f"  graphs/ - Dependency network data")
            print(f"  metrics/ - Risk assessment CSV")
            print(f"  reports/ - Comprehensive analysis")

        return graph, risk_analyzer, results

    except Exception as e:
        print(f"Analysis failed: {e}")
        return None, None, None


def example_depth_comparison():
    """Example: Compare analysis at different depths"""
    print("\n=== DEPTH COMPARISON EXAMPLE ===")

    # Create a simple graph for testing
    graph = DependencyGraph("Depth Test")

    # Layer 1: Main app
    app = SoftwareComponent("app", "1.0", SoftwareType.APPLICATION, criticality_score=10.0)
    graph.add_component(app)

    # Layer 2: Direct dependencies
    web_framework = SoftwareComponent("web_framework", "2.0", SoftwareType.FRAMEWORK, criticality_score=8.0)
    db_client = SoftwareComponent("db_client", "1.5", SoftwareType.LIBRARY, criticality_score=7.0)
    graph.add_component(web_framework)
    graph.add_component(db_client)
    graph.add_dependency(app.id, web_framework.id)
    graph.add_dependency(app.id, db_client.id)

    # Layer 3: Transitive dependencies
    http_lib = SoftwareComponent("http_lib", "3.0", SoftwareType.LIBRARY, criticality_score=6.0)
    json_parser = SoftwareComponent("json_parser", "1.1", SoftwareType.LIBRARY, criticality_score=5.0)
    graph.add_component(http_lib)
    graph.add_component(json_parser)
    graph.add_dependency(web_framework.id, http_lib.id)
    graph.add_dependency(db_client.id, json_parser.id)

    # Compare different depths
    test_depths = [1, 2, 3, None]  # None = unlimited

    print(f"Impact analysis for '{web_framework.name}' at different depths:")
    print(f"{'Depth':<8} {'Impact':<8} {'Dependents':<12}")
    print("-" * 30)

    for depth in test_depths:
        if depth is None:
            impact = graph.calculate_impact_score(web_framework.id)
            dependents = len(graph.get_dependents(web_framework.id))
            depth_str = "unlimited"
        else:
            impact = graph.calculate_impact_score(web_framework.id, max_depth=depth)
            dependents = len(graph.get_dependents(web_framework.id, max_depth=depth))
            depth_str = str(depth)

        print(f"{depth_str:<8} {impact:<8.1f} {dependents:<12}")

    return graph


def example_output_management():
    """Example: Demonstrate output organization"""
    print("\n=== OUTPUT MANAGEMENT EXAMPLE ===")

    # Initialize output manager
    output_manager = OutputManager("demo_outputs")

    # Show directory structure
    print(f"Output directory: {output_manager.base_dir}")
    print(f"Subdirectories created:")
    for subdir in ["graphs", "reports", "metrics", "visualizations"]:
        path = output_manager.base_dir / subdir
        print(f"  {subdir}/ - {path}")

    # Show all projects
    projects = output_manager.list_all_projects()
    print(f"\nAnalyzed projects: {len(projects)}")
    for project in projects:
        print(f"  - {project}")

    # Show output summary
    summary = output_manager.get_output_summary()
    print(f"\nOutput summary:")
    for category, count in summary['output_directories'].items():
        print(f"  {category}: {count} files")

    return output_manager


def main():
    """Run all examples"""
    print("Supply Chain Analyzer - Professional Examples")
    print("=" * 60)

    # Run examples
    graph1, analyzer1 = example_manual_dependency_graph()
    graph2, analyzer2, results2 = example_github_analysis()
    graph3 = example_depth_comparison()
    output_mgr = example_output_management()

    print(f"\n" + "=" * 60)
    print("EXAMPLES COMPLETED")
    print("=" * 60)
    print(f"Key features demonstrated:")
    print(f"  [x] Organized output management")
    print(f"  [x] Configurable analysis depth")
    print(f"  [x] Professional file structure")
    print(f"  [x] GitHub repository analysis")
    print(f"  [x] Risk assessment and metrics")
    print(f"\nTo change analysis depth in any script:")
    print(f"  Just modify the MAX_DEPTH variable!")


if __name__ == "__main__":
    main()