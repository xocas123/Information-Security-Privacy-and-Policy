"""
Test script for the configurable depth analysis functionality

This demonstrates how to control the depth of dependency analysis
and shows the impact of different depth settings on risk assessment.
"""

from test_home_assistant import create_home_assistant_dependency_graph, add_realistic_vulnerabilities
from dependency_graph import DependencyGraph
import json


def test_depth_functionality():
    """Test the new depth-configurable dependency analysis"""

    print("Configurable Depth Analysis - Test Suite")
    print("=" * 50)

    # Create the Home Assistant dependency graph
    graph = create_home_assistant_dependency_graph()
    add_realistic_vulnerabilities(graph)

    # Define the maximum depth variable - easily changeable
    MAX_DEPTH = 3  # <-- CHANGE THIS VALUE TO CONTROL ANALYSIS DEPTH

    print(f"\nUsing MAX_DEPTH = {MAX_DEPTH}")
    print("-" * 30)

    # Test 1: Compare impact scores at different depths
    print("\n1. Impact Score Comparison by Depth")
    print("   (Testing certifi - SSL certificate library)")

    certifi_id = "certifi:2024.8.30"
    component_name = graph.components[certifi_id].name

    print(f"\n   Component: {component_name}")

    for depth in range(1, MAX_DEPTH + 2):  # Test one level beyond MAX_DEPTH
        try:
            impact = graph.calculate_impact_score(certifi_id, max_depth=depth)
            dependents = graph.get_dependents(certifi_id, max_depth=depth)
            print(f"   Depth {depth}: Impact = {impact:.1f}, Dependents = {len(dependents)}")
        except Exception as e:
            print(f"   Depth {depth}: Error - {e}")

    # Unlimited depth for comparison
    unlimited_impact = graph.calculate_impact_score(certifi_id)
    unlimited_dependents = graph.get_dependents(certifi_id)
    print(f"   Unlimited: Impact = {unlimited_impact:.1f}, Dependents = {len(unlimited_dependents)}")

    # Test 2: Detailed depth analysis
    print(f"\n2. Detailed Depth Analysis (MAX_DEPTH = {MAX_DEPTH})")

    analysis = graph.analyze_dependency_depth(certifi_id, max_depth=MAX_DEPTH)

    print(f"\n   Component: {analysis['component_name']}")
    print(f"   Analysis depth: {analysis['max_depth_analyzed']}")

    print(f"\n   Dependencies by depth:")
    for depth, data in analysis['dependencies_by_depth'].items():
        print(f"     Depth {depth}: {data['count']} components")
        if data['components']:
            print(f"       -> {', '.join(data['components'])}")

    print(f"\n   Dependents by depth:")
    for depth, data in analysis['dependents_by_depth'].items():
        print(f"     Depth {depth}: {data['count']} components")
        if data['components']:
            print(f"       -> {', '.join(data['components'])}")

    print(f"\n   Impact progression:")
    for depth, impact in analysis['impact_by_depth'].items():
        print(f"     Depth {depth}: {impact}")

    # Test 3: Compare different components at fixed depth
    print(f"\n3. Component Comparison at Depth {MAX_DEPTH}")

    test_components = [
        "homeassistant:2024.1.0",
        "aiohttp:3.12.15",
        "certifi:2024.8.30",
        "pyyaml:6.0.2"
    ]

    print(f"\n   Depth-limited analysis (depth={MAX_DEPTH}):")
    for comp_id in test_components:
        if comp_id in graph.components:
            comp_name = graph.components[comp_id].name
            impact = graph.calculate_impact_score(comp_id, max_depth=MAX_DEPTH)
            dependents = len(graph.get_dependents(comp_id, max_depth=MAX_DEPTH))
            print(f"     {comp_name}: Impact={impact:.1f}, Dependents={dependents}")

    # Test 4: Demonstrate easy depth configuration
    print(f"\n4. Easy Depth Configuration Demo")
    print(f"   Current MAX_DEPTH = {MAX_DEPTH}")
    print(f"   To change analysis depth, modify MAX_DEPTH variable in this script")

    # Show what happens with different depth values
    demo_depths = [1, 2, 3, 5]
    target_component = "certifi:2024.8.30"

    print(f"\n   Impact of {graph.components[target_component].name} at different depths:")
    for depth in demo_depths:
        impact = graph.calculate_impact_score(target_component, max_depth=depth)
        dependents = len(graph.get_dependents(target_component, max_depth=depth))
        print(f"     Depth {depth}: Impact={impact:.1f}, Dependents={dependents}")

    # Test 5: Export depth analysis to JSON
    print(f"\n5. Exporting Depth Analysis")

    # Export detailed analysis for the most critical component
    critical_components = graph.find_critical_components(min_dependents=1)
    if critical_components:
        most_critical_id = critical_components[0][0]
        detailed_analysis = graph.analyze_dependency_depth(most_critical_id, max_depth=MAX_DEPTH)

        output_file = f"depth_analysis_max_{MAX_DEPTH}.json"
        with open(output_file, 'w') as f:
            json.dump(detailed_analysis, f, indent=2)

        print(f"   Detailed analysis exported to: {output_file}")
        print(f"   Component analyzed: {detailed_analysis['component_name']}")

    return graph, analysis


def demonstrate_depth_configuration():
    """Show how different MAX_DEPTH values affect analysis"""

    print("\n" + "=" * 60)
    print("DEPTH CONFIGURATION DEMONSTRATION")
    print("=" * 60)

    graph = create_home_assistant_dependency_graph()
    add_realistic_vulnerabilities(graph)

    # Test different depth configurations
    depth_configs = [1, 2, 3, 5, None]  # None = unlimited
    target_component = "certifi:2024.8.30"

    print(f"\nAnalyzing {graph.components[target_component].name} with different depth limits:")
    print(f"{'Depth':<8} {'Impact':<8} {'Dependents':<12} {'Dependencies':<12}")
    print("-" * 45)

    for depth in depth_configs:
        if depth is None:
            impact = graph.calculate_impact_score(target_component)
            dependents = len(graph.get_dependents(target_component))
            dependencies = len(graph.get_dependencies(target_component))
            depth_str = "Unlimited"
        else:
            impact = graph.calculate_impact_score(target_component, max_depth=depth)
            dependents = len(graph.get_dependents(target_component, max_depth=depth))
            dependencies = len(graph.get_dependencies(target_component, max_depth=depth))
            depth_str = str(depth)

        print(f"{depth_str:<8} {impact:<8.1f} {dependents:<12} {dependencies:<12}")

    print(f"\nKey Insights:")
    print(f"- Shallow depths (1-2) focus on immediate impacts")
    print(f"- Deeper analysis (3-5) reveals broader system effects")
    print(f"- Unlimited depth shows complete dependency tree")
    print(f"- Choose depth based on your analysis needs:")
    print(f"  * Depth 1-2: Direct impact assessment")
    print(f"  * Depth 3-4: Moderate scope analysis")
    print(f"  * Depth 5+: Comprehensive dependency mapping")


if __name__ == "__main__":
    # Run the depth functionality tests
    graph, analysis = test_depth_functionality()

    # Show depth configuration examples
    demonstrate_depth_configuration()

    print(f"\n" + "=" * 60)
    print("USAGE SUMMARY")
    print("=" * 60)
    print(f"New depth-configurable methods:")
    print(f"")
    print(f"1. graph.get_dependencies(component_id, max_depth=N)")
    print(f"2. graph.get_dependents(component_id, max_depth=N)")
    print(f"3. graph.calculate_impact_score(component_id, max_depth=N)")
    print(f"4. graph.analyze_dependency_depth(component_id, max_depth=N)")
    print(f"")
    print(f"Where N is your desired maximum depth (integer)")
    print(f"Set MAX_DEPTH variable to easily control analysis scope!")
    print("=" * 60)