"""
Simple demonstration of how to easily change the maximum depth for dependency analysis

Just change the MAX_DEPTH variable below to control how deep the analysis goes!
"""

from test_home_assistant import create_home_assistant_dependency_graph, add_realistic_vulnerabilities

# =============================================================================
# CONFIGURATION: Change this value to control analysis depth
# =============================================================================
MAX_DEPTH = 5  # <-- CHANGE THIS NUMBER (1-10 or None for unlimited)
# =============================================================================

def main():
    print(f"Dependency Analysis with MAX_DEPTH = {MAX_DEPTH}")
    print("=" * 50)

    # Create the graph
    graph = create_home_assistant_dependency_graph()
    add_realistic_vulnerabilities(graph)

    # Find the most critical component
    critical_components = graph.find_critical_components(min_dependents=1)
    if not critical_components:
        print("No critical components found")
        return

    target_component = critical_components[0][0]  # Most critical
    component_name = graph.components[target_component].name

    print(f"\nAnalyzing: {component_name}")
    print(f"Max depth: {MAX_DEPTH}")
    print("-" * 30)

    # Get analysis with current MAX_DEPTH setting
    if MAX_DEPTH is None:
        dependencies = graph.get_dependencies(target_component)
        dependents = graph.get_dependents(target_component)
        impact = graph.calculate_impact_score(target_component)
        depth_str = "unlimited"
    else:
        dependencies = graph.get_dependencies(target_component, max_depth=MAX_DEPTH)
        dependents = graph.get_dependents(target_component, max_depth=MAX_DEPTH)
        impact = graph.calculate_impact_score(target_component, max_depth=MAX_DEPTH)
        depth_str = str(MAX_DEPTH)

    print(f"Results (depth={depth_str}):")
    print(f"  Dependencies found: {len(dependencies)}")
    print(f"  Dependents found: {len(dependents)}")
    print(f"  Impact score: {impact:.1f}")

    if dependents:
        print(f"\n  Components that depend on {component_name}:")
        for dep_id in dependents[:5]:  # Show first 5
            dep_name = graph.components[dep_id].name if dep_id in graph.components else dep_id
            print(f"    - {dep_name}")
        if len(dependents) > 5:
            print(f"    ... and {len(dependents) - 5} more")

    # Show detailed depth analysis if MAX_DEPTH is set
    if MAX_DEPTH is not None:
        print(f"\nDetailed depth analysis:")
        analysis = graph.analyze_dependency_depth(target_component, max_depth=MAX_DEPTH)

        for depth in range(1, MAX_DEPTH + 1):
            depth_key = str(depth)
            if depth_key in analysis['dependents_by_depth']:
                dep_count = analysis['dependents_by_depth'][depth_key]['count']
                impact_at_depth = analysis['impact_by_depth'][depth_key]
                print(f"  Depth {depth}: {dep_count} dependents, impact = {impact_at_depth}")
            else:
                print(f"  Depth {depth}: No data available")

    print(f"\nTo change analysis depth:")
    print(f"  1. Edit this file")
    print(f"  2. Change MAX_DEPTH = {MAX_DEPTH} to your desired value")
    print(f"  3. Run the script again")
    print(f"\nSuggested values:")
    print(f"  MAX_DEPTH = 1    # Direct dependencies only")
    print(f"  MAX_DEPTH = 2    # Two levels deep")
    print(f"  MAX_DEPTH = 3    # Three levels deep")
    print(f"  MAX_DEPTH = None # Unlimited depth")

if __name__ == "__main__":
    main()