"""
Example usage of the Software Supply Chain Risk Simulator

This script demonstrates how to use the dependency graph module
to model software dependencies and simulate attack scenarios.
"""

import json
from datetime import datetime
from dependency_graph import (
    create_sample_graph,
    DependencyGraph,
    SoftwareComponent,
    SoftwareType,
    Vulnerability,
    VulnerabilityLevel
)
from analysis_metrics import RiskAnalyzer


def main():
    """Demonstrate the key features of the Software Supply Chain Risk Simulator"""

    print("🔗 Software Supply Chain Risk Simulator - Demo")
    print("=" * 60)

    # 1. Create a sample software dependency graph
    print("\n1. Creating sample software dependency graph...")
    graph = create_sample_graph()

    # Display basic statistics
    stats = graph.get_graph_stats()
    print(f"   📊 Graph Statistics:")
    print(f"   - Total components: {stats['total_components']}")
    print(f"   - Total dependencies: {stats['total_dependencies']}")
    print(f"   - Applications: {stats['applications']}")
    print(f"   - Libraries: {stats['libraries']}")
    print(f"   - Services: {stats['services']}")
    print(f"   - Compromised components: {stats['compromised_components']}")

    # 2. Identify critical components
    print("\n2. Identifying critical components...")
    critical_components = graph.find_critical_components(min_dependents=1)
    print(f"   🎯 Critical Components (with dependents):")
    for comp_id, dependent_count in critical_components:
        component = graph.components[comp_id]
        print(f"   - {component.name}: {dependent_count} dependents")

    # 3. Calculate impact scores
    print("\n3. Calculating impact scores...")
    print(f"   💥 Component Impact Analysis:")
    for comp_id, component in graph.components.items():
        impact = graph.calculate_impact_score(comp_id)
        print(f"   - {component.name}: Impact Score = {impact:.1f}")

    # 4. Simulate attack propagation
    print("\n4. Simulating attack propagation scenarios...")

    # Scenario 1: Log4j compromise
    log4j_id = "log4j:2.17.0"
    if log4j_id in graph.components:
        print(f"\n   🔴 Scenario 1: Log4j Library Compromise")
        result1 = graph.simulate_attack_propagation(
            initial_compromise=log4j_id,
            simulation_days=30,
            detection_probability=0.15
        )

        print(f"   - Initial compromise: {result1['initial_compromise']}")
        print(f"   - Components compromised: {result1['compromised_count']}/{result1['total_components']}")
        print(f"   - Compromise percentage: {result1['compromise_percentage']:.1f}%")
        print(f"   - Applications affected: {result1['applications_affected']}")
        print(f"   - Attack progression events: {len(result1['timeline'])}")
        print(f"   - Detection events: {len(result1['detection_events'])}")

    # 5. Multiple scenario comparison
    print("\n5. Running multiple attack scenarios...")
    scenarios = [
        {
            'name': 'Log4j_Attack',
            'initial_component': 'log4j:2.17.0',
            'simulation_days': 30,
            'detection_probability': 0.1
        },
        {
            'name': 'Express_Framework_Attack',
            'initial_component': 'express:4.18.2',
            'simulation_days': 30,
            'detection_probability': 0.15
        }
    ]

    if all(scenario['initial_component'] in graph.components for scenario in scenarios):
        comparison_results = graph.simulate_multiple_scenarios(scenarios)
        print(f"\n   📈 Scenario Comparison Results:")
        print(f"   - Most impactful scenario: {comparison_results['summary']['most_impactful']}")
        print(f"   - Fastest spreading scenario: {comparison_results['summary']['fastest_spread']}")
        print(f"   - Average compromise rate: {comparison_results['summary']['avg_compromise_rate']:.1f}%")

    # 6. Risk analysis
    print("\n6. Performing comprehensive risk analysis...")
    analyzer = RiskAnalyzer(graph)

    risk_assessment = analyzer.calculate_supply_chain_risk_score()
    print(f"\n   🛡️  Risk Assessment Results:")
    print(f"   - Overall risk score: {risk_assessment['overall_risk_score']:.1f}/10")
    print(f"   - High-risk components: {risk_assessment['high_risk_components']}")
    print(f"   - High-risk percentage: {risk_assessment['high_risk_percentage']:.1f}%")

    print(f"\n   📊 Risk Distribution:")
    for level, count in risk_assessment['risk_distribution'].items():
        print(f"   - {level.title()}: {count} components")

    # 7. Generate recommendations
    print("\n7. Generating security recommendations...")
    if 'result1' in locals():
        report = analyzer.generate_risk_report([result1])
        print(f"\n   💡 Key Recommendations:")
        for i, rec in enumerate(report['recommendations'][:3], 1):  # Show top 3
            print(f"   {i}. [{rec['priority']}] {rec['title']}")
            print(f"      {rec['description']}")

    # 8. Visualizations (commented out to avoid display issues in demo)
    print("\n8. Visualization capabilities available:")
    print("   - graph.visualize_graph() - Network diagram with risk highlighting")
    print("   - graph.create_impact_heatmap() - Component impact analysis")
    print("   - graph.visualize_attack_path(component_id) - Attack propagation paths")
    print("   - analyzer.create_risk_dashboard() - Comprehensive risk dashboard")

    # 9. Export capabilities
    print("\n9. Data export capabilities:")
    print("   📁 Available export formats:")
    print("   - JSON: graph.export_to_json('software_dependencies.json')")
    print("   - CSV metrics: analyzer.export_metrics_to_csv('risk_metrics.csv')")

    # 10. Patching race simulation
    print("\n10. Simulating patching vs attack race...")
    if log4j_id in graph.components:
        attack_scenario = {
            'initial_component': log4j_id,
            'simulation_days': 60,
            'detection_probability': 0.1
        }

        patching_results = graph.simulate_patching_race(
            attack_scenario,
            organization_types=['enterprise', 'large', 'medium', 'small']
        )

        print(f"\n   ⚡ Patching Effectiveness by Organization Type:")
        for org_type, results in patching_results.items():
            effectiveness = results['patch_effectiveness']
            print(f"   - {org_type.title()}: {effectiveness:.1f}% effective")


def demonstrate_enterprise_scenarios():
    """Demonstrate scenarios specific to enterprise software stacks"""

    print("\n" + "="*60)
    print("🏢 ENTERPRISE SOFTWARE SPECIFIC SCENARIOS")
    print("="*60)

    # Create a more detailed graph with enterprise-specific components
    graph = DependencyGraph("Detailed Enterprise Software Dependencies")

    # Add enterprise applications
    crm_app = SoftwareComponent(
        name="crm_application",
        version="5.2.0",
        software_type=SoftwareType.APPLICATION,
        vendor="SalesForce",
        description="Customer relationship management platform",
        criticality_score=9.5
    )

    # Add ERP system
    erp_system = SoftwareComponent(
        name="erp_system",
        version="12.1.0",
        software_type=SoftwareType.APPLICATION,
        vendor="SAP",
        description="Enterprise resource planning system",
        criticality_score=8.5
    )

    # Add HR portal
    hr_portal = SoftwareComponent(
        name="hr_portal",
        version="3.4.0",
        software_type=SoftwareType.APPLICATION,
        vendor="Workday",
        description="Human resources management portal",
        criticality_score=8.0
    )

    # Add common enterprise infrastructure
    message_queue = SoftwareComponent(
        name="rabbitmq",
        version="3.11.0",
        software_type=SoftwareType.SERVICE,
        vendor="VMware",
        description="Message broker for enterprise communication",
        criticality_score=7.5
    )

    primary_db = SoftwareComponent(
        name="postgresql",
        version="15.2.0",
        software_type=SoftwareType.DATABASE,
        vendor="PostgreSQL",
        description="Primary relational database",
        criticality_score=8.0
    )

    cache_service = SoftwareComponent(
        name="memcached",
        version="1.6.17",
        software_type=SoftwareType.SERVICE,
        vendor="Memcached",
        description="Distributed memory caching system",
        criticality_score=6.5
    )

    # Critical shared libraries
    openssl = SoftwareComponent(
        name="openssl",
        version="3.0.8",
        software_type=SoftwareType.LIBRARY,
        vendor="OpenSSL Foundation",
        description="Cryptographic library for secure communications",
        criticality_score=9.0
    )

    # Add all components
    for component in [crm_app, erp_system, hr_portal, message_queue,
                     primary_db, cache_service, openssl]:
        graph.add_component(component)

    # Create realistic dependency relationships
    graph.add_dependency(crm_app.id, primary_db.id, "direct")
    graph.add_dependency(crm_app.id, cache_service.id, "direct")
    graph.add_dependency(crm_app.id, openssl.id, "transitive")

    graph.add_dependency(erp_system.id, message_queue.id, "direct")
    graph.add_dependency(erp_system.id, openssl.id, "direct")

    graph.add_dependency(hr_portal.id, message_queue.id, "direct")
    graph.add_dependency(hr_portal.id, openssl.id, "transitive")

    graph.add_dependency(primary_db.id, openssl.id, "direct")
    graph.add_dependency(cache_service.id, openssl.id, "direct")
    graph.add_dependency(message_queue.id, openssl.id, "direct")

    # Add a critical vulnerability (simulating a heartbleed-like scenario)
    heartbleed_variant = Vulnerability(
        cve_id="CVE-2024-XXXX",
        severity=VulnerabilityLevel.CRITICAL,
        description="Critical buffer overflow in OpenSSL affecting enterprise communications",
        affected_versions=["3.0.8"],
        discovery_date=datetime(2024, 1, 15),
        patch_available=False,  # Zero-day scenario
        exploit_probability=0.9
    )

    graph.add_vulnerability(openssl.id, heartbleed_variant)

    # Analyze this enterprise-specific scenario
    print(f"\n📊 Enterprise Software Dependency Analysis:")
    stats = graph.get_graph_stats()
    print(f"- Applications: {stats['applications']}")
    print(f"- Supporting services: {stats['services']}")
    print(f"- Critical shared libraries: 1")

    # Simulate OpenSSL compromise impact
    print(f"\n🚨 Critical Scenario: OpenSSL Zero-Day Exploitation")
    openssl_attack = graph.simulate_attack_propagation(
        initial_compromise=openssl.id,
        simulation_days=14,  # Shorter timeline for critical vuln
        detection_probability=0.05  # Low detection for zero-day
    )

    print(f"\nAttack Impact Assessment:")
    print(f"- Time horizon: {openssl_attack['simulation_days']} days")
    print(f"- Components compromised: {openssl_attack['compromised_count']}/{openssl_attack['total_components']}")
    print(f"- Applications affected: {openssl_attack['applications_affected']}/3")
    print(f"- Overall compromise rate: {openssl_attack['compromise_percentage']:.1f}%")

    if openssl_attack['timeline']:
        print(f"\nAttack Timeline:")
        for event in openssl_attack['timeline'][:5]:  # Show first 5 events
            print(f"- Day {event['day']}: {event['component_name']} compromised")

    # Risk analysis for this scenario
    analyzer = RiskAnalyzer(graph)
    enterprise_risk_report = analyzer.generate_risk_report([openssl_attack])

    print(f"\n💡 Enterprise Software Risk Assessment:")
    summary = enterprise_risk_report['executive_summary']
    print(f"- Overall risk level: {summary['overall_risk_level']}")
    print(f"- Applications at risk: {summary['applications_count']}")
    print(f"- Critical vulnerabilities: {summary['critical_vulnerabilities']}")

    print(f"\n🛡️ Top Priority Recommendations:")
    for i, rec in enumerate(enterprise_risk_report['recommendations'][:2], 1):
        print(f"{i}. [{rec['priority']}] {rec['title']}")
        print(f"   Action: {rec['action_items'][0]}")

    return graph, analyzer


if __name__ == "__main__":
    # Run the main demonstration
    main()

    # Run enterprise software specific scenarios
    demonstrate_enterprise_scenarios()

    print("\n" + "="*60)
    print("✅ Demo completed! This simulation framework supports:")
    print("   • Dependency mapping for software packages")
    print("   • Vulnerability propagation modeling")
    print("   • Risk assessment and metrics")
    print("   • Attack scenario comparison")
    print("   • Patching effectiveness analysis")
    print("   • Visual dashboards and reports")
    print("\n💡 Ready for general software supply chain risk analysis")
    print("="*60)