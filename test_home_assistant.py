"""
Test the dependency graph module with real Home Assistant dependencies from GitHub
https://github.com/home-assistant/core

This script creates a realistic dependency graph based on Home Assistant's actual requirements
and demonstrates vulnerability propagation analysis.
"""

from datetime import datetime
from dependency_graph import (
    DependencyGraph,
    SoftwareComponent,
    SoftwareType,
    Vulnerability,
    VulnerabilityLevel
)
from analysis_metrics import RiskAnalyzer


def create_home_assistant_dependency_graph() -> DependencyGraph:
    """Create a dependency graph based on Home Assistant's actual GitHub dependencies"""

    graph = DependencyGraph("Home Assistant Core Dependencies")

    # Main Home Assistant Core Application
    home_assistant_core = SoftwareComponent(
        name="homeassistant",
        version="2024.1.0",
        software_type=SoftwareType.APPLICATION,
        vendor="Home Assistant",
        description="Open source home automation platform",
        criticality_score=10.0  # Core application - highest criticality
    )

    # Core HTTP/Async Framework Dependencies
    aiohttp = SoftwareComponent(
        name="aiohttp",
        version="3.12.15",
        software_type=SoftwareType.FRAMEWORK,
        vendor="aio-libs",
        description="Async HTTP client/server for asyncio and Python",
        criticality_score=9.0  # Critical for web interface and API
    )

    # Database Layer
    sqlalchemy = SoftwareComponent(
        name="sqlalchemy",
        version="2.0.41",
        software_type=SoftwareType.LIBRARY,
        vendor="SQLAlchemy",
        description="Database toolkit and ORM",
        criticality_score=8.5  # Critical for data persistence
    )

    # Template Engine
    jinja2 = SoftwareComponent(
        name="jinja2",
        version="3.1.6",
        software_type=SoftwareType.LIBRARY,
        vendor="Pallets",
        description="Template engine for Python",
        criticality_score=7.0  # Important for UI rendering
    )

    # Cryptographic Library
    cryptography = SoftwareComponent(
        name="cryptography",
        version="45.0.7",
        software_type=SoftwareType.LIBRARY,
        vendor="PyCA",
        description="Cryptographic recipes and primitives",
        criticality_score=9.5  # Critical for security
    )

    # Configuration Parsing
    pyyaml = SoftwareComponent(
        name="pyyaml",
        version="6.0.2",
        software_type=SoftwareType.LIBRARY,
        vendor="PyYAML",
        description="YAML parser and emitter for Python",
        criticality_score=8.0  # Critical for configuration
    )

    # HTTP Client Library
    requests = SoftwareComponent(
        name="requests",
        version="2.32.5",
        software_type=SoftwareType.LIBRARY,
        vendor="PSF",
        description="HTTP library for Python",
        criticality_score=7.5  # Important for external API calls
    )

    # Network Discovery
    zeroconf = SoftwareComponent(
        name="zeroconf",
        version="0.147.2",
        software_type=SoftwareType.LIBRARY,
        vendor="python-zeroconf",
        description="Zero-configuration networking (Bonjour/Avahi)",
        criticality_score=6.5  # Important for device discovery
    )

    # Data Validation
    voluptuous = SoftwareComponent(
        name="voluptuous",
        version="0.15.2",
        software_type=SoftwareType.LIBRARY,
        vendor="Alec Thomas",
        description="Data validation library",
        criticality_score=6.0  # Important for input validation
    )

    # Bluetooth Integration
    home_assistant_bluetooth = SoftwareComponent(
        name="home-assistant-bluetooth",
        version="1.12.2",
        software_type=SoftwareType.LIBRARY,
        vendor="Home Assistant",
        description="Bluetooth integration for Home Assistant",
        criticality_score=5.5  # Optional but important for IoT
    )

    # DNS Resolution
    aiodns = SoftwareComponent(
        name="aiodns",
        version="3.2.0",
        software_type=SoftwareType.LIBRARY,
        vendor="Saúl Ibarra Corretgé",
        description="Simple DNS resolver for asyncio",
        criticality_score=5.0  # Supporting library
    )

    # SSL Certificates
    certifi = SoftwareComponent(
        name="certifi",
        version="2024.8.30",
        software_type=SoftwareType.LIBRARY,
        vendor="Certifi",
        description="Python package for providing Mozilla's CA certificates",
        criticality_score=8.0  # Critical for HTTPS
    )

    # Add all components to the graph
    components = [
        home_assistant_core, aiohttp, sqlalchemy, jinja2, cryptography,
        pyyaml, requests, zeroconf, voluptuous, home_assistant_bluetooth,
        aiodns, certifi
    ]

    for component in components:
        graph.add_component(component)

    # Define realistic dependency relationships based on Home Assistant architecture

    # Core application depends on major frameworks
    graph.add_dependency(home_assistant_core.id, aiohttp.id, "direct")
    graph.add_dependency(home_assistant_core.id, sqlalchemy.id, "direct")
    graph.add_dependency(home_assistant_core.id, jinja2.id, "direct")
    graph.add_dependency(home_assistant_core.id, cryptography.id, "direct")
    graph.add_dependency(home_assistant_core.id, pyyaml.id, "direct")
    graph.add_dependency(home_assistant_core.id, zeroconf.id, "direct")
    graph.add_dependency(home_assistant_core.id, voluptuous.id, "direct")
    graph.add_dependency(home_assistant_core.id, home_assistant_bluetooth.id, "direct")

    # aiohttp dependencies
    graph.add_dependency(aiohttp.id, certifi.id, "direct")
    graph.add_dependency(aiohttp.id, aiodns.id, "direct")

    # requests depends on certifi for SSL
    graph.add_dependency(requests.id, certifi.id, "direct")

    # Home Assistant uses requests for external API calls
    graph.add_dependency(home_assistant_core.id, requests.id, "direct")

    # Transitive dependencies through framework usage
    graph.add_dependency(home_assistant_core.id, certifi.id, "transitive")
    graph.add_dependency(home_assistant_core.id, aiodns.id, "transitive")

    return graph


def add_realistic_vulnerabilities(graph: DependencyGraph) -> None:
    """Add realistic vulnerabilities based on common Python package security issues"""

    # CVE-2023-40217: Python SSL vulnerability affecting certifi usage
    ssl_vulnerability = Vulnerability(
        cve_id="CVE-2023-40217",
        severity=VulnerabilityLevel.HIGH,
        description="TLS handshake bypass vulnerability in Python SSL module",
        affected_versions=["2024.8.30"],
        discovery_date=datetime(2023, 8, 25),
        patch_available=True,
        exploit_probability=0.4
    )
    graph.add_vulnerability("certifi:2024.8.30", ssl_vulnerability)

    # Simulated aiohttp vulnerability (based on historical issues)
    aiohttp_vulnerability = Vulnerability(
        cve_id="CVE-2024-XXXX",
        severity=VulnerabilityLevel.CRITICAL,
        description="HTTP request smuggling vulnerability in aiohttp",
        affected_versions=["3.12.15"],
        discovery_date=datetime(2024, 1, 15),
        patch_available=False,  # Zero-day scenario
        exploit_probability=0.8
    )
    graph.add_vulnerability("aiohttp:3.12.15", aiohttp_vulnerability)

    # PyYAML deserialization vulnerability (historical pattern)
    yaml_vulnerability = Vulnerability(
        cve_id="CVE-2020-14343",
        severity=VulnerabilityLevel.HIGH,
        description="Arbitrary code execution through unsafe YAML loading",
        affected_versions=["6.0.2"],
        discovery_date=datetime(2020, 7, 14),
        patch_available=True,
        exploit_probability=0.6
    )
    graph.add_vulnerability("pyyaml:6.0.2", yaml_vulnerability)

    # SQLAlchemy SQL injection vulnerability (simulated)
    sqlalchemy_vulnerability = Vulnerability(
        cve_id="CVE-2024-YYYY",
        severity=VulnerabilityLevel.MEDIUM,
        description="SQL injection in SQLAlchemy query construction",
        affected_versions=["2.0.41"],
        discovery_date=datetime(2024, 2, 1),
        patch_available=True,
        exploit_probability=0.3
    )
    graph.add_vulnerability("sqlalchemy:2.0.41", sqlalchemy_vulnerability)


def run_home_assistant_analysis():
    """Run comprehensive analysis on Home Assistant dependency graph"""

    print("Home Assistant Supply Chain Risk Analysis")
    print("=" * 60)
    print("Source: https://github.com/home-assistant/core")
    print()

    # Create the dependency graph
    print("1. Building Home Assistant dependency graph...")
    graph = create_home_assistant_dependency_graph()

    # Add vulnerabilities
    print("2. Adding realistic vulnerabilities...")
    add_realistic_vulnerabilities(graph)

    # Display basic statistics
    stats = graph.get_graph_stats()
    print(f"\nDependency Graph Statistics:")
    print(f"   - Total components: {stats['total_components']}")
    print(f"   - Total dependencies: {stats['total_dependencies']}")
    print(f"   - Applications: {stats['applications']}")
    print(f"   - Libraries: {stats['libraries']}")
    print(f"   - Frameworks: {stats.get('frameworks', 0)}")
    print(f"   - Compromised components: {stats['compromised_components']}")

    # Identify critical components
    print(f"\nCritical Components Analysis:")
    critical_components = graph.find_critical_components(min_dependents=1)
    for comp_id, dependent_count in critical_components[:5]:
        component = graph.components[comp_id]
        impact = graph.calculate_impact_score(comp_id)
        print(f"   - {component.name}: {dependent_count} dependents, impact score: {impact:.1f}")

    # Run attack simulations
    print(f"\nAttack Simulation Scenarios:")

    scenarios = [
        {
            'name': 'aiohttp_compromise',
            'initial_component': 'aiohttp:3.12.15',
            'description': 'HTTP framework zero-day exploitation'
        },
        {
            'name': 'certifi_compromise',
            'initial_component': 'certifi:2024.8.30',
            'description': 'SSL certificate library compromise'
        },
        {
            'name': 'pyyaml_compromise',
            'initial_component': 'pyyaml:6.0.2',
            'description': 'YAML parser exploitation'
        }
    ]

    simulation_results = []

    for scenario in scenarios:
        print(f"\n   Scenario: {scenario['description']}")
        result = graph.simulate_attack_propagation(
            initial_compromise=scenario['initial_component'],
            simulation_days=21,  # 3-week simulation
            detection_probability=0.12  # 12% daily detection rate
        )

        simulation_results.append(result)

        print(f"      - Initial component: {graph.components[result['initial_compromise']].name}")
        print(f"      - Components compromised: {result['compromised_count']}/{result['total_components']}")
        print(f"      - Compromise rate: {result['compromise_percentage']:.1f}%")
        print(f"      - Applications affected: {result['applications_affected']}")
        print(f"      - Detection events: {len(result['detection_events'])}")

        if result['timeline']:
            print(f"      - Attack timeline: {len(result['timeline'])} propagation events")
            # Show first few propagation events
            for event in result['timeline'][:3]:
                print(f"        Day {event['day']}: {event['component_name']}")

    # Risk Analysis
    print(f"\nRisk Assessment:")
    analyzer = RiskAnalyzer(graph)
    risk_report = analyzer.generate_risk_report(simulation_results)

    summary = risk_report['executive_summary']
    print(f"   - Overall risk level: {summary['overall_risk_level']}")
    print(f"   - High-risk components: {risk_report['risk_assessment']['high_risk_components']}")
    print(f"   - Critical vulnerabilities: {summary['critical_vulnerabilities']}")

    # Compare simulation scenarios
    if len(simulation_results) > 1:
        comparison = analyzer._compare_scenarios(simulation_results)
        print(f"\nScenario Comparison:")
        print(f"   - Average compromise rate: {comparison['average_compromise_rate']:.1f}%")
        print(f"   - Most severe scenario: {comparison['max_compromise_rate']:.1f}% compromise")
        print(f"   - Least severe scenario: {comparison['min_compromise_rate']:.1f}% compromise")

    # Show recommendations
    print(f"\nSecurity Recommendations:")
    for i, rec in enumerate(risk_report['recommendations'][:4], 1):
        print(f"   {i}. [{rec['priority']}] {rec['title']}")
        print(f"      {rec['description']}")
        if rec['action_items']:
            print(f"      Action: {rec['action_items'][0]}")

    # Patching effectiveness analysis
    print(f"\nPatching Race Analysis:")
    if simulation_results:
        best_scenario = min(simulation_results, key=lambda x: x['compromise_percentage'])

        patching_results = graph.simulate_patching_race(
            {
                'initial_component': best_scenario['initial_compromise'],
                'simulation_days': 30,
                'detection_probability': 0.1
            },
            organization_types=['enterprise', 'medium', 'small']
        )

        print(f"   Patching effectiveness by organization size:")
        for org_type, results in patching_results.items():
            effectiveness = results['patch_effectiveness']
            vulnerable_window = len(results['vulnerable_window_components'])
            print(f"   - {org_type.title()}: {effectiveness:.1f}% effective, {vulnerable_window} components at risk")

    # Export results
    print(f"\nExporting Results:")
    graph.export_to_json("home_assistant_dependencies.json")
    analyzer.export_metrics_to_csv("home_assistant_risk_metrics.csv")
    print(f"   - Dependency graph: home_assistant_dependencies.json")
    print(f"   - Risk metrics: home_assistant_risk_metrics.csv")

    print(f"\nHome Assistant supply chain analysis complete!")
    print(f"   This analysis demonstrates real-world dependency risk assessment")
    print(f"   for a popular open-source home automation platform.")

    return graph, analyzer, simulation_results


if __name__ == "__main__":
    graph, analyzer, results = run_home_assistant_analysis()

    print(f"\nAdditional Analysis Available:")
    print(f"   - graph.visualize_graph('home_assistant_graph.png')")
    print(f"   - graph.create_impact_heatmap('home_assistant_impact.png')")
    print(f"   - analyzer.create_risk_dashboard('home_assistant_dashboard.png')")
    print(f"   - graph.visualize_attack_path('aiohttp:3.12.15', 'attack_path.png')")