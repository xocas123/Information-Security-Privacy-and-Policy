"""
Software Supply Chain Risk Simulator - Dependency Graph Module

This module provides classes and functions for modeling software dependency graphs
and simulating vulnerability propagation through software supply chains.
"""

import networkx as nx
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from datetime import datetime, timedelta
from typing import Dict, List, Set, Tuple, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
import json
import random
import numpy as np


class SoftwareType(Enum):
    """Types of software components"""
    APPLICATION = "application"
    LIBRARY = "library"
    FRAMEWORK = "framework"
    UTILITY = "utility"
    OPERATING_SYSTEM = "operating_system"
    SERVICE = "service"
    DATABASE = "database"


class VulnerabilityLevel(Enum):
    """Severity levels for vulnerabilities"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class SoftwareComponent:
    """Represents a software component in the dependency graph"""
    name: str
    version: str
    software_type: SoftwareType
    vendor: str = ""
    description: str = ""
    is_compromised: bool = False
    compromise_time: Optional[datetime] = None
    patch_time_days: int = 30  # Average days to patch
    criticality_score: float = 1.0  # 1-10 scale for component importance

    def __post_init__(self):
        self.id = f"{self.name}:{self.version}"


@dataclass
class Vulnerability:
    """Represents a vulnerability that can propagate through dependencies"""
    cve_id: str
    severity: VulnerabilityLevel
    description: str
    affected_versions: List[str]
    discovery_date: datetime
    patch_available: bool = False
    exploit_probability: float = 0.1  # 0-1 probability of exploitation


class DependencyGraph:
    """Main class for managing software dependency graphs and vulnerability simulation"""

    def __init__(self, name: str = "Software Dependencies"):
        self.name = name
        self.graph = nx.DiGraph()
        self.components: Dict[str, SoftwareComponent] = {}
        self.vulnerabilities: Dict[str, Vulnerability] = {}
        self.simulation_log: List[Dict[str, Any]] = []

    def add_component(self, component: SoftwareComponent) -> None:
        """Add a software component to the dependency graph"""
        self.components[component.id] = component
        self.graph.add_node(
            component.id,
            name=component.name,
            version=component.version,
            software_type=component.software_type.value,
            is_compromised=component.is_compromised,
            criticality_score=component.criticality_score
        )

    def add_dependency(self, dependent_id: str, dependency_id: str,
                      dependency_type: str = "direct") -> None:
        """Add a dependency relationship between components"""
        if dependent_id in self.components and dependency_id in self.components:
            self.graph.add_edge(dependency_id, dependent_id,
                              dependency_type=dependency_type)

    def add_vulnerability(self, component_id: str, vulnerability: Vulnerability) -> None:
        """Add a vulnerability to a specific component"""
        if component_id in self.components:
            self.vulnerabilities[f"{component_id}:{vulnerability.cve_id}"] = vulnerability
            # Mark component as potentially compromised
            component = self.components[component_id]
            if not vulnerability.patch_available:
                component.is_compromised = True
                component.compromise_time = vulnerability.discovery_date

    def get_dependencies(self, component_id: str, direct_only: bool = False) -> List[str]:
        """Get all dependencies of a component"""
        if component_id not in self.graph:
            return []

        if direct_only:
            return list(self.graph.predecessors(component_id))
        else:
            # Get all transitive dependencies
            return list(nx.ancestors(self.graph, component_id))

    def get_dependents(self, component_id: str, direct_only: bool = False) -> List[str]:
        """Get all components that depend on this component"""
        if component_id not in self.graph:
            return []

        if direct_only:
            return list(self.graph.successors(component_id))
        else:
            # Get all transitive dependents
            return list(nx.descendants(self.graph, component_id))

    def find_critical_components(self, min_dependents: int = 5) -> List[Tuple[str, int]]:
        """Find components with the most dependents (potential single points of failure)"""
        critical_components = []
        for component_id in self.components:
            dependent_count = len(self.get_dependents(component_id))
            if dependent_count >= min_dependents:
                critical_components.append((component_id, dependent_count))

        return sorted(critical_components, key=lambda x: x[1], reverse=True)

    def calculate_impact_score(self, component_id: str) -> float:
        """Calculate the potential impact of compromising a component"""
        if component_id not in self.components:
            return 0.0

        component = self.components[component_id]
        dependents = self.get_dependents(component_id)

        # Base impact from component's own criticality
        impact = component.criticality_score

        # Add impact from all affected dependents
        for dependent_id in dependents:
            if dependent_id in self.components:
                dependent = self.components[dependent_id]
                impact += dependent.criticality_score * 0.5  # Transitive impact is reduced

        return impact

    def get_graph_stats(self) -> Dict[str, Any]:
        """Get basic statistics about the dependency graph"""
        return {
            "total_components": len(self.components),
            "total_dependencies": self.graph.number_of_edges(),
            "applications": len([c for c in self.components.values()
                               if c.software_type == SoftwareType.APPLICATION]),
            "libraries": len([c for c in self.components.values()
                            if c.software_type == SoftwareType.LIBRARY]),
            "services": len([c for c in self.components.values()
                           if c.software_type == SoftwareType.SERVICE]),
            "compromised_components": len([c for c in self.components.values()
                                         if c.is_compromised]),
            "average_dependencies_per_component": (
                sum(len(self.get_dependencies(c_id)) for c_id in self.components) /
                len(self.components) if self.components else 0
            ),
            "critical_components": len(self.find_critical_components())
        }

    def export_to_json(self, filepath: str) -> None:
        """Export dependency graph to JSON format"""
        export_data = {
            "name": self.name,
            "components": {
                comp_id: {
                    "name": comp.name,
                    "version": comp.version,
                    "software_type": comp.software_type.value,
                    "vendor": comp.vendor,
                    "description": comp.description,
                    "is_compromised": comp.is_compromised,
                    "compromise_time": comp.compromise_time.isoformat() if comp.compromise_time else None,
                    "patch_time_days": comp.patch_time_days,
                    "criticality_score": comp.criticality_score
                }
                for comp_id, comp in self.components.items()
            },
            "dependencies": [
                {
                    "from": edge[0],
                    "to": edge[1],
                    "type": self.graph.edges[edge].get("dependency_type", "direct")
                }
                for edge in self.graph.edges()
            ],
            "vulnerabilities": {
                vuln_id: {
                    "cve_id": vuln.cve_id,
                    "severity": vuln.severity.value,
                    "description": vuln.description,
                    "affected_versions": vuln.affected_versions,
                    "discovery_date": vuln.discovery_date.isoformat(),
                    "patch_available": vuln.patch_available,
                    "exploit_probability": vuln.exploit_probability
                }
                for vuln_id, vuln in self.vulnerabilities.items()
            }
        }

        with open(filepath, 'w') as f:
            json.dump(export_data, f, indent=2)

    def visualize_graph(self, output_file: str = None, highlight_compromised: bool = True,
                       show_criticality: bool = True, layout: str = "spring") -> None:
        """Visualize the dependency graph with different layouts and highlighting"""
        plt.figure(figsize=(12, 8))

        # Choose layout
        if layout == "spring":
            pos = nx.spring_layout(self.graph, k=1, iterations=50)
        elif layout == "circular":
            pos = nx.circular_layout(self.graph)
        elif layout == "hierarchical":
            pos = nx.nx_agraph.graphviz_layout(self.graph, prog='dot')
        else:
            pos = nx.spring_layout(self.graph)

        # Color nodes based on software type and compromise status
        node_colors = []
        node_sizes = []

        for node_id in self.graph.nodes():
            component = self.components[node_id]

            # Base color by software type
            if component.software_type == SoftwareType.APPLICATION:
                color = '#FF6B6B'  # Red for applications
            elif component.software_type == SoftwareType.LIBRARY:
                color = '#4ECDC4'  # Teal for libraries
            elif component.software_type == SoftwareType.FRAMEWORK:
                color = '#45B7D1'  # Blue for frameworks
            elif component.software_type == SoftwareType.SERVICE:
                color = '#F39C12'  # Orange for services
            elif component.software_type == SoftwareType.DATABASE:
                color = '#9B59B6'  # Purple for databases
            else:
                color = '#96CEB4'  # Green for others

            # Darken if compromised
            if highlight_compromised and component.is_compromised:
                color = '#2C3E50'  # Dark color for compromised

            node_colors.append(color)

            # Size based on criticality if enabled
            if show_criticality:
                size = max(200, component.criticality_score * 100)
            else:
                size = 300
            node_sizes.append(size)

        # Draw the graph
        nx.draw(self.graph, pos,
                node_color=node_colors,
                node_size=node_sizes,
                with_labels=True,
                labels={node: self.components[node].name for node in self.graph.nodes()},
                font_size=8,
                font_weight='bold',
                arrows=True,
                arrowsize=20,
                edge_color='gray',
                alpha=0.7)

        # Create legend
        legend_elements = [
            mpatches.Patch(color='#FF6B6B', label='Application'),
            mpatches.Patch(color='#4ECDC4', label='Library'),
            mpatches.Patch(color='#45B7D1', label='Framework'),
            mpatches.Patch(color='#F39C12', label='Service'),
            mpatches.Patch(color='#9B59B6', label='Database'),
            mpatches.Patch(color='#96CEB4', label='Other')
        ]

        if highlight_compromised:
            legend_elements.append(mpatches.Patch(color='#2C3E50', label='Compromised'))

        plt.legend(handles=legend_elements, loc='upper left', bbox_to_anchor=(1, 1))
        plt.title(f"{self.name}\nDependency Graph Visualization")
        plt.tight_layout()

        if output_file:
            plt.savefig(output_file, dpi=300, bbox_inches='tight')
        else:
            plt.show()

    def create_impact_heatmap(self, output_file: str = None) -> None:
        """Create a heatmap showing potential impact of compromising each component"""
        components = list(self.components.keys())
        impact_scores = [self.calculate_impact_score(comp_id) for comp_id in components]
        dependent_counts = [len(self.get_dependents(comp_id)) for comp_id in components]

        plt.figure(figsize=(10, 6))

        # Create scatter plot with impact vs dependents
        scatter = plt.scatter(dependent_counts, impact_scores,
                            c=impact_scores, s=100, alpha=0.7, cmap='Reds')

        # Add labels for high-impact components
        for i, comp_id in enumerate(components):
            if impact_scores[i] > max(impact_scores) * 0.7:  # Top 30% by impact
                plt.annotate(self.components[comp_id].name,
                           (dependent_counts[i], impact_scores[i]),
                           xytext=(5, 5), textcoords='offset points', fontsize=8)

        plt.colorbar(scatter, label='Impact Score')
        plt.xlabel('Number of Dependents')
        plt.ylabel('Impact Score')
        plt.title('Component Impact Analysis\n(Size and color indicate potential impact)')
        plt.grid(True, alpha=0.3)

        if output_file:
            plt.savefig(output_file, dpi=300, bbox_inches='tight')
        else:
            plt.show()

    def visualize_attack_path(self, source_component: str, output_file: str = None) -> None:
        """Visualize how an attack would propagate from a source component"""
        if source_component not in self.components:
            raise ValueError(f"Component {source_component} not found in graph")

        plt.figure(figsize=(12, 8))

        # Get all components that would be affected
        affected_components = self.get_dependents(source_component)

        # Create position layout
        pos = nx.spring_layout(self.graph, k=1, iterations=50)

        # Color nodes based on their relationship to the attack source
        node_colors = []
        for node_id in self.graph.nodes():
            if node_id == source_component:
                node_colors.append('#E74C3C')  # Red for attack source
            elif node_id in affected_components:
                node_colors.append('#F39C12')  # Orange for affected
            else:
                node_colors.append('#95A5A6')  # Gray for unaffected

        # Draw the graph
        nx.draw(self.graph, pos,
                node_color=node_colors,
                node_size=500,
                with_labels=True,
                labels={node: self.components[node].name for node in self.graph.nodes()},
                font_size=8,
                font_weight='bold',
                arrows=True,
                arrowsize=20,
                edge_color='gray',
                alpha=0.7)

        # Highlight attack propagation paths
        attack_edges = []
        for affected in affected_components:
            try:
                path = nx.shortest_path(self.graph, source_component, affected)
                for i in range(len(path) - 1):
                    attack_edges.append((path[i], path[i + 1]))
            except nx.NetworkXNoPath:
                continue

        if attack_edges:
            nx.draw_networkx_edges(self.graph, pos, edgelist=attack_edges,
                                 edge_color='red', width=3, alpha=0.8, arrows=True)

        # Create legend
        legend_elements = [
            mpatches.Patch(color='#E74C3C', label='Attack Source'),
            mpatches.Patch(color='#F39C12', label='Affected Components'),
            mpatches.Patch(color='#95A5A6', label='Unaffected'),
        ]
        plt.legend(handles=legend_elements, loc='upper left', bbox_to_anchor=(1, 1))

        plt.title(f"Attack Propagation from {self.components[source_component].name}\n"
                  f"Potentially affects {len(affected_components)} components")
        plt.tight_layout()

        if output_file:
            plt.savefig(output_file, dpi=300, bbox_inches='tight')
        else:
            plt.show()

    @classmethod
    def load_from_json(cls, filepath: str) -> 'DependencyGraph':
        """Load dependency graph from JSON format"""
        with open(filepath, 'r') as f:
            data = json.load(f)

        graph = cls(data["name"])

        # Load components
        for comp_id, comp_data in data["components"].items():
            component = SoftwareComponent(
                name=comp_data["name"],
                version=comp_data["version"],
                software_type=SoftwareType(comp_data["software_type"]),
                vendor=comp_data.get("vendor", ""),
                description=comp_data.get("description", ""),
                is_compromised=comp_data.get("is_compromised", False),
                compromise_time=datetime.fromisoformat(comp_data["compromise_time"])
                              if comp_data.get("compromise_time") else None,
                patch_time_days=comp_data.get("patch_time_days", 30),
                criticality_score=comp_data.get("criticality_score", 1.0)
            )
            graph.add_component(component)

        # Load dependencies
        for dep in data["dependencies"]:
            graph.add_dependency(dep["to"], dep["from"], dep.get("type", "direct"))

        # Load vulnerabilities
        for vuln_id, vuln_data in data["vulnerabilities"].items():
            component_id = vuln_id.split(":")[0] + ":" + vuln_id.split(":")[1]
            vulnerability = Vulnerability(
                cve_id=vuln_data["cve_id"],
                severity=VulnerabilityLevel(vuln_data["severity"]),
                description=vuln_data["description"],
                affected_versions=vuln_data["affected_versions"],
                discovery_date=datetime.fromisoformat(vuln_data["discovery_date"]),
                patch_available=vuln_data.get("patch_available", False),
                exploit_probability=vuln_data.get("exploit_probability", 0.1)
            )
            graph.add_vulnerability(component_id, vulnerability)

        return graph

    def simulate_attack_propagation(self, initial_compromise: str,
                                  simulation_days: int = 30,
                                  detection_probability: float = 0.1) -> Dict[str, Any]:
        """Simulate how a vulnerability propagates through the dependency graph over time"""
        if initial_compromise not in self.components:
            raise ValueError(f"Component {initial_compromise} not found")

        # Reset simulation state
        for component in self.components.values():
            component.is_compromised = False
            component.compromise_time = None

        # Initialize the attack
        start_time = datetime.now()
        self.components[initial_compromise].is_compromised = True
        self.components[initial_compromise].compromise_time = start_time

        compromised_timeline = []
        detection_events = []

        # Track which components are compromised over time
        current_compromised = {initial_compromise}

        for day in range(simulation_days):
            current_date = start_time + timedelta(days=day)

            # Check for new compromises from existing ones
            new_compromises = set()

            for comp_id in list(current_compromised):
                component = self.components[comp_id]
                dependents = self.get_dependents(comp_id, direct_only=True)

                for dependent_id in dependents:
                    if dependent_id not in current_compromised:
                        dependent = self.components[dependent_id]

                        # Calculate compromise probability based on:
                        # - Time since initial compromise
                        # - Component criticality
                        # - Vulnerability exploit probability

                        days_since_compromise = (current_date - component.compromise_time).days
                        base_probability = 0.05  # 5% base chance per day

                        # Increase probability over time (attackers get better access)
                        time_factor = min(1.0, days_since_compromise / 7.0)  # Peaks at 1 week

                        # Higher criticality components are more likely to be targeted
                        criticality_factor = dependent.criticality_score / 10.0

                        # Vulnerability-specific factors
                        vuln_factor = 1.0
                        for vuln_key in self.vulnerabilities:
                            if dependent_id in vuln_key:
                                vuln = self.vulnerabilities[vuln_key]
                                vuln_factor = max(vuln_factor, vuln.exploit_probability)

                        compromise_probability = base_probability * time_factor * criticality_factor * vuln_factor

                        if random.random() < compromise_probability:
                            new_compromises.add(dependent_id)
                            dependent.is_compromised = True
                            dependent.compromise_time = current_date

                            compromised_timeline.append({
                                'day': day,
                                'date': current_date.isoformat(),
                                'component_id': dependent_id,
                                'component_name': dependent.name,
                                'source_component': comp_id,
                                'compromise_probability': compromise_probability
                            })

            current_compromised.update(new_compromises)

            # Check for detection events
            for comp_id in current_compromised:
                component = self.components[comp_id]
                if random.random() < detection_probability:
                    detection_events.append({
                        'day': day,
                        'date': current_date.isoformat(),
                        'component_id': comp_id,
                        'component_name': component.name,
                        'days_since_compromise': (current_date - component.compromise_time).days
                    })

        # Calculate final statistics
        total_components = len(self.components)
        compromised_count = len(current_compromised)
        applications_compromised = len([
            comp_id for comp_id in current_compromised
            if self.components[comp_id].software_type == SoftwareType.APPLICATION
        ])

        return {
            'initial_compromise': initial_compromise,
            'simulation_days': simulation_days,
            'total_components': total_components,
            'compromised_count': compromised_count,
            'compromise_percentage': (compromised_count / total_components) * 100,
            'applications_affected': applications_compromised,
            'timeline': compromised_timeline,
            'detection_events': detection_events,
            'final_compromised_components': list(current_compromised)
        }

    def simulate_multiple_scenarios(self, scenarios: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Run multiple attack scenarios and compare results"""
        results = {}

        for scenario in scenarios:
            scenario_name = scenario['name']
            initial_component = scenario['initial_component']
            simulation_days = scenario.get('simulation_days', 30)
            detection_prob = scenario.get('detection_probability', 0.1)

            print(f"Running scenario: {scenario_name}")
            result = self.simulate_attack_propagation(
                initial_component, simulation_days, detection_prob
            )
            results[scenario_name] = result

        # Compare scenarios
        comparison = {
            'scenarios': results,
            'summary': {
                'most_impactful': max(results.keys(),
                                    key=lambda x: results[x]['compromise_percentage']),
                'fastest_spread': min(results.keys(),
                                    key=lambda x: len(results[x]['timeline']) if results[x]['timeline'] else float('inf')),
                'avg_compromise_rate': np.mean([r['compromise_percentage'] for r in results.values()])
            }
        }

        return comparison

    def calculate_time_to_patch(self, component_id: str, organization_type: str = "large") -> int:
        """Calculate realistic patching timelines based on organization type and component criticality"""
        if component_id not in self.components:
            return 0

        component = self.components[component_id]

        # Base patching times by organization type (days)
        base_times = {
            "enterprise": {"critical": 3, "high": 7, "medium": 30, "low": 90},
            "large": {"critical": 7, "high": 14, "medium": 45, "low": 120},
            "medium": {"critical": 14, "high": 30, "medium": 60, "low": 180},
            "small": {"critical": 30, "high": 60, "medium": 90, "low": 365}
        }

        # Determine vulnerability severity affecting this component
        max_severity = VulnerabilityLevel.LOW
        for vuln_key in self.vulnerabilities:
            if component_id in vuln_key:
                vuln = self.vulnerabilities[vuln_key]
                if vuln.severity.value == "critical":
                    max_severity = VulnerabilityLevel.CRITICAL
                    break
                elif vuln.severity.value == "high" and max_severity != VulnerabilityLevel.CRITICAL:
                    max_severity = VulnerabilityLevel.HIGH
                elif vuln.severity.value == "medium" and max_severity not in [VulnerabilityLevel.CRITICAL, VulnerabilityLevel.HIGH]:
                    max_severity = VulnerabilityLevel.MEDIUM

        base_time = base_times[organization_type][max_severity.value]

        # Adjust based on component type
        if component.software_type == SoftwareType.APPLICATION:
            # Applications get priority
            base_time = int(base_time * 0.7)
        elif component.software_type == SoftwareType.OPERATING_SYSTEM:
            # OS patches take longer due to testing requirements
            base_time = int(base_time * 1.5)
        elif component.software_type == SoftwareType.DATABASE:
            # Database patches require careful testing
            base_time = int(base_time * 1.3)

        # Add some randomness
        variation = random.uniform(0.8, 1.4)
        return int(base_time * variation)

    def simulate_patching_race(self, attack_scenario: Dict[str, Any],
                             organization_types: List[str] = None) -> Dict[str, Any]:
        """Simulate a race between attack propagation and patching efforts"""
        if organization_types is None:
            organization_types = ["enterprise", "large", "medium", "small"]

        results = {}

        for org_type in organization_types:
            # Run attack simulation
            attack_result = self.simulate_attack_propagation(
                attack_scenario['initial_component'],
                attack_scenario.get('simulation_days', 30),
                attack_scenario.get('detection_probability', 0.1)
            )

            # Calculate patching timeline
            patching_timeline = {}
            for comp_id in self.components:
                patch_time = self.calculate_time_to_patch(comp_id, org_type)
                patching_timeline[comp_id] = patch_time

            # Determine which components were compromised before they could be patched
            vulnerable_window = []
            for event in attack_result['timeline']:
                comp_id = event['component_id']
                compromise_day = event['day']
                patch_day = patching_timeline[comp_id]

                if compromise_day < patch_day:
                    vulnerable_window.append({
                        'component_id': comp_id,
                        'component_name': event['component_name'],
                        'compromise_day': compromise_day,
                        'patch_day': patch_day,
                        'vulnerability_window': patch_day - compromise_day
                    })

            results[org_type] = {
                'attack_result': attack_result,
                'patching_timeline': patching_timeline,
                'vulnerable_window_components': vulnerable_window,
                'components_saved_by_patching': (
                    attack_result['compromised_count'] - len(vulnerable_window)
                ),
                'patch_effectiveness': (
                    (attack_result['compromised_count'] - len(vulnerable_window)) /
                    attack_result['compromised_count'] * 100
                    if attack_result['compromised_count'] > 0 else 100
                )
            }

        return results


def create_sample_graph() -> DependencyGraph:
    """Create a sample dependency graph for common software packages"""
    graph = DependencyGraph("Sample Software Dependencies")

    # Add applications
    web_app = SoftwareComponent(
        name="webapp",
        version="1.5.0",
        software_type=SoftwareType.APPLICATION,
        vendor="Company Inc",
        description="Main web application",
        criticality_score=9.0
    )

    api_service = SoftwareComponent(
        name="api_service",
        version="2.1.0",
        software_type=SoftwareType.SERVICE,
        vendor="Company Inc",
        description="REST API service",
        criticality_score=8.0
    )

    background_worker = SoftwareComponent(
        name="background_worker",
        version="1.2.0",
        software_type=SoftwareType.APPLICATION,
        vendor="Company Inc",
        description="Background task processor",
        criticality_score=7.5
    )

    # Add common dependencies
    express_js = SoftwareComponent(
        name="express",
        version="4.18.2",
        software_type=SoftwareType.FRAMEWORK,
        vendor="Express",
        description="Web framework for Node.js",
        criticality_score=6.0
    )

    lodash = SoftwareComponent(
        name="lodash",
        version="4.17.21",
        software_type=SoftwareType.LIBRARY,
        vendor="John-David Dalton",
        description="JavaScript utility library",
        criticality_score=4.0
    )

    log4j = SoftwareComponent(
        name="log4j",
        version="2.17.0",
        software_type=SoftwareType.LIBRARY,
        vendor="Apache",
        description="Java logging library",
        criticality_score=8.5
    )

    redis = SoftwareComponent(
        name="redis",
        version="7.0.0",
        software_type=SoftwareType.DATABASE,
        vendor="Redis Ltd",
        description="In-memory data structure store",
        criticality_score=7.0
    )

    # Add components to graph
    for component in [web_app, api_service, background_worker, express_js, lodash, log4j, redis]:
        graph.add_component(component)

    # Add dependencies
    graph.add_dependency(web_app.id, express_js.id, "direct")
    graph.add_dependency(api_service.id, log4j.id, "direct")
    graph.add_dependency(background_worker.id, redis.id, "direct")
    graph.add_dependency(express_js.id, lodash.id, "direct")
    graph.add_dependency(api_service.id, redis.id, "direct")
    graph.add_dependency(web_app.id, lodash.id, "transitive")

    # Add sample vulnerability (Log4Shell)
    log4shell = Vulnerability(
        cve_id="CVE-2021-44228",
        severity=VulnerabilityLevel.CRITICAL,
        description="Log4Shell - Remote code execution in Log4j",
        affected_versions=["2.0", "2.17.0"],
        discovery_date=datetime(2021, 12, 9),
        patch_available=True,
        exploit_probability=0.8
    )

    graph.add_vulnerability(log4j.id, log4shell)

    return graph