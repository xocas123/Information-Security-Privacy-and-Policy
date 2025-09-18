"""
Software Supply Chain Risk Simulator - Analysis and Metrics Module

This module provides advanced analysis functions and risk metrics calculation
for dependency graphs and vulnerability propagation simulations.
"""

import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from typing import Dict, List, Any, Tuple
import numpy as np
from datetime import datetime, timedelta
from dependency_graph import DependencyGraph, SoftwareType, VulnerabilityLevel


class RiskAnalyzer:
    """Advanced risk analysis and metrics calculation for software supply chains"""

    def __init__(self, dependency_graph: DependencyGraph):
        self.graph = dependency_graph

    def calculate_supply_chain_risk_score(self) -> Dict[str, Any]:
        """Calculate an overall supply chain risk score for the software infrastructure"""

        # Component-level risk factors
        component_risks = {}
        for comp_id, component in self.graph.components.items():

            # Base risk from component type and criticality
            type_risk = {
                SoftwareType.APPLICATION: 9,
                SoftwareType.LIBRARY: 6,
                SoftwareType.FRAMEWORK: 7,
                SoftwareType.UTILITY: 5,
                SoftwareType.OPERATING_SYSTEM: 8,
                SoftwareType.SERVICE: 8,
                SoftwareType.DATABASE: 9
            }

            base_risk = type_risk.get(component.software_type, 5)
            criticality_risk = component.criticality_score

            # Dependency risk (more dependents = higher risk)
            dependents_count = len(self.graph.get_dependents(comp_id))
            dependency_risk = min(10, dependents_count)  # Cap at 10

            # Vulnerability risk
            vuln_risk = 0
            for vuln_key in self.graph.vulnerabilities:
                if comp_id in vuln_key:
                    vuln = self.graph.vulnerabilities[vuln_key]
                    severity_scores = {
                        VulnerabilityLevel.CRITICAL: 10,
                        VulnerabilityLevel.HIGH: 7,
                        VulnerabilityLevel.MEDIUM: 4,
                        VulnerabilityLevel.LOW: 1
                    }
                    vuln_risk = max(vuln_risk, severity_scores[vuln.severity])

            # Calculate compound risk score (0-100)
            compound_risk = (base_risk * 0.3 +
                           criticality_risk * 0.25 +
                           dependency_risk * 0.25 +
                           vuln_risk * 0.2)

            component_risks[comp_id] = {
                'component_name': component.name,
                'base_risk': base_risk,
                'criticality_risk': criticality_risk,
                'dependency_risk': dependency_risk,
                'vulnerability_risk': vuln_risk,
                'compound_risk': compound_risk
            }

        # Overall system risk
        total_risk = sum(cr['compound_risk'] for cr in component_risks.values())
        avg_risk = total_risk / len(component_risks) if component_risks else 0

        # High-risk component threshold
        high_risk_threshold = 7.0
        high_risk_components = [
            comp_id for comp_id, risk in component_risks.items()
            if risk['compound_risk'] >= high_risk_threshold
        ]

        return {
            'overall_risk_score': avg_risk,
            'total_components': len(self.graph.components),
            'high_risk_components': len(high_risk_components),
            'high_risk_percentage': (len(high_risk_components) / len(self.graph.components)) * 100,
            'component_risks': component_risks,
            'risk_distribution': self._calculate_risk_distribution(component_risks),
            'critical_paths': self._identify_critical_attack_paths()
        }

    def _calculate_risk_distribution(self, component_risks: Dict[str, Dict]) -> Dict[str, int]:
        """Calculate distribution of components across risk levels"""
        distribution = {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}

        for risk_data in component_risks.values():
            risk_score = risk_data['compound_risk']
            if risk_score < 3:
                distribution['low'] += 1
            elif risk_score < 6:
                distribution['medium'] += 1
            elif risk_score < 8:
                distribution['high'] += 1
            else:
                distribution['critical'] += 1

        return distribution

    def _identify_critical_attack_paths(self) -> List[Dict[str, Any]]:
        """Identify the most critical attack propagation paths"""
        critical_paths = []

        # Find components with high impact potential
        high_impact_components = []
        for comp_id in self.graph.components:
            impact_score = self.graph.calculate_impact_score(comp_id)
            if impact_score > 15:  # Threshold for high impact
                high_impact_components.append((comp_id, impact_score))

        # Sort by impact score
        high_impact_components.sort(key=lambda x: x[1], reverse=True)

        # Analyze attack paths from top components
        for comp_id, impact_score in high_impact_components[:5]:  # Top 5
            dependents = self.graph.get_dependents(comp_id)
            applications_affected = [
                dep for dep in dependents
                if self.graph.components[dep].software_type == SoftwareType.APPLICATION
            ]

            critical_paths.append({
                'source_component': comp_id,
                'source_name': self.graph.components[comp_id].name,
                'impact_score': impact_score,
                'total_dependents': len(dependents),
                'applications_affected': len(applications_affected),
                'affected_applications': [
                    self.graph.components[dep].name for dep in applications_affected
                ]
            })

        return critical_paths

    def analyze_simulation_results(self, simulation_results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze and provide insights from attack simulation results"""

        timeline = simulation_results.get('timeline', [])
        detection_events = simulation_results.get('detection_events', [])

        if not timeline:
            return {'error': 'No timeline data in simulation results'}

        # Convert to DataFrame for easier analysis
        df_timeline = pd.DataFrame(timeline)
        df_timeline['day'] = pd.to_numeric(df_timeline['day'])

        # Calculate propagation metrics
        daily_infections = df_timeline.groupby('day').size()
        cumulative_infections = daily_infections.cumsum()

        # Peak infection rate
        peak_day = daily_infections.idxmax() if len(daily_infections) > 0 else 0
        peak_infections = daily_infections.max() if len(daily_infections) > 0 else 0

        # Time to critical mass (50% of components)
        total_components = simulation_results['total_components']
        critical_mass_threshold = total_components * 0.5
        time_to_critical_mass = None

        for day, cumulative in cumulative_infections.items():
            if cumulative >= critical_mass_threshold:
                time_to_critical_mass = day
                break

        # Analyze component types affected
        component_types_affected = {}
        for event in timeline:
            comp_id = event['component_id']
            comp_type = self.graph.components[comp_id].software_type.value
            component_types_affected[comp_type] = component_types_affected.get(comp_type, 0) + 1

        # Detection effectiveness
        detection_rate = len(detection_events) / simulation_results['compromised_count'] if simulation_results['compromised_count'] > 0 else 0
        avg_detection_delay = np.mean([event['days_since_compromise'] for event in detection_events]) if detection_events else float('inf')

        return {
            'propagation_metrics': {
                'peak_infection_day': peak_day,
                'peak_infections_per_day': peak_infections,
                'time_to_critical_mass': time_to_critical_mass,
                'final_infection_rate': simulation_results['compromise_percentage'],
                'average_daily_spread': len(timeline) / simulation_results['simulation_days']
            },
            'component_impact': {
                'types_affected': component_types_affected,
                'applications_compromised': simulation_results['applications_affected'],
                'total_compromised': simulation_results['compromised_count']
            },
            'detection_analysis': {
                'detection_rate': detection_rate,
                'average_detection_delay_days': avg_detection_delay,
                'total_detections': len(detection_events)
            },
            'timeline_data': {
                'daily_infections': daily_infections.to_dict(),
                'cumulative_infections': cumulative_infections.to_dict()
            }
        }

    def generate_risk_report(self, simulation_results: List[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Generate a comprehensive risk assessment report"""

        report = {
            'report_date': datetime.now().isoformat(),
            'executive_summary': {},
            'risk_assessment': {},
            'simulation_analysis': {},
            'recommendations': []
        }

        # Risk Assessment
        risk_score = self.calculate_supply_chain_risk_score()
        report['risk_assessment'] = risk_score

        # Executive Summary
        report['executive_summary'] = {
            'overall_risk_level': self._categorize_risk_level(risk_score['overall_risk_score']),
            'total_components_analyzed': risk_score['total_components'],
            'high_risk_components': risk_score['high_risk_components'],
            'applications_count': len([
                c for c in self.graph.components.values()
                if c.software_type == SoftwareType.APPLICATION
            ]),
            'critical_vulnerabilities': len([
                v for v in self.graph.vulnerabilities.values()
                if v.severity == VulnerabilityLevel.CRITICAL
            ])
        }

        # Simulation Analysis (if provided)
        if simulation_results:
            combined_analysis = {}
            for i, sim_result in enumerate(simulation_results):
                analysis = self.analyze_simulation_results(sim_result)
                combined_analysis[f'scenario_{i+1}'] = analysis

            report['simulation_analysis'] = {
                'scenarios_analyzed': len(simulation_results),
                'detailed_results': combined_analysis,
                'cross_scenario_comparison': self._compare_scenarios(simulation_results)
            }

        # Generate Recommendations
        report['recommendations'] = self._generate_recommendations(risk_score, simulation_results)

        return report

    def _categorize_risk_level(self, risk_score: float) -> str:
        """Categorize overall risk level"""
        if risk_score < 3:
            return "LOW"
        elif risk_score < 6:
            return "MEDIUM"
        elif risk_score < 8:
            return "HIGH"
        else:
            return "CRITICAL"

    def _compare_scenarios(self, simulation_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Compare multiple simulation scenarios"""
        if not simulation_results:
            return {}

        compromise_rates = [result['compromise_percentage'] for result in simulation_results]
        app_impacts = [result['applications_affected'] for result in simulation_results]

        return {
            'average_compromise_rate': np.mean(compromise_rates),
            'max_compromise_rate': np.max(compromise_rates),
            'min_compromise_rate': np.min(compromise_rates),
            'average_application_impact': np.mean(app_impacts),
            'max_application_impact': np.max(app_impacts),
            'compromise_rate_variance': np.var(compromise_rates)
        }

    def _generate_recommendations(self, risk_assessment: Dict[str, Any],
                                simulation_results: List[Dict[str, Any]] = None) -> List[Dict[str, str]]:
        """Generate actionable security recommendations"""
        recommendations = []

        # High-risk component recommendations
        if risk_assessment['high_risk_percentage'] > 20:
            recommendations.append({
                'priority': 'HIGH',
                'category': 'Risk Mitigation',
                'title': 'Address High-Risk Components',
                'description': f"{risk_assessment['high_risk_components']} components identified as high-risk. "
                             f"Prioritize security hardening and monitoring for these systems.",
                'action_items': [
                    'Implement additional monitoring for high-risk components',
                    'Accelerate patching timelines for critical dependencies',
                    'Consider alternative, more secure component options'
                ]
            })

        # Critical attack path recommendations
        if risk_assessment['critical_paths']:
            recommendations.append({
                'priority': 'HIGH',
                'category': 'Attack Surface Reduction',
                'title': 'Secure Critical Attack Paths',
                'description': f"Identified {len(risk_assessment['critical_paths'])} critical attack propagation paths.",
                'action_items': [
                    'Implement network segmentation to limit lateral movement',
                    'Deploy endpoint detection and response (EDR) tools',
                    'Regular security assessments of critical components'
                ]
            })

        # Vulnerability management recommendations
        critical_vulns = len([v for v in self.graph.vulnerabilities.values()
                            if v.severity == VulnerabilityLevel.CRITICAL])
        if critical_vulns > 0:
            recommendations.append({
                'priority': 'CRITICAL',
                'category': 'Vulnerability Management',
                'title': 'Address Critical Vulnerabilities',
                'description': f"{critical_vulns} critical vulnerabilities detected in the dependency chain.",
                'action_items': [
                    'Emergency patching for all critical vulnerabilities',
                    'Implement vulnerability scanning automation',
                    'Establish vendor security communication channels'
                ]
            })

        # Simulation-based recommendations
        if simulation_results:
            avg_compromise = np.mean([r['compromise_percentage'] for r in simulation_results])
            if avg_compromise > 30:
                recommendations.append({
                    'priority': 'MEDIUM',
                    'category': 'Incident Response',
                    'title': 'Improve Incident Detection and Response',
                    'description': f"Simulations show potential for {avg_compromise:.1f}% system compromise.",
                    'action_items': [
                        'Enhance security monitoring and alerting systems',
                        'Develop and test incident response playbooks',
                        'Implement automated threat hunting capabilities'
                    ]
                })

        # Supply chain security recommendations
        library_count = len([c for c in self.graph.components.values()
                           if c.software_type == SoftwareType.LIBRARY])
        if library_count > 10:
            recommendations.append({
                'priority': 'MEDIUM',
                'category': 'Supply Chain Security',
                'title': 'Implement Supply Chain Security Controls',
                'description': f"Large number of third-party libraries ({library_count}) increases supply chain risk.",
                'action_items': [
                    'Implement software bill of materials (SBOM) tracking',
                    'Regular dependency audits and updates',
                    'Vendor security assessment program',
                    'Consider dependency pinning and integrity verification'
                ]
            })

        return recommendations

    def create_risk_dashboard(self, output_file: str = None,
                            simulation_results: List[Dict[str, Any]] = None) -> None:
        """Create a comprehensive risk assessment dashboard"""

        fig, axes = plt.subplots(2, 3, figsize=(18, 12))
        fig.suptitle('Software Supply Chain Risk Assessment Dashboard', fontsize=16, fontweight='bold')

        # 1. Risk Score Distribution
        risk_assessment = self.calculate_supply_chain_risk_score()
        risk_dist = risk_assessment['risk_distribution']

        ax1 = axes[0, 0]
        categories = list(risk_dist.keys())
        values = list(risk_dist.values())
        colors = ['green', 'yellow', 'orange', 'red']

        ax1.pie(values, labels=categories, colors=colors, autopct='%1.1f%%', startangle=90)
        ax1.set_title('Component Risk Distribution')

        # 2. High-Impact Components
        ax2 = axes[0, 1]
        component_risks = risk_assessment['component_risks']
        top_risks = sorted(component_risks.items(),
                          key=lambda x: x[1]['compound_risk'], reverse=True)[:10]

        comp_names = [self.graph.components[comp_id].name for comp_id, _ in top_risks]
        risk_scores = [data['compound_risk'] for _, data in top_risks]

        bars = ax2.barh(range(len(comp_names)), risk_scores, color='steelblue')
        ax2.set_yticks(range(len(comp_names)))
        ax2.set_yticklabels(comp_names, fontsize=8)
        ax2.set_xlabel('Risk Score')
        ax2.set_title('Top 10 Highest Risk Components')
        ax2.grid(True, alpha=0.3)

        # 3. Dependency Network Metrics
        ax3 = axes[0, 2]
        dependency_counts = [len(self.graph.get_dependents(comp_id))
                           for comp_id in self.graph.components]

        ax3.hist(dependency_counts, bins=10, color='lightcoral', alpha=0.7, edgecolor='black')
        ax3.set_xlabel('Number of Dependents')
        ax3.set_ylabel('Number of Components')
        ax3.set_title('Dependency Distribution')
        ax3.grid(True, alpha=0.3)

        # 4. Vulnerability Severity Breakdown
        ax4 = axes[1, 0]
        vuln_severity = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        for vuln in self.graph.vulnerabilities.values():
            vuln_severity[vuln.severity.value.title()] += 1

        severity_labels = list(vuln_severity.keys())
        severity_counts = list(vuln_severity.values())
        severity_colors = ['red', 'orange', 'yellow', 'green']

        bars = ax4.bar(severity_labels, severity_counts, color=severity_colors, alpha=0.7)
        ax4.set_ylabel('Number of Vulnerabilities')
        ax4.set_title('Vulnerability Severity Distribution')
        ax4.grid(True, alpha=0.3)

        # 5. Simulation Results (if available)
        if simulation_results:
            ax5 = axes[1, 1]
            scenario_names = [f"Scenario {i+1}" for i in range(len(simulation_results))]
            compromise_rates = [result['compromise_percentage'] for result in simulation_results]

            bars = ax5.bar(scenario_names, compromise_rates, color='darkred', alpha=0.7)
            ax5.set_ylabel('Compromise Percentage (%)')
            ax5.set_title('Simulation Results Comparison')
            ax5.grid(True, alpha=0.3)

            # Add value labels on bars
            for bar, rate in zip(bars, compromise_rates):
                height = bar.get_height()
                ax5.text(bar.get_x() + bar.get_width()/2., height + 1,
                        f'{rate:.1f}%', ha='center', va='bottom')
        else:
            ax5 = axes[1, 1]
            ax5.text(0.5, 0.5, 'No Simulation Data\nAvailable',
                    ha='center', va='center', transform=ax5.transAxes,
                    fontsize=12, style='italic')
            ax5.set_title('Simulation Results')

        # 6. Risk Timeline (mock data for demonstration)
        ax6 = axes[1, 2]
        dates = pd.date_range(start='2023-01-01', end='2023-12-31', freq='M')
        risk_trend = np.random.normal(risk_assessment['overall_risk_score'], 0.5, len(dates))

        ax6.plot(dates, risk_trend, marker='o', linewidth=2, color='darkblue')
        ax6.set_ylabel('Overall Risk Score')
        ax6.set_title('Risk Trend Over Time')
        ax6.grid(True, alpha=0.3)
        ax6.tick_params(axis='x', rotation=45)

        plt.tight_layout()

        if output_file:
            plt.savefig(output_file, dpi=300, bbox_inches='tight')
        else:
            plt.show()

    def export_metrics_to_csv(self, filepath: str) -> None:
        """Export detailed metrics to CSV for further analysis"""

        risk_assessment = self.calculate_supply_chain_risk_score()

        # Prepare data for export
        export_data = []
        for comp_id, component in self.graph.components.items():
            risk_data = risk_assessment['component_risks'][comp_id]

            # Count vulnerabilities for this component
            vuln_count = len([1 for v_key in self.graph.vulnerabilities.keys()
                            if comp_id in v_key])

            export_data.append({
                'component_id': comp_id,
                'component_name': component.name,
                'version': component.version,
                'software_type': component.software_type.value,
                'vendor': component.vendor,
                'criticality_score': component.criticality_score,
                'is_compromised': component.is_compromised,
                'dependencies_count': len(self.graph.get_dependencies(comp_id)),
                'dependents_count': len(self.graph.get_dependents(comp_id)),
                'vulnerability_count': vuln_count,
                'base_risk': risk_data['base_risk'],
                'criticality_risk': risk_data['criticality_risk'],
                'dependency_risk': risk_data['dependency_risk'],
                'vulnerability_risk': risk_data['vulnerability_risk'],
                'compound_risk_score': risk_data['compound_risk'],
                'impact_score': self.graph.calculate_impact_score(comp_id)
            })

        df = pd.DataFrame(export_data)
        df.to_csv(filepath, index=False)
        print(f"Metrics exported to {filepath}")