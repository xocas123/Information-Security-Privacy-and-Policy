"""
Test the GitHub analyzer with multiple different repositories
to demonstrate how well it generalizes across different projects.
"""

from github_analyzer import analyze_github_repo

# Configure analysis depth - easy to change!
MAX_DEPTH = 2
MAX_COMPONENTS = 20

def test_multiple_repositories():
    """Test analysis on various types of repositories"""

    # Test repositories of different types and complexity
    test_repos = [
        {
            'url': 'https://github.com/requests/requests',
            'description': 'Popular Python HTTP library',
            'expected_type': 'python'
        },
        {
            'url': 'https://github.com/django/django',
            'description': 'Django web framework',
            'expected_type': 'python'
        },
        {
            'url': 'https://github.com/psf/black',
            'description': 'Python code formatter',
            'expected_type': 'python'
        },
        {
            'url': 'https://github.com/fastapi/fastapi',
            'description': 'Modern Python web framework',
            'expected_type': 'python'
        },
        {
            'url': 'https://github.com/express/express',
            'description': 'Node.js web framework',
            'expected_type': 'nodejs'
        }
    ]

    print(f"Multi-Repository Dependency Analysis")
    print(f"Configuration: MAX_DEPTH={MAX_DEPTH}, MAX_COMPONENTS={MAX_COMPONENTS}")
    print("=" * 70)

    results = []

    for i, repo_info in enumerate(test_repos, 1):
        print(f"\n[{i}/{len(test_repos)}] ANALYZING: {repo_info['description']}")
        print(f"URL: {repo_info['url']}")
        print(f"Expected type: {repo_info['expected_type']}")
        print("-" * 50)

        try:
            graph, analyzer, analysis = analyze_github_repo(
                repo_info['url'],
                max_components=MAX_COMPONENTS,
                max_depth=MAX_DEPTH
            )

            if graph and analysis:
                repo_name = repo_info['url'].split('/')[-1]
                stats = analysis.get('stats', {})
                risk = analysis.get('risk_assessment', {})

                result = {
                    'name': repo_name,
                    'url': repo_info['url'],
                    'description': repo_info['description'],
                    'success': True,
                    'components': stats.get('total_components', 0),
                    'libraries': stats.get('libraries', 0),
                    'dependencies': stats.get('total_dependencies', 0),
                    'risk_score': risk.get('overall_risk_score', 0),
                    'high_risk_components': risk.get('high_risk_components', 0)
                }

                print(f"SUCCESS - Found {result['components']} components, {result['libraries']} libraries")
                print(f"  Risk score: {result['risk_score']:.1f}/10")

            else:
                result = {
                    'name': repo_info['url'].split('/')[-1],
                    'url': repo_info['url'],
                    'description': repo_info['description'],
                    'success': False,
                    'error': 'Analysis failed'
                }
                print(f"FAILED - Could not analyze repository")

        except Exception as e:
            result = {
                'name': repo_info['url'].split('/')[-1],
                'url': repo_info['url'],
                'description': repo_info['description'],
                'success': False,
                'error': str(e)
            }
            print(f"ERROR - {str(e)}")

        results.append(result)

    # Summary comparison
    print(f"\n{'='*70}")
    print("SUMMARY COMPARISON")
    print("=" * 70)

    successful_analyses = [r for r in results if r['success']]
    failed_analyses = [r for r in results if not r['success']]

    print(f"Overall Results:")
    print(f"  Successful analyses: {len(successful_analyses)}/{len(results)}")
    print(f"  Failed analyses: {len(failed_analyses)}")

    if successful_analyses:
        print(f"\nSuccessful Repository Analysis:")
        print(f"{'Repository':<15} {'Components':<12} {'Libraries':<10} {'Risk Score':<10}")
        print("-" * 50)

        for result in successful_analyses:
            print(f"{result['name']:<15} {result['components']:<12} {result['libraries']:<10} {result['risk_score']:<10.1f}")

        # Find most/least risky
        highest_risk = max(successful_analyses, key=lambda x: x['risk_score'])
        lowest_risk = min(successful_analyses, key=lambda x: x['risk_score'])
        most_complex = max(successful_analyses, key=lambda x: x['components'])

        print(f"\nKey Insights:")
        print(f"  Highest risk: {highest_risk['name']} (risk: {highest_risk['risk_score']:.1f})")
        print(f"  Lowest risk: {lowest_risk['name']} (risk: {lowest_risk['risk_score']:.1f})")
        print(f"  Most complex: {most_complex['name']} ({most_complex['components']} components)")

    if failed_analyses:
        print(f"\nFailed Analyses:")
        for result in failed_analyses:
            print(f"  {result['name']}: {result['error']}")

    # Show how easy it is to change configuration
    print(f"\n{'='*70}")
    print("CONFIGURATION")
    print("=" * 70)
    print(f"Current settings:")
    print(f"  MAX_DEPTH = {MAX_DEPTH}")
    print(f"  MAX_COMPONENTS = {MAX_COMPONENTS}")
    print(f"")
    print(f"To change analysis scope:")
    print(f"  1. Edit this file")
    print(f"  2. Modify MAX_DEPTH and MAX_COMPONENTS variables at the top")
    print(f"  3. Run the script again")
    print(f"")
    print(f"Suggested configurations:")
    print(f"  Quick analysis: MAX_DEPTH=1, MAX_COMPONENTS=10")
    print(f"  Standard analysis: MAX_DEPTH=2, MAX_COMPONENTS=20")
    print(f"  Deep analysis: MAX_DEPTH=3, MAX_COMPONENTS=50")

    return results


if __name__ == "__main__":
    results = test_multiple_repositories()

    print(f"\n{'='*70}")
    print("GENERALIZATION ASSESSMENT")
    print("=" * 70)

    successful = len([r for r in results if r['success']])
    total = len(results)

    print(f"GitHub Analyzer Generalization Results:")
    print(f"  Success rate: {successful}/{total} ({successful/total*100:.1f}%)")

    if successful >= total * 0.8:
        print(f"  Assessment: EXCELLENT - Works well across different repository types")
    elif successful >= total * 0.6:
        print(f"  Assessment: GOOD - Works for most repositories with minor issues")
    elif successful >= total * 0.4:
        print(f"  Assessment: MODERATE - Works for some repositories, needs improvement")
    else:
        print(f"  Assessment: POOR - Significant issues with generalization")

    print(f"\nThe dependency graph module can analyze any GitHub repository")
    print(f"that contains standard dependency files (requirements.txt, setup.py, package.json, etc.)")
    print(f"Simply change the repository URL and adjust MAX_DEPTH as needed!")