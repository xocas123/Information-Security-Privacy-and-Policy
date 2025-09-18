# Supply Chain Risk Analyzer

A professional tool for analyzing software dependency graphs and assessing supply chain security risks.

## 🚀 Features

- **Automated GitHub Repository Analysis** - Analyze any GitHub repository's dependencies
- **Configurable Depth Analysis** - Control how deep the dependency analysis goes
- **Professional Output Management** - Organized folder structure with timestamped files
- **Risk Assessment & Metrics** - Comprehensive security risk evaluation
- **Multiple Export Formats** - JSON, CSV, and visualization outputs
- **Command Line Interface** - Professional CLI for automated workflows
- **Extensible Architecture** - Easy to add new analyzers and output formats

## 📦 Installation

```bash
pip install -e .
```

## ⚡ Quick Start

### Command Line Usage

```bash
# Analyze a GitHub repository
python -m supply_chain_analyzer analyze-github https://github.com/requests/requests

# Analyze with custom settings
python -m supply_chain_analyzer analyze-github https://github.com/django/django --max-depth 3 --max-components 50

# List all analyzed projects
python -m supply_chain_analyzer list-projects

# Show output directory status
python -m supply_chain_analyzer status
```

### Python API Usage

```python
from supply_chain_analyzer import GitHubDependencyAnalyzer

# Analyze a repository
analyzer = GitHubDependencyAnalyzer("https://github.com/requests/requests")
graph, risk_analyzer, results = analyzer.analyze_repository(max_depth=2)

# Results are automatically saved to organized folders
print(f"Risk score: {results['risk_assessment']['overall_risk_score']:.1f}/10")
```

### 🎛️ Easy Configuration

The analysis depth is easily configurable:

```python
# Quick analysis - direct dependencies only
MAX_DEPTH = 1

# Standard analysis - 2 levels deep
MAX_DEPTH = 2

# Deep analysis - 3+ levels
MAX_DEPTH = 3

# No limit
MAX_DEPTH = None
```

## 📁 Project Structure

```
supply_chain_analyzer/
├── core/                   # Core dependency graph functionality
│   ├── dependency_graph.py # Main graph implementation
│   └── output_manager.py   # Organized output management
├── analyzers/              # Analysis modules
│   ├── risk_analyzer.py    # Risk assessment and metrics
│   └── github_analyzer.py  # GitHub repository analysis
├── config/                 # Configuration management
│   └── settings.py         # Settings and configuration
├── examples/               # Usage examples
│   └── basic_usage.py      # Basic usage demonstrations
├── outputs/                # Organized output directory
│   ├── graphs/             # Dependency graph JSON files
│   ├── reports/            # Analysis reports
│   ├── metrics/            # Risk metrics CSV files
│   └── visualizations/     # Generated charts and graphs
└── cli.py                  # Command line interface
```

## 📊 Output Organization

All analysis results are automatically organized in a clean folder structure:

- **`outputs/graphs/`** - Dependency network data (JSON)
- **`outputs/reports/`** - Comprehensive analysis reports (JSON)
- **`outputs/metrics/`** - Risk assessment metrics (CSV)
- **`outputs/visualizations/`** - Generated charts and graphs (PNG)

Files are automatically timestamped and organized by project name.

## 🔧 Examples

### Test the Professional CLI

```bash
cd supply_chain_analyzer/examples
python basic_usage.py
```

### Analyze Multiple Projects

```python
repos = [
    "https://github.com/requests/requests",
    "https://github.com/django/django",
    "https://github.com/fastapi/fastapi"
]

for repo_url in repos:
    analyzer = GitHubDependencyAnalyzer(repo_url)
    graph, risk_analyzer, results = analyzer.analyze_repository()
    print(f"{repo_url}: Risk score {results['risk_assessment']['overall_risk_score']:.1f}")
```

## 🎯 Key Improvements Made

### ✅ **Professional Code Organization**
- Proper Python package structure with `__init__.py` files
- Separated core functionality, analyzers, and configuration
- Clean import statements and module organization

### ✅ **Organized Output Management**
- Automatic folder structure creation (`outputs/graphs/`, `outputs/reports/`, etc.)
- Timestamped filenames with project-based organization
- Professional output manager class handling all file operations

### ✅ **Easy Configuration Control**
- Simple `MAX_DEPTH` variable to control analysis scope
- Centralized configuration management
- Command-line parameter support

### ✅ **Professional CLI Interface**
- Complete command-line tool with subcommands
- Help documentation and usage examples
- Project management and cleanup tools

### ✅ **Clean Code Structure**
- Removed redundant files and consolidated functionality
- Updated all import statements for proper package structure
- Professional naming conventions and documentation

## 📈 Usage Summary

**Before (Messy):**
- Files scattered in root directory
- Hard-coded paths and parameters
- Manual output management
- Inconsistent naming

**After (Professional):**
```
✓ Organized package structure
✓ Automatic output folder management
✓ Easy depth configuration (change one variable!)
✓ Professional CLI interface
✓ Consistent, timestamped outputs
✓ Comprehensive documentation
```

The code is now production-ready with a professional structure that makes it easy to:
- Change analysis parameters (`MAX_DEPTH = 3`)
- Find organized outputs in clean folder structure
- Use via command line or Python API
- Extend with new analyzers and features