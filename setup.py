"""
Setup script for Supply Chain Risk Analyzer.
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="supply-chain-analyzer",
    version="1.0.0",
    author="Claude Code Assistant",
    author_email="claude@anthropic.com",
    description="Professional tool for analyzing software dependency graphs and supply chain risks",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/example/supply-chain-analyzer",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=[
        "networkx>=2.8",
        "matplotlib>=3.5",
        "pandas>=1.5",
        "numpy>=1.20",
        "requests>=2.25",
        "seaborn>=0.11",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0",
            "pytest-cov>=4.0",
            "black>=22.0",
            "flake8>=5.0",
            "mypy>=0.991",
        ],
        "viz": [
            "plotly>=5.0",
            "graphviz>=0.20",
        ],
    },
    entry_points={
        "console_scripts": [
            "supply-chain-analyzer=supply_chain_analyzer.cli:main",
        ],
    },
    include_package_data=True,
    package_data={
        "supply_chain_analyzer": [
            "config/*.json",
            "examples/*.py",
        ],
    },
)