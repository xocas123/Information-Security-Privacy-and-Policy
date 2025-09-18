"""
Main entry point for the Supply Chain Analyzer package.

This allows the package to be run as a module:
    python -m supply_chain_analyzer
"""

from .cli import main

if __name__ == '__main__':
    exit(main())