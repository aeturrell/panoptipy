import sys
from pathlib import Path

import click

from .checks import CheckStatus
from .config import Config
from .core import Scanner
from .registry import CheckRegistry
from .reporters import get_reporter


@click.group()
def cli():
    """PanoptiPy - Python code quality assessment tool."""
    pass


@cli.command()
@click.argument("path", type=click.Path(exists=True))
@click.option(
    "--config", "-c", type=click.Path(exists=True), help="Path to config file"
)
@click.option(
    "--format",
    "-f",
    type=str,
    default="console",
    help="Output format (console, html, json)",
)
def scan(path, config, format):
    """Scan a local codebase for code quality issues."""
    # Load configuration
    config_obj = Config.load(Path(config) if config else None)

    # Get critical checks from config
    critical_checks = config_obj.get("checks.critical", [])

    # Set up registry and load checks
    registry = CheckRegistry()
    registry.load_builtin_checks()
    registry.load_plugins()

    # Run scan
    scanner = Scanner(registry, config_obj)
    results = scanner.scan(Path(path))

    # Generate report
    reporter = get_reporter(format)
    reporter.report(results, scanner.rate(results))

    # Return appropriate exit code
    critical_failures = any(
        r.status == CheckStatus.FAIL and r.check_id in critical_checks for r in results
    )
    sys.exit(1 if critical_failures else 0)
