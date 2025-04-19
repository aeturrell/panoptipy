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
@click.argument("paths", type=click.Path(exists=True), nargs=-1, required=True)
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
@click.option(
    "--aggregate/--no-aggregate",
    default=False,
    help="Aggregate results across all repositories",
)
def scan(paths, config, format, aggregate):
    """Scan one or more local codebases for code quality issues.

    PATHS: One or more paths to codebases (directories) to scan.
    """
    # Load configuration
    config_obj = Config.load(Path(config) if config else None)

    # Get critical checks from config
    critical_checks = config_obj.get("checks.critical", [])

    # Set up registry and load checks
    registry = CheckRegistry(config=config_obj)
    registry.load_builtin_checks()
    registry.load_plugins()

    # Create scanner
    scanner = Scanner(registry, config_obj)

    # Scan repositories
    combined_results = scanner.scan_multiple([Path(path) for path in paths])

    # Create aggregated report if requested, otherwise individual reports
    reporter = get_reporter(format, config=config_obj)

    if aggregate:
        # Flatten all results and calculate overall rating
        all_results = [
            result
            for repo_results in combined_results.values()
            for result in repo_results
        ]
        overall_rating = scanner.rate(all_results)
        reporter.report_multiple(combined_results, overall_rating)
    else:
        # Report each repository separately
        has_critical_failures = False
        for path, results in combined_results.items():
            rating = scanner.rate(results)
            print(
                f"\n-------------------------------\n     Results for {path}     \n-------------------------------"
            )
            reporter.report(results, rating)

            # Check for critical failures in this repo
            repo_critical_failures = any(
                r.status == CheckStatus.FAIL and r.check_id in critical_checks
                for r in results
            )
            has_critical_failures = has_critical_failures or repo_critical_failures

    # Return appropriate exit code
    if aggregate:
        # Check for any critical failures across all repos
        critical_failures = any(
            r.status == CheckStatus.FAIL and r.check_id in critical_checks
            for repo_results in combined_results.values()
            for r in repo_results
        )
        sys.exit(1 if critical_failures else 0)
    else:
        sys.exit(1 if has_critical_failures else 0)
