import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Callable, Dict, List, Optional

import click

from .checks import CheckStatus
from .config import Config
from .core import Scanner
from .github import GitHubClient, GitHubScanner
from .registry import CheckRegistry
from .reporters import get_reporter

reporters_accepting_output_paths: List[str] = ["json", "parquet", "svg", "html"]


@click.group()
def cli() -> None:
    """PanoptiPy - Python code quality assessment tool."""
    pass


def common_output_options(func):
    options = [
        click.option(
            "--config", "-c", type=click.Path(exists=True), help="Path to config file"
        ),
        click.option(
            "--format",
            "-f",
            type=str,
            default="console",
            help="Output format (console, json, parquet, svg, html)",
        ),
        click.option(
            "--output",
            type=click.Path(path_type=Path),
            help="Output file path (required for parquet, svg, and html formats; optional for json)",
        ),
    ]
    for option in reversed(options):
        func = option(func)
    return func


def github_scan_options(func: Callable) -> Callable:
    options = [
        click.option(
            "--token",
            type=str,
            envvar="GITHUB_TOKEN",
            help="GitHub personal access token (can also be set via GITHUB_TOKEN env var)",
        ),
        click.option(
            "--exclude-forks/--include-forks",
            default=True,
            help="Exclude forked repositories",
        ),
        click.option(
            "--max-repos",
            type=int,
            default=None,
            help="Maximum number of repositories to scan",
        ),
    ]
    for option in reversed(options):
        func = option(func)
    return func


def run_scan(
    scan_sources: Callable[[Scanner], Dict[Path, list]],
    config_path: Optional[str],
    format: str,
    output: Optional[Path],
    critical_check_ids: List[str],
) -> None:
    config_obj = Config.load(Path(config_path) if config_path else None)
    registry = CheckRegistry(config=config_obj)
    registry.load_builtin_checks()
    registry.load_plugins()
    scanner = Scanner(registry, config_obj)
    combined_results = scan_sources(scanner)

    reporter = get_reporter(
        format=format,
        output_path=output if format in reporters_accepting_output_paths else None,
        config=config_obj,
    )

    has_critical_failures = False
    for path, results in combined_results.items():
        rating = scanner.rate(results)
        reporter.report(results, rating, repo_path=path)
        if any(
            r.status == CheckStatus.FAIL and r.check_id in critical_check_ids
            for r in results
        ):
            has_critical_failures = True
    sys.exit(1 if has_critical_failures else 0)


@cli.command()
@click.argument("paths", type=click.Path(exists=True), nargs=-1, required=True)
@common_output_options
def scan(
    paths: Sequence[str],
    config: Optional[str],
    format: str,
    output: Optional[Path],
) -> None:
    """Scan one or more local codebases for code quality issues."""

    def scan_sources(scanner):
        return scanner.scan_multiple([Path(p) for p in paths])

    config_obj = Config.load(Path(config) if config else None)
    critical_checks = config_obj.get("checks.critical", [])
    run_scan(scan_sources, config, format, output, critical_checks)


@cli.command()
@click.argument("username", type=str, required=True)
@common_output_options
@github_scan_options
@click.option(
    "--include-private/--public-only",
    default=False,
    help="Include private repositories (requires token with private repo access)",
)
def scan_user(
    username: str,
    config: Optional[str],
    format: str,
    output: Optional[Path],
    include_private: bool,
    exclude_forks: bool,
    max_repos: Optional[int],
    token: Optional[str],
) -> None:
    """Scan public repositories of a GitHub user."""
    if not token:
        click.echo("Error: GitHub token is required.", err=True)
        sys.exit(1)

    config_obj = Config.load(Path(config) if config else None)
    critical_checks = config_obj.get("checks.critical", [])

    registry = CheckRegistry(config=config_obj)
    registry.load_builtin_checks()
    registry.load_plugins()
    scanner = Scanner(registry, config_obj)

    github_client = GitHubClient(token)
    github_scanner = GitHubScanner(github_client)

    def scan_repo(path):
        return scanner.scan(path)  # Use the scanner with loaded checks

    def scan_sources(_):  # Ignore the parameter since we're using a closure
        return github_scanner.scan_user_repositories(
            username,
            scan_repo,
            include_private="PRIVATE" if include_private else "PUBLIC",
            exclude_forks=exclude_forks,
            max_repos=max_repos,
        )

    run_scan(scan_sources, config, format, output, critical_checks)


@cli.command()
@click.argument("org", type=str, required=True)
@click.argument("team", type=str, required=True)
@common_output_options
@github_scan_options
def scan_team(
    org: str,
    team: str,
    config: Optional[str],
    format: str,
    output: Optional[Path],
    exclude_forks: bool,
    max_repos: Optional[int],
    token: Optional[str],
) -> None:
    """Scan repositories accessible to a team within a GitHub organization."""
    if not token:
        click.echo("Error: GitHub token is required.", err=True)
        sys.exit(1)

    config_obj = Config.load(Path(config) if config else None)
    critical_checks = config_obj.get("checks.critical", [])

    registry = CheckRegistry(config=config_obj)
    registry.load_builtin_checks()
    registry.load_plugins()
    scanner = Scanner(registry, config_obj)

    github_client = GitHubClient(token)
    github_scanner = GitHubScanner(github_client)

    def scan_repo(path):
        return scanner.scan(path)  # Use the scanner with loaded checks

    def scan_sources(_):  # Ignore the parameter since we're using a closure
        return github_scanner.scan_team_repositories(
            org,
            team,
            scan_repo,
            exclude_forks=exclude_forks,
            max_repos=max_repos,
        )

    run_scan(scan_sources, config, format, output, critical_checks)


if __name__ == "__main__":
    cli()
