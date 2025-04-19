import sys
from pathlib import Path

import click

from .checks import CheckStatus
from .config import Config
from .core import Scanner
from .github import GitHubClient, GitHubScanner
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
@click.option(
    "--output",
    type=click.Path(path_type=Path),
    help="Output file path (required for parquet format)",
)
def scan(paths, config, format, aggregate, output):
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

    # Create reporter
    reporter = get_reporter(
        format=format,
        output_path=output if format == "parquet" else None,
    )

    if aggregate:
        # Create a single report for all repositories
        all_results = [
            result
            for repo_results in combined_results.values()
            for result in repo_results
        ]
        overall_rating = scanner.rate(all_results)
        # Pass dictionary for multiple repos
        reporter.report(combined_results, overall_rating)
    else:
        # Report each repository separately
        has_critical_failures = False
        for path, results in combined_results.items():
            rating = scanner.rate(results)

            # Pass list for single repo
            reporter.report(results, rating, repo_path=path)

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


@cli.command()
@click.argument("username", type=str, required=True)
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
@click.option(
    "--output",
    type=click.Path(path_type=Path),
    help="Output file path (required for parquet format)",
)
@click.option(
    "--include-private/--public-only",
    default=False,
    help="Include private repositories (requires token with private repo access)",
)
@click.option(
    "--exclude-forks/--include-forks",
    default=True,
    help="Exclude forked repositories",
)
@click.option(
    "--max-repos",
    type=int,
    default=None,
    help="Maximum number of repositories to scan",
)
@click.option(
    "--token",
    type=str,
    envvar="GITHUB_TOKEN",
    help="GitHub personal access token (can also be set via GITHUB_TOKEN env var)",
)
def scan_user(
    username,
    config,
    format,
    aggregate,
    output,
    include_private,
    exclude_forks,
    max_repos,
    token,
):
    """Scan public repositories of a GitHub user.

    USERNAME: GitHub username
    """
    if not token:
        click.echo(
            "Error: GitHub token is required. Provide --token or set GITHUB_TOKEN environment variable.",
            err=True,
        )
        sys.exit(1)

    # Load configuration
    config_obj = Config.load(Path(config) if config else None)

    # Get critical checks from config
    critical_checks = config_obj.get("checks.critical", [])

    # Set up registry and load checks
    registry = CheckRegistry(config=config_obj)
    registry.load_builtin_checks()
    registry.load_plugins()

    # Create scanner
    local_scanner = Scanner(registry, config_obj)

    # Create GitHub client and scanner
    github_client = GitHubClient(token)
    github_scanner = GitHubScanner(github_client)

    click.echo(f"Scanning repositories for GitHub user: {username}")

    # Define scanner function to pass to GitHub scanner
    def scan_repo(path):
        return local_scanner.scan(path)

    # Scan repositories
    inc_priv = "PRIVATE" if include_private else "PUBLIC"
    combined_results = github_scanner.scan_user_repositories(
        username,
        scan_repo,
        include_private=inc_priv,
        exclude_forks=exclude_forks,
        max_repos=max_repos,
    )

    # Create reporter
    reporter = get_reporter(
        format=format,
        output_path=output if format == "parquet" else None,
    )

    if aggregate:
        # Create a single report for all repositories
        all_results = [
            result
            for repo_results in combined_results.values()
            for result in repo_results
        ]
        overall_rating = local_scanner.rate(all_results)
        # Pass dictionary for multiple repos
        reporter.report(combined_results, overall_rating)
    else:
        # Report each repository separately
        has_critical_failures = False
        for path, results in combined_results.items():
            rating = local_scanner.rate(results)

            # Pass list for single repo
            reporter.report(results, rating, repo_path=path)

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


@cli.command()
@click.argument("org", type=str, required=True)
@click.argument("team", type=str, required=True)
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
@click.option(
    "--output",
    type=click.Path(path_type=Path),
    help="Output file path (required for parquet format)",
)
@click.option(
    "--exclude-forks/--include-forks",
    default=True,
    help="Exclude forked repositories",
)
@click.option(
    "--max-repos",
    type=int,
    default=None,
    help="Maximum number of repositories to scan",
)
@click.option(
    "--token",
    type=str,
    envvar="GITHUB_TOKEN",
    help="GitHub personal access token (can also be set via GITHUB_TOKEN env var)",
)
def scan_team(
    org, team, config, format, aggregate, output, exclude_forks, max_repos, token
):
    """Scan repositories accessible to a team within a GitHub organization.

    ORG: GitHub organization name
    TEAM: Team slug (name in URL format)
    """
    if not token:
        click.echo(
            "Error: GitHub token is required. Provide --token or set GITHUB_TOKEN environment variable.",
            err=True,
        )
        sys.exit(1)

    # Load configuration
    config_obj = Config.load(Path(config) if config else None)

    # Get critical checks from config
    critical_checks = config_obj.get("checks.critical", [])

    # Set up registry and load checks
    registry = CheckRegistry(config=config_obj)
    registry.load_builtin_checks()
    registry.load_plugins()

    # Create scanner
    local_scanner = Scanner(registry, config_obj)

    # Create GitHub client and scanner
    github_client = GitHubClient(token)
    github_scanner = GitHubScanner(github_client)

    click.echo(f"Scanning repositories for team {team} in organization {org}")

    # Define scanner function to pass to GitHub scanner
    def scan_repo(path):
        return local_scanner.scan(path)

    # Scan repositories
    combined_results = github_scanner.scan_team_repositories(
        org, team, scan_repo, exclude_forks=exclude_forks, max_repos=max_repos
    )

    # Create reporter
    reporter = get_reporter(
        format=format,
        output_path=output if format == "parquet" else None,
    )

    if aggregate:
        # Create a single report for all repositories
        all_results = [
            result
            for repo_results in combined_results.values()
            for result in repo_results
        ]
        overall_rating = local_scanner.rate(all_results)
        # Pass dictionary for multiple repos
        reporter.report(combined_results, overall_rating)
    else:
        # Report each repository separately
        has_critical_failures = False
        for path, results in combined_results.items():
            rating = local_scanner.rate(results)

            # Pass list for single repo
            reporter.report(results, rating, repo_path=path)

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


if __name__ == "__main__":
    cli()
