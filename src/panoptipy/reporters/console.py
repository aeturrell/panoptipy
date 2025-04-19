"""Console reporter for panoptipy using Rich for terminal output."""

from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Union

from rich.console import Console
from rich.emoji import Emoji
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.text import Text

if TYPE_CHECKING:
    from ..checks import CheckResult
    from ..rating import CodebaseRating

from .base_reporter import BaseReporter


class ConsoleReporter(BaseReporter):
    """Reporter that formats check results for the console using Rich."""

    # Status symbols and colors for different check statuses
    STATUS_STYLES: Dict[str, Dict[str, Any]] = {
        "pass": {"symbol": "✓", "color": "green", "emoji": "white_heavy_check_mark"},
        "fail": {"symbol": "✗", "color": "red", "emoji": "x"},
        "warning": {"symbol": "!", "color": "yellow", "emoji": "warning"},
        "skip": {"symbol": "-", "color": "blue", "emoji": "information"},
        "error": {"symbol": "?", "color": "magenta", "emoji": "question_mark"},
    }

    # Colors for codebase ratings
    RATING_STYLES: Dict[str, str] = {
        "gold": "yellow",
        "silver": "bright_white",
        "bronze": "orange3",
        "problematic": "red",
    }

    def __init__(self, use_emoji: bool = True, show_details: bool = False):
        """Initialize the console reporter.

        Args:
            use_emoji: Whether to use emoji instead of simple symbols
            show_details: Whether to show detailed information for failures
        """
        self.console = Console()
        self.use_emoji = use_emoji
        self.show_details = show_details

    def report(
        self,
        results: Union[List["CheckResult"], Dict[Path, List["CheckResult"]]],
        rating: Optional["CodebaseRating"] = None,
        repo_path: Optional[Path] = None,
    ) -> None:
        """Generate a console report for check results.

        Args:
            results: Either a list of check results or a dictionary mapping paths to results
            rating: Overall rating for the codebase
            repo_path: Path to the repository being reported
        """
        # Handle both list and dictionary inputs
        if isinstance(results, dict):
            # Multiple repositories
            for repo_path, repo_results in results.items():
                self.console.print(f"\n[bold blue]Repository:[/bold blue] {repo_path}")
                self._display_rating(rating)
                self._display_summary(repo_results)
                self._display_results_table(repo_results, repo_path)
                if self.show_details:
                    self._display_details(repo_results, repo_path)
        else:
            # Single repository
            if repo_path:
                self.console.print(f"\n[bold blue]Repository:[/bold blue] {repo_path}")
            self._display_rating(rating)
            self._display_summary(results)
            self._display_results_table(results, repo_path)
            if self.show_details:
                self._display_details(results, repo_path)

    def report_with_progress(self, checks: List[str]) -> None:
        """Display a progress indicator while checks are running.

        Args:
            checks: List of check IDs being run
        """
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console,
        ) as progress:
            task = progress.add_task("[cyan]Running checks...", total=len(checks))

            # This function would be called as each check completes
            # In a real implementation, this would be integrated with the scanner
            for check in checks:
                progress.update(task, advance=1, description=f"Running check: {check}")

    def _display_rating(self, rating: "CodebaseRating") -> None:
        """Display the overall codebase rating.

        Args:
            rating: Overall rating for the codebase
        """
        rating_value = rating.value
        color = self.RATING_STYLES.get(rating_value, "white")

        self.console.print("\n")
        self.console.print(
            Panel(
                Text(f"Codebase Rating: {rating_value.upper()}", style=f"bold {color}"),
                title="Panoptipy Report",
                border_style=color,
            )
        )

    def _display_summary(self, results: List["CheckResult"]) -> None:
        """Display summary statistics of check results.

        Args:
            results: List of check results
        """
        # Count results by status
        status_counts = {}
        for result in results:
            status = result.status.value
            status_counts[status] = status_counts.get(status, 0) + 1

        total = len(results)
        pass_count = status_counts.get("pass", 0)
        pass_percentage = (pass_count / total) * 100 if total > 0 else 0

        # Display summary
        self.console.print("\n[bold]Summary:[/bold]")
        self.console.print(f"Total checks: {total}")

        for status, count in status_counts.items():
            style = self.STATUS_STYLES.get(status, {}).get("color", "white")
            self.console.print(
                f"{status.capitalize()}: [bold {style}]{count}[/bold {style}]"
            )

        color = (
            "green"
            if pass_percentage >= 80
            else "yellow"
            if pass_percentage >= 60
            else "red"
        )
        self.console.print(
            f"Pass rate: [bold {color}]{pass_percentage:.1f}%[/bold {color}]"
        )

    def _display_results_table(
        self, results: List["CheckResult"], repo_path: Path
    ) -> None:
        """Display a table of check results.

        Args:
            results: List of check results
            repo_path: Path to the repository
        """
        table = Table(title=f"\nCheck Results for {repo_path}")

        # Add columns
        table.add_column("Status", justify="center", width=8)
        table.add_column("Check ID", style="cyan")
        table.add_column("Message")

        # Sort results: failures first, then warnings, then passes
        sorted_results = sorted(
            results,
            key=lambda r: (
                0
                if r.status.value == "fail"
                else 1
                if r.status.value == "warning"
                else 2
                if r.status.value == "error"
                else 3
                if r.status.value == "skip"
                else 4
            ),
        )

        # Add rows
        for result in sorted_results:
            status = result.status.value
            style_info = self.STATUS_STYLES.get(status, {})

            # Create status indicator with proper styling
            if self.use_emoji and "emoji" in style_info:
                try:
                    status_indicator = Emoji(style_info["emoji"])
                except (KeyError, ValueError):
                    # Fall back to symbol if emoji fails
                    status_indicator = Text(
                        style_info.get("symbol", "?"),
                        style=style_info.get("color", "white"),
                    )
            else:
                status_indicator = Text(
                    style_info.get("symbol", "?"),
                    style=style_info.get("color", "white"),
                )

            table.add_row(status_indicator, result.check_id, result.message)

        self.console.print(table)

    def _display_details(self, results: List["CheckResult"], repo_path: Path) -> None:
        """Display detailed information for failed and warning checks.

        Args:
            results: List of check results
            repo_path: Path to the repository
        """
        # Filter for results with details
        detailed_results = [
            r
            for r in results
            if r.details and (r.status.value == "fail" or r.status.value == "warning")
        ]

        if not detailed_results:
            return

        self.console.print("\n[bold]Details:[/bold]")

        for result in detailed_results:
            status = result.status.value
            color = self.STATUS_STYLES.get(status, {}).get("color", "white")

            self.console.print(
                Panel(
                    self._format_details(result.details),
                    title=f"[{color}]{result.check_id}[/{color}]",
                    border_style=color,
                )
            )

    def _format_details(self, details: Dict[str, Any]) -> str:
        """Format details dictionary for display.

        Args:
            details: Dictionary of detailed information

        Returns:
            Formatted string representation of details
        """
        if not details:
            return ""

        lines = []
        for key, value in details.items():
            if isinstance(value, list):
                lines.append(f"[bold]{key}:[/bold]")
                # Limit list items to prevent overwhelming output
                max_items = 10
                for i, item in enumerate(value[:max_items]):
                    lines.append(f"  • {item}")
                if len(value) > max_items:
                    lines.append(f"  ... and {len(value) - max_items} more")
            elif isinstance(value, dict):
                lines.append(f"[bold]{key}:[/bold]")
                for k, v in value.items():
                    lines.append(f"  • {k}: {v}")
            else:
                lines.append(f"[bold]{key}:[/bold] {value}")

        return "\n".join(lines)


def create_reporter(
    show_details: bool = True, use_emoji: bool = True
) -> ConsoleReporter:
    """Create a console reporter with the specified options.

    Args:
        show_details: Whether to show detailed information for failures
        use_emoji: Whether to use emoji instead of simple symbols

    Returns:
        Configured console reporter
    """
    return ConsoleReporter(use_emoji=use_emoji, show_details=show_details)
