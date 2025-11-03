"""Console reporter for panoptipy using Rich for terminal output."""

from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Literal, Optional, Union

from rich import box
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

    def __init__(
        self,
        use_emoji: bool = True,
        show_details: bool = False,
        export_format: Optional[Literal["svg", "html"]] = None,
        output_path: Optional[Path] = None,
    ):
        """Initialize the console reporter.

        Args:
            use_emoji: Whether to use emoji instead of simple symbols
            show_details: Whether to show detailed information for failures
            export_format: Format to export console output to (svg or html)
            output_path: Path to save exported output (required if export_format is set)
        """
        self.export_format = export_format
        self.output_path = output_path

        # If exporting, enable recording on the console
        record = export_format is not None
        self.console = Console(
            force_terminal=True, color_system="auto", safe_box=True, record=record
        )

        self.use_emoji = use_emoji
        self.show_details = show_details

        # Check if Unicode is supported
        self.unicode_supported = self.console.encoding == "utf-8"

        # Add ASCII fallbacks if Unicode isn't supported (Windows!!!)
        if not self.unicode_supported:
            # Update symbols with ASCII alternatives
            self.STATUS_STYLES = {
                "pass": {
                    "symbol": "√",
                    "ascii_symbol": "+",
                    "color": "green",
                    "emoji": "white_heavy_check_mark",
                },
                "fail": {
                    "symbol": "✗",
                    "ascii_symbol": "X",
                    "color": "red",
                    "emoji": "x",
                },
                "warning": {
                    "symbol": "!",
                    "ascii_symbol": "!",
                    "color": "yellow",
                    "emoji": "warning",
                },
                "skip": {
                    "symbol": "-",
                    "ascii_symbol": "-",
                    "color": "blue",
                    "emoji": "information",
                },
                "error": {
                    "symbol": "?",
                    "ascii_symbol": "?",
                    "color": "magenta",
                    "emoji": "question_mark",
                },
            }

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
                if rating:
                    self._display_rating(rating)
                self._display_summary(repo_results)
                self._display_results_table(repo_results, repo_path)
                if self.show_details:
                    self._display_details(repo_results, repo_path)
        else:
            # Single repository
            if repo_path:
                self.console.print(f"\n[bold blue]Repository:[/bold blue] {repo_path}")
            if rating:
                self._display_rating(rating)
            self._display_summary(results)
            self._display_results_table(results, repo_path)
            if self.show_details:
                self._display_details(results, repo_path)

        # Export the console output if requested
        if self.export_format and self.output_path:
            self._export_console_output()

    def _export_console_output(self) -> None:
        """Export the console output to the specified format."""
        if not self.export_format or not self.output_path:
            return

        if self.export_format == "svg":
            self.console.save_svg(self.output_path, title="Panoptipy Report")
        elif self.export_format == "html":
            self.console.save_html(self.output_path)

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
        # Import here to avoid circular imports
        from ..config import Config
        from ..rating import RatingCalculator

        # Create calculator with default config if needed
        calculator = RatingCalculator(Config.load())
        stats = calculator.calculate_summary_stats(results)

        # Display summary
        self.console.print("\n[bold]Summary:[/bold]")
        self.console.print(f"Total checks: {stats['total_checks']}")

        for status, count in stats["status_counts"].items():
            style = self.STATUS_STYLES.get(status, {}).get("color", "white")
            self.console.print(
                f"{status.capitalize()}: [bold {style}]{count}[/bold {style}]"
            )

        color = (
            "green"
            if stats["pass_percentage"] >= 80
            else "yellow"
            if stats["pass_percentage"] >= 60
            else "red"
        )
        self.console.print(
            f"Pass rate: [bold {color}]{stats['pass_percentage']:.1f}%[/bold {color}]"
        )

    def _display_results_table(
        self, results: List["CheckResult"], repo_path: Path
    ) -> None:
        """Display a table of check results.

        Args:
            results: List of check results
            repo_path: Path to the repository
        """
        table = Table(
            title=f"\nCheck Results for {repo_path}",
            box=box.ROUNDED,  # Explicitly set box style
            show_header=True,
            header_style="bold magenta",
            # expand=True makes the table use the full available width
            # This can sometimes help distribute space more evenly
            expand=True,
        )

        # Add columns with more explicit width control
        table.add_column(
            "Status", justify="center", width=8
        )  # Keep fixed width for status symbol
        table.add_column(
            "Check ID", style="cyan", min_width=15, ratio=1
        )  # Give Check ID some space, let it expand
        table.add_column(
            "Message", ratio=3
        )  # Let Message take the most space proportionally

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

            # Create status indicator
            if self.use_emoji and "emoji" in style_info and self.unicode_supported:
                try:
                    status_indicator = Emoji(style_info["emoji"])
                except (KeyError, ValueError):
                    # Fall back to symbol if emoji fails
                    symbol = style_info.get(
                        "ascii_symbol" if not self.unicode_supported else "symbol", "?"
                    )
                    status_indicator = Text(
                        symbol,
                        style=style_info.get("color", "white"),
                    )
            else:
                symbol = style_info.get(
                    "ascii_symbol" if not self.unicode_supported else "symbol", "?"
                )
                status_indicator = Text(
                    symbol,
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
    show_details: bool = True,
    use_emoji: bool = True,
    export_format: Optional[Literal["svg", "html"]] = None,
    output_path: Optional[Path] = None,
) -> ConsoleReporter:
    """Create a console reporter with the specified options.

    Args:
        show_details: Whether to show detailed information for failures
        use_emoji: Whether to use emoji instead of simple symbols
        export_format: Format to export console output to (svg or html)
        output_path: Path to save exported output (required if export_format is set)

    Returns:
        Configured console reporter
    """
    return ConsoleReporter(
        use_emoji=use_emoji,
        show_details=show_details,
        export_format=export_format,
        output_path=output_path,
    )
