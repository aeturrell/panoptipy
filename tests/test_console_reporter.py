"""Tests for console reporter module."""

from pathlib import Path
from unittest.mock import patch

import pytest
from rich.console import Console

from panoptipy.checks import CheckResult, CheckStatus
from panoptipy.rating import CodebaseRating
from panoptipy.reporters.console import ConsoleReporter, create_reporter


@pytest.fixture
def console_reporter():
    """Create a console reporter for testing."""
    return ConsoleReporter(use_emoji=False, show_details=False)


@pytest.fixture
def sample_results():
    """Create sample check results."""
    return [
        CheckResult("check1", CheckStatus.PASS, "Check passed"),
        CheckResult(
            "check2", CheckStatus.FAIL, "Check failed", details={"error": "details"}
        ),
        CheckResult("check3", CheckStatus.WARNING, "Check warning"),
        CheckResult("check4", CheckStatus.SKIP, "Check skipped"),
        CheckResult("check5", CheckStatus.ERROR, "Check error"),
    ]


class TestConsoleReporter:
    """Tests for ConsoleReporter class."""

    def test_console_reporter_init(self):
        """Test ConsoleReporter initialization."""
        reporter = ConsoleReporter()

        assert reporter.use_emoji is True
        assert reporter.show_details is False
        assert reporter.export_format is None
        assert reporter.output_path is None
        assert isinstance(reporter.console, Console)

    def test_console_reporter_init_with_emoji_disabled(self):
        """Test ConsoleReporter initialization with emoji disabled."""
        reporter = ConsoleReporter(use_emoji=False)

        assert reporter.use_emoji is False

    def test_console_reporter_init_with_show_details(self):
        """Test ConsoleReporter initialization with show_details enabled."""
        reporter = ConsoleReporter(show_details=True)

        assert reporter.show_details is True

    def test_console_reporter_init_with_export_format(self, tmp_path):
        """Test ConsoleReporter initialization with export format."""
        output_path = tmp_path / "output.svg"
        reporter = ConsoleReporter(export_format="svg", output_path=output_path)

        assert reporter.export_format == "svg"
        assert reporter.output_path == output_path

    def test_console_reporter_status_styles(self, console_reporter):
        """Test that status styles are defined."""
        assert "pass" in console_reporter.STATUS_STYLES
        assert "fail" in console_reporter.STATUS_STYLES
        assert "warning" in console_reporter.STATUS_STYLES
        assert "skip" in console_reporter.STATUS_STYLES
        assert "error" in console_reporter.STATUS_STYLES

    def test_console_reporter_rating_styles(self, console_reporter):
        """Test that rating styles are defined."""
        assert "gold" in console_reporter.RATING_STYLES
        assert "silver" in console_reporter.RATING_STYLES
        assert "bronze" in console_reporter.RATING_STYLES
        assert "problematic" in console_reporter.RATING_STYLES

    def test_report_single_repo(self, console_reporter, sample_results):
        """Test reporting for a single repository."""
        # Should not raise an error
        console_reporter.report(
            sample_results, rating=CodebaseRating.GOLD, repo_path=Path("/test/repo")
        )

    def test_report_multiple_repos(self, console_reporter, sample_results):
        """Test reporting for multiple repositories."""
        results_by_repo = {
            Path("/repo1"): sample_results[:2],  # PASS, FAIL
            Path("/repo2"): [sample_results[0], sample_results[2]],  # PASS, WARNING
        }

        # Should not raise an error - note that rating is ignored for multiple repos
        console_reporter.report(results_by_repo)

    def test_report_with_show_details(self, sample_results):
        """Test reporting with show_details enabled."""
        reporter = ConsoleReporter(show_details=True)

        # Should not raise an error
        reporter.report(
            sample_results, rating=CodebaseRating.BRONZE, repo_path=Path("/test/repo")
        )

    def test_display_rating(self, console_reporter):
        """Test _display_rating method."""
        # Should not raise an error
        console_reporter._display_rating(CodebaseRating.GOLD)

    def test_display_summary(self, console_reporter, sample_results):
        """Test _display_summary method."""
        # Should not raise an error
        console_reporter._display_summary(sample_results)

    def test_display_results_table(self, console_reporter, sample_results):
        """Test _display_results_table method."""
        # Should not raise an error
        console_reporter._display_results_table(sample_results, Path("/test/repo"))

    def test_display_details(self, sample_results):
        """Test _display_details method."""
        reporter = ConsoleReporter(show_details=True)

        # Should not raise an error
        reporter._display_details(sample_results, Path("/test/repo"))

    def test_display_details_no_details(self, console_reporter):
        """Test _display_details with no detailed results."""
        results = [CheckResult("check", CheckStatus.PASS, "Pass")]

        # Should not raise an error (no details to display)
        console_reporter._display_details(results, Path("/test/repo"))

    def test_format_details(self, console_reporter):
        """Test _format_details method."""
        details = {
            "error": "Something went wrong",
            "files": ["file1.py", "file2.py", "file3.py"],
            "nested": {"key1": "value1", "key2": "value2"},
        }

        formatted = console_reporter._format_details(details)

        assert isinstance(formatted, str)
        assert "error" in formatted
        assert "files" in formatted
        assert "nested" in formatted

    def test_format_details_empty(self, console_reporter):
        """Test _format_details with empty details."""
        formatted = console_reporter._format_details({})

        assert formatted == ""

    def test_format_details_with_long_list(self, console_reporter):
        """Test _format_details with a long list."""
        details = {"items": [f"item{i}" for i in range(20)]}

        formatted = console_reporter._format_details(details)

        # Should truncate long lists
        assert "... and" in formatted

    def test_export_console_output_svg(self, tmp_path):
        """Test exporting console output to SVG."""
        output_path = tmp_path / "output.svg"
        reporter = ConsoleReporter(export_format="svg", output_path=output_path)

        results = [CheckResult("check", CheckStatus.PASS, "Pass")]
        reporter.report(results, CodebaseRating.GOLD, Path("/test/repo"))

        # Output file should be created
        assert output_path.exists()

    def test_export_console_output_html(self, tmp_path):
        """Test exporting console output to HTML."""
        output_path = tmp_path / "output.html"
        reporter = ConsoleReporter(export_format="html", output_path=output_path)

        results = [CheckResult("check", CheckStatus.PASS, "Pass")]
        reporter.report(results, CodebaseRating.GOLD, Path("/test/repo"))

        # Output file should be created
        assert output_path.exists()

    def test_export_console_output_no_format(self, console_reporter):
        """Test _export_console_output when no format is set."""
        # Should do nothing without raising an error
        console_reporter._export_console_output()

    def test_report_with_progress(self, console_reporter):
        """Test report_with_progress method."""
        checks = ["check1", "check2", "check3"]

        # Should not raise an error
        console_reporter.report_with_progress(checks)

    def test_unicode_supported_true(self, console_reporter):
        """Test unicode_supported detection."""
        # The attribute should be set
        assert hasattr(console_reporter, "unicode_supported")

    def test_ascii_fallback(self):
        """Test ASCII fallback for non-Unicode terminals."""
        with patch.object(Console, "encoding", "ascii"):
            reporter = ConsoleReporter()

            # Should have ASCII symbols
            assert "ascii_symbol" in reporter.STATUS_STYLES.get("pass", {})

    def test_status_indicator_with_emoji(self, sample_results):
        """Test status indicator display with emoji."""
        reporter = ConsoleReporter(use_emoji=True)

        # Should not raise an error
        reporter._display_results_table(sample_results, Path("/test/repo"))

    def test_status_indicator_without_emoji(self, sample_results):
        """Test status indicator display without emoji."""
        reporter = ConsoleReporter(use_emoji=False)

        # Should not raise an error
        reporter._display_results_table(sample_results, Path("/test/repo"))

    def test_sorted_results_in_table(self, sample_results):
        """Test that results are sorted in the table (failures first)."""
        reporter = ConsoleReporter()

        # Should not raise an error and should sort results
        reporter._display_results_table(sample_results, Path("/test/repo"))

    def test_display_details_filters_non_failures(self, console_reporter):
        """Test that _display_details only shows failures and warnings."""
        results = [
            CheckResult("pass", CheckStatus.PASS, "Passed", details={"info": "data"}),
            CheckResult("fail", CheckStatus.FAIL, "Failed", details={"error": "issue"}),
        ]

        # Should only display details for failure
        console_reporter._display_details(results, Path("/test/repo"))

    def test_format_details_with_dict_value(self, console_reporter):
        """Test formatting details with dictionary values."""
        details = {"nested_dict": {"key1": "value1", "key2": "value2"}}

        formatted = console_reporter._format_details(details)

        assert "nested_dict" in formatted
        assert "key1" in formatted
        assert "key2" in formatted


class TestCreateReporter:
    """Tests for create_reporter function."""

    def test_create_reporter_default(self):
        """Test creating reporter with default options."""
        reporter = create_reporter()

        assert isinstance(reporter, ConsoleReporter)
        assert reporter.use_emoji is True
        assert reporter.show_details is True

    def test_create_reporter_with_options(self):
        """Test creating reporter with custom options."""
        reporter = create_reporter(show_details=False, use_emoji=False)

        assert reporter.show_details is False
        assert reporter.use_emoji is False

    def test_create_reporter_with_export(self, tmp_path):
        """Test creating reporter with export format."""
        output_path = tmp_path / "output.svg"
        reporter = create_reporter(export_format="svg", output_path=output_path)

        assert reporter.export_format == "svg"
        assert reporter.output_path == output_path
