"""Tests for reporters/__init__.py module."""

from pathlib import Path

import pytest

from panoptipy.config import Config
from panoptipy.reporters import get_reporter
from panoptipy.reporters.console import ConsoleReporter
from panoptipy.reporters.json import JSONReporter
from panoptipy.reporters.parquet import ParquetReporter


class TestGetReporter:
    """Tests for get_reporter function."""

    def test_get_console_reporter(self):
        """Test getting console reporter."""
        reporter = get_reporter(format="console")

        assert isinstance(reporter, ConsoleReporter)

    def test_get_json_reporter(self):
        """Test getting JSON reporter."""
        reporter = get_reporter(format="json")

        assert isinstance(reporter, JSONReporter)

    def test_get_json_reporter_with_output_path(self, tmp_path):
        """Test getting JSON reporter with output path."""
        output_path = tmp_path / "output.json"
        reporter = get_reporter(format="json", output_path=output_path)

        assert isinstance(reporter, JSONReporter)
        assert reporter.output_path == output_path

    def test_get_parquet_reporter(self, tmp_path):
        """Test getting parquet reporter."""
        output_path = tmp_path / "output.parquet"
        reporter = get_reporter(format="parquet", output_path=output_path)

        assert isinstance(reporter, ParquetReporter)
        assert reporter.output_path == output_path

    def test_get_parquet_reporter_without_output_path(self):
        """Test that parquet reporter requires output path."""
        with pytest.raises(ValueError, match="output_path is required"):
            get_reporter(format="parquet")

    def test_get_svg_reporter(self, tmp_path):
        """Test getting SVG reporter (console with export)."""
        output_path = tmp_path / "output.svg"
        reporter = get_reporter(format="svg", output_path=output_path)

        assert isinstance(reporter, ConsoleReporter)
        assert reporter.export_format == "svg"
        assert reporter.output_path == output_path

    def test_get_svg_reporter_without_output_path(self):
        """Test that SVG reporter requires output path."""
        with pytest.raises(ValueError, match="output_path is required"):
            get_reporter(format="svg")

    def test_get_html_reporter(self, tmp_path):
        """Test getting HTML reporter (console with export)."""
        output_path = tmp_path / "output.html"
        reporter = get_reporter(format="html", output_path=output_path)

        assert isinstance(reporter, ConsoleReporter)
        assert reporter.export_format == "html"
        assert reporter.output_path == output_path

    def test_get_html_reporter_without_output_path(self):
        """Test that HTML reporter requires output path."""
        with pytest.raises(ValueError, match="output_path is required"):
            get_reporter(format="html")

    def test_get_reporter_with_invalid_format(self):
        """Test getting reporter with invalid format."""
        with pytest.raises(ValueError, match="Unknown reporter format"):
            get_reporter(format="invalid")

    def test_get_reporter_with_config(self):
        """Test getting reporter with config."""
        config = Config({"reporters": {"show_details": True}})
        reporter = get_reporter(format="console", config=config)

        assert isinstance(reporter, ConsoleReporter)
        assert reporter.show_details is True

    def test_get_reporter_with_config_show_details_false(self):
        """Test getting reporter with show_details=False in config."""
        config = Config({"reporters": {"show_details": False}})
        reporter = get_reporter(format="console", config=config)

        assert reporter.show_details is False

    def test_get_reporter_explicit_show_details_overrides_config(self):
        """Test that explicit show_details overrides config."""
        config = Config({"reporters": {"show_details": True}})
        reporter = get_reporter(format="console", config=config, show_details=False)

        # Explicit parameter should override config
        assert reporter.show_details is False

    def test_get_reporter_with_additional_kwargs(self):
        """Test getting reporter with additional keyword arguments."""
        reporter = get_reporter(format="console", use_emoji=False)

        assert isinstance(reporter, ConsoleReporter)
        assert reporter.use_emoji is False

    def test_get_reporter_json_with_show_details(self):
        """Test getting JSON reporter with show_details."""
        reporter = get_reporter(format="json", show_details=True)

        assert isinstance(reporter, JSONReporter)
        assert reporter.show_details is True

    def test_get_reporter_parquet_with_kwargs(self, tmp_path):
        """Test getting parquet reporter with additional kwargs."""
        output_path = tmp_path / "output.parquet"
        reporter = get_reporter(format="parquet", output_path=output_path, show_details=True)

        assert isinstance(reporter, ParquetReporter)
        assert reporter.show_details is True

    def test_get_reporter_console_default_show_details_from_config(self):
        """Test that console reporter uses default show_details from config."""
        config = Config({"reporters": {"show_details": False}})
        reporter = get_reporter(format="console", config=config)

        assert reporter.show_details is False

    def test_get_reporter_without_config(self):
        """Test getting reporter without config."""
        reporter = get_reporter(format="console")

        # Should use defaults
        assert isinstance(reporter, ConsoleReporter)
