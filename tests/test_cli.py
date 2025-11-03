"""Tests for cli.py module."""

import sys
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import pytest
from click.testing import CliRunner

from panoptipy.checks import CheckResult, CheckStatus
from panoptipy.cli import cli, common_output_options, run_scan
from panoptipy.config import Config
from panoptipy.rating import CodebaseRating


@pytest.fixture
def runner():
    """Create a CLI test runner."""
    return CliRunner()


@pytest.fixture
def mock_scanner():
    """Create a mock scanner."""
    scanner = MagicMock()
    scanner.scan_multiple.return_value = {
        Path("/test/repo"): [
            CheckResult("test_check", CheckStatus.PASS, "Test passed")
        ]
    }
    scanner.rate.return_value = CodebaseRating.GOLD
    return scanner


def test_cli_group(runner):
    """Test that CLI group is accessible."""
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "PanoptiPy" in result.output


def test_common_output_options_decorator():
    """Test that common_output_options decorator adds options."""

    @common_output_options
    def dummy_func():
        pass

    # Check that the function has been wrapped with click options
    assert hasattr(dummy_func, "__click_params__")
    # Should have 3 options: config, format, output
    assert len(dummy_func.__click_params__) == 3


@patch("panoptipy.cli.CheckRegistry")
@patch("panoptipy.cli.Scanner")
@patch("panoptipy.cli.Config")
@patch("panoptipy.cli.get_reporter")
def test_run_scan_success(mock_get_reporter, mock_config, mock_scanner_cls, mock_registry_cls, tmp_path):
    """Test run_scan function with successful scan."""
    # Setup mocks
    mock_config_obj = MagicMock()
    mock_config.load.return_value = mock_config_obj

    mock_registry = MagicMock()
    mock_registry_cls.return_value = mock_registry

    mock_scanner = MagicMock()
    mock_scanner_cls.return_value = mock_scanner
    mock_scanner.rate.return_value = CodebaseRating.GOLD

    mock_reporter = MagicMock()
    mock_get_reporter.return_value = mock_reporter

    # Create scan_sources function
    results = {tmp_path: [CheckResult("test", CheckStatus.PASS, "Pass")]}

    def scan_sources(scanner):
        return results

    # Run scan
    with pytest.raises(SystemExit) as exc_info:
        run_scan(scan_sources, None, "console", None, [])

    # Should exit with 0 (success)
    assert exc_info.value.code == 0

    # Verify calls
    mock_config.load.assert_called_once()
    mock_registry_cls.assert_called_once_with(config=mock_config_obj)
    mock_registry.load_builtin_checks.assert_called_once()
    mock_registry.load_plugins.assert_called_once()
    mock_reporter.report.assert_called_once()


@patch("panoptipy.cli.CheckRegistry")
@patch("panoptipy.cli.Scanner")
@patch("panoptipy.cli.Config")
@patch("panoptipy.cli.get_reporter")
def test_run_scan_with_critical_failure(
    mock_get_reporter, mock_config, mock_scanner_cls, mock_registry_cls, tmp_path
):
    """Test run_scan with critical check failure."""
    # Setup mocks
    mock_config_obj = MagicMock()
    mock_config.load.return_value = mock_config_obj

    mock_registry = MagicMock()
    mock_registry_cls.return_value = mock_registry

    mock_scanner = MagicMock()
    mock_scanner_cls.return_value = mock_scanner
    mock_scanner.rate.return_value = CodebaseRating.problematic

    mock_reporter = MagicMock()
    mock_get_reporter.return_value = mock_reporter

    # Create scan_sources function with critical failure
    results = {
        tmp_path: [CheckResult("critical_check", CheckStatus.FAIL, "Critical failure")]
    }

    def scan_sources(scanner):
        return results

    # Run scan with critical check
    with pytest.raises(SystemExit) as exc_info:
        run_scan(scan_sources, None, "console", None, ["critical_check"])

    # Should exit with 1 (failure)
    assert exc_info.value.code == 1


@patch("panoptipy.cli.CheckRegistry")
@patch("panoptipy.cli.Scanner")
@patch("panoptipy.cli.Config")
@patch("panoptipy.cli.get_reporter")
def test_run_scan_with_config_file(
    mock_get_reporter, mock_config, mock_scanner_cls, mock_registry_cls, tmp_path
):
    """Test run_scan with config file path."""
    config_path = tmp_path / "config.toml"
    config_path.write_text('[tool.panoptipy]\n[tool.panoptipy.checks]\nenabled = ["*"]')

    mock_config_obj = MagicMock()
    mock_config.load.return_value = mock_config_obj

    mock_registry = MagicMock()
    mock_registry_cls.return_value = mock_registry

    mock_scanner = MagicMock()
    mock_scanner_cls.return_value = mock_scanner
    mock_scanner.rate.return_value = CodebaseRating.GOLD

    mock_reporter = MagicMock()
    mock_get_reporter.return_value = mock_reporter

    results = {tmp_path: [CheckResult("test", CheckStatus.PASS, "Pass")]}

    def scan_sources(scanner):
        return results

    with pytest.raises(SystemExit):
        run_scan(scan_sources, str(config_path), "console", None, [])

    # Verify config was loaded with path
    mock_config.load.assert_called_once()
    call_args = mock_config.load.call_args[0][0]
    assert call_args == Path(str(config_path))


@patch("panoptipy.cli.CheckRegistry")
@patch("panoptipy.cli.Scanner")
@patch("panoptipy.cli.Config")
@patch("panoptipy.cli.get_reporter")
def test_run_scan_with_json_format(
    mock_get_reporter, mock_config, mock_scanner_cls, mock_registry_cls, tmp_path
):
    """Test run_scan with JSON output format."""
    mock_config_obj = MagicMock()
    mock_config.load.return_value = mock_config_obj

    mock_registry = MagicMock()
    mock_registry_cls.return_value = mock_registry

    mock_scanner = MagicMock()
    mock_scanner_cls.return_value = mock_scanner
    mock_scanner.rate.return_value = CodebaseRating.GOLD

    mock_reporter = MagicMock()
    mock_get_reporter.return_value = mock_reporter

    output_path = tmp_path / "output.json"
    results = {tmp_path: [CheckResult("test", CheckStatus.PASS, "Pass")]}

    def scan_sources(scanner):
        return results

    with pytest.raises(SystemExit):
        run_scan(scan_sources, None, "json", output_path, [])

    # Verify reporter was created with correct format and output path
    mock_get_reporter.assert_called_once()
    call_kwargs = mock_get_reporter.call_args[1]
    assert call_kwargs["format"] == "json"
    assert call_kwargs["output_path"] == output_path


@patch("panoptipy.cli.run_scan")
@patch("panoptipy.cli.Config")
def test_scan_command_single_path(mock_config, mock_run_scan, runner, tmp_path):
    """Test scan command with a single path."""
    mock_config_obj = MagicMock()
    mock_config_obj.get.return_value = []
    mock_config.load.return_value = mock_config_obj

    # Prevent SystemExit
    mock_run_scan.side_effect = lambda *args, **kwargs: None

    result = runner.invoke(cli, ["scan", str(tmp_path)])

    # Command should execute
    assert "Error" not in result.output or result.exit_code == 0
    mock_run_scan.assert_called_once()


@patch("panoptipy.cli.run_scan")
@patch("panoptipy.cli.Config")
def test_scan_command_multiple_paths(mock_config, mock_run_scan, runner, tmp_path):
    """Test scan command with multiple paths."""
    mock_config_obj = MagicMock()
    mock_config_obj.get.return_value = []
    mock_config.load.return_value = mock_config_obj

    mock_run_scan.side_effect = lambda *args, **kwargs: None

    path1 = tmp_path / "repo1"
    path2 = tmp_path / "repo2"
    path1.mkdir()
    path2.mkdir()

    result = runner.invoke(cli, ["scan", str(path1), str(path2)])

    assert "Error" not in result.output or result.exit_code == 0
    mock_run_scan.assert_called_once()


@patch("panoptipy.cli.run_scan")
@patch("panoptipy.cli.Config")
def test_scan_command_with_format_option(mock_config, mock_run_scan, runner, tmp_path):
    """Test scan command with format option."""
    mock_config_obj = MagicMock()
    mock_config_obj.get.return_value = []
    mock_config.load.return_value = mock_config_obj

    mock_run_scan.side_effect = lambda *args, **kwargs: None

    result = runner.invoke(cli, ["scan", str(tmp_path), "--format", "json"])

    mock_run_scan.assert_called_once()
    # Check that format was passed correctly
    call_args = mock_run_scan.call_args
    assert call_args[0][2] == "json"  # format is the 3rd positional argument


@patch("panoptipy.cli.run_scan")
@patch("panoptipy.cli.Config")
def test_scan_command_with_output_option(mock_config, mock_run_scan, runner, tmp_path):
    """Test scan command with output option."""
    mock_config_obj = MagicMock()
    mock_config_obj.get.return_value = []
    mock_config.load.return_value = mock_config_obj

    mock_run_scan.side_effect = lambda *args, **kwargs: None

    output_file = tmp_path / "output.json"

    result = runner.invoke(
        cli, ["scan", str(tmp_path), "--output", str(output_file)]
    )

    mock_run_scan.assert_called_once()
    call_args = mock_run_scan.call_args
    assert call_args[0][3] == output_file  # output is the 4th positional argument


def test_scan_command_no_paths(runner):
    """Test scan command without providing paths."""
    result = runner.invoke(cli, ["scan"])

    # Should fail with missing argument error
    assert result.exit_code != 0
    assert "Missing argument" in result.output or "required" in result.output.lower()


def test_scan_command_invalid_path(runner):
    """Test scan command with non-existent path."""
    result = runner.invoke(cli, ["scan", "/nonexistent/path"])

    # Should fail due to path validation
    assert result.exit_code != 0


@patch("panoptipy.cli.run_scan")
@patch("panoptipy.cli.Config")
def test_scan_command_with_config_option(mock_config, mock_run_scan, runner, tmp_path):
    """Test scan command with config file option."""
    config_file = tmp_path / "config.toml"
    config_file.write_text('[tool.panoptipy]\n[tool.panoptipy.checks]\nenabled = ["*"]')

    mock_config_obj = MagicMock()
    mock_config_obj.get.return_value = []
    mock_config.load.return_value = mock_config_obj

    mock_run_scan.side_effect = lambda *args, **kwargs: None

    result = runner.invoke(
        cli, ["scan", str(tmp_path), "--config", str(config_file)]
    )

    mock_run_scan.assert_called_once()
    # Config path should be passed
    call_args = mock_run_scan.call_args
    assert call_args[0][1] == str(config_file)
