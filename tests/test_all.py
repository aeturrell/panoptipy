import subprocess
from pathlib import Path
from unittest.mock import MagicMock, mock_open, patch

import pytest
import toml

from panoptipy.checks import CheckStatus, ReadmeCheck
from panoptipy.config import Config


def run_command(command):
    """Helper to run command using Popen and return (stdout, stderr, returncode)."""
    process = subprocess.Popen(
        command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    stdout, stderr = process.communicate()
    return stdout, stderr, process.returncode


def test_cli_without_config():
    """Test that CLI works with default configuration."""
    stdout, stderr, returncode = run_command(["panoptipy", "scan", "."])

    # Check that the command executed
    assert returncode in (0, 1), f"CLI failed: {stderr}"


@pytest.fixture
def config_file(tmp_path):
    """Create a temporary TOML config file."""
    config = {
        "tool": {
            "panoptipy": {
                "checks": {
                    "enabled": ["large_files", "docstrings"],
                    "disabled": [],
                    "critical": ["docstrings"],
                },
                "thresholds": {
                    "max_file_size": 1000,
                    "min_readme_length": 200,  # Custom minimum README content length in characters
                },
            }
        }
    }
    config_path = tmp_path / "test_config.toml"
    with open(config_path, "w") as f:
        toml.dump(config, f)
    return config_path


def test_cli_with_config(config_file):
    """Test that CLI correctly uses configuration from TOML file."""
    stdout, stderr, returncode = run_command(
        ["panoptipy", "scan", ".", f"--config={config_file}"]
    )

    # Check that the command executed
    assert returncode in (0, 1), f"CLI failed: {stderr}"

    # Check output contains evidence of config being used
    output = stdout + stderr
    assert "large_files" in output, "Expected enabled check not found in output"
    assert "(1000KB)" in output, "Expected threshold not found in output"

    # Since ruff_linting is marked as critical, it should affect the return code
    if "fail" in output and "docstrings" in output:
        assert returncode == 1, "Expected failure due to critical check"


def test_cli_with_invalid_config(tmp_path):
    """Test that CLI handles invalid configuration gracefully."""
    invalid_config = tmp_path / "invalid.toml"
    with open(invalid_config, "w") as f:
        f.write("this is not valid toml ][")

    stdout, stderr, returncode = run_command(
        ["panoptipy", "scan", ".", f"--config={invalid_config}"]
    )

    # Should fail gracefully with error message
    assert returncode != 0
    assert "Error" in (stderr + stdout)


def test_cli_format_options():
    """Test that CLI correctly handles different output formats."""
    # Test JSON format
    stdout, stderr, returncode = run_command(
        ["panoptipy", "scan", ".", "--format=json"]
    )
    assert returncode in (0, 1), f"CLI failed: {stderr}"
    stripped = stdout.strip()
    assert stripped.startswith("{"), "JSON output should start with '{'"
    assert stripped.endswith("}"), "JSON output should end with '}'"

    # Test invalid format
    stdout, stderr, returncode = run_command(
        ["panoptipy", "scan", ".", "--format=invalid"]
    )
    assert returncode != 0, "Should fail with invalid format"
    assert "Error" in (stderr + stdout)


@pytest.fixture
def readme_check():
    config = Config({"thresholds": {"min_readme_length": 50}})
    return ReadmeCheck(config=config)


@pytest.fixture
def mock_codebase():
    codebase = MagicMock()
    codebase.root_path = Path("/fake/repo")
    return codebase


@patch("pathlib.Path.exists")
@patch("pathlib.Path.is_file")
def test_no_readme_found(mock_is_file, mock_exists, readme_check, mock_codebase):
    # Mock no README files exist
    mock_exists.return_value = False
    mock_is_file.return_value = True

    result = readme_check.run(mock_codebase)

    assert result.status == CheckStatus.FAIL
    assert result.check_id == "readme"
    assert "No README file found" in result.message
    assert not result.details["readme_found"]


@patch("pathlib.Path.exists")
@patch("pathlib.Path.is_file")
@patch("builtins.open", new_callable=mock_open, read_data="   \n  \t  ")
def test_empty_readme(
    mock_file, mock_is_file, mock_exists, readme_check, mock_codebase
):
    # Mock README.md exists but is empty
    mock_exists.return_value = True
    mock_is_file.return_value = True

    result = readme_check.run(mock_codebase)

    assert result.status == CheckStatus.FAIL
    assert result.check_id == "readme"
    assert "insufficient content" in result.message
    assert result.details["readme_found"]
    assert not result.details["has_content"]


@patch("pathlib.Path.exists")
@patch("pathlib.Path.is_file")
def test_valid_readme(mock_is_file, mock_exists, readme_check, mock_codebase):
    # Mock README.md exists with content
    mock_exists.return_value = True
    mock_is_file.return_value = True

    # Setup different content for different README files
    readme_contents = {
        "/fake/repo/README.md": "This is a README with plenty of content that will definitely pass the check because it is much longer than the minimum threshold of 50 characters.",
    }

    def mock_open_side_effect(file, *args, **kwargs):
        file_path = str(file)
        content = readme_contents.get(file_path, "")
        return mock_open(read_data=content)()

    with patch("builtins.open", side_effect=mock_open_side_effect):
        result = readme_check.run(mock_codebase)

    assert result.status == CheckStatus.PASS
    assert result.check_id == "readme"
    assert "sufficient content" in result.message
    assert result.details["readme_found"]
    assert result.details["has_content"]


@patch("pathlib.Path.exists")
@patch("pathlib.Path.is_file")
def test_multiple_readme_files(mock_is_file, mock_exists, readme_check, mock_codebase):
    # Mock multiple README files exist
    mock_exists.return_value = True
    mock_is_file.return_value = True

    # Setup different content for different README files
    readme_contents = {
        "/fake/repo/README.md": "# Empty",  # Too short
        "/fake/repo/README.rst": "This README has enough content to pass the check.",  # Long enough
    }

    def mock_open_side_effect(file, *args, **kwargs):
        file_path = str(file)
        content = readme_contents.get(file_path, "")
        return mock_open(read_data=content)()

    with patch("builtins.open", side_effect=mock_open_side_effect):
        result = readme_check.run(mock_codebase)

    # Should fail because at least one README does not have enough content
    assert result.status == CheckStatus.FAIL
