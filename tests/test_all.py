import subprocess

import pytest
import toml


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
    result = subprocess.run(
        ["panoptipy", "scan", ".", f"--config={config_file}"],
        capture_output=True,
        text=True,
    )
    print(result.stdout)
    # Check that the command executed
    assert result.returncode in (0, 1), f"CLI failed: {result.stderr}"

    # Check output contains evidence of config being used
    output = result.stdout + result.stderr
    assert "large_files" in output, "Expected enabled check not found in output"
    assert "(1000KB)" in output, "Expected threshold not found in output"

    # Since ruff_linting is marked as critical, it should affect the return code
    if "fail" in output and "docstrings" in output:
        assert result.returncode == 1, "Expected failure due to critical check"


def test_cli_without_config():
    """Test that CLI works with default configuration."""
    result = subprocess.run(
        ["panoptipy", "scan", "."],
        capture_output=True,
        text=True,
    )

    # Check that the command executed
    assert result.returncode in (0, 1), f"CLI failed: {result.stderr}"


def test_cli_with_invalid_config(tmp_path):
    """Test that CLI handles invalid configuration gracefully."""
    invalid_config = tmp_path / "invalid.toml"
    with open(invalid_config, "w") as f:
        f.write("this is not valid toml ][")

    result = subprocess.run(
        ["panoptipy", "scan", ".", f"--config={invalid_config}"],
        capture_output=True,
        text=True,
    )

    # Should fail gracefully with error message
    assert result.returncode != 0
    assert "Error" in (result.stderr + result.stdout)
