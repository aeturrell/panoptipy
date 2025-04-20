import subprocess

import pytest
import toml


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

    print(stdout)
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
