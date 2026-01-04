"""Tests for utility functions and additional checks in checks.py."""

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from panoptipy.checks import (
    Check,
    CheckResult,
    CheckStatus,
    DocstringCheck,
    fail_result,
    get_tracked_files,
    parse_tool_output,
    safe_check_run,
    success_result,
)


def test_check_status_enum():
    """Test CheckStatus enum values."""
    assert CheckStatus.PASS.value == "pass"
    assert CheckStatus.FAIL.value == "fail"
    assert CheckStatus.WARNING.value == "warning"
    assert CheckStatus.SKIP.value == "skip"
    assert CheckStatus.ERROR.value == "error"


def test_check_result_dataclass():
    """Test CheckResult dataclass creation."""
    result = CheckResult(
        check_id="test_check",
        status=CheckStatus.PASS,
        message="Test message",
        repo_path=Path("/test/repo"),
        details={"key": "value"},
    )

    assert result.check_id == "test_check"
    assert result.status == CheckStatus.PASS
    assert result.message == "Test message"
    assert result.repo_path == Path("/test/repo")
    assert result.details == {"key": "value"}


def test_check_result_optional_fields():
    """Test CheckResult with optional fields as None."""
    result = CheckResult(
        check_id="test_check", status=CheckStatus.PASS, message="Test message"
    )

    assert result.repo_path is None
    assert result.details is None


def test_check_base_class():
    """Test Check base class."""
    check = Check("test_check", "Test description")

    assert check.check_id == "test_check"
    assert check.description == "Test description"
    assert check.category == "general"


def test_check_run_not_implemented():
    """Test that Check.run() raises NotImplementedError."""
    check = Check("test_check", "Test description")

    with pytest.raises(NotImplementedError):
        check.run(MagicMock())


def test_success_result():
    """Test success_result helper function."""
    result = success_result("test_check", "Success message")

    assert result.check_id == "test_check"
    assert result.status == CheckStatus.PASS
    assert result.message == "Success message"
    assert result.details is None


def test_success_result_with_details():
    """Test success_result with details."""
    details = {"files_checked": 10}
    result = success_result("test_check", "Success", details)

    assert result.details == details


def test_fail_result():
    """Test fail_result helper function."""
    result = fail_result("test_check", "Failure message")

    assert result.check_id == "test_check"
    assert result.status == CheckStatus.FAIL
    assert result.message == "Failure message"
    assert result.details is None


def test_fail_result_with_details():
    """Test fail_result with details."""
    details = {"errors": ["error1", "error2"]}
    result = fail_result("test_check", "Failed", details)

    assert result.details == details


def test_safe_check_run_success():
    """Test safe_check_run with successful check."""

    def check_fn():
        return CheckResult("test_check", CheckStatus.PASS, "Success")

    result = safe_check_run(check_fn, "test_check")

    assert result.status == CheckStatus.PASS
    assert result.message == "Success"


def test_safe_check_run_with_exception():
    """Test safe_check_run when check raises exception."""

    def check_fn():
        raise ValueError("Something went wrong")

    result = safe_check_run(check_fn, "test_check")

    assert result.status == CheckStatus.ERROR
    assert "Error executing check" in result.message
    assert "Something went wrong" in result.message
    assert result.details is not None
    assert result.details["error"] == "Something went wrong"


def test_safe_check_run_preserves_check_id():
    """Test that safe_check_run uses correct check_id on error."""

    def check_fn():
        raise RuntimeError("Error")

    result = safe_check_run(check_fn, "custom_check_id")

    assert result.check_id == "custom_check_id"


def test_parse_tool_output():
    """Test parse_tool_output function."""
    output = """file1.py:10:5: E501 Line too long
file2.py:20:1: W503 Line break before binary operator
file3.py:30:10: F401 Unused import"""

    def line_parser(line):
        if not line:
            return None
        parts = line.split(":", 3)
        if len(parts) < 4:
            return None
        return {
            "file": parts[0],
            "line": int(parts[1]),
            "column": int(parts[2]),
            "message": parts[3].strip(),
        }

    issues = parse_tool_output(output, line_parser)

    assert len(issues) == 3
    assert issues[0]["file"] == "file1.py"
    assert issues[0]["line"] == 10
    assert issues[1]["file"] == "file2.py"
    assert issues[2]["file"] == "file3.py"


def test_parse_tool_output_with_invalid_lines():
    """Test parse_tool_output with some invalid lines."""
    output = """valid.py:10:5: Error message
invalid line without proper format
another.py:20:1: Another error"""

    def line_parser(line):
        if not line:
            return None
        parts = line.split(":", 3)
        if len(parts) < 4:
            return None
        return {"file": parts[0], "line": int(parts[1])}

    issues = parse_tool_output(output, line_parser)

    assert len(issues) == 2
    assert issues[0]["file"] == "valid.py"
    assert issues[1]["file"] == "another.py"


def test_parse_tool_output_empty():
    """Test parse_tool_output with empty output."""
    issues = parse_tool_output("", lambda line: {"data": line})

    assert issues == []


def test_parse_tool_output_parser_returns_none():
    """Test parse_tool_output when parser returns None."""
    output = """line1
line2
line3"""

    def line_parser(line):
        return None  # Parser ignores all lines

    issues = parse_tool_output(output, line_parser)

    assert issues == []


def test_parse_tool_output_parser_raises_exception():
    """Test parse_tool_output when parser raises exception."""
    output = """line1
line2
line3"""

    def line_parser(line):
        if line == "line2":
            raise ValueError("Parser error")
        return {"line": line}

    issues = parse_tool_output(output, line_parser)

    # Should skip line2 and continue with others
    assert len(issues) == 2
    assert issues[0]["line"] == "line1"
    assert issues[1]["line"] == "line3"


@patch("panoptipy.checks.subprocess.run")
def test_get_tracked_files_success(mock_run):
    """Test get_tracked_files with successful git command."""
    import os

    mock_run.return_value = MagicMock(
        stdout="file1.py\nfile2.py\nfile3.py\n", returncode=0
    )

    test_root = str(Path("/test/repo"))
    files = get_tracked_files(test_root)

    assert len(files) == 3
    assert os.path.join(test_root, "file1.py") in files
    assert os.path.join(test_root, "file2.py") in files
    assert os.path.join(test_root, "file3.py") in files


@patch("panoptipy.checks.subprocess.run")
def test_get_tracked_files_with_pattern(mock_run):
    """Test get_tracked_files with file pattern."""
    mock_run.return_value = MagicMock(stdout="test.py\nutils.py\n", returncode=0)

    test_root = str(Path("/test/repo"))
    get_tracked_files(test_root, "*.py")

    mock_run.assert_called_once()
    cmd = mock_run.call_args[0][0]
    assert "*.py" in cmd


@patch("panoptipy.checks.subprocess.run")
def test_get_tracked_files_subprocess_error(mock_run):
    """Test get_tracked_files when subprocess raises error."""
    mock_run.side_effect = subprocess.SubprocessError("Git error")

    test_root = str(Path("/test/repo"))
    files = get_tracked_files(test_root)

    assert files == set()


@patch("panoptipy.checks.subprocess.run")
def test_get_tracked_files_file_not_found(mock_run):
    """Test get_tracked_files when git is not found."""
    mock_run.side_effect = FileNotFoundError("git not found")

    test_root = str(Path("/test/repo"))
    files = get_tracked_files(test_root)

    assert files == set()


@patch("panoptipy.checks.subprocess.run")
def test_get_tracked_files_empty_output(mock_run):
    """Test get_tracked_files with empty output."""
    mock_run.return_value = MagicMock(stdout="", returncode=0)

    test_root = str(Path("/test/repo"))
    files = get_tracked_files(test_root)

    assert files == set()


@patch("panoptipy.checks.subprocess.run")
def test_get_tracked_files_strips_whitespace(mock_run):
    """Test that get_tracked_files strips whitespace from filenames."""
    mock_run.return_value = MagicMock(
        stdout="  file1.py  \n\n  file2.py  \n", returncode=0
    )

    test_root = str(Path("/test/repo"))
    files = get_tracked_files(test_root)

    assert len(files) == 2
    # Verify no extra whitespace in paths
    for file in files:
        assert not file.endswith(" ")
        assert not file.startswith(" ")


def test_docstring_check_init():
    """Test DocstringCheck initialization."""
    check = DocstringCheck()

    assert check.check_id == "docstrings"
    assert "docstrings" in check.description.lower()
    assert check.category == "documentation"


def test_docstring_check_is_public():
    """Test DocstringCheck._is_public method."""
    check = DocstringCheck()

    assert check._is_public("public_function") is True
    assert check._is_public("PublicClass") is True
    assert check._is_public("_private_function") is False
    assert check._is_public("__dunder__") is False


def test_docstring_check_is_test():
    """Test DocstringCheck._is_test method."""
    import os

    check = DocstringCheck()

    # Test file paths - use os.path.join for cross-platform compatibility
    test_file_path = os.path.join("path", "to", "test_file.py")
    tests_path = os.path.join("path", "to", "tests", "file.py")
    test_module_path = os.path.join("path", "to", "Test_Module.py")
    regular_path = os.path.join("path", "to", "file.py")

    assert check._is_test("func", test_file_path) is True
    assert check._is_test("func", tests_path) is True
    assert check._is_test("func", test_module_path) is True

    # Test function/class names
    assert check._is_test("test_function", regular_path) is True
    assert check._is_test("function_test", regular_path) is True
    assert check._is_test("MyTests", regular_path) is True
    assert check._is_test("MyTest", regular_path) is True

    # Non-test cases
    assert check._is_test("regular_function", regular_path) is False
    assert check._is_test("MyClass", regular_path) is False


def test_docstring_check_category():
    """Test that DocstringCheck has correct category."""
    check = DocstringCheck()

    assert check.category == "documentation"
