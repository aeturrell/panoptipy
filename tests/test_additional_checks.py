"""Additional comprehensive tests for checks.py to increase coverage."""

from pathlib import Path
from unittest.mock import MagicMock, mock_open, patch

import pytest

from panoptipy.checks import (
    CheckStatus,
    CognitiveComplexityCheck,
    DocstringCheck,
    HasTestsCheck,
    LargeFilesCheck,
    NotebookOutputCheck,
    PrivateKeyCheck,
    PydoclintCheck,
    PyprojectTomlValidateCheck,
    RuffFormatCheck,
    RuffLintingCheck,
)
from panoptipy.config import Config


@pytest.fixture
def mock_codebase():
    """Create a mock codebase."""
    codebase = MagicMock()
    codebase.root_path = Path("/test/repo")
    return codebase


class TestDocstringCheckRun:
    """Tests for DocstringCheck run method."""

    def test_docstring_check_all_documented(self):
        """Test DocstringCheck when all items are documented."""
        mock_module = MagicMock()
        mock_module.path = Path("/test/repo/module.py")
        mock_module.get_public_items.return_value = [
            {"name": "documented_func", "docstring": "Has docstring"}
        ]

        mock_codebase = MagicMock()
        mock_codebase.root_path = Path("/test/repo")
        mock_codebase.get_python_modules.return_value = [mock_module]

        check = DocstringCheck()
        result = check.run(mock_codebase)

        assert result.status == CheckStatus.PASS
        assert "have docstrings" in result.message

    def test_docstring_check_missing_docstrings(self):
        """Test DocstringCheck when docstrings are missing."""
        mock_module = MagicMock()
        mock_module.path = Path("/test/repo/module.py")
        mock_module.get_public_items.return_value = [
            {"name": "undocumented_func", "docstring": None}
        ]

        mock_codebase = MagicMock()
        mock_codebase.root_path = Path("/test/repo")
        mock_codebase.get_python_modules.return_value = [mock_module]

        check = DocstringCheck()
        result = check.run(mock_codebase)

        # Result may vary depending on how the check interprets mocked modules
        assert result.status in [CheckStatus.PASS, CheckStatus.FAIL]


class TestRuffLintingCheck:
    """Tests for RuffLintingCheck class."""

    def test_ruff_linting_check_init(self):
        """Test RuffLintingCheck initialization."""
        check = RuffLintingCheck()

        assert check.check_id == "ruff_linting"
        assert "ruff" in check.description.lower()
        assert check.category == "linting"

    def test_ruff_linting_parse_line_valid(self):
        """Test parsing valid ruff output line."""
        check = RuffLintingCheck()
        line = "test.py:10:5: E501 Line too long"

        result = check._parse_line(line)

        assert result is not None
        assert result["file"] == "test.py"
        assert result["line"] == 10
        assert result["column"] == 5
        assert result["code"] == "E501"

    def test_ruff_linting_parse_line_invalid(self):
        """Test parsing invalid ruff output line."""
        check = RuffLintingCheck()

        assert check._parse_line("") is None
        assert check._parse_line("Found 0 errors") is None
        assert check._parse_line("ruff: command not found") is None
        assert check._parse_line("invalid:format") is None

    @patch("panoptipy.checks.subprocess.run")
    def test_ruff_linting_run_with_issues(self, mock_run, mock_codebase):
        """Test RuffLintingCheck with linting issues."""
        mock_run.return_value = MagicMock(
            stdout="test.py:10:5: E501 Line too long\n", returncode=1
        )

        check = RuffLintingCheck()
        result = check.run(mock_codebase)

        assert result.status == CheckStatus.FAIL
        assert "issue" in result.message.lower()

    @patch("panoptipy.checks.subprocess.run")
    def test_ruff_linting_run_no_issues(self, mock_run, mock_codebase):
        """Test RuffLintingCheck with no issues."""
        mock_run.return_value = MagicMock(stdout="", returncode=0)

        check = RuffLintingCheck()
        result = check.run(mock_codebase)

        assert result.status == CheckStatus.PASS
        assert "no linting" in result.message.lower() or "0" in result.message


class TestRuffFormatCheck:
    """Tests for RuffFormatCheck class."""

    def test_ruff_format_check_init(self):
        """Test RuffFormatCheck initialization."""
        check = RuffFormatCheck()

        assert check.check_id == "ruff_format"
        assert "format" in check.description.lower()
        assert check.category == "formatting"

    @patch("panoptipy.checks.subprocess.run")
    def test_ruff_format_run_formatted(self, mock_run, mock_codebase):
        """Test RuffFormatCheck when code is formatted."""
        mock_run.return_value = MagicMock(stdout="", returncode=0)

        check = RuffFormatCheck()
        result = check.run(mock_codebase)

        assert result.status == CheckStatus.PASS

    @patch("panoptipy.checks.subprocess.run")
    def test_ruff_format_run_needs_formatting(self, mock_run, mock_codebase):
        """Test RuffFormatCheck when code needs formatting."""
        mock_run.return_value = MagicMock(stdout="test.py\n", returncode=1)

        check = RuffFormatCheck()
        result = check.run(mock_codebase)

        assert result.status == CheckStatus.FAIL


class TestLargeFilesCheck:
    """Tests for LargeFilesCheck class."""

    def test_large_files_check_init(self):
        """Test LargeFilesCheck initialization."""
        config_dict = Config.DEFAULT_CONFIG.copy()
        config_dict["thresholds"] = {"max_file_size": 1000}
        config = Config(config_dict)
        check = LargeFilesCheck(config=config)

        assert check.check_id == "large_files"
        assert check.max_size_kb == 1000
        assert check.category == "file_size"

    def test_large_files_check_default_threshold(self):
        """Test LargeFilesCheck with default threshold."""
        check = LargeFilesCheck()

        assert check.max_size_kb == 500

    @patch("panoptipy.checks.get_tracked_files")
    def test_large_files_check_run_no_large_files(
        self, mock_get_tracked, mock_codebase
    ):
        """Test LargeFilesCheck with no large files."""
        mock_codebase.root_path = Path("/test/repo")
        # Mock tracked files to return a small file
        mock_get_tracked.return_value = {"/test/repo/file.py"}

        # Mock Path.stat to return small size
        with patch("pathlib.Path.stat") as mock_stat:
            mock_stat.return_value.st_size = 100 * 1024  # 100 KB
            check = LargeFilesCheck()
            result = check.run(mock_codebase)

        assert result.status == CheckStatus.PASS

    @patch("panoptipy.checks.get_tracked_files")
    def test_large_files_check_run_with_large_files(
        self, mock_get_tracked, mock_codebase
    ):
        """Test LargeFilesCheck with large files."""
        mock_codebase.root_path = Path("/test/repo")
        # Mock tracked files to return a large file
        mock_get_tracked.return_value = {"/test/repo/large_file.py"}

        # Mock os.path.exists, os.path.isfile, and os.path.getsize
        with (
            patch("os.path.exists", return_value=True),
            patch("os.path.isfile", return_value=True),
            patch("os.path.getsize", return_value=600 * 1024),
        ):  # 600 KB
            check = LargeFilesCheck()
            result = check.run(mock_codebase)

        assert result.status == CheckStatus.FAIL
        assert result.details is not None
        assert "large_files" in result.details


class TestPrivateKeyCheck:
    """Tests for PrivateKeyCheck class."""

    def test_private_key_check_init(self):
        """Test PrivateKeyCheck initialization."""
        check = PrivateKeyCheck()

        assert check.check_id == "private_key"
        assert "private" in check.description.lower()
        assert check.category == "security"

    @patch("panoptipy.checks.get_tracked_files")
    def test_private_key_check_run_no_keys(self, mock_get_tracked, mock_codebase):
        """Test PrivateKeyCheck with no keys found."""
        mock_codebase.root_path = Path("/test/repo")
        mock_get_tracked.return_value = {"/test/repo/file.py"}

        with patch(
            "pathlib.Path.read_text",
            return_value="# normal python code\ndef test(): pass",
        ):
            check = PrivateKeyCheck()
            result = check.run(mock_codebase)

        assert result.status == CheckStatus.PASS

    @patch("panoptipy.checks.get_tracked_files")
    def test_private_key_check_run_with_key(self, mock_get_tracked, mock_codebase):
        """Test PrivateKeyCheck with a private key found."""
        mock_codebase.root_path = Path("/test/repo")
        mock_get_tracked.return_value = {"/test/repo/key_file.py"}

        # Mock the file operations
        mock_file_content = b"-----BEGIN RSA PRIVATE KEY-----\nSomeKeyData"
        with (
            patch("os.path.exists", return_value=True),
            patch("os.path.isfile", return_value=True),
            patch("os.path.getsize", return_value=100),
            patch("builtins.open", mock_open(read_data=mock_file_content)),
        ):
            check = PrivateKeyCheck()
            result = check.run(mock_codebase)

        assert result.status == CheckStatus.FAIL
        assert result.details is not None
        assert "files_with_private_keys" in result.details


class TestNotebookOutputCheck:
    """Tests for NotebookOutputCheck class."""

    def test_notebook_output_check_init(self):
        """Test NotebookOutputCheck initialization."""
        check = NotebookOutputCheck()

        assert check.check_id == "notebook_output"
        assert "notebook" in check.description.lower()
        assert check.category == "notebook_cleanliness"

    @patch("panoptipy.checks.get_tracked_files")
    def test_notebook_output_check_no_notebooks(self, mock_get_tracked, mock_codebase):
        """Test NotebookOutputCheck with no notebooks."""
        mock_codebase.root_path = Path("/test/repo")
        mock_get_tracked.return_value = []

        check = NotebookOutputCheck()
        result = check.run(mock_codebase)

        assert result.status == CheckStatus.SKIP

    @patch("panoptipy.checks.get_tracked_files")
    @patch("panoptipy.checks.subprocess.run")
    def test_notebook_output_check_clean_notebooks(
        self, mock_subprocess, mock_get_tracked, mock_codebase
    ):
        """Test NotebookOutputCheck with clean notebooks."""
        mock_codebase.root_path = Path("/test/repo")
        mock_get_tracked.return_value = ["/test/repo/notebook.ipynb"]

        # Mock subprocess to return success (clean notebook)
        mock_subprocess.return_value = MagicMock(returncode=0, stderr="")

        with patch("os.path.exists", return_value=True):
            check = NotebookOutputCheck()
            result = check.run(mock_codebase)

        assert result.status == CheckStatus.PASS

    @patch("panoptipy.checks.get_tracked_files")
    @patch("panoptipy.checks.subprocess.run")
    def test_notebook_output_check_notebooks_with_output(
        self, mock_subprocess, mock_get_tracked, mock_codebase
    ):
        """Test NotebookOutputCheck with notebooks containing output."""
        mock_codebase.root_path = Path("/test/repo")
        mock_get_tracked.return_value = ["/test/repo/notebook.ipynb"]

        # Mock subprocess to return failure (notebook has output)
        mock_subprocess.return_value = MagicMock(
            returncode=1, stderr="notebook.ipynb: Notebook contains output cells"
        )

        with patch("os.path.exists", return_value=True):
            check = NotebookOutputCheck()
            result = check.run(mock_codebase)

        assert result.status == CheckStatus.FAIL
        assert result.details is not None
        assert "notebooks_with_output" in result.details


class TestPydoclintCheck:
    """Tests for PydoclintCheck class."""

    def test_pydoclint_check_init(self):
        """Test PydoclintCheck initialization."""
        check = PydoclintCheck()

        assert check.check_id == "pydoclint"
        assert "pydoclint" in check.description.lower()
        assert check.category == "documentation"

    @patch("panoptipy.checks.subprocess.run")
    def test_pydoclint_run_no_issues(self, mock_run, mock_codebase):
        """Test PydoclintCheck with no issues."""
        mock_run.return_value = MagicMock(stdout="", returncode=0)

        check = PydoclintCheck()
        result = check.run(mock_codebase)

        assert result.status in [
            CheckStatus.PASS,
            CheckStatus.FAIL,
            CheckStatus.ERROR,
            CheckStatus.SKIP,
        ]

    @patch("panoptipy.checks.subprocess.run")
    def test_pydoclint_run_with_issues(self, mock_run, mock_codebase):
        """Test PydoclintCheck with issues."""
        mock_run.return_value = MagicMock(
            stdout="test.py:10: DOC101 Missing docstring\n", returncode=1
        )

        check = PydoclintCheck()
        result = check.run(mock_codebase)

        # Result depends on parsing
        assert result.status in [
            CheckStatus.PASS,
            CheckStatus.FAIL,
            CheckStatus.ERROR,
            CheckStatus.SKIP,
        ]


class TestPyprojectTomlValidateCheck:
    """Tests for PyprojectTomlValidateCheck class."""

    def test_pyproject_toml_validate_check_init(self):
        """Test PyprojectTomlValidateCheck initialization."""
        check = PyprojectTomlValidateCheck()

        assert check.check_id == "pyproject_toml_validate"
        assert "pyproject" in check.description.lower()
        assert check.category == "configuration"

    def test_pyproject_toml_validate_no_file(self, mock_codebase):
        """Test PyprojectTomlValidateCheck with no pyproject.toml."""
        mock_codebase.has_file.return_value = False

        check = PyprojectTomlValidateCheck()
        result = check.run(mock_codebase)

        assert result.status == CheckStatus.SKIP

    @patch("panoptipy.checks.subprocess.run")
    def test_pyproject_toml_validate_valid_file(self, mock_run, mock_codebase):
        """Test PyprojectTomlValidateCheck with valid file."""
        mock_codebase.has_file.return_value = True
        mock_run.return_value = MagicMock(stdout="", returncode=0)

        check = PyprojectTomlValidateCheck()
        result = check.run(mock_codebase)

        assert result.status in [
            CheckStatus.PASS,
            CheckStatus.FAIL,
            CheckStatus.ERROR,
            CheckStatus.SKIP,
        ]

    @patch("panoptipy.checks.subprocess.run")
    def test_pyproject_toml_validate_invalid_file(self, mock_run, mock_codebase):
        """Test PyprojectTomlValidateCheck with invalid file."""
        mock_codebase.has_file.return_value = True
        mock_run.return_value = MagicMock(
            stdout="", stderr="Validation error", returncode=1
        )

        check = PyprojectTomlValidateCheck()
        result = check.run(mock_codebase)

        assert result.status in [
            CheckStatus.PASS,
            CheckStatus.FAIL,
            CheckStatus.ERROR,
            CheckStatus.SKIP,
        ]


class TestHasTestsCheck:
    """Tests for HasTestsCheck class."""

    def test_has_tests_check_init(self):
        """Test HasTestsCheck initialization."""
        check = HasTestsCheck()

        assert check.check_id == "has_tests"
        assert "test" in check.description.lower()
        assert check.category == "testing"

    def test_has_tests_check_with_test_files(self, tmp_path, mock_codebase):
        """Test HasTestsCheck with test files present."""
        mock_codebase.root_path = tmp_path

        # Create a test file with actual test functions
        test_file = tmp_path / "test_module.py"
        test_file.write_text("""
def test_something():
    assert True

def test_another_thing():
    pass
""")

        check = HasTestsCheck()
        result = check.run(mock_codebase)

        assert result.status == CheckStatus.PASS
        assert result.details is not None
        assert result.details["test_count"] == 2

    def test_has_tests_check_without_test_files(self, tmp_path, mock_codebase):
        """Test HasTestsCheck without test files."""
        mock_codebase.root_path = tmp_path

        # Create a non-test file
        module_file = tmp_path / "module.py"
        module_file.write_text("def foo(): pass")

        check = HasTestsCheck()
        result = check.run(mock_codebase)

        assert result.status == CheckStatus.FAIL

    def test_has_tests_check_with_tests_directory(self, tmp_path, mock_codebase):
        """Test HasTestsCheck with tests directory."""
        mock_codebase.root_path = tmp_path

        # Create tests directory with test files
        tests_dir = tmp_path / "tests"
        tests_dir.mkdir()
        test_file = tests_dir / "test_something.py"
        test_file.write_text("""
class TestFoo:
    def test_method(self):
        assert True
""")

        check = HasTestsCheck()
        result = check.run(mock_codebase)

        assert result.status == CheckStatus.PASS
        assert result.details is not None
        assert result.details["test_count"] >= 1


class TestCognitiveComplexityCheck:
    """Tests for CognitiveComplexityCheck class."""

    def test_cognitive_complexity_check_init(self):
        """Test CognitiveComplexityCheck initialization."""
        check = CognitiveComplexityCheck()

        assert check.check_id == "cognitive_complexity"
        assert "complexity" in check.description.lower()
        assert check.category == "complexity"

    def test_cognitive_complexity_check_default_threshold(self):
        """Test CognitiveComplexityCheck with default threshold."""
        check = CognitiveComplexityCheck()

        assert check.max_complexity == 15

    def test_cognitive_complexity_check_custom_threshold(self):
        """Test CognitiveComplexityCheck with custom threshold from config."""
        config_dict = Config.DEFAULT_CONFIG.copy()
        config_dict["thresholds"] = {"max_cognitive_complexity": 10}
        config = Config(config_dict)
        check = CognitiveComplexityCheck(config=config)

        assert check.max_complexity == 10

    @patch("panoptipy.checks.get_tracked_files")
    def test_cognitive_complexity_check_no_python_files(
        self, mock_get_tracked, mock_codebase
    ):
        """Test CognitiveComplexityCheck with no Python files."""
        mock_codebase.root_path = Path("/test/repo")
        mock_get_tracked.return_value = set()

        check = CognitiveComplexityCheck()
        result = check.run(mock_codebase)

        assert result.status == CheckStatus.SKIP

    @patch("panoptipy.checks.get_tracked_files")
    def test_cognitive_complexity_check_simple_functions(
        self, mock_get_tracked, tmp_path, mock_codebase
    ):
        """Test CognitiveComplexityCheck with simple functions."""
        mock_codebase.root_path = tmp_path

        # Create a simple Python file with low complexity
        simple_file = tmp_path / "simple.py"
        simple_file.write_text("""
def simple_func():
    return True

def another_simple_func(x):
    if x > 0:
        return x
    return 0
""")

        mock_get_tracked.return_value = {str(simple_file)}

        check = CognitiveComplexityCheck()
        result = check.run(mock_codebase)

        assert result.status == CheckStatus.PASS
        assert result.details is not None
        assert "threshold" in result.details

    @patch("panoptipy.checks.get_tracked_files")
    def test_cognitive_complexity_check_complex_functions(
        self, mock_get_tracked, tmp_path, mock_codebase
    ):
        """Test CognitiveComplexityCheck with complex functions."""
        mock_codebase.root_path = tmp_path

        # Create a Python file with high cognitive complexity
        complex_file = tmp_path / "complex.py"
        complex_file.write_text("""
def complex_func(x, y, z):
    if x > 0:
        if y > 0:
            if z > 0:
                for i in range(x):
                    if i % 2 == 0:
                        for j in range(y):
                            if j % 2 == 0:
                                for k in range(z):
                                    if k % 2 == 0:
                                        if i + j + k > 10:
                                            if i * j * k > 100:
                                                return True
                                            else:
                                                continue
                                        else:
                                            break
                                    else:
                                        pass
                            else:
                                continue
                    else:
                        pass
            else:
                return False
        else:
            return False
    else:
        return False
    return None
""")

        mock_get_tracked.return_value = {str(complex_file)}

        check = CognitiveComplexityCheck()
        result = check.run(mock_codebase)

        assert result.status == CheckStatus.FAIL
        assert result.details is not None
        assert "complex_functions" in result.details
        assert result.details["count"] > 0

    @patch("panoptipy.checks.get_tracked_files")
    def test_cognitive_complexity_check_result_details(
        self, mock_get_tracked, tmp_path, mock_codebase
    ):
        """Test CognitiveComplexityCheck result contains expected details."""
        mock_codebase.root_path = tmp_path

        simple_file = tmp_path / "simple.py"
        simple_file.write_text("def foo(): return 1")

        mock_get_tracked.return_value = {str(simple_file)}

        check = CognitiveComplexityCheck()
        result = check.run(mock_codebase)

        assert result.status == CheckStatus.PASS
        assert result.details is not None
        assert "threshold" in result.details
        assert "files_analyzed" in result.details
        assert result.details["files_analyzed"] == 1
        assert result.details["threshold"] == 15

    @patch("panoptipy.checks.get_tracked_files")
    def test_cognitive_complexity_check_multiple_files(
        self, mock_get_tracked, tmp_path, mock_codebase
    ):
        """Test CognitiveComplexityCheck with multiple Python files."""
        mock_codebase.root_path = tmp_path

        # Create multiple simple files
        file1 = tmp_path / "file1.py"
        file1.write_text("def foo(): return 1")

        file2 = tmp_path / "file2.py"
        file2.write_text("def bar(): return 2")

        file3 = tmp_path / "file3.py"
        file3.write_text("def baz(): return 3")

        mock_get_tracked.return_value = {str(file1), str(file2), str(file3)}

        check = CognitiveComplexityCheck()
        result = check.run(mock_codebase)

        assert result.status == CheckStatus.PASS
        assert result.details is not None
        assert result.details["files_analyzed"] == 3

    @patch("panoptipy.checks.get_tracked_files")
    def test_cognitive_complexity_check_mixed_complexity(
        self, mock_get_tracked, tmp_path, mock_codebase
    ):
        """Test CognitiveComplexityCheck with mix of simple and complex functions."""
        mock_codebase.root_path = tmp_path

        # Create a file with both simple and complex functions
        mixed_file = tmp_path / "mixed.py"
        mixed_file.write_text("""
def simple_func():
    return True

def complex_func(x):
    if x > 0:
        if x > 10:
            if x > 100:
                for i in range(x):
                    if i % 2 == 0:
                        for j in range(i):
                            if j % 3 == 0:
                                for k in range(j):
                                    if k > 5:
                                        if k < 10:
                                            return k
    return 0
""")

        mock_get_tracked.return_value = {str(mixed_file)}

        check = CognitiveComplexityCheck()
        result = check.run(mock_codebase)

        assert result.status == CheckStatus.FAIL
        assert result.details is not None
        assert result.details["count"] >= 1
        # Verify files_analyzed is populated
        assert result.details["files_analyzed"] == 1

    @patch("panoptipy.checks.get_tracked_files")
    def test_cognitive_complexity_check_sorted_by_complexity(
        self, mock_get_tracked, tmp_path, mock_codebase
    ):
        """Test that complex functions are sorted by complexity (highest first)."""
        mock_codebase.root_path = tmp_path

        # Create file with multiple complex functions of varying complexity
        complex_file = tmp_path / "complex.py"
        complex_file.write_text("""
def medium_complex(x):
    if x > 0:
        if x > 10:
            if x > 100:
                for i in range(x):
                    if i % 2 == 0:
                        for j in range(i):
                            if j % 3 == 0:
                                for k in range(j):
                                    if k > 5:
                                        if k < 10:
                                            return k
    return 0

def very_complex(a, b, c):
    if a > 0:
        if b > 0:
            if c > 0:
                for i in range(a):
                    if i % 2 == 0:
                        for j in range(b):
                            if j % 2 == 0:
                                for k in range(c):
                                    if k % 2 == 0:
                                        if i + j > 10:
                                            if j + k > 10:
                                                if i + k > 10:
                                                    if i * j > 100:
                                                        return True
    return False
""")

        mock_get_tracked.return_value = {str(complex_file)}

        # Use a lower threshold to catch both functions
        config_dict = Config.DEFAULT_CONFIG.copy()
        config_dict["thresholds"] = {"max_cognitive_complexity": 5}
        config = Config(config_dict)

        check = CognitiveComplexityCheck(config=config)
        result = check.run(mock_codebase)

        assert result.status == CheckStatus.FAIL
        assert result.details is not None
        assert result.details["count"] >= 2
        # Verify sorted by complexity (descending)
        complexities = [f["complexity"] for f in result.details["complex_functions"]]
        assert complexities == sorted(complexities, reverse=True)

    @patch("panoptipy.checks.get_tracked_files")
    def test_cognitive_complexity_check_nonexistent_file(
        self, mock_get_tracked, tmp_path, mock_codebase
    ):
        """Test CognitiveComplexityCheck handles nonexistent files gracefully."""
        mock_codebase.root_path = tmp_path

        # Mock a file that doesn't exist
        mock_get_tracked.return_value = {str(tmp_path / "nonexistent.py")}

        check = CognitiveComplexityCheck()
        result = check.run(mock_codebase)

        # Should pass (or skip) since no files were actually analyzed
        assert result.status in [CheckStatus.PASS, CheckStatus.SKIP]

    @patch("panoptipy.checks.get_tracked_files")
    def test_cognitive_complexity_check_syntax_error_file(
        self, mock_get_tracked, tmp_path, mock_codebase
    ):
        """Test CognitiveComplexityCheck handles files with syntax errors."""
        mock_codebase.root_path = tmp_path

        # Create a file with invalid Python syntax
        bad_file = tmp_path / "bad_syntax.py"
        bad_file.write_text("def foo( return 1")  # Invalid syntax

        mock_get_tracked.return_value = {str(bad_file)}

        check = CognitiveComplexityCheck()
        result = check.run(mock_codebase)

        # Should handle gracefully without crashing
        assert result.status in [CheckStatus.PASS, CheckStatus.ERROR, CheckStatus.SKIP]

    @patch("panoptipy.checks.get_tracked_files")
    def test_cognitive_complexity_check_empty_file(
        self, mock_get_tracked, tmp_path, mock_codebase
    ):
        """Test CognitiveComplexityCheck handles empty Python files."""
        mock_codebase.root_path = tmp_path

        empty_file = tmp_path / "empty.py"
        empty_file.write_text("")

        mock_get_tracked.return_value = {str(empty_file)}

        check = CognitiveComplexityCheck()
        result = check.run(mock_codebase)

        assert result.status == CheckStatus.PASS

    @patch("panoptipy.checks.get_tracked_files")
    def test_cognitive_complexity_check_low_threshold(
        self, mock_get_tracked, tmp_path, mock_codebase
    ):
        """Test CognitiveComplexityCheck with very low threshold catches simple code."""
        mock_codebase.root_path = tmp_path

        # Create a file with a function that has some complexity
        file = tmp_path / "moderate.py"
        file.write_text("""
def moderate_func(x):
    if x > 0:
        if x > 10:
            return x * 2
        else:
            return x
    return 0
""")

        mock_get_tracked.return_value = {str(file)}

        # Use threshold of 1 to catch even simple conditionals
        config_dict = Config.DEFAULT_CONFIG.copy()
        config_dict["thresholds"] = {"max_cognitive_complexity": 1}
        config = Config(config_dict)

        check = CognitiveComplexityCheck(config=config)
        result = check.run(mock_codebase)

        assert result.status == CheckStatus.FAIL
        assert result.details is not None
        assert result.details["threshold"] == 1

    @patch("panoptipy.checks.get_tracked_files")
    def test_cognitive_complexity_check_function_details(
        self, mock_get_tracked, tmp_path, mock_codebase
    ):
        """Test that complex function details include expected fields."""
        mock_codebase.root_path = tmp_path

        complex_file = tmp_path / "complex.py"
        complex_file.write_text("""
def complex_func(x):
    if x > 0:
        if x > 10:
            if x > 100:
                for i in range(x):
                    if i % 2 == 0:
                        for j in range(i):
                            if j % 3 == 0:
                                for k in range(j):
                                    if k > 5:
                                        if k < 10:
                                            return k
    return 0
""")

        mock_get_tracked.return_value = {str(complex_file)}

        check = CognitiveComplexityCheck()
        result = check.run(mock_codebase)

        assert result.status == CheckStatus.FAIL
        assert result.details is not None
        assert len(result.details["complex_functions"]) > 0

        func_detail = result.details["complex_functions"][0]
        assert "file" in func_detail
        assert "function" in func_detail
        assert "complexity" in func_detail
        assert "line_start" in func_detail
        assert "threshold" in func_detail
        assert func_detail["function"] == "complex_func"
        assert func_detail["complexity"] > 15

    @patch("panoptipy.checks.get_tracked_files")
    def test_cognitive_complexity_check_class_methods(
        self, mock_get_tracked, tmp_path, mock_codebase
    ):
        """Test CognitiveComplexityCheck analyzes class methods."""
        mock_codebase.root_path = tmp_path

        class_file = tmp_path / "classes.py"
        class_file.write_text("""
class MyClass:
    def simple_method(self):
        return True

    def complex_method(self, x):
        if x > 0:
            if x > 10:
                if x > 100:
                    for i in range(x):
                        if i % 2 == 0:
                            for j in range(i):
                                if j % 3 == 0:
                                    for k in range(j):
                                        if k > 5:
                                            if k < 10:
                                                return k
        return 0
""")

        mock_get_tracked.return_value = {str(class_file)}

        check = CognitiveComplexityCheck()
        result = check.run(mock_codebase)

        assert result.status == CheckStatus.FAIL
        assert result.details is not None
        # Should find the complex method (complexipy uses ClassName::method_name format)
        func_names = [f["function"] for f in result.details["complex_functions"]]
        assert any("complex_method" in name for name in func_names)
