"""Tests for core.py module."""

import ast
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import pytest

from panoptipy.checks import CheckResult, CheckStatus
from panoptipy.config import Config
from panoptipy.core import (
    Codebase,
    FileInfo,
    PythonModule,
    Scanner,
    _scan_single_repo,
    pattern_matches,
)
from panoptipy.rating import CodebaseRating
from panoptipy.registry import CheckRegistry


@pytest.fixture
def file_info(tmp_path):
    """Create a sample FileInfo object."""
    test_file = tmp_path / "test.py"
    content = "def test():\n    pass\n"
    test_file.write_text(content)

    return FileInfo(
        path=test_file,
        content=content,
        is_binary=False,
        size_bytes=len(content),
    )


@pytest.fixture
def python_module(file_info):
    """Create a sample PythonModule object."""
    return PythonModule(file_info)


class TestFileInfo:
    """Tests for FileInfo dataclass."""

    def test_file_info_creation(self, file_info):
        """Test FileInfo object creation."""
        assert isinstance(file_info.path, Path)
        assert isinstance(file_info.content, str)
        assert file_info.is_binary is False
        assert file_info.size_bytes > 0

    def test_file_info_extension(self, tmp_path):
        """Test FileInfo extension property."""
        py_file = tmp_path / "test.py"
        py_file.write_text("# test")

        info = FileInfo(path=py_file, content="# test", is_binary=False, size_bytes=6)
        assert info.extension == ".py"

    def test_file_info_is_python(self, tmp_path):
        """Test FileInfo is_python property."""
        py_file = tmp_path / "test.py"
        txt_file = tmp_path / "test.txt"

        py_info = FileInfo(path=py_file, content="", is_binary=False, size_bytes=0)
        txt_info = FileInfo(path=txt_file, content="", is_binary=False, size_bytes=0)

        assert py_info.is_python is True
        assert txt_info.is_python is False

    def test_file_info_line_count(self, file_info):
        """Test FileInfo line_count property."""
        assert file_info.line_count == 2


class TestPythonModule:
    """Tests for PythonModule class."""

    def test_python_module_creation(self, python_module):
        """Test PythonModule object creation."""
        assert isinstance(python_module.file_info, FileInfo)
        assert isinstance(python_module.path, Path)
        assert isinstance(python_module.content, str)

    def test_python_module_ast(self, python_module):
        """Test PythonModule ast property."""
        module_ast = python_module.ast
        assert isinstance(module_ast, ast.Module)
        assert len(module_ast.body) > 0

    def test_python_module_ast_invalid_syntax(self, tmp_path):
        """Test PythonModule ast property with invalid syntax."""
        invalid_file = tmp_path / "invalid.py"
        invalid_content = "def test(\n  pass"  # Invalid syntax
        invalid_file.write_text(invalid_content)

        info = FileInfo(
            path=invalid_file,
            content=invalid_content,
            is_binary=False,
            size_bytes=len(invalid_content),
        )
        module = PythonModule(info)

        # Should return a minimal AST without raising an error
        module_ast = module.ast
        assert isinstance(module_ast, ast.Module)
        assert len(module_ast.body) == 0

    def test_python_module_get_public_items(self, tmp_path):
        """Test getting public items from a Python module."""
        code = '''
def public_function():
    """A public function."""
    pass

def _private_function():
    """A private function."""
    pass

class PublicClass:
    """A public class."""
    pass

class _PrivateClass:
    """A private class."""
    pass
'''
        py_file = tmp_path / "module.py"
        py_file.write_text(code)

        info = FileInfo(path=py_file, content=code, is_binary=False, size_bytes=len(code))
        module = PythonModule(info)

        public_items = module.get_public_items()

        # Should have 2 public items (function and class)
        assert len(public_items) == 2

        # Check that public items are included
        names = [item["name"] for item in public_items]
        assert "public_function" in names
        assert "PublicClass" in names

        # Check that private items are excluded
        assert "_private_function" not in names
        assert "_PrivateClass" not in names

    def test_python_module_get_public_items_with_docstrings(self, tmp_path):
        """Test getting public items with docstrings."""
        code = '''
def documented_function():
    """This function has a docstring."""
    pass

def undocumented_function():
    pass
'''
        py_file = tmp_path / "module.py"
        py_file.write_text(code)

        info = FileInfo(path=py_file, content=code, is_binary=False, size_bytes=len(code))
        module = PythonModule(info)

        public_items = module.get_public_items()

        # Find the documented function
        documented = [item for item in public_items if item["name"] == "documented_function"][0]
        undocumented = [item for item in public_items if item["name"] == "undocumented_function"][0]

        assert documented["docstring"] == "This function has a docstring."
        assert undocumented["docstring"] is None


class TestCodebase:
    """Tests for Codebase class."""

    def test_codebase_init_with_nonexistent_path(self):
        """Test Codebase initialization with non-existent path."""
        with pytest.raises(FileNotFoundError):
            Codebase(Path("/nonexistent/path"))

    @patch("panoptipy.core.subprocess.run")
    def test_codebase_init_with_non_git_repo(self, mock_run, tmp_path):
        """Test Codebase initialization with non-git repository."""
        mock_run.side_effect = subprocess.CalledProcessError(1, "git")

        with pytest.raises(RuntimeError, match="not part of a Git repository"):
            Codebase(tmp_path)

    @patch("panoptipy.core.subprocess.run")
    def test_codebase_is_git_repository(self, mock_run, tmp_path):
        """Test _is_git_repository method."""
        mock_run.return_value = MagicMock(stdout="true\n")

        codebase = Codebase(tmp_path)
        assert codebase._is_git_repository() is True

    @patch("panoptipy.core.subprocess.run")
    def test_codebase_scan_files(self, mock_run, tmp_path):
        """Test scanning files in codebase."""
        # Mock git ls-files output
        py_file = tmp_path / "test.py"
        py_file.write_text("# test file")

        mock_run.side_effect = [
            MagicMock(stdout="true\n"),  # is_git_repository
            MagicMock(stdout=f"test.py\0"),  # ls-files
        ]

        codebase = Codebase(tmp_path)
        codebase.scan_files()

        files = codebase.get_all_files()
        assert len(files) > 0

    @patch("panoptipy.core.subprocess.run")
    def test_codebase_get_python_modules(self, mock_run, tmp_path):
        """Test getting Python modules from codebase."""
        py_file = tmp_path / "module.py"
        py_file.write_text("def test(): pass")

        mock_run.side_effect = [
            MagicMock(stdout="true\n"),
            MagicMock(stdout=f"module.py\0"),
        ]

        codebase = Codebase(tmp_path)
        modules = codebase.get_python_modules()

        assert len(modules) > 0
        assert all(isinstance(m, PythonModule) for m in modules)

    @patch("panoptipy.core.subprocess.run")
    def test_codebase_has_file(self, mock_run, tmp_path):
        """Test checking if file exists in codebase."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")

        mock_run.side_effect = [
            MagicMock(stdout="true\n"),
            MagicMock(stdout=f"test.txt\0"),
        ]

        codebase = Codebase(tmp_path)
        assert codebase.has_file("test.txt") is True
        assert codebase.has_file("nonexistent.txt") is False

    @patch("panoptipy.core.subprocess.run")
    def test_codebase_get_file_by_name(self, mock_run, tmp_path):
        """Test getting file by name."""
        test_file = tmp_path / "config.toml"
        test_file.write_text("# config")

        mock_run.side_effect = [
            MagicMock(stdout="true\n"),
            MagicMock(stdout=f"config.toml\0"),
        ]

        codebase = Codebase(tmp_path)
        file_info = codebase.get_file_by_name("config.toml")

        assert file_info is not None
        assert file_info.path.name == "config.toml"

    @patch("panoptipy.core.subprocess.run")
    def test_codebase_get_file_by_name_not_found(self, mock_run, tmp_path):
        """Test getting non-existent file by name."""
        mock_run.side_effect = [
            MagicMock(stdout="true\n"),
            MagicMock(stdout=""),
        ]

        codebase = Codebase(tmp_path)
        file_info = codebase.get_file_by_name("nonexistent.txt")

        assert file_info is None

    @patch("panoptipy.core.subprocess.run")
    def test_codebase_find_files_by_extension(self, mock_run, tmp_path):
        """Test finding files by extension."""
        py_file1 = tmp_path / "test1.py"
        py_file2 = tmp_path / "test2.py"
        txt_file = tmp_path / "test.txt"

        py_file1.write_text("# python 1")
        py_file2.write_text("# python 2")
        txt_file.write_text("text")

        mock_run.side_effect = [
            MagicMock(stdout="true\n"),
            MagicMock(stdout=f"test1.py\0test2.py\0test.txt\0"),
        ]

        codebase = Codebase(tmp_path)
        py_files = codebase.find_files_by_extension(".py")

        assert len(py_files) == 2
        assert all(f.extension == ".py" for f in py_files)

    @patch("panoptipy.core.subprocess.run")
    def test_codebase_find_files_by_extension_without_dot(self, mock_run, tmp_path):
        """Test finding files by extension without leading dot."""
        py_file = tmp_path / "test.py"
        py_file.write_text("# python")

        mock_run.side_effect = [
            MagicMock(stdout="true\n"),
            MagicMock(stdout=f"test.py\0"),
        ]

        codebase = Codebase(tmp_path)
        py_files = codebase.find_files_by_extension("py")

        assert len(py_files) == 1

    @patch("panoptipy.core.subprocess.run")
    def test_codebase_scan_files_git_not_found(self, mock_run, tmp_path):
        """Test scan_files when git is not found."""
        mock_run.side_effect = [
            MagicMock(stdout="true\n"),
            FileNotFoundError("git not found"),
        ]

        codebase = Codebase(tmp_path)

        with pytest.raises(RuntimeError, match="Git command not found"):
            codebase.scan_files()

    @patch("panoptipy.core.subprocess.run")
    def test_codebase_scan_files_binary_file(self, mock_run, tmp_path):
        """Test scanning binary files."""
        binary_file = tmp_path / "image.png"
        binary_file.write_bytes(b"\x89PNG\r\n\x1a\n")

        mock_run.side_effect = [
            MagicMock(stdout="true\n"),
            MagicMock(stdout=f"image.png\0"),
        ]

        codebase = Codebase(tmp_path)
        codebase.scan_files()

        files = codebase.get_all_files()
        png_file = [f for f in files if f.path.name == "image.png"][0]

        assert png_file.is_binary is True


class TestScanner:
    """Tests for Scanner class."""

    @pytest.fixture
    def config(self):
        """Create a test config."""
        return Config(Config.DEFAULT_CONFIG.copy())

    @pytest.fixture
    def registry(self, config):
        """Create a test registry."""
        reg = CheckRegistry(config=config)
        reg.load_builtin_checks()
        return reg

    @pytest.fixture
    def scanner(self, registry, config):
        """Create a test scanner."""
        return Scanner(registry, config)

    def test_scanner_init(self, scanner, registry, config):
        """Test Scanner initialization."""
        assert scanner.registry == registry
        assert scanner.config == config
        assert scanner.rating_calculator is not None

    def test_scanner_get_enabled_checks(self, scanner):
        """Test getting enabled checks."""
        checks = scanner._get_enabled_checks()

        assert isinstance(checks, list)
        assert len(checks) > 0

    def test_scanner_get_enabled_checks_with_disabled(self, config):
        """Test getting enabled checks with some disabled."""
        config_dict = Config.DEFAULT_CONFIG.copy()
        config_dict["checks"]["disabled"] = ["docstrings"]
        config = Config(config_dict)

        registry = CheckRegistry(config=config)
        registry.load_builtin_checks()

        scanner = Scanner(registry, config)
        checks = scanner._get_enabled_checks()

        # docstrings should be disabled
        check_ids = [c.check_id for c in checks]
        assert "docstrings" not in check_ids

    @patch("panoptipy.core.Codebase")
    def test_scanner_scan(self, mock_codebase_cls, scanner, tmp_path):
        """Test scanning a codebase."""
        mock_codebase = MagicMock()
        mock_codebase.get_all_files.return_value = []
        mock_codebase_cls.return_value = mock_codebase

        results = scanner.scan(tmp_path)

        assert isinstance(results, list)
        mock_codebase.scan_files.assert_called_once()

    @patch("panoptipy.core.Codebase")
    def test_scanner_scan_with_check_error(self, mock_codebase_cls, scanner, tmp_path):
        """Test scanning when a check raises an error."""
        mock_codebase = MagicMock()
        mock_codebase.get_all_files.return_value = []
        mock_codebase_cls.return_value = mock_codebase

        # Make one check raise an error
        scanner.registry.checks["docstrings"].run = Mock(side_effect=Exception("Test error"))

        results = scanner.scan(tmp_path)

        # Should have error results for failed checks
        error_results = [r for r in results if r.status == CheckStatus.ERROR]
        assert len(error_results) > 0

    def test_scanner_rate(self, scanner):
        """Test rating calculation."""
        results = [
            CheckResult("check1", CheckStatus.PASS, "Pass"),
            CheckResult("check2", CheckStatus.PASS, "Pass"),
        ]

        rating = scanner.rate(results)

        assert isinstance(rating, CodebaseRating)

    @patch("panoptipy.core.Codebase")
    def test_scanner_scan_multiple(self, mock_codebase_cls, scanner, tmp_path):
        """Test scanning multiple repositories."""
        mock_codebase = MagicMock()
        mock_codebase.get_all_files.return_value = []
        mock_codebase_cls.return_value = mock_codebase

        path1 = tmp_path / "repo1"
        path2 = tmp_path / "repo2"
        path1.mkdir()
        path2.mkdir()

        results = scanner.scan_multiple([path1, path2])

        assert isinstance(results, dict)
        assert len(results) == 2
        assert path1 in results
        assert path2 in results

    @patch("panoptipy.core.Codebase")
    def test_scanner_scan_multiple_with_error(self, mock_codebase_cls, scanner, tmp_path):
        """Test scanning multiple repositories when one fails."""
        # Make the first scan succeed and second fail
        def codebase_side_effect(path):
            if "repo2" in str(path):
                raise Exception("Scan error")
            mock = MagicMock()
            mock.get_all_files.return_value = []
            return mock

        mock_codebase_cls.side_effect = codebase_side_effect

        path1 = tmp_path / "repo1"
        path2 = tmp_path / "repo2"
        path1.mkdir()
        path2.mkdir()

        results = scanner.scan_multiple([path1, path2])

        # Should have results for both, but repo2 should be empty
        assert path1 in results
        assert path2 in results
        assert len(results[path2]) == 0


class TestPatternMatches:
    """Tests for pattern_matches function."""

    def test_pattern_matches_wildcard(self):
        """Test pattern matching with wildcard."""
        assert pattern_matches("*", "any_check") is True
        assert pattern_matches("*", "another_check") is True

    def test_pattern_matches_exact(self):
        """Test exact pattern matching."""
        assert pattern_matches("docstrings", "docstrings") is True
        assert pattern_matches("docstrings", "ruff_linting") is False

    def test_pattern_matches_prefix_wildcard(self):
        """Test pattern matching with prefix wildcard."""
        assert pattern_matches("ruff_*", "ruff_linting") is True
        assert pattern_matches("ruff_*", "ruff_format") is True
        assert pattern_matches("ruff_*", "docstrings") is False

    def test_pattern_matches_suffix_wildcard(self):
        """Test pattern matching with suffix wildcard."""
        assert pattern_matches("*_check", "test_check") is True
        assert pattern_matches("*_check", "another_check") is True
        assert pattern_matches("*_check", "docstrings") is False

    def test_pattern_matches_middle_wildcard(self):
        """Test pattern matching with middle wildcard."""
        assert pattern_matches("test_*_check", "test_something_check") is True
        assert pattern_matches("test_*_check", "test_check") is False


class TestScanSingleRepo:
    """Tests for _scan_single_repo function."""

    @patch("panoptipy.core.Scanner")
    @patch("panoptipy.core.CheckRegistry")
    def test_scan_single_repo_success(self, mock_registry_cls, mock_scanner_cls, tmp_path):
        """Test _scan_single_repo with successful scan."""
        mock_registry = MagicMock()
        mock_registry_cls.return_value = mock_registry

        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = [
            CheckResult("test", CheckStatus.PASS, "Pass")
        ]
        mock_scanner_cls.return_value = mock_scanner

        config_dict = Config.DEFAULT_CONFIG.copy()
        path, results = _scan_single_repo((tmp_path, config_dict))

        assert path == tmp_path
        assert len(results) == 1

    @patch("panoptipy.core.Config.from_dict")
    def test_scan_single_repo_error(self, mock_from_dict, tmp_path):
        """Test _scan_single_repo when an error occurs."""
        mock_from_dict.side_effect = Exception("Config error")

        config_dict = {}
        path, results = _scan_single_repo((tmp_path, config_dict))

        # Should return empty results on error
        assert path == tmp_path
        assert results == []
