"""Core scanning engine for panoptipy.

This module contains the main scanning logic, including the Codebase class for representing
a code repository and the Scanner class that runs checks against the codebase.
"""

import ast
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from .checks.base import CheckResult, CheckStatus
from .config import Config
from .rating import CodebaseRating, RatingCalculator
from .registry import CheckRegistry

logger = logging.getLogger(__name__)


@dataclass
class FileInfo:
    """Information about a file in the codebase."""

    path: Path
    content: str
    is_binary: bool
    size_bytes: int

    @property
    def extension(self) -> str:
        """Get the file extension."""
        return self.path.suffix.lower()

    @property
    def is_python(self) -> bool:
        """Check if this is a Python file."""
        return self.extension == ".py"

    @property
    def line_count(self) -> int:
        """Count the number of lines in the file."""
        return len(self.content.splitlines())


class PythonModule:
    """Represents a Python module for analysis."""

    def __init__(self, file_info: FileInfo):
        self.file_info = file_info
        self.path = file_info.path
        self.content = file_info.content
        self._ast: Optional[ast.Module] = None

    @property
    def ast(self) -> ast.Module:
        """Get the AST for this module, parsing if necessary."""
        if self._ast is None:
            try:
                self._ast = ast.parse(self.content)
            except SyntaxError:
                logger.warning(f"Failed to parse {self.path} as Python")
                # Create a minimal AST for analysis
                self._ast = ast.Module(body=[], type_ignores=[])
        return self._ast

    def get_public_items(self) -> List[Dict[str, Any]]:
        """Get all public functions, classes, and methods."""
        items = []

        for node in ast.walk(self.ast):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                # Skip private/internal items
                if node.name.startswith("_") and not (
                    node.name.startswith("__") and node.name.endswith("__")
                ):
                    continue

                # Get docstring if it exists
                docstring = ast.get_docstring(node)

                items.append(
                    {
                        "name": node.name,
                        "type": type(node).__name__,
                        "lineno": node.lineno,
                        "docstring": docstring,
                    }
                )

        return items


class Codebase:
    """Represents a full codebase for analysis."""

    def __init__(self, root_path: Path):
        """Initialize a codebase from a root directory.

        Args:
            root_path: Path to the root of the codebase
        """
        self.root_path = root_path.absolute()
        self._files: Dict[Path, FileInfo] = {}
        self._python_modules: Dict[Path, PythonModule] = {}
        self._ignored_patterns: Set[str] = set()

        # Common patterns to ignore
        self.add_ignore_pattern("__pycache__")
        self.add_ignore_pattern(".git")
        self.add_ignore_pattern(".venv")
        self.add_ignore_pattern("venv")
        self.add_ignore_pattern(".pytest_cache")
        self.add_ignore_pattern(".mypy_cache")
        self.add_ignore_pattern(".nox")
        self.add_ignore_pattern(".tox")
        self.add_ignore_pattern("build")
        self.add_ignore_pattern("dist")
        self.add_ignore_pattern(".eggs")
        self.add_ignore_pattern("*.egg-info")
        self.add_ignore_pattern(".coverage")
        self.add_ignore_pattern("htmlcov")
        self.add_ignore_pattern(".idea")
        self.add_ignore_pattern(".vs")
        self.add_ignore_pattern(".vscode")
        self.add_ignore_pattern("node_modules")

    def add_ignore_pattern(self, pattern: str) -> None:
        """Add a pattern to ignore when scanning files.

        Args:
            pattern: Directory or file pattern to ignore
        """
        self._ignored_patterns.add(pattern)

    def scan_files(self) -> None:
        """Scan the codebase to find and load all files."""
        self._files = {}

        for root, dirs, files in os.walk(self.root_path):
            # Filter out ignored directories
            dirs[:] = [d for d in dirs if d not in self._ignored_patterns]

            for file in files:
                path = Path(root) / file
                rel_path = path.relative_to(self.root_path)

                # Skip ignored files
                if any(pattern in str(rel_path) for pattern in self._ignored_patterns):
                    continue

                try:
                    is_binary = False
                    size_bytes = path.stat().st_size

                    # Try to read as text, fall back to binary
                    try:
                        content = path.read_text(encoding="utf-8")
                    except UnicodeDecodeError:
                        content = ""
                        is_binary = True

                    file_info = FileInfo(
                        path=path,
                        content=content,
                        is_binary=is_binary,
                        size_bytes=size_bytes,
                    )
                    self._files[rel_path] = file_info

                    # Create Python module if it's a Python file
                    if not is_binary and path.suffix.lower() == ".py":
                        self._python_modules[rel_path] = PythonModule(file_info)

                except Exception as e:
                    logger.warning(f"Failed to read {path}: {e}")

    def get_all_files(self) -> List[FileInfo]:
        """Get information about all files in the codebase.

        Returns:
            List of FileInfo objects for all files
        """
        if not self._files:
            self.scan_files()
        return list(self._files.values())

    def get_python_modules(self) -> List[PythonModule]:
        """Get all Python modules in the codebase.

        Returns:
            List of PythonModule objects
        """
        if not self._python_modules:
            self.scan_files()
        return list(self._python_modules.values())

    def has_file(self, filename: str) -> bool:
        """Check if a file exists in the codebase.

        Args:
            filename: Name of the file to check for

        Returns:
            True if the file exists, False otherwise
        """
        if not self._files:
            self.scan_files()

        return any(f.path.name == filename for f in self._files.values())

    def get_file_by_name(self, filename: str) -> Optional[FileInfo]:
        """Get a file by name.

        Args:
            filename: Name of the file to get

        Returns:
            FileInfo for the file, or None if not found
        """
        if not self._files:
            self.scan_files()

        for file in self._files.values():
            if file.path.name == filename:
                return file

        return None

    def find_files_by_extension(self, extension: str) -> List[FileInfo]:
        """Find all files with a specific extension.

        Args:
            extension: File extension to search for (e.g., '.py')

        Returns:
            List of FileInfo objects matching the extension
        """
        if not extension.startswith("."):
            extension = f".{extension}"

        return [
            f
            for f in self.get_all_files()
            if f.path.suffix.lower() == extension.lower()
        ]


class Scanner:
    """Main scanner that runs checks against a codebase."""

    def __init__(self, registry: CheckRegistry, config: Config):
        """Initialize a scanner with a check registry and configuration.

        Args:
            registry: Registry containing checks to run
            config: Configuration for the scanner
        """
        self.registry = registry
        self.config = config
        self.rating_calculator = RatingCalculator(config)

    def _get_enabled_checks(self) -> List[Any]:
        """Get the list of enabled checks based on configuration.

        Returns:
            List of Check objects to run
        """
        all_checks = list(self.registry.checks.values())

        # Get enabled/disabled check IDs from config
        enabled_patterns = self.config.get_check_patterns("enabled")
        disabled_patterns = self.config.get_check_patterns("disabled")

        # Filter checks based on patterns
        enabled_checks = []
        for check in all_checks:
            # Skip if explicitly disabled
            if any(
                pattern_matches(pattern, check.check_id)
                for pattern in disabled_patterns
            ):
                logger.debug(f"Check {check.check_id} is disabled by configuration")
                continue

            # Include if enabled
            if any(
                pattern_matches(pattern, check.check_id) for pattern in enabled_patterns
            ):
                enabled_checks.append(check)

        logger.info(f"Running {len(enabled_checks)} enabled checks")
        return enabled_checks

    def scan(self, path: Path) -> List[CheckResult]:
        """Scan a codebase and run all enabled checks.

        Args:
            path: Path to the codebase to scan

        Returns:
            List of check results
        """
        logger.info(f"Starting scan of {path}")

        # Create codebase object and scan files
        codebase = Codebase(path)
        codebase.scan_files()

        logger.info(f"Found {len(codebase.get_all_files())} files in codebase")

        # Get enabled checks
        checks = self._get_enabled_checks()

        # Run all checks
        results = []
        for check in checks:
            try:
                logger.debug(f"Running check: {check.check_id}")
                result = check.run(codebase)
                results.append(result)
                logger.debug(f"Check {check.check_id} result: {result.status}")
            except Exception as e:
                logger.error(f"Error running check {check.check_id}: {e}")
                # Create a failure result for the check
                results.append(
                    CheckResult(
                        check_id=check.check_id,
                        status=CheckStatus.ERROR,
                        message=f"Check failed with error: {str(e)}",
                    )
                )

        return results

    def rate(self, results: List[CheckResult]) -> CodebaseRating:
        """Calculate the overall rating for a codebase based on check results.

        Args:
            results: List of check results

        Returns:
            Overall rating for the codebase
        """
        return self.rating_calculator.calculate_rating(results)


def pattern_matches(pattern: str, check_id: str) -> bool:
    """Check if a pattern matches a check ID.

    Supports wildcards with * character.

    Args:
        pattern: Pattern to match against (may contain * wildcards)
        check_id: Check ID to test

    Returns:
        True if the pattern matches the check ID
    """
    if pattern == "*":
        return True

    if "*" not in pattern:
        return pattern == check_id

    # Convert glob pattern to regex
    import re

    regex_pattern = "^" + re.escape(pattern).replace("\\*", ".*") + "$"
    return bool(re.match(regex_pattern, check_id))
