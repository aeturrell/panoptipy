"""Core scanning engine for panoptipy.

This module contains the main scanning logic, including the Codebase class for representing
a code repository and the Scanner class that runs checks against the codebase.
"""

import ast
import logging
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

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
    """Represents a codebase for analysis, including only files tracked by Git."""

    def __init__(self, root_path: Path):
        """Initialize a codebase from a root directory.

        Only files tracked by Git within this path will be included.

        Args:
            root_path: Path to the root of the codebase (must be within a Git repository).

        Raises:
            FileNotFoundError: If the root_path does not exist.
            RuntimeError: If the root_path is not part of a Git repository or Git is not found.
        """
        if not root_path.is_dir():
            raise FileNotFoundError(
                f"Root path does not exist or is not a directory: {root_path}"
            )

        self.root_path = root_path.absolute()
        self._files: Dict[Path, FileInfo] = {}
        self._python_modules: Dict[Path, PythonModule] = {}

        # Check if it's a Git repository
        if not self._is_git_repository():
            raise RuntimeError(
                f"Path is not part of a Git repository: {self.root_path}"
            )

    def _is_git_repository(self) -> bool:
        """Check if the root_path is inside a Git repository."""
        try:
            result = subprocess.run(
                ["git", "rev-parse", "--is-inside-work-tree"],
                cwd=self.root_path,
                capture_output=True,
                text=True,
                check=True,
                encoding="utf-8",
            )
            return result.stdout.strip() == "true"
        except (FileNotFoundError, subprocess.CalledProcessError):
            # Git not found or not a git repo
            return False

    def scan_files(self) -> None:
        """Scan the codebase using 'git ls-files' to find and load tracked files."""
        self._files = {}
        self._python_modules = {}

        try:
            # Use 'git ls-files -z' to list all tracked files, null-terminated
            # -z handles filenames with spaces or special characters safely.
            # --cached lists files in the index (staged)
            # --others lists untracked files (we don't want these)
            # --exclude-standard respects .gitignore, .git/info/exclude etc.
            # Running 'git ls-files -z' gets all files tracked by git
            result = subprocess.run(
                ["git", "ls-files", "-z"],
                cwd=self.root_path,
                capture_output=True,
                check=True,  # Raise CalledProcessError if git command fails
                encoding="utf-8",  # Git typically uses UTF-8 for file paths
                errors="surrogateescape",  # Handle potential non-UTF8 paths gracefully
            )

            # Split the null-terminated string into relative paths
            relative_paths = result.stdout.strip("\0").split("\0")

            for rel_path_str in relative_paths:
                if not rel_path_str:  # Skip empty strings if any
                    continue

                # Decode potential surrogate escapes back if needed, although usually paths are fine
                # rel_path_str = os.fsdecode(rel_path_str.encode('utf-8', 'surrogateescape')) # May not be needed

                rel_path = Path(rel_path_str)
                path = self.root_path / rel_path

                # Although git ls-files lists tracked files, double-check existence
                # in case of weird states (e.g., deleted but still tracked before commit)
                if not path.is_file():
                    logger.warning(f"File listed by git ls-files not found: {path}")
                    continue

                try:
                    is_binary = False
                    size_bytes = path.stat().st_size

                    # Try to read as text, fall back if it fails (likely binary)
                    try:
                        # Use git's preferred encoding detection logic if possible,
                        # otherwise fallback to utf-8 attempt. For simplicity,
                        # we stick to the original utf-8 attempt here.
                        content = path.read_text(encoding="utf-8")
                    except UnicodeDecodeError:
                        logger.debug(
                            f"Could not decode {path} as UTF-8, treating as binary."
                        )
                        content = (
                            ""  # Or read as bytes if needed by FileInfo/PythonModule
                        )
                        is_binary = True
                    except OSError as e:  # Handle potential read errors
                        logger.warning(f"Could not read file {path}: {e}")
                        continue  # Skip this file

                    file_info = FileInfo(
                        path=path,  # Store absolute path maybe? Or keep consistent with key? Let's use absolute path here.
                        content=content,
                        is_binary=is_binary,
                        size_bytes=size_bytes,
                    )
                    # Use relative path as the key for consistency
                    self._files[rel_path] = file_info

                    # Create Python module if it's a Python file
                    if not is_binary and path.suffix.lower() == ".py":
                        self._python_modules[rel_path] = PythonModule(file_info)

                except Exception as e:
                    # Catch broader exceptions during file processing
                    logger.warning(f"Failed to process file {path}: {e}")

        except FileNotFoundError:
            logger.error(
                "Git command not found. Please ensure Git is installed and in PATH."
            )
            raise RuntimeError("Git command not found.")
        except subprocess.CalledProcessError as e:
            logger.error(f"Git command failed: {e.stderr}")
            # Raise specific error or handle depending on desired behaviour
            raise RuntimeError(f"Git command failed: {e.stderr}")
        except Exception as e:
            logger.exception(f"An unexpected error occurred during file scanning: {e}")
            raise  # Re-raise unexpected exceptions

    def get_all_files(self) -> List[FileInfo]:
        """Get information about all files tracked by Git in the codebase.

        Returns:
            List of FileInfo objects for all tracked files.
        """
        if not self._files:
            self.scan_files()
        return list(self._files.values())

    def get_python_modules(self) -> List[PythonModule]:
        """Get all Python modules tracked by Git in the codebase.

        Returns:
            List of PythonModule objects.
        """
        if not self._python_modules:
            # Ensure files are scanned first if modules are requested directly
            self.scan_files()
        return list(self._python_modules.values())

    # --- Methods below generally don't need changes, but rely on _files populated by scan_files ---

    def has_file(self, filename: str) -> bool:
        """Check if a file with the given name exists in the tracked files.

        Args:
            filename: Base name of the file to check for (e.g., 'setup.py').

        Returns:
            True if a tracked file with that name exists, False otherwise.
        """
        if not self._files:
            self.scan_files()
        # Use the keys (relative paths) for checking
        return any(rel_path.name == filename for rel_path in self._files.keys())

    def get_file_by_name(self, filename: str) -> Optional[FileInfo]:
        """Get a tracked file by its base name.

        Note: If multiple files with the same name exist in different
              directories, this returns the first one encountered.

        Args:
            filename: Base name of the file to get (e.g., 'requirements.txt').

        Returns:
            FileInfo for the first tracked file found with that name, or None if not found.
        """
        if not self._files:
            self.scan_files()

        for rel_path, file_info in self._files.items():
            if rel_path.name == filename:
                return file_info
        return None

    def find_files_by_extension(self, extension: str) -> List[FileInfo]:
        """Find all tracked files with a specific extension.

        Args:
            extension: File extension to search for (e.g., '.py', 'py').

        Returns:
            List of FileInfo objects for tracked files matching the extension.
        """
        if not extension.startswith("."):
            extension = f".{extension}"

        # Ensure files are loaded
        all_files = self.get_all_files()

        return [
            f
            for f in all_files
            # Check suffix on the relative path used as key, or the absolute path in FileInfo
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
