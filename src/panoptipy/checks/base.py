"""Base classes for implementing checks in panoptipy."""

import ast
import os
import subprocess
import tempfile
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set, Tuple

import toml
from validate_pyproject import api, errors

# Use TYPE_CHECKING to avoid circular imports
if TYPE_CHECKING:
    from ..core import Codebase  # Only imported for type checking


class CheckStatus(Enum):
    """Status of a check run."""

    PASS = "pass"
    FAIL = "fail"
    WARNING = "warning"
    SKIP = "skip"
    ERROR = "error"  # Added for check execution errors


@dataclass
class CheckResult:
    """Result of a single code quality check."""

    check_id: str
    status: CheckStatus  # Enum: PASS, FAIL, WARNING, SKIP, ERROR
    message: str
    details: Optional[Dict[str, Any]] = None


class Check:
    """Base class for all checks."""

    def __init__(self, check_id: str, description: str):
        self.check_id = check_id
        self.description = description

    def run(self, codebase: "Codebase") -> CheckResult:
        """Run this check against a codebase."""
        raise NotImplementedError("Subclasses must implement run()")

    @property
    def category(self) -> str:
        """Category this check belongs to."""
        return "general"


class DocstringCheck(Check):
    """Check for proper docstrings in public functions and classes."""

    def __init__(self):
        super().__init__(
            check_id="docstrings",
            description="Checks that public functions and classes have docstrings (excluding tests)",
        )

    def _is_public(self, name: str) -> bool:
        """Check if an item name represents a public function/class.

        Args:
            name: Name of the function or class

        Returns:
            bool: True if the item is public (doesn't start with underscore)
        """
        return not name.startswith("_")

    def _is_test(self, name: str, module_path: str) -> bool:
        """Check if an item is a test.

        Args:
            name: Name of the function or class
            module_path: Path to the module containing the item

        Returns:
            bool: True if the item is a test
        """
        # Check if in a test file
        if any(part in str(module_path).lower() for part in ["test", "tests"]):
            return True

        # Check if name indicates a test
        return (
            name.startswith("test_")
            or name.endswith("_test")
            or name.endswith("Tests")
            or name.endswith("Test")
        )

    def run(self, codebase: "Codebase") -> CheckResult:
        missing_docstrings = []

        for module in codebase.get_python_modules():
            module_path = str(module.path)
            for item in module.get_public_items():
                # Get the name from either dict or object
                item_name = item.get("name") if isinstance(item, dict) else item.name

                # Skip if not public or if it's a test
                if not self._is_public(item_name) or self._is_test(
                    item_name, module_path
                ):
                    continue

                # Get docstring from either dict or object
                docstring = (
                    item.get("docstring") if isinstance(item, dict) else item.docstring
                )

                if not docstring:
                    missing_docstrings.append(f"{module_path}:{item_name}")

        if missing_docstrings:
            return CheckResult(
                check_id=self.check_id,
                status=CheckStatus.FAIL,
                message=f"Found {len(missing_docstrings)} public items without docstrings",
                details={"missing_docstrings": missing_docstrings},
            )

        return CheckResult(
            check_id=self.check_id,
            status=CheckStatus.PASS,
            message="All public items have docstrings",
        )


class RuffLintingCheck(Check):
    """Check that runs ruff linter to identify code issues."""

    def __init__(self):
        super().__init__(
            check_id="ruff_linting",
            description="Checks code for linting errors using ruff",
        )

    @property
    def category(self) -> str:
        """Category this check belongs to."""
        return "linting"

    def _parse_ruff_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse ruff output into structured format.

        Args:
            output: Console output from ruff command

        Returns:
            List of dictionaries containing parsed linting errors
        """
        issues = []
        lines = output.strip().split("\n")

        for line in lines:
            if not line or line.startswith("Found") or line.startswith("ruff"):
                continue

            try:
                # Expected format: file_path:line:col: error_code error_message
                parts = line.split(":", 3)
                if len(parts) < 4:
                    continue

                file_path = parts[0]
                line_num = int(parts[1])
                col = int(parts[2])

                # Further split error code and message
                error_part = parts[3].strip()
                error_code, error_message = error_part.split(" ", 1)

                issues.append(
                    {
                        "file": file_path,
                        "line": line_num,
                        "column": col,
                        "code": error_code,
                        "message": error_message.strip(),
                    }
                )
            except (ValueError, IndexError):
                # Skip lines that don't match expected format
                continue

        return issues

    def run(self, codebase: "Codebase") -> CheckResult:
        """Run ruff linting check against the codebase.

        Args:
            codebase: The codebase to check

        Returns:
            CheckResult: Result of the check
        """
        # Create a temporary directory to write output
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as temp_file:
            output_path = temp_file.name

        try:
            # Get the root directory of the codebase
            root_dir = codebase.root_path

            # Run ruff on the entire codebase
            result = subprocess.run(
                ["ruff", "check", str(root_dir)],
                capture_output=True,
                text=True,
                check=False,  # Don't raise exception on linting errors
            )

            # Parse output
            linting_issues = self._parse_ruff_output(result.stdout)

            # Get total count of issues
            issue_count = len(linting_issues)

            if issue_count > 0:
                return CheckResult(
                    check_id=self.check_id,
                    status=CheckStatus.FAIL,
                    message=f"Found {issue_count} linting issues in codebase",
                    details={"issues": linting_issues, "issue_count": issue_count},
                )

            return CheckResult(
                check_id=self.check_id,
                status=CheckStatus.PASS,
                message="No linting issues found",
            )

        except Exception as e:
            # Handle any exceptions during the check execution
            return CheckResult(
                check_id=self.check_id,
                status=CheckStatus.ERROR,
                message=f"Error executing ruff linting check: {str(e)}",
                details={"error": str(e)},
            )
        finally:
            # Clean up temp file
            if os.path.exists(output_path):
                os.unlink(output_path)


class RuffFormatCheck(Check):
    """Check that verifies code formatting using ruff format."""

    def __init__(self):
        super().__init__(
            check_id="ruff_format",
            description="Checks that code follows proper formatting using ruff format",
        )

    @property
    def category(self) -> str:
        """Category this check belongs to."""
        return "formatting"

    def _parse_format_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse ruff format output into structured format.

        Args:
            output: Console output from ruff format command

        Returns:
            List of dictionaries containing parsed formatting issues
        """
        issues = []
        lines = output.strip().split("\n")

        # Format output is usually file paths of files that would be reformatted
        for line in lines:
            line = line.strip()
            if (
                not line
                or line.startswith("would reformat")
                or line.startswith("Oh no!")
            ):
                continue

            # Each line should be a file path of a file that needs formatting
            if os.path.exists(line):
                issues.append(
                    {
                        "file": line,
                        "issue": "Formatting does not match ruff format style",
                    }
                )

        return issues

    def run(self, codebase: "Codebase") -> CheckResult:
        """Run ruff format check against the codebase.

        Args:
            codebase: The codebase to check

        Returns:
            CheckResult: Result of the check
        """
        try:
            # Get the root directory of the codebase
            root_dir = codebase.root_path

            # Run ruff format with check flag (doesn't modify files)
            result = subprocess.run(
                ["ruff", "format", "--check", str(root_dir)],
                capture_output=True,
                text=True,
                check=False,  # Don't raise exception on formatting errors
            )

            # Parse output - if exit code is non-zero, formatting issues were found
            if result.returncode != 0:
                formatting_issues = self._parse_format_output(result.stdout)
                issue_count = len(formatting_issues)

                return CheckResult(
                    check_id=self.check_id,
                    status=CheckStatus.FAIL,
                    message=f"Found {issue_count} files with formatting issues",
                    details={"issues": formatting_issues, "issue_count": issue_count},
                )

            return CheckResult(
                check_id=self.check_id,
                status=CheckStatus.PASS,
                message="All files are properly formatted",
            )

        except Exception as e:
            # Handle any exceptions during the check execution
            return CheckResult(
                check_id=self.check_id,
                status=CheckStatus.ERROR,
                message=f"Error executing ruff format check: {str(e)}",
                details={"error": str(e)},
            )


class LargeFilesCheck(Check):
    """Check that detects large files among version-controlled files."""

    def __init__(self, max_size_kb: Optional[int] = None):
        """Initialize the large files check.

        Args:
            max_size_kb: Maximum allowed file size in KB. If None, uses default (500KB)
        """
        super().__init__(
            check_id="large_files",
            description="Checks for large files that exceed size threshold",
        )
        self.max_size_kb = max_size_kb

    @property
    def category(self) -> str:
        """Category this check belongs to."""
        return "file_size"

    def _get_tracked_files(self, root_dir: str) -> Set[str]:
        """Get list of files under version control.

        Args:
            root_dir: Root directory of the codebase

        Returns:
            Set of file paths that are under version control
        """
        try:
            # Run git command to get all tracked files
            result = subprocess.run(
                ["git", "ls-files"],
                cwd=root_dir,
                capture_output=True,
                text=True,
                check=True,
            )

            # Convert output to a set of file paths
            tracked_files = set()
            for line in result.stdout.splitlines():
                if line.strip():
                    tracked_files.add(os.path.join(root_dir, line.strip()))

            return tracked_files
        except (subprocess.SubprocessError, FileNotFoundError):
            # If git command fails, return empty set
            return set()

    def _parse_large_files_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse pre-commit output to identify large files.

        Args:
            output: Console output from pre-commit command

        Returns:
            List of dictionaries containing information about large files
        """
        large_files = []
        lines = output.strip().split("\n")

        for line in lines:
            line = line.strip()
            if not line or line.startswith("check-added-large-files"):
                continue

            # Example output: "foo.py: 501.0 KB (limit: 500.0 KB)"
            if ":" in line:
                try:
                    file_part, size_part = line.split(":", 1)
                    file_path = file_part.strip()

                    # Extract size information
                    size_info = size_part.strip()
                    size_kb = float(size_info.split(" KB")[0].strip())

                    # Extract limit if present
                    limit_kb = None
                    if "(limit:" in size_info:
                        limit_part = size_info.split("(limit:")[1].strip()
                        limit_kb = float(limit_part.split(" KB")[0].strip())

                    large_files.append(
                        {"file": file_path, "size_kb": size_kb, "limit_kb": limit_kb}
                    )
                except (ValueError, IndexError):
                    # Skip lines that don't match expected format
                    continue

        return large_files

    def _get_file_size_kb(self, filepath: str) -> float:
        """Get file size in kilobytes.

        Args:
            filepath: Path to the file

        Returns:
            Size of the file in KB
        """
        try:
            size_bytes = os.path.getsize(filepath)
            return size_bytes / 1024.0
        except (FileNotFoundError, PermissionError):
            return 0.0

    def run(self, codebase: "Codebase") -> CheckResult:
        """Run large files check against the codebase.

        Args:
            codebase: The codebase to check

        Returns:
            CheckResult: Result of the check
        """
        try:
            # Get the root directory of the codebase
            root_dir = codebase.root_path

            # Instead of running pre-commit, directly check file sizes of tracked files
            tracked_files = self._get_tracked_files(root_dir)

            # Default size limit if not specified
            max_size = self.max_size_kb or 500.0

            # Check each tracked file against the size limit
            large_files = []
            for filepath in tracked_files:
                if os.path.exists(filepath) and os.path.isfile(filepath):
                    size_kb = self._get_file_size_kb(filepath)
                    if size_kb > max_size:
                        # Get path relative to root directory for better reporting
                        relative_path = os.path.relpath(filepath, root_dir)

                        large_files.append(
                            {
                                "file": relative_path,
                                "size_kb": size_kb,
                                "limit_kb": max_size,
                            }
                        )

            # Report results
            if large_files:
                file_count = len(large_files)
                max_size_display = f"{max_size}KB"

                return CheckResult(
                    check_id=self.check_id,
                    status=CheckStatus.FAIL,
                    message=f"Found {file_count} files exceeding size threshold ({max_size_display})",
                    details={
                        "large_files": large_files,
                        "count": file_count,
                        "max_size_kb": max_size,
                    },
                )

            max_size_display = f"{max_size}KB"
            return CheckResult(
                check_id=self.check_id,
                status=CheckStatus.PASS,
                message=f"No version-controlled files exceed size threshold ({max_size_display})",
            )

        except Exception as e:
            # Handle any exceptions during the check execution
            return CheckResult(
                check_id=self.check_id,
                status=CheckStatus.ERROR,
                message=f"Error executing large files check: {str(e)}",
                details={"error": str(e)},
            )


class PrivateKeyCheck(Check):
    """Check that detects private keys in files that are under version control."""

    # Common private key patterns to detect
    BLACKLIST = [
        b"BEGIN RSA PRIVATE KEY",
        b"BEGIN DSA PRIVATE KEY",
        b"BEGIN EC PRIVATE KEY",
        b"BEGIN OPENSSH PRIVATE KEY",
        b"BEGIN PRIVATE KEY",
        b"PuTTY-User-Key-File-2",
        b"BEGIN SSH2 ENCRYPTED PRIVATE KEY",
        b"BEGIN PGP PRIVATE KEY BLOCK",
        b"BEGIN ENCRYPTED PRIVATE KEY",
        b"BEGIN OpenVPN Static key V1",
    ]

    def __init__(self, additional_patterns: Optional[List[bytes]] = None):
        """Initialize the private key detection check.

        Args:
            additional_patterns: Optional list of additional byte patterns to detect
        """
        super().__init__(
            check_id="private_key",
            description="Checks for private keys in version-controlled files",
        )

        # Add any additional patterns to the blacklist
        self.blacklist = self.BLACKLIST.copy()
        if additional_patterns:
            self.blacklist.extend(additional_patterns)

    @property
    def category(self) -> str:
        """Category this check belongs to."""
        return "security"

    def _get_tracked_files(self, root_dir: str) -> Set[str]:
        """Get list of files under version control.

        Args:
            root_dir: Root directory of the codebase

        Returns:
            Set of file paths that are under version control
        """
        try:
            # Run git command to get all tracked files
            result = subprocess.run(
                ["git", "ls-files"],
                cwd=root_dir,
                capture_output=True,
                text=True,
                check=True,
            )

            # Convert output to a set of file paths
            tracked_files = set()
            for line in result.stdout.splitlines():
                if line.strip():
                    tracked_files.add(os.path.join(root_dir, line.strip()))

            return tracked_files
        except (subprocess.SubprocessError, FileNotFoundError):
            # If git command fails, return empty set
            return set()

    def _check_file(self, filepath: str) -> Optional[str]:
        """Check if a file contains private key patterns.

        Args:
            filepath: Path to the file to check

        Returns:
            Optional[str]: If private key detected, returns the specific pattern found, else None
        """
        try:
            # Skip binary files or files that are too large (>1MB)
            if not os.path.isfile(filepath) or os.path.getsize(filepath) > 1024 * 1024:
                return None

            with open(filepath, "rb") as f:
                content = f.read()

                for pattern in self.blacklist:
                    if pattern in content:
                        return pattern.decode("utf-8", errors="replace")

            return None
        except (IOError, PermissionError):
            # Skip files we can't read
            return None

    def run(self, codebase: "Codebase") -> CheckResult:
        """Run private key detection check against the codebase.

        Args:
            codebase: The codebase to check

        Returns:
            CheckResult: Result of the check
        """
        try:
            # Get the root directory of the codebase
            root_dir = codebase.root_path

            # Get all files under version control
            tracked_files = self._get_tracked_files(root_dir)

            # Check for private keys in tracked files
            private_key_files = []

            for filepath in tracked_files:
                # Skip if file doesn't exist or can't be read
                if not os.path.exists(filepath):
                    continue

                # Check if file contains private key
                pattern_found = self._check_file(filepath)

                if pattern_found:
                    # Get path relative to root directory
                    relative_path = os.path.relpath(filepath, root_dir)

                    private_key_files.append(
                        {
                            "file": relative_path,
                            "pattern": pattern_found,
                            "message": f"Contains private key pattern: {pattern_found}",
                        }
                    )

            # Check results
            if private_key_files:
                file_count = len(private_key_files)

                return CheckResult(
                    check_id=self.check_id,
                    status=CheckStatus.FAIL,
                    message=f"Found {file_count} files containing private keys",
                    details={
                        "files_with_private_keys": private_key_files,
                        "count": file_count,
                    },
                )

            return CheckResult(
                check_id=self.check_id,
                status=CheckStatus.PASS,
                message="No private keys detected in version-controlled files",
            )

        except Exception as e:
            # Handle any exceptions during the check execution
            return CheckResult(
                check_id=self.check_id,
                status=CheckStatus.ERROR,
                message=f"Error executing private key detection check: {str(e)}",
                details={"error": str(e)},
            )


class NotebookOutputCheck(Check):
    """Check that verifies Jupyter notebooks don't contain outputs or excessive metadata."""

    def __init__(self):
        """Initialize the notebook output check."""
        super().__init__(
            check_id="notebook_output",
            description="Checks that Jupyter notebooks don't contain output cells or unnecessary metadata",
        )

    @property
    def category(self) -> str:
        """Category this check belongs to."""
        return "notebook_cleanliness"

    def _get_tracked_notebooks(self, root_dir: str) -> Set[str]:
        """Get list of Jupyter notebooks under version control.

        Args:
            root_dir: Root directory of the codebase

        Returns:
            Set of notebook file paths that are under version control
        """
        try:
            # Run git command to get all tracked files
            result = subprocess.run(
                ["git", "ls-files", "*.ipynb"],
                cwd=root_dir,
                capture_output=True,
                text=True,
                check=True,
            )

            # Convert output to a set of notebook file paths
            tracked_notebooks = set()
            for line in result.stdout.splitlines():
                if line.strip():
                    tracked_notebooks.add(os.path.join(root_dir, line.strip()))

            return tracked_notebooks
        except (subprocess.SubprocessError, FileNotFoundError):
            # If git command fails, return empty set
            return set()

    def _verify_notebook(self, notebook_path: str) -> Dict[str, Any]:
        """Verify if a Jupyter notebook has outputs stripped using nbstripout.

        Args:
            notebook_path: Path to the notebook file

        Returns:
            Dict with verification result and any error messages
        """
        try:
            # Run nbstripout --verify on the notebook
            result = subprocess.run(
                ["nbstripout", "--verify", notebook_path],
                capture_output=True,
                text=True,
                check=False,  # Don't raise exception on verification failure
            )

            # If returncode is 0, notebook is clean
            is_clean = result.returncode == 0

            # Error message if not clean
            error_msg = None
            if not is_clean:
                # Extract the error message from stderr
                lines = result.stderr.strip().split("\n")
                for line in lines:
                    if (
                        "Notebook contains output cells" in line
                        or "Notebook contains metadata" in line
                    ):
                        error_msg = line.strip()
                        break

                # If we couldn't extract a specific message, use a generic one
                if not error_msg:
                    error_msg = "Notebook contains outputs or unnecessary metadata"

            return {"is_clean": is_clean, "error_message": error_msg}
        except FileNotFoundError:
            # nbstripout is not installed
            return {
                "is_clean": False,
                "error_message": "nbstripout command not found. Please install it with 'pip install nbstripout'",
            }
        except Exception as e:
            # Other errors
            return {
                "is_clean": False,
                "error_message": f"Error verifying notebook: {str(e)}",
            }

    def run(self, codebase: "Codebase") -> CheckResult:
        """Run notebook output check against the codebase.

        Args:
            codebase: The codebase to check

        Returns:
            CheckResult: Result of the check
        """
        try:
            # Get the root directory of the codebase
            root_dir = codebase.root_path

            # Get all Jupyter notebooks under version control
            tracked_notebooks = self._get_tracked_notebooks(root_dir)

            # Skip check if no notebooks found
            if not tracked_notebooks:
                return CheckResult(
                    check_id=self.check_id,
                    status=CheckStatus.SKIP,
                    message="No Jupyter notebooks found in version-controlled files",
                )

            # Check each notebook
            notebooks_with_output = []

            for notebook_path in tracked_notebooks:
                # Skip if file doesn't exist or can't be read
                if not os.path.exists(notebook_path):
                    continue

                # Verify notebook
                verification = self._verify_notebook(notebook_path)

                if not verification["is_clean"]:
                    # Get path relative to root directory for better reporting
                    relative_path = os.path.relpath(notebook_path, root_dir)

                    notebooks_with_output.append(
                        {"file": relative_path, "error": verification["error_message"]}
                    )

            # Check results
            if notebooks_with_output:
                notebook_count = len(notebooks_with_output)
                return CheckResult(
                    check_id=self.check_id,
                    status=CheckStatus.FAIL,
                    message=f"Found {notebook_count} notebooks with outputs or excess metadata",
                    details={
                        "notebooks_with_output": notebooks_with_output,
                        "count": notebook_count,
                    },
                )

            return CheckResult(
                check_id=self.check_id,
                status=CheckStatus.PASS,
                message="All notebooks are properly stripped of outputs and excess metadata",
            )

        except Exception as e:
            # Handle any exceptions during the check execution
            return CheckResult(
                check_id=self.check_id,
                status=CheckStatus.ERROR,
                message=f"Error executing notebook output check: {str(e)}",
                details={"error": str(e)},
            )


class PydoclintCheck(Check):
    """Check that verifies docstrings match type signatures using pydoclint."""

    def __init__(self):
        """Initialize the pydoclint check."""
        super().__init__(
            check_id="pydoclint",
            description="Checks that docstrings match type signatures using pydoclint",
        )

    @property
    def category(self) -> str:
        """Category this check belongs to."""
        return "documentation"

    def _get_tracked_python_files(self, root_dir: str) -> Set[str]:
        """Get list of Python files under version control.

        Args:
            root_dir: Root directory of the codebase

        Returns:
            Set of Python file paths that are under version control
        """
        try:
            # Run git command to get all tracked Python files
            result = subprocess.run(
                ["git", "ls-files", "*.py"],
                cwd=root_dir,
                capture_output=True,
                text=True,
                check=True,
            )

            # Convert output to a set of file paths
            tracked_files = set()
            for line in result.stdout.splitlines():
                if line.strip():
                    tracked_files.add(os.path.join(root_dir, line.strip()))

            return tracked_files
        except (subprocess.SubprocessError, FileNotFoundError):
            # If git command fails, return empty set
            return set()

    def _has_docstring_and_types(self, file_path: str) -> Tuple[bool, bool]:
        """Check if a Python file has docstrings and type signatures.

        Args:
            file_path: Path to the Python file

        Returns:
            Tuple of (has_docstrings, has_type_signatures)
        """
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                file_content = f.read()

            # Parse the file
            tree = ast.parse(file_content)

            has_docstrings = False
            has_type_signatures = False

            # Check for functions and classes
            for node in ast.walk(tree):
                # Check for docstrings in functions and classes
                if isinstance(
                    node, (ast.FunctionDef, ast.ClassDef, ast.AsyncFunctionDef)
                ):
                    # Check for docstring
                    if (
                        ast.get_docstring(node) is not None
                        and ast.get_docstring(node).strip()
                    ):
                        has_docstrings = True

                    # For functions, check for type signatures
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        # Check return annotation
                        if node.returns is not None:
                            has_type_signatures = True

                        # Check argument annotations
                        for arg in node.args.args:
                            if arg.annotation is not None:
                                has_type_signatures = True
                                break

                # If we've found both, we can stop early
                if has_docstrings and has_type_signatures:
                    break

            return has_docstrings, has_type_signatures
        except Exception:
            # If parsing fails, assume no docstrings or type signatures
            return False, False

    def _parse_pydoclint_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse pydoclint output into structured format.

        Args:
            output: Console output from pydoclint command

        Returns:
            List of dictionaries containing parsed docstring issues
        """
        issues = []
        lines = output.strip().split("\n")

        for line in lines:
            line = line.strip()
            if not line:
                continue

            try:
                # Expected format: file_path:line: [error_code] error_message
                parts = line.split(":", 2)
                if len(parts) < 3:
                    continue

                file_path = parts[0]
                line_num = int(parts[1])
                error_part = parts[2].strip()

                # Extract error code if present
                error_code = None
                error_message = error_part

                if "[" in error_part and "]" in error_part:
                    code_start = error_part.find("[")
                    code_end = error_part.find("]")
                    error_code = error_part[code_start + 1 : code_end].strip()
                    error_message = error_part[code_end + 1 :].strip()

                issues.append(
                    {
                        "file": file_path,
                        "line": line_num,
                        "code": error_code,
                        "message": error_message,
                    }
                )
            except (ValueError, IndexError):
                # Skip lines that don't match expected format
                continue

        return issues

    def run(self, codebase: "Codebase") -> CheckResult:
        """Run pydoclint check against the codebase.

        Args:
            codebase: The codebase to check

        Returns:
            CheckResult: Result of the check
        """
        try:
            # Get the root directory of the codebase
            root_dir = codebase.root_path

            # Get all Python files under version control
            tracked_python_files = self._get_tracked_python_files(root_dir)

            # Skip check if no Python files found
            if not tracked_python_files:
                return CheckResult(
                    check_id=self.check_id,
                    status=CheckStatus.SKIP,
                    message="No Python files found in version-controlled files",
                )

            # Filter files that have both docstrings and type signatures
            files_to_check = []
            skipped_files = []

            for file_path in tracked_python_files:
                # Skip if file doesn't exist or can't be read
                if not os.path.exists(file_path):
                    continue

                has_docstrings, has_type_signatures = self._has_docstring_and_types(
                    file_path
                )
                if has_docstrings and has_type_signatures:
                    files_to_check.append(file_path)
                else:
                    # Record skipped file and reason
                    relative_path = os.path.relpath(file_path, root_dir)
                    skipped_files.append(
                        {
                            "file": relative_path,
                            "reason": f"Missing {'docstrings' if not has_docstrings else ''}"
                            f"{' and ' if not has_docstrings and not has_type_signatures else ''}"
                            f"{'type signatures' if not has_type_signatures else ''}",
                        }
                    )

            # Skip check if no files have both docstrings and type signatures
            if not files_to_check:
                return CheckResult(
                    check_id=self.check_id,
                    status=CheckStatus.SKIP,
                    message="No Python files with both docstrings and type signatures found",
                    details={"skipped_files": skipped_files},
                )

            # Run pydoclint on each file
            docstring_issues = []

            for file_path in files_to_check:
                try:
                    # Run pydoclint on the file
                    result = subprocess.run(
                        ["pydoclint", file_path],
                        capture_output=True,
                        text=True,
                        check=False,  # Don't raise exception on issues
                    )

                    # Parse output if there were issues
                    if result.returncode != 0:
                        issues = self._parse_pydoclint_output(
                            result.stdout or result.stderr
                        )
                        for issue in issues:
                            # Add relative path for better reporting
                            issue["file"] = os.path.relpath(issue["file"], root_dir)
                        docstring_issues.extend(issues)
                except FileNotFoundError:
                    # pydoclint is not installed
                    return CheckResult(
                        check_id=self.check_id,
                        status=CheckStatus.ERROR,
                        message="pydoclint command not found. Please install it with 'pip install pydoclint'",
                    )

            # Check results
            if docstring_issues:
                issue_count = len(docstring_issues)

                return CheckResult(
                    check_id=self.check_id,
                    status=CheckStatus.FAIL,
                    message=f"Found {issue_count} docstring issues in {len(files_to_check)} files",
                    details={
                        "docstring_issues": docstring_issues,
                        "count": issue_count,
                        "files_checked": len(files_to_check),
                        "files_skipped": len(skipped_files),
                        "skipped_files": skipped_files,
                    },
                )

            return CheckResult(
                check_id=self.check_id,
                status=CheckStatus.PASS,
                message=f"All docstrings match type signatures in {len(files_to_check)} files",
                details={
                    "files_checked": len(files_to_check),
                    "files_skipped": len(skipped_files),
                },
            )

        except Exception as e:
            # Handle any exceptions during the check execution
            return CheckResult(
                check_id=self.check_id,
                status=CheckStatus.ERROR,
                message=f"Error executing pydoclint check: {str(e)}",
                details={"error": str(e)},
            )


class PyprojectTomlValidateCheck(Check):
    """
    Checks for the presence and validates pyproject.toml using the
    'validate-pyproject' API directly.

    - SKIPS if pyproject.toml is not found at the codebase root.
    - FAILS if 'validate-pyproject' reports errors for the file.
    - PASSES if 'validate-pyproject' validates the file successfully.
    - ERRORS if the pyproject.toml cannot be parsed.
    """

    def __init__(self):
        super().__init__(
            check_id="pyproject_toml_validate",
            description="Checks pyproject.toml format and schema using validate-pyproject API",
        )

    @property
    def category(self) -> str:
        """Category this check belongs to."""
        return "configuration"

    def run(self, codebase: "Codebase") -> CheckResult:
        """Run the pyproject.toml validation check against the codebase using the API."""

        pyproject_path = os.path.join(codebase.root_path, "pyproject.toml")

        if not os.path.exists(pyproject_path):
            return CheckResult(
                check_id=self.check_id,
                status=CheckStatus.SKIP,
                message="pyproject.toml not found in the codebase root.",
            )

        try:
            with open(pyproject_path, "r", encoding="utf-8") as f:
                pyproject_toml_str = f.read()
            pyproject_as_dict = toml.loads(pyproject_toml_str)

            validator = api.Validator()
            validator(pyproject_as_dict)

            return CheckResult(
                check_id=self.check_id,
                status=CheckStatus.PASS,
                message="pyproject.toml validated successfully by validate-pyproject API.",
            )

        except FileNotFoundError:
            # This should ideally be caught by the initial os.path.exists check,
            # but keeping it for robustness.
            return CheckResult(
                check_id=self.check_id,
                status=CheckStatus.SKIP,
                message="pyproject.toml not found in the codebase root.",
            )
        except toml.TomlDecodeError as e:
            return CheckResult(
                check_id=self.check_id,
                status=CheckStatus.ERROR,
                message=f"Error parsing pyproject.toml: {e}",
                details={"error": str(e)},
            )
        except errors.ValidationError as ex:
            return CheckResult(
                check_id=self.check_id,
                status=CheckStatus.FAIL,
                message=f"pyproject.toml validation failed: {ex.message}",
                details={"error": str(ex), "context": ex.context},
            )
        except Exception as e:
            # Catch any other unexpected errors
            return CheckResult(
                check_id=self.check_id,
                status=CheckStatus.ERROR,
                message=f"An unexpected error occurred while validating pyproject.toml: {e}",
                details={"error": str(e)},
            )
