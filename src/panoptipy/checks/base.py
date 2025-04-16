"""Base classes for implementing checks in panoptipy."""

import json
import os
import subprocess
import tempfile
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Any, Dict, List, Optional

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
    """Check that detects large files using pre-commit's check-added-large-files hook."""

    def __init__(self, max_size_kb: Optional[int] = None):
        """Initialize the large files check.

        Args:
            max_size_kb: Maximum allowed file size in KB. If None, uses pre-commit's default (500KB)
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

            # Prepare command to run only the check-added-large-files hook
            cmd = ["pre-commit", "run", "check-added-large-files", "--all-files"]

            # Add custom max size if specified
            if self.max_size_kb is not None:
                cmd.extend(
                    [
                        "--config",
                        json.dumps(
                            {
                                "repos": [
                                    {
                                        "repo": "local",
                                        "hooks": [
                                            {
                                                "id": "check-added-large-files",
                                                "args": [f"--maxkb={self.max_size_kb}"],
                                            }
                                        ],
                                    }
                                ]
                            }
                        ),
                    ]
                )

            # Run pre-commit with specific hook
            result = subprocess.run(
                cmd,
                cwd=str(root_dir),
                capture_output=True,
                text=True,
                check=False,  # Don't raise exception on found issues
            )

            # Parse output - non-zero exit code means large files found
            if result.returncode != 0:
                large_files = self._parse_large_files_output(
                    result.stdout or result.stderr
                )
                file_count = len(large_files)

                max_size_display = (
                    f"{self.max_size_kb}KB" if self.max_size_kb else "default limit"
                )

                return CheckResult(
                    check_id=self.check_id,
                    status=CheckStatus.FAIL,
                    message=f"Found {file_count} files exceeding size threshold ({max_size_display})",
                    details={
                        "large_files": large_files,
                        "count": file_count,
                        "max_size_kb": self.max_size_kb
                        or (large_files[0].get("limit_kb") if large_files else 500),
                    },
                )

            max_size_display = (
                f"{self.max_size_kb}KB" if self.max_size_kb else "default limit"
            )
            return CheckResult(
                check_id=self.check_id,
                status=CheckStatus.PASS,
                message=f"No files exceed size threshold ({max_size_display})",
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
    """Check that detects private keys in files without relying on external tools."""

    # Common private key patterns to detect
    BLACKLIST = [
        b'BEGIN RSA PRIVATE KEY',
        b'BEGIN DSA PRIVATE KEY',
        b'BEGIN EC PRIVATE KEY',
        b'BEGIN OPENSSH PRIVATE KEY',
        b'BEGIN PRIVATE KEY',
        b'PuTTY-User-Key-File-2',
        b'BEGIN SSH2 ENCRYPTED PRIVATE KEY',
        b'BEGIN PGP PRIVATE KEY BLOCK',
        b'BEGIN ENCRYPTED PRIVATE KEY',
        b'BEGIN OpenVPN Static key V1',
    ]

    def __init__(self, additional_patterns: Optional[List[bytes]] = None):
        """Initialize the standalone private key detection check.
        
        Args:
            additional_patterns: Optional list of additional byte patterns to detect
        """
        super().__init__(
            check_id="detect_private_key",
            description="Checks for files containing private keys or credentials using direct file scanning"
        )
        
        # Add any additional patterns to the blacklist
        self.blacklist = self.BLACKLIST.copy()
        if additional_patterns:
            self.blacklist.extend(additional_patterns)

    @property
    def category(self) -> str:
        """Category this check belongs to."""
        return "security"

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
                
            with open(filepath, 'rb') as f:
                content = f.read()
                
                for pattern in self.blacklist:
                    if pattern in content:
                        return pattern.decode('utf-8', errors='replace')
                        
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
            # Get all files in the codebase
            root_dir = codebase.root_path
            private_key_files = []
            
            # List of file extensions to skip
            skip_extensions = ['.jpg', '.png', '.gif', '.pdf', '.zip', '.tar', 
                              '.gz', '.mp3', '.mp4', '.avi', '.mov', '.exe']
            
            # Walk through all files in the codebase
            for dirpath, _, filenames in os.walk(root_dir):
                for filename in filenames:
                    # Skip files with binary extensions
                    if any(filename.lower().endswith(ext) for ext in skip_extensions):
                        continue
                        
                    filepath = os.path.join(dirpath, filename)
                    relative_path = os.path.relpath(filepath, root_dir)
                    
                    # Check if file contains private key
                    pattern_found = self._check_file(filepath)
                    
                    if pattern_found:
                        private_key_files.append({
                            "file": relative_path,
                            "pattern": pattern_found,
                            "message": f"Contains private key pattern: {pattern_found}"
                        })
            
            # Check results
            if private_key_files:
                file_count = len(private_key_files)
                
                return CheckResult(
                    check_id=self.check_id,
                    status=CheckStatus.FAIL,
                    message=f"Found {file_count} files containing private keys",
                    details={
                        "files_with_private_keys": private_key_files,
                        "count": file_count
                    }
                )
            
            return CheckResult(
                check_id=self.check_id,
                status=CheckStatus.PASS,
                message="No private keys detected in codebase",
            )
            
        except Exception as e:
            # Handle any exceptions during the check execution
            return CheckResult(
                check_id=self.check_id,
                status=CheckStatus.ERROR,
                message=f"Error executing private key detection check: {str(e)}",
                details={"error": str(e)}
            )
