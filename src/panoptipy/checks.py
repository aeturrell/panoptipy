"""Base classes for implementing checks in panoptipy."""

import ast
import logging
import os
import re
import subprocess
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional, Set, Tuple, Union

import toml
from validate_pyproject import api, errors

from .config import Config  # Add this import at the top with other imports

# Use TYPE_CHECKING to avoid circular imports
if TYPE_CHECKING:
    from .core import Codebase  # Only imported for type checking


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
    repo_path: Optional[Path] = None
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


def get_tracked_files(
    root_dir: Union[str, Path], pattern: Optional[str] = None
) -> Set[str]:
    try:
        cmd = ["git", "ls-files"]
        if pattern:
            cmd.append(pattern)
        root_dir_str = str(root_dir)
        result = subprocess.run(
            cmd,
            cwd=root_dir_str,
            capture_output=True,
            text=True,
            check=True,
        )
        return {
            os.path.join(root_dir_str, line.strip())
            for line in result.stdout.splitlines()
            if line.strip()
        }
    except (subprocess.SubprocessError, FileNotFoundError):
        return set()


def safe_check_run(check_fn: Callable[[], CheckResult], check_id: str) -> CheckResult:
    try:
        return check_fn()
    except Exception as e:
        return CheckResult(
            check_id=check_id,
            status=CheckStatus.ERROR,
            message=f"Error executing check: {e}",
            details={"error": str(e)},
        )


def parse_tool_output(
    output: str, line_parser: Callable[[str], Optional[Dict[str, Any]]]
) -> List[Dict[str, Any]]:
    issues = []
    for line in output.strip().splitlines():
        try:
            parsed = line_parser(line.strip())
            if parsed:
                issues.append(parsed)
        except Exception:
            continue
    return issues


def success_result(
    check_id: str, message: str, details: Optional[Dict[str, Any]] = None
) -> CheckResult:
    return CheckResult(
        check_id=check_id, status=CheckStatus.PASS, message=message, details=details
    )


def fail_result(
    check_id: str, message: str, details: Optional[Dict[str, Any]] = None
) -> CheckResult:
    return CheckResult(
        check_id=check_id, status=CheckStatus.FAIL, message=message, details=details
    )


class DocstringCheck(Check):
    """Check to ensure documentation included via docstrings in Python codebase.

    This class implements a check that verifies the presence of docstrings for all public
    functions and classes in a Python codebase, excluding test files and test-related items.
    The check considers an item "public" if it doesn't start with an underscore, and identifies
    test-related items through various common naming patterns.


    Attributes:
        check_id (str): Identifier for this check, set to "docstrings"
        description (str): Human-readable description of what this check does

    """

    def __init__(self):
        super().__init__(
            check_id="docstrings",
            description="Checks that public functions and classes have docstrings (excluding tests)",
        )

    @property
    def category(self) -> str:
        return "documentation"

    def _is_public(self, name: str) -> bool:
        return not name.startswith("_")

    def _is_test(self, name: str, module_path: str) -> bool:
        lower_path = module_path.lower()
        return (
            "test" in lower_path
            or name.startswith("test_")
            or name.endswith("_test")
            or name.endswith("Tests")
            or name.endswith("Test")
        )

    def _run_logic(self, codebase: "Codebase") -> CheckResult:
        missing_docstrings = []
        for module in codebase.get_python_modules():
            module_path = str(module.path)
            root_dir = codebase.root_path
            relative_path = os.path.relpath(module.path, root_dir)
            for item in module.get_public_items():
                item_name = item.get("name") if isinstance(item, dict) else item.name
                if not isinstance(item_name, str):
                    continue
                if not self._is_public(item_name) or self._is_test(
                    item_name, module_path
                ):
                    continue
                docstring = (
                    item.get("docstring") if isinstance(item, dict) else item.docstring
                )
                if not docstring:
                    missing_docstrings.append(f"{str(relative_path)}:{item_name}")

        if missing_docstrings:
            return fail_result(
                check_id=self.check_id,
                message=f"Found {len(missing_docstrings)} public items without docstrings",
                details={"missing_docstrings": missing_docstrings},
            )

        return success_result(
            check_id=self.check_id,
            message="All public items have docstrings",
        )

    def run(self, codebase: "Codebase") -> CheckResult:
        return safe_check_run(lambda: self._run_logic(codebase), self.check_id)


class RuffLintingCheck(Check):
    """A Check implementation that performs linting using the Ruff linter.

    This class runs the Ruff linter on a codebase to identify code style and quality issues.

    Attributes:
        check_id (str): Unique identifier "ruff_linting" for this check
        description (str): Human readable description of what this check does

    """

    def __init__(self):
        super().__init__(
            check_id="ruff_linting",
            description="Checks code for linting errors using ruff",
        )

    @property
    def category(self) -> str:
        return "linting"

    def _parse_line(self, line: str) -> Optional[Dict[str, Any]]:
        if not line or line.startswith("Found") or line.startswith("ruff"):
            return None
        parts = line.split(":", 3)
        if len(parts) < 4:
            return None
        try:
            file_path = parts[0]
            line_num = int(parts[1])
            col = int(parts[2])
            error_code, error_message = parts[3].strip().split(" ", 1)
            return {
                "file": file_path,
                "line": line_num,
                "column": col,
                "code": error_code,
                "message": error_message.strip(),
            }
        except Exception:
            return None

    def _run_logic(self, codebase: "Codebase") -> CheckResult:
        root_dir = codebase.root_path
        result = subprocess.run(
            ["ruff", "check", str(root_dir)],
            capture_output=True,
            text=True,
            check=False,
        )
        issues = parse_tool_output(result.stdout, self._parse_line)
        if issues:
            return fail_result(
                check_id=self.check_id,
                message=f"Found {len(issues)} linting issues in codebase",
                details={"issues": issues, "issue_count": len(issues)},
            )
        return success_result(check_id=self.check_id, message="No linting issues found")

    def run(self, codebase: "Codebase") -> CheckResult:
        return safe_check_run(lambda: self._run_logic(codebase), self.check_id)


class RuffFormatCheck(Check):
    """A check class that verifies code formatting using ruff format.

    This class implements a check to ensure that code follows formatting
    according to ruff format standards. It runs the 'ruff format --check' command
    on the codebase and reports any formatting inconsistencies.

    Attributes:
        check_id (str): Identifier for this check, set to "ruff_format"
        description (str): Description of what this check does
    """

    def __init__(self):
        super().__init__(
            check_id="ruff_format",
            description="Checks that code follows proper formatting using ruff format",
        )

    @property
    def category(self) -> str:
        return "formatting"

    def _extract_files_with_issues(self, output: str) -> List[Dict[str, Any]]:
        """Extract files that would be reformatted from the output."""

        issues = []

        # Find all lines matching the pattern "Would reformat: path/to/file.py"
        file_matches = re.findall(r"Would reformat: (.*?)$", output, re.MULTILINE)

        for file_path in file_matches:
            file_path = file_path.strip()
            if file_path and os.path.exists(file_path):
                issues.append(
                    {
                        "file": file_path,
                    }
                )

        return issues

    def _run_logic(self, codebase: "Codebase") -> CheckResult:
        root_dir = codebase.root_path
        result = subprocess.run(
            ["ruff", "format", "--check", str(root_dir)],
            capture_output=True,
            text=True,
            check=False,
        )

        # Combine stdout and stderr for parsing
        output = f"{result.stdout}\n{result.stderr}".strip()

        # Extract files with issues
        issues = self._extract_files_with_issues(output)
        issue_count = len(issues)

        if issue_count > 0 or result.returncode != 0:
            return fail_result(
                check_id=self.check_id,
                message=f"Found {issue_count} files with formatting issues",
                details={"issues": issues, "issue_count": issue_count},
            )

        return success_result(check_id=self.check_id, message="All files are formatted")

    def run(self, codebase: "Codebase") -> CheckResult:
        return safe_check_run(lambda: self._run_logic(codebase), self.check_id)


class PrivateKeyCheck(Check):
    """A security check that scans files for private key patterns.

    This class implements a security check to detect private keys in version-controlled files
    by looking for common private key header patterns. It helps prevent accidental exposure
    of sensitive credentials in source code repositories.

    Attributes:
        BLACKLIST (List[bytes]): Default list of byte patterns indicating private keys
        blacklist (List[bytes]): Instance copy of BLACKLIST that can be extended

    Args:
        additional_patterns (Optional[List[bytes]], optional): Additional patterns to check.
            These patterns will be added to the default BLACKLIST. Defaults to None.

    """

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
        super().__init__(
            check_id="private_key",
            description="Checks for private keys in version-controlled files",
        )
        self.blacklist = self.BLACKLIST.copy()
        if additional_patterns:
            self.blacklist.extend(additional_patterns)

    @property
    def category(self) -> str:
        return "security"

    def _check_file(self, filepath: str) -> Optional[str]:
        try:
            if not os.path.isfile(filepath) or os.path.getsize(filepath) > 1024 * 1024:
                return None
            with open(filepath, "rb") as f:
                content = f.read()
                for pattern in self.blacklist:
                    if pattern in content:
                        return pattern.decode("utf-8", errors="replace")
            return None
        except (IOError, PermissionError):
            return None

    def _run_logic(self, codebase: "Codebase") -> CheckResult:
        root_dir = codebase.root_path
        tracked_files = get_tracked_files(root_dir)
        private_key_files = []

        for filepath in tracked_files:
            if not os.path.exists(filepath):
                continue
            pattern_found = self._check_file(filepath)
            if pattern_found:
                relative_path = os.path.relpath(filepath, root_dir)
                private_key_files.append(
                    {
                        "file": relative_path,
                        "pattern": pattern_found,
                        "message": f"Contains private key pattern: {pattern_found}",
                    }
                )

        if private_key_files:
            return fail_result(
                check_id=self.check_id,
                message=f"Found {len(private_key_files)} files containing private keys",
                details={
                    "files_with_private_keys": private_key_files,
                    "count": len(private_key_files),
                },
            )

        return success_result(
            check_id=self.check_id,
            message="No private keys detected in version-controlled files",
        )

    def run(self, codebase: "Codebase") -> CheckResult:
        return safe_check_run(lambda: self._run_logic(codebase), self.check_id)


class LargeFilesCheck(Check):
    """A check that identifies large files in version control that exceed a specified size threshold.

    This check examines all tracked files in the repository and reports those that are larger
    than the configured maximum size. This helps identify potentially problematic large files
    that could bloat the repository or data that have been added to version
    control by mistake.

    Attributes:
        max_size_kb (int): Maximum allowed file size in kilobytes. Defaults to 500KB if not specified.
        check_id (str): Unique identifier for this check ("large_files")
    """

    def __init__(self, config: Optional[Config] = None):
        super().__init__(
            check_id="large_files",
            description="Checks for large files that exceed size threshold",
        )
        self.config = config
        self.max_size_kb = (
            config.get("thresholds.max_file_size", 500) if config else 500
        )

    @property
    def category(self) -> str:
        return "file_size"

    def _get_file_size_kb(self, filepath: str) -> float:
        try:
            return os.path.getsize(filepath) / 1024.0
        except (FileNotFoundError, PermissionError):
            return 0.0

    def _run_logic(self, codebase: "Codebase") -> CheckResult:
        root_dir = codebase.root_path
        tracked_files = get_tracked_files(root_dir)
        large_files = []
        for filepath in tracked_files:
            if os.path.exists(filepath) and os.path.isfile(filepath):
                size_kb = self._get_file_size_kb(filepath)
                if size_kb > self.max_size_kb:
                    relative_path = os.path.relpath(filepath, root_dir)
                    large_files.append(
                        {
                            "file": relative_path,
                            "size_kb": size_kb,
                            "limit_kb": self.max_size_kb,
                        }
                    )

        if large_files:
            return fail_result(
                check_id=self.check_id,
                message=f"Found {len(large_files)} files exceeding size threshold ({self.max_size_kb}KB)",
                details={
                    "large_files": large_files,
                    "count": len(large_files),
                    "max_size_kb": self.max_size_kb,
                },
            )

        return success_result(
            check_id=self.check_id,
            message=f"No version-controlled files exceed size threshold ({self.max_size_kb}KB)",
        )

    def run(self, codebase: "Codebase") -> CheckResult:
        return safe_check_run(lambda: self._run_logic(codebase), self.check_id)


class NotebookOutputCheck(Check):
    def __init__(self):
        super().__init__(
            check_id="notebook_output",
            description="Checks that Jupyter notebooks don't contain output cells or unnecessary metadata",
        )

    @property
    def category(self) -> str:
        return "notebook_cleanliness"

    def _verify_notebook(self, notebook_path: str) -> Dict[str, Any]:
        try:
            result = subprocess.run(
                ["nbstripout", "--verify", notebook_path],
                capture_output=True,
                text=True,
                check=False,
            )
            is_clean = result.returncode == 0
            error_msg = None
            if not is_clean:
                for line in result.stderr.strip().split("\n"):
                    if "output cells" in line or "metadata" in line:
                        error_msg = line.strip()
                        break
                error_msg = (
                    error_msg or "Notebook contains outputs or unnecessary metadata"
                )
            return {"is_clean": is_clean, "error_message": error_msg}
        except FileNotFoundError:
            return {
                "is_clean": False,
                "error_message": "nbstripout command not found. Please install it with 'pip install nbstripout'",
            }
        except Exception as e:
            return {
                "is_clean": False,
                "error_message": f"Error verifying notebook: {e}",
            }

    def _run_logic(self, codebase: "Codebase") -> CheckResult:
        root_dir = codebase.root_path
        notebooks = get_tracked_files(root_dir, "*.ipynb")
        if not notebooks:
            return CheckResult(
                check_id=self.check_id,
                status=CheckStatus.SKIP,
                message="No Jupyter notebooks found in version-controlled files",
            )
        notebooks_with_output = []
        for notebook_path in notebooks:
            if not os.path.exists(notebook_path):
                continue
            result = self._verify_notebook(notebook_path)
            if not result["is_clean"]:
                rel_path = os.path.relpath(notebook_path, root_dir)
                notebooks_with_output.append(
                    {"file": rel_path, "error": result["error_message"]}
                )

        if notebooks_with_output:
            return fail_result(
                check_id=self.check_id,
                message=f"Found {len(notebooks_with_output)} notebooks with outputs or excess metadata",
                details={
                    "notebooks_with_output": notebooks_with_output,
                    "count": len(notebooks_with_output),
                },
            )

        return success_result(
            check_id=self.check_id,
            message="All notebooks are stripped of outputs and excess metadata",
        )

    def run(self, codebase: "Codebase") -> CheckResult:
        return safe_check_run(lambda: self._run_logic(codebase), self.check_id)


class PydoclintCheck(Check):
    """A check implementation to validate docstring compatibility with type signatures using pydoclint.

    This class extends the base Check class to verify that docstrings in Python files
    match their corresponding type signatures. It uses the pydoclint tool to perform
    the validation.

    The check will:
    1. Find all Python files in version control
    2. Filter files to only those containing both docstrings and type annotations
    3. Run pydoclint on the filtered files
    4. Report any mismatches between docstrings and type signatures

    Attributes:
        check_id (str): Identifier for this check, set to "pydoclint"
        description (str): Description of what this check does

    """

    def __init__(self):
        super().__init__(
            check_id="pydoclint",
            description="Checks that docstrings match type signatures using pydoclint",
        )

    @property
    def category(self) -> str:
        return "documentation"

    def _has_docstring_and_types(self, file_path: str) -> Tuple[bool, bool]:
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                file_content = f.read()
            tree = ast.parse(file_content)
            has_docstrings = False
            has_types = False
            for node in ast.walk(tree):
                if isinstance(
                    node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
                ):
                    if ast.get_docstring(node):
                        has_docstrings = True
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        if node.returns or any(
                            arg.annotation for arg in node.args.args
                        ):
                            has_types = True
                if has_docstrings and has_types:
                    break
            return has_docstrings, has_types
        except Exception:
            return False, False

    def _parse_line(self, line: str) -> Optional[Dict[str, Any]]:
        try:
            parts = line.split(":", 2)
            if len(parts) < 3:
                return None
            file_path, line_num, rest = parts
            line_num = int(line_num)
            code, message = None, rest.strip()
            if "[" in rest and "]" in rest:
                code_start = rest.find("[") + 1
                code_end = rest.find("]")
                code = rest[code_start:code_end]
                message = rest[code_end + 1 :].strip()
            return {
                "file": file_path.strip(),
                "line": line_num,
                "code": code,
                "message": message,
            }
        except Exception:
            return None

    def _run_logic(self, codebase: "Codebase") -> CheckResult:
        root_dir = codebase.root_path
        python_files = get_tracked_files(root_dir, "*.py")
        if not python_files:
            return CheckResult(
                check_id=self.check_id,
                status=CheckStatus.SKIP,
                message="No Python files found in version-controlled files",
            )
        to_check, skipped = [], []
        for file in python_files:
            if not os.path.exists(file):
                continue
            has_doc, has_type = self._has_docstring_and_types(file)
            if has_doc and has_type:
                to_check.append(file)
            else:
                skipped.append(
                    {
                        "file": os.path.relpath(file, root_dir),
                        "reason": "Missing "
                        + ("docstrings" if not has_doc else "")
                        + (" and " if not has_doc and not has_type else "")
                        + ("type signatures" if not has_type else ""),
                    }
                )
        if not to_check:
            return CheckResult(
                check_id=self.check_id,
                status=CheckStatus.SKIP,
                message="No functions with both docstrings and type signatures to check; skipping",
                details={"skipped_files": skipped},
            )
        issues = []
        for file in to_check:
            result = subprocess.run(
                ["pydoclint", file],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode != 0:
                parsed = parse_tool_output(
                    result.stdout or result.stderr, self._parse_line
                )
                for item in parsed:
                    item["file"] = os.path.relpath(item["file"], root_dir)
                issues.extend(parsed)

        if issues:
            return fail_result(
                check_id=self.check_id,
                message=f"Found {len(issues)} places in {len(to_check)} files where docstrings do not match type signatures",
                details={
                    "docstring_issues": issues,
                    "files_checked": len(to_check),
                    "files_skipped": len(skipped),
                    "skipped_files": skipped,
                },
            )

        return success_result(
            check_id=self.check_id,
            message=f"All docstrings match type signatures in {len(to_check)} files",
            details={"files_checked": len(to_check), "files_skipped": len(skipped)},
        )

    def run(self, codebase: "Codebase") -> CheckResult:
        return safe_check_run(lambda: self._run_logic(codebase), self.check_id)


class PyprojectTomlValidateCheck(Check):
    """A check class that validates the pyproject.toml file format and schema.

    This check validates both the TOML syntax and the schema of pyproject.toml
    using the validate-pyproject API. It verifies that the file exists in the
    codebase root directory and contains valid configuration.

    Attributes:
        check_id (str): Identifier for this check, set to "pydoclint"
        description (str): Description of what this check does

    """

    def __init__(self):
        super().__init__(
            check_id="pyproject_toml_validate",
            description="Checks pyproject.toml format and schema using validate-pyproject API",
        )

    @property
    def category(self) -> str:
        return "configuration"

    def _run_logic(self, codebase: "Codebase") -> CheckResult:
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

            return success_result(
                check_id=self.check_id,
                message="pyproject.toml validated successfully by validate-pyproject API.",
            )

        except toml.TomlDecodeError as e:
            return CheckResult(
                check_id=self.check_id,
                status=CheckStatus.ERROR,
                message=f"Error parsing pyproject.toml: {e}",
                details={"error": str(e)},
            )
        except errors.ValidationError as ex:
            return fail_result(
                check_id=self.check_id,
                message=f"pyproject.toml validation failed: {ex.message}",
                details={"error": str(ex)},
            )

    def run(self, codebase: "Codebase") -> CheckResult:
        return safe_check_run(lambda: self._run_logic(codebase), self.check_id)


class HasTestsCheck(Check):
    """A check that identifies test files and test functions without executing code.

    This check searches for test files following standard Python testing conventions
    (test_*.py or *_test.py) and identifies test functions using AST parsing. It counts
    and reports test functions that follow these patterns:

    * Functions prefixed with 'test_'
    * Methods prefixed with 'test_' inside classes prefixed with 'Test'
    * Static and class methods prefixed with 'test_' inside test classes

    The check provides a count of all identified test items without executing any code.

    Attributes:
        check_id (str): Identifier for this check, set to "has_tests"
        description (str): Description of what this check does
    """

    def __init__(self):
        super().__init__(
            check_id="has_tests",
            description="Checks if tests are present in the codebase using AST parsing",
        )

    @property
    def category(self) -> str:
        return "testing"

    def _find_test_files(self, root_dir: Path) -> List[Path]:
        """Find all test files recursively in the given directory.

        Args:
            root_dir: Root directory to search in

        Returns:
            List of paths to test files
        """
        test_files = []

        for path in root_dir.glob("**/*.py"):
            # Skip hidden directories and files, but allow parent directory references
            if any(
                part.startswith(".") and part not in [".", ".."] for part in path.parts
            ):
                continue

            # Check if file matches test patterns
            if path.name.startswith("test_") or path.stem.endswith("_test"):
                test_files.append(path)

        return test_files

    def _is_test_class(self, class_node: ast.ClassDef) -> bool:
        """Check if a class is a test class (starts with 'Test' and has no __init__).

        Args:
            class_node: AST ClassDef node

        Returns:
            True if this is a test class, False otherwise
        """
        if not class_node.name.startswith("Test"):
            return False

        # Check if it has an __init__ method
        for node in class_node.body:
            if isinstance(node, ast.FunctionDef) and node.name == "__init__":
                return False

        return True

    def _extract_test_items(self, file_path: Path) -> List[Dict[str, Any]]:
        """Extract test items from a Python file using AST parsing.

        Args:
            file_path: Path to the Python file

        Returns:
            List of dictionaries with test item information
        """
        test_items = []

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            tree = ast.parse(content)

            # Track current class for context
            current_class = None

            for node in ast.walk(tree):
                # Handle class definitions
                if isinstance(node, ast.ClassDef):
                    current_class = node if self._is_test_class(node) else None

                # Handle function definitions
                elif isinstance(node, ast.FunctionDef):
                    is_test_function = False
                    decorator_list = [
                        d.id for d in node.decorator_list if isinstance(d, ast.Name)
                    ]

                    # Test function outside class
                    if node.name.startswith("test_") and current_class is None:
                        is_test_function = True
                        item_type = "function"
                        class_name = None

                    # Test method inside test class
                    elif (
                        node.name.startswith("test_")
                        and current_class is not None
                        and node.name != "__init__"
                    ):
                        is_test_function = True
                        item_type = "method"
                        class_name = current_class.name

                        # Check for staticmethod or classmethod
                        if "staticmethod" in decorator_list:
                            item_type = "staticmethod"
                        elif "classmethod" in decorator_list:
                            item_type = "classmethod"

                    if is_test_function:
                        test_items.append(
                            {
                                "name": node.name,
                                "type": item_type,
                                "class": class_name,
                                "file": str(file_path),
                                "line": node.lineno,
                            }
                        )

        except Exception as e:
            # Log error but continue with other files
            logging.warning(f"Error parsing file {file_path}: {e}")

        return test_items

    def _run_logic(self, codebase: "Codebase") -> CheckResult:
        root_dir = codebase.root_path

        # Find all test files
        test_files = self._find_test_files(root_dir)

        if not test_files:
            return fail_result(
                check_id=self.check_id,
                message="No test files found in the codebase",
                details={"test_count": 0, "test_files": [], "test_items": []},
            )

        # Extract test items from all files
        all_test_items = []
        test_file_paths = []

        for file_path in test_files:
            test_items = self._extract_test_items(file_path)
            if test_items:
                test_file_paths.append(str(file_path.relative_to(root_dir)))
                all_test_items.extend(test_items)

        test_count = len(all_test_items)

        if test_count > 0:
            return success_result(
                check_id=self.check_id,
                message=f"Found {test_count} tests in the codebase",
                details={
                    "test_count": test_count,
                    "test_files": test_file_paths,
                    "test_items": all_test_items,
                },
            )
        else:
            return fail_result(
                check_id=self.check_id,
                message="No tests found in the codebase",
                details={
                    "test_count": 0,
                    "test_files": test_file_paths,
                    "test_items": [],
                },
            )

    def run(self, codebase: "Codebase") -> CheckResult:
        return safe_check_run(lambda: self._run_logic(codebase), self.check_id)


class SqlLintingCheck(Check):
    """A check that lints SQL files using sqlfluff.

    This check finds SQL files with database-relevant extensions and lints them
    using sqlfluff. It tries multiple SQL dialects for each file extension and
    only fails if ALL dialects fail.

    Attributes:
        check_id (str): Identifier for this check, set to "sql_linting"
        description (str): Description of what this check does
        extension_to_dialects (Dict[str, List[str]]): Mapping of file extensions to possible SQL dialects
    """

    def __init__(self):
        super().__init__(
            check_id="sql_linting",
            description="Checks SQL files for linting errors using sqlfluff",
        )
        # Map file extensions to possible SQL dialects
        self.extension_to_dialects = {
            ".sql": ["ansi", "postgres", "mysql", "sqlite", "bigquery", "snowflake"],
            ".pgsql": ["postgres"],
            ".psql": ["postgres"],
            ".mysql": ["mysql"],
            ".bq": ["bigquery"],
            ".ddl": ["ansi", "postgres", "mysql"],
            ".dml": ["ansi", "postgres", "mysql"],
            ".sqlite": ["sqlite"],
            ".sqlite3": ["sqlite"],
            ".db": ["sqlite"],
            ".db3": ["sqlite"],
            ".s3db": ["sqlite"],
            ".sl3": ["sqlite"],
        }

    @property
    def category(self) -> str:
        return "linting"

    def _get_sql_files(self, root_dir: str) -> List[str]:
        """Find all SQL files in the repository."""
        sql_files = []
        for ext in self.extension_to_dialects.keys():
            pattern = f"*{ext}"
            files = get_tracked_files(root_dir, pattern)
            sql_files.extend(files)
        return sql_files

    def _lint_file_with_dialect(
        self, file_path: str, dialect: str
    ) -> Tuple[bool, str, str]:
        """Lint a SQL file with a specific dialect.

        Args:
            file_path: Path to SQL file
            dialect: SQL dialect to use

        Returns:
            Tuple of (success, stdout, stderr)
        """
        try:
            result = subprocess.run(
                ["sqlfluff", "lint", "--dialect", dialect, file_path],
                capture_output=True,
                text=True,
                check=False,
            )
            # sqlfluff returns 0 for no issues, non-zero for issues or errors
            success = result.returncode == 0
            return success, result.stdout, result.stderr
        except FileNotFoundError:
            return False, "", "sqlfluff command not found"

    def _parse_sqlfluff_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse sqlfluff output to extract issues."""
        issues = []
        lines = output.strip().split("\n")
        for line in lines:
            # Match lines like: L:   1 | P:   1 | LT01 | Expected single...
            if "|" in line and ("L:" in line or "P:" in line):
                parts = [p.strip() for p in line.split("|")]
                if len(parts) >= 4:
                    try:
                        # Extract line number
                        line_num = None
                        for part in parts:
                            if part.startswith("L:"):
                                line_num = int(part.split(":")[1].strip())
                                break

                        # Extract code and message
                        code = parts[2] if len(parts) > 2 else ""
                        message = parts[3] if len(parts) > 3 else ""

                        if code and message:
                            issues.append(
                                {
                                    "line": line_num,
                                    "code": code,
                                    "message": message,
                                }
                            )
                    except (ValueError, IndexError):
                        continue
        return issues

    def _run_logic(self, codebase: "Codebase") -> CheckResult:
        root_dir = str(codebase.root_path)

        # Find all SQL files
        sql_files = self._get_sql_files(root_dir)

        if not sql_files:
            return CheckResult(
                check_id=self.check_id,
                status=CheckStatus.SKIP,
                message="No SQL files found in version-controlled files",
            )

        all_dialects_failed = []

        for file_path in sql_files:
            if not os.path.exists(file_path):
                continue

            # Get file extension
            file_ext = os.path.splitext(file_path)[1]
            dialects = self.extension_to_dialects.get(file_ext, ["ansi"])

            # Try each dialect
            dialect_results = {}
            any_success = False

            for dialect in dialects:
                success, stdout, stderr = self._lint_file_with_dialect(
                    file_path, dialect
                )
                dialect_results[dialect] = {
                    "success": success,
                    "stdout": stdout,
                    "stderr": stderr,
                }

                if success:
                    any_success = True
                    break  # Found a dialect that works, no need to try others

            # If no dialect succeeded, record the file
            if not any_success:
                rel_path = os.path.relpath(file_path, root_dir)

                # Use the output from the first dialect tried
                first_dialect = dialects[0]
                output = dialect_results[first_dialect]["stdout"]
                issues = self._parse_sqlfluff_output(output)

                all_dialects_failed.append(
                    {
                        "file": rel_path,
                        "dialects_tried": dialects,
                        "issues": issues,
                        "issue_count": len(issues),
                    }
                )

        if all_dialects_failed:
            total_issues = sum(f["issue_count"] for f in all_dialects_failed)
            return fail_result(
                check_id=self.check_id,
                message=f"Found {total_issues} SQL linting issues in {len(all_dialects_failed)} files",
                details={
                    "files_with_issues": all_dialects_failed,
                    "file_count": len(all_dialects_failed),
                    "total_issues": total_issues,
                },
            )

        return success_result(
            check_id=self.check_id,
            message=f"All {len(sql_files)} SQL files passed linting",
            details={"files_checked": len(sql_files)},
        )

    def run(self, codebase: "Codebase") -> CheckResult:
        return safe_check_run(lambda: self._run_logic(codebase), self.check_id)


class ReadmeCheck(Check):
    """A check that verifies the existence and content of a README file.

    This check searches for README files in common formats (md, rst, txt) in the
    repository root and verifies that they contain sufficient content. A README
    is considered "empty" if it contains fewer than a configurable number of
    non-whitespace characters.

    Attributes:
        check_id (str): Identifier for this check, set to "readme"
        description (str): Description of what this check does
        min_content_length (int): Minimum content length (in characters) for a README
            to be considered non-empty
    """

    def __init__(self, config: Optional[Config] = None):
        super().__init__(
            check_id="readme",
            description="Checks for the existence and content of a README file",
        )
        self.config = config
        # Get minimum content length from config, default to 100 characters
        self.min_content_length = (
            config.get("thresholds.min_readme_length", 100) if config else 100
        )
        # Common README extensions
        self.readme_patterns = ["README.md", "README.rst", "README.txt", "README"]

    @property
    def category(self) -> str:
        return "documentation"

    def _find_readme_files(self, root_dir: Path) -> List[Path]:
        """Find README files in the repository root.

        Args:
            root_dir: Repository root directory

        Returns:
            List of paths to README files
        """
        readme_files = []
        for pattern in self.readme_patterns:
            readme_path = root_dir / pattern
            if readme_path.exists() and readme_path.is_file():
                readme_files.append(readme_path)
        return readme_files

    def _check_readme_content(self, readme_path: Path) -> Dict[str, Any]:
        """Check if a README file has meaningful content.

        Args:
            readme_path: Path to the README file

        Returns:
            Dictionary with content length information
        """
        try:
            with open(readme_path, "r", encoding="utf-8") as f:
                content = f.read()

            # Remove whitespace to get actual content length
            non_whitespace_content = "".join(content.split())
            content_length = len(non_whitespace_content)

            return {
                "file": str(readme_path),
                "content_length": content_length,
                "has_content": content_length >= self.min_content_length,
                "min_required": self.min_content_length,
            }
        except Exception as e:
            return {
                "file": str(readme_path),
                "error": str(e),
                "has_content": False,
                "min_required": self.min_content_length,
            }

    def _run_logic(self, codebase: "Codebase") -> CheckResult:
        root_dir = codebase.root_path

        # Find all README files in repository root
        readme_files = self._find_readme_files(root_dir)

        if not readme_files:
            return fail_result(
                check_id=self.check_id,
                message="No README file found in repository root",
                details={
                    "readme_found": False,
                    "patterns_checked": self.readme_patterns,
                },
            )

        # Check content of all README files
        readme_details = []
        has_content = False

        for readme_path in readme_files:
            content_info = self._check_readme_content(readme_path)
            readme_details.append(content_info)
            if content_info.get("has_content", False):
                has_content = True

        if not has_content:
            return fail_result(
                check_id=self.check_id,
                message=f"README exists but contains insufficient content (min: {self.min_content_length} chars)",
                details={
                    "readme_found": True,
                    "has_content": False,
                    "readme_files": readme_details,
                    "min_content_length": self.min_content_length,
                },
            )

        return success_result(
            check_id=self.check_id,
            message="README exists with sufficient content",
            details={
                "readme_found": True,
                "has_content": True,
                "readme_files": readme_details,
                "min_content_length": self.min_content_length,
            },
        )

    def run(self, codebase: "Codebase") -> CheckResult:
        return safe_check_run(lambda: self._run_logic(codebase), self.check_id)


class CognitiveComplexityCheck(Check):
    """A check that measures cognitive complexity of Python functions using complexipy.

    Cognitive complexity is a measure of how difficult code is to understand,
    as opposed to cyclomatic complexity which measures how difficult code is to test.
    High cognitive complexity indicates code that may be hard to read and maintain.

    This check analyzes all Python files in the codebase and reports functions
    that exceed a configurable complexity threshold.

    Attributes:
        check_id (str): Identifier for this check, set to "cognitive_complexity"
        description (str): Description of what this check does
        max_complexity (int): Maximum allowed cognitive complexity per function
    """

    def __init__(self, config: Optional[Config] = None):
        super().__init__(
            check_id="cognitive_complexity",
            description="Checks cognitive complexity of Python functions using complexipy",
        )
        self.config = config
        # Default threshold of 15 is commonly used as a reasonable limit
        self.max_complexity = (
            config.get("thresholds.max_cognitive_complexity", 15) if config else 15
        )

    @property
    def category(self) -> str:
        return "complexity"

    def _analyze_file(self, file_path: str, root_dir: str) -> List[Dict[str, Any]]:
        """Analyze a single Python file for cognitive complexity.

        Args:
            file_path: Absolute path to the Python file
            root_dir: Root directory of the codebase

        Returns:
            List of dictionaries with function complexity information
        """
        try:
            from complexipy import file_complexity

            result = file_complexity(file_path)
            complex_functions = []

            for func in result.functions:
                if func.complexity > self.max_complexity:
                    rel_path = os.path.relpath(file_path, root_dir)
                    complex_functions.append(
                        {
                            "file": rel_path,
                            "function": func.name,
                            "complexity": func.complexity,
                            "line_start": func.line_start,
                            "threshold": self.max_complexity,
                        }
                    )

            return complex_functions
        except Exception as e:
            logging.warning(f"Error analyzing file {file_path}: {e}")
            return []

    def _run_logic(self, codebase: "Codebase") -> CheckResult:
        root_dir = str(codebase.root_path)

        # Get all Python files tracked by git
        python_files = get_tracked_files(root_dir, "*.py")

        if not python_files:
            return CheckResult(
                check_id=self.check_id,
                status=CheckStatus.SKIP,
                message="No Python files found in version-controlled files",
            )

        # Analyze each file
        all_complex_functions = []
        files_analyzed = 0

        for file_path in python_files:
            if not os.path.exists(file_path):
                continue

            files_analyzed += 1
            complex_functions = self._analyze_file(file_path, root_dir)
            all_complex_functions.extend(complex_functions)

        if all_complex_functions:
            # Sort by complexity (highest first)
            all_complex_functions.sort(key=lambda x: x["complexity"], reverse=True)

            return fail_result(
                check_id=self.check_id,
                message=f"Found {len(all_complex_functions)} functions exceeding cognitive complexity threshold ({self.max_complexity})",
                details={
                    "complex_functions": all_complex_functions,
                    "count": len(all_complex_functions),
                    "threshold": self.max_complexity,
                    "files_analyzed": files_analyzed,
                },
            )

        return success_result(
            check_id=self.check_id,
            message=f"All functions are within cognitive complexity threshold ({self.max_complexity})",
            details={
                "threshold": self.max_complexity,
                "files_analyzed": files_analyzed,
            },
        )

    def run(self, codebase: "Codebase") -> CheckResult:
        return safe_check_run(lambda: self._run_logic(codebase), self.check_id)
