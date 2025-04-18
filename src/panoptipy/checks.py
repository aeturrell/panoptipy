"""Base classes for implementing checks in panoptipy."""

import ast
import os
import subprocess
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional, Set, Tuple

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


def get_tracked_files(root_dir: str, pattern: Optional[str] = None) -> Set[str]:
    try:
        cmd = ["git", "ls-files"]
        if pattern:
            cmd.append(pattern)
        result = subprocess.run(
            cmd,
            cwd=root_dir,
            capture_output=True,
            text=True,
            check=True,
        )
        return {
            os.path.join(root_dir, line.strip())
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
    """Check to ensure proper documentation through docstrings in Python codebase.

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
            for item in module.get_public_items():
                item_name = item.get("name") if isinstance(item, dict) else item.name
                if not self._is_public(item_name) or self._is_test(
                    item_name, module_path
                ):
                    continue
                docstring = (
                    item.get("docstring") if isinstance(item, dict) else item.docstring
                )
                if not docstring:
                    missing_docstrings.append(f"{module_path}:{item_name}")

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

    This class implements a check to ensure that code follows proper formatting
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

    def _parse_line(self, line: str) -> Optional[Dict[str, Any]]:
        if line and os.path.exists(line):
            return {
                "file": line,
                "issue": "Formatting does not match ruff format style",
            }
        return None

    def _run_logic(self, codebase: "Codebase") -> CheckResult:
        root_dir = codebase.root_path
        result = subprocess.run(
            ["ruff", "format", "--check", str(root_dir)],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            issues = parse_tool_output(result.stdout, self._parse_line)
            return fail_result(
                check_id=self.check_id,
                message=f"Found {len(issues)} files with formatting issues",
                details={"issues": issues, "issue_count": len(issues)},
            )
        return success_result(
            check_id=self.check_id, message="All files are properly formatted"
        )

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
            message="All notebooks are properly stripped of outputs and excess metadata",
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
                message="No Python files with both docstrings and type signatures found",
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
                message=f"Found {len(issues)} docstring issues in {len(to_check)} files",
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
                details={"error": str(ex), "context": ex.context},
            )

    def run(self, codebase: "Codebase") -> CheckResult:
        return safe_check_run(lambda: self._run_logic(codebase), self.check_id)
