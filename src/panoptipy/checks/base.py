"""Base classes for implementing checks in panoptipy."""

from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Any, Dict, Optional

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
            print(missing_docstrings)
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
