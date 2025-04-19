from pathlib import Path
from typing import TYPE_CHECKING, Dict, List

if TYPE_CHECKING:
    from ..checks import CheckResult
    from ..rating import CodebaseRating


class BaseReporter:
    """Base class for all reporters."""

    def report(
        self,
        results_by_repo: Dict[Path, List["CheckResult"]],
        ratings: Dict[Path, "CodebaseRating"],
    ) -> None:
        """Report results for multiple repositories.

        Args:
            results_by_repo: Dictionary mapping repository paths to their check results
            ratings: Dictionary mapping repository paths to their overall ratings
        """
        raise NotImplementedError()

    def report_single(
        self, results: List["CheckResult"], rating: "CodebaseRating", repo_path: Path
    ) -> None:
        """Report results for a single repository.

        Args:
            results: List of check results
            rating: Overall rating for the codebase
            repo_path: Path to the repository
        """
        raise NotImplementedError()
