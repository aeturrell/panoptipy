from pathlib import Path
from typing import TYPE_CHECKING, Dict, List, Optional, Union

if TYPE_CHECKING:
    from ..checks import CheckResult
    from ..rating import CodebaseRating


class BaseReporter:
    """Base class for all reporters."""

    def report(
        self,
        results: Union[List["CheckResult"], Dict[Path, List["CheckResult"]]],
        rating: Optional["CodebaseRating"] = None,
        repo_path: Optional[Path] = None,
    ) -> None:
        """Report results for one or more repositories.

        Args:
            results: Either a list of check results or a dictionary mapping paths to results
            rating: Overall rating for the codebase (for single repo)
            repo_path: Path to the repository (for single repo)
        """
        raise NotImplementedError()

    def report_single(
        self,
        results: List["CheckResult"],
        rating: Optional["CodebaseRating"],
        repo_path: Path,
    ) -> None:
        """Report results for a single repository.

        Args:
            results: List of check results
            rating: Overall rating for the codebase
            repo_path: Path to the repository
        """
        raise NotImplementedError()
