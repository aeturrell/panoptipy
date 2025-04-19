"""JSON reporter for panoptipy."""

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Union

if TYPE_CHECKING:
    from ..checks import CheckResult
    from ..rating import CodebaseRating

from .base_reporter import BaseReporter


class JSONReporter(BaseReporter):
    """Reporter that outputs check results in JSON format."""

    def __init__(self, show_details: bool = False):
        """Initialize the JSON reporter.

        Args:
            show_details: Whether to include detailed information in output
        """
        self.show_details = show_details

    def report(
        self,
        results: Union[List["CheckResult"], Dict[Path, List["CheckResult"]]],
        rating: Optional["CodebaseRating"] = None,
        repo_path: Optional[Path] = None,
    ) -> None:
        """Generate a JSON report for check results.

        Args:
            results: Either a list of check results or a dictionary mapping paths to results
            rating: Overall rating for the codebase(s)
            repo_path: Path to the repository (only used for single repo reports)
        """
        if isinstance(results, dict):
            # Multiple repositories report
            report_data = {
                "repositories": {
                    str(path): {
                        "rating": self._get_rating_value(rating),
                        "summary": self._generate_summary(repo_results),
                        "results": self._serialize_results(repo_results),
                    }
                    for path, repo_results in results.items()
                }
            }
        else:
            # Single repository report
            report_data = {
                "repository": str(repo_path) if repo_path else None,
                "rating": self._get_rating_value(rating),
                "summary": self._generate_summary(results),
                "results": self._serialize_results(results),
            }

        print(json.dumps(report_data, indent=2))

    def _get_rating_value(self, rating: Optional["CodebaseRating"]) -> Optional[str]:
        """Safely get rating value, handling None case."""
        return rating.value if rating else None

    def _generate_summary(self, results: List["CheckResult"]) -> Dict[str, Any]:
        """Generate summary statistics.

        Args:
            results: List of check results

        Returns:
            Summary dictionary
        """
        status_counts = {}
        for result in results:
            status = result.status.value
            status_counts[status] = status_counts.get(status, 0) + 1

        total = len(results)
        pass_count = status_counts.get("pass", 0)
        pass_percentage = (pass_count / total) * 100 if total > 0 else 0.0

        return {
            "total_checks": total,
            "status_counts": status_counts,
            "pass_rate": round(pass_percentage, 1),
        }

    def _serialize_results(self, results: List["CheckResult"]) -> List[Dict[str, Any]]:
        """Convert check results to JSON-serializable format."""
        return [
            {
                "check_id": result.check_id,
                "status": result.status.value,
                "message": result.message,
                "details": result.details
                if self.show_details and result.details
                else None,
            }
            for result in results
        ]


def create_reporter(show_details: bool = False) -> JSONReporter:
    """Create a JSON reporter with the specified options.

    Args:
        show_details: Whether to include detailed information in output

    Returns:
        Configured JSON reporter
    """
    return JSONReporter(show_details=show_details)
