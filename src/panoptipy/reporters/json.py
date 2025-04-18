"""JSON reporter for panoptipy."""

import json
from typing import TYPE_CHECKING, Any, Dict, List

if TYPE_CHECKING:
    from ..checks import CheckResult
    from ..rating import CodebaseRating


class JSONReporter:
    """Reporter that outputs check results in JSON format."""

    def __init__(self, show_details: bool = False):
        """Initialize the JSON reporter.

        Args:
            show_details: Whether to include detailed information in output
        """
        self.show_details = show_details

    def report(self, results: List["CheckResult"], rating: "CodebaseRating") -> None:
        """Generate a JSON report of check results.

        Args:
            results: List of check results
            rating: Overall rating for the codebase
        """
        report_data = {
            "rating": rating.value,
            "summary": self._generate_summary(results),
            "results": self._serialize_results(results),
        }

        print(json.dumps(report_data, indent=2))

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
        """Serialize the check results into JSON-compatible format.

        Args:
            results: List of check results

        Returns:
            List of result dictionaries
        """
        serialized = []
        for result in results:
            result_data = {
                "check_id": result.check_id,
                "status": result.status.value,
                "message": result.message,
            }
            if self.show_details and result.details:
                result_data["details"] = result.details
            serialized.append(result_data)
        return serialized


def create_reporter(show_details: bool = False) -> JSONReporter:
    """Create a JSON reporter with the specified options.

    Args:
        show_details: Whether to include detailed information in output

    Returns:
        Configured JSON reporter
    """
    return JSONReporter(show_details=show_details)
