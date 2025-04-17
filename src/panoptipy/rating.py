# src/panoptipy/rating.py
"""Rating system for panoptipy codebase analysis."""

from enum import Enum
from typing import List

from .checks import CheckResult, CheckStatus
from .config import Config


class CodebaseRating(Enum):
    """Rating levels for codebases."""

    GOLD = "gold"
    SILVER = "silver"
    BRONZE = "bronze"
    problematic = "problematic"


class RatingCalculator:
    """Calculates ratings for codebases based on check results."""

    def __init__(self, config: Config):
        """Initialise the rating calculator with configuration.

        Args:
            config: Configuration containing rating thresholds
        """
        self.config = config
        self.critical_checks = set(config.get("rating", {}).get("critical_checks", []))

    def calculate_rating(self, results: List[CheckResult]) -> CodebaseRating:
        """Calculate the overall rating for a codebase based on check results.

        Args:
            results: List of check results

        Returns:
            Overall rating for the codebase
        """
        # Check for critical failures that would make the codebase problematic
        if self._has_critical_failures(results):
            return CodebaseRating.problematic

        # Calculate pass ratio
        pass_ratio = self._calculate_pass_ratio(results)

        # Apply rating thresholds
        thresholds = self.config.get("rating", {}).get("thresholds", {})
        gold_threshold = thresholds.get("gold", 0.9)
        silver_threshold = thresholds.get("silver", 0.7)
        bronze_threshold = thresholds.get("bronze", 0.5)

        if pass_ratio >= gold_threshold:
            return CodebaseRating.GOLD
        elif pass_ratio >= silver_threshold:
            return CodebaseRating.SILVER
        elif pass_ratio >= bronze_threshold:
            return CodebaseRating.BRONZE
        else:
            return CodebaseRating.problematic

    def _has_critical_failures(self, results: List[CheckResult]) -> bool:
        """Check if there are any failures in critical checks.

        Args:
            results: List of check results

        Returns:
            True if any critical checks have failed
        """
        for result in results:
            if (
                result.check_id in self.critical_checks
                or result.check_id.startswith("critical.")
            ) and result.status == CheckStatus.FAIL:
                return True
        return False

    def _calculate_pass_ratio(self, results: List[CheckResult]) -> float:
        """Calculate the ratio of passing checks to total checks.

        Args:
            results: List of check results

        Returns:
            Ratio of passing checks (0.0 to 1.0)
        """
        if not results:
            return 0.0

        passed = sum(1 for r in results if r.status == CheckStatus.PASS)
        total = len(results)

        return passed / total
