"""Tests for rating.py module."""

import pytest

from panoptipy.checks import CheckResult, CheckStatus
from panoptipy.config import Config
from panoptipy.rating import CodebaseRating, RatingCalculator


@pytest.fixture
def default_config():
    """Create a default config for testing."""
    return Config(Config.DEFAULT_CONFIG.copy())


@pytest.fixture
def rating_config():
    """Create a config with rating thresholds."""
    return Config({
        "rating": {
            "thresholds": {
                "gold": 0.9,
                "silver": 0.7,
                "bronze": 0.5
            },
            "critical_checks": ["critical_check"]
        }
    })


@pytest.fixture
def calculator(rating_config):
    """Create a rating calculator with test config."""
    return RatingCalculator(rating_config)


def test_codebase_rating_enum():
    """Test that CodebaseRating enum has expected values."""
    assert CodebaseRating.GOLD.value == "gold"
    assert CodebaseRating.SILVER.value == "silver"
    assert CodebaseRating.BRONZE.value == "bronze"
    assert CodebaseRating.problematic.value == "problematic"


def test_rating_calculator_init(rating_config):
    """Test rating calculator initialization."""
    calc = RatingCalculator(rating_config)

    assert calc.config == rating_config
    assert "critical_check" in calc.critical_checks


def test_calculate_rating_gold(calculator):
    """Test calculating gold rating."""
    results = [
        CheckResult("check1", CheckStatus.PASS, "Pass"),
        CheckResult("check2", CheckStatus.PASS, "Pass"),
        CheckResult("check3", CheckStatus.PASS, "Pass"),
        CheckResult("check4", CheckStatus.PASS, "Pass"),
        CheckResult("check5", CheckStatus.PASS, "Pass"),
        CheckResult("check6", CheckStatus.PASS, "Pass"),
        CheckResult("check7", CheckStatus.PASS, "Pass"),
        CheckResult("check8", CheckStatus.PASS, "Pass"),
        CheckResult("check9", CheckStatus.PASS, "Pass"),
        CheckResult("check10", CheckStatus.FAIL, "Fail"),  # 90% pass rate
    ]

    rating = calculator.calculate_rating(results)
    assert rating == CodebaseRating.GOLD


def test_calculate_rating_silver(calculator):
    """Test calculating silver rating."""
    results = [
        CheckResult("check1", CheckStatus.PASS, "Pass"),
        CheckResult("check2", CheckStatus.PASS, "Pass"),
        CheckResult("check3", CheckStatus.PASS, "Pass"),
        CheckResult("check4", CheckStatus.PASS, "Pass"),
        CheckResult("check5", CheckStatus.PASS, "Pass"),
        CheckResult("check6", CheckStatus.PASS, "Pass"),
        CheckResult("check7", CheckStatus.PASS, "Pass"),
        CheckResult("check8", CheckStatus.FAIL, "Fail"),
        CheckResult("check9", CheckStatus.FAIL, "Fail"),
        CheckResult("check10", CheckStatus.FAIL, "Fail"),  # 70% pass rate
    ]

    rating = calculator.calculate_rating(results)
    assert rating == CodebaseRating.SILVER


def test_calculate_rating_bronze(calculator):
    """Test calculating bronze rating."""
    results = [
        CheckResult("check1", CheckStatus.PASS, "Pass"),
        CheckResult("check2", CheckStatus.PASS, "Pass"),
        CheckResult("check3", CheckStatus.PASS, "Pass"),
        CheckResult("check4", CheckStatus.PASS, "Pass"),
        CheckResult("check5", CheckStatus.PASS, "Pass"),
        CheckResult("check6", CheckStatus.FAIL, "Fail"),
        CheckResult("check7", CheckStatus.FAIL, "Fail"),
        CheckResult("check8", CheckStatus.FAIL, "Fail"),
        CheckResult("check9", CheckStatus.FAIL, "Fail"),
        CheckResult("check10", CheckStatus.FAIL, "Fail"),  # 50% pass rate
    ]

    rating = calculator.calculate_rating(results)
    assert rating == CodebaseRating.BRONZE


def test_calculate_rating_problematic(calculator):
    """Test calculating problematic rating."""
    results = [
        CheckResult("check1", CheckStatus.PASS, "Pass"),
        CheckResult("check2", CheckStatus.FAIL, "Fail"),
        CheckResult("check3", CheckStatus.FAIL, "Fail"),
        CheckResult("check4", CheckStatus.FAIL, "Fail"),
        CheckResult("check5", CheckStatus.FAIL, "Fail"),
        CheckResult("check6", CheckStatus.FAIL, "Fail"),
        CheckResult("check7", CheckStatus.FAIL, "Fail"),
        CheckResult("check8", CheckStatus.FAIL, "Fail"),
        CheckResult("check9", CheckStatus.FAIL, "Fail"),
        CheckResult("check10", CheckStatus.FAIL, "Fail"),  # 10% pass rate
    ]

    rating = calculator.calculate_rating(results)
    assert rating == CodebaseRating.problematic


def test_calculate_rating_with_critical_failure(calculator):
    """Test that critical failures result in problematic rating."""
    results = [
        CheckResult("check1", CheckStatus.PASS, "Pass"),
        CheckResult("check2", CheckStatus.PASS, "Pass"),
        CheckResult("check3", CheckStatus.PASS, "Pass"),
        CheckResult("check4", CheckStatus.PASS, "Pass"),
        CheckResult("check5", CheckStatus.PASS, "Pass"),
        CheckResult("check6", CheckStatus.PASS, "Pass"),
        CheckResult("check7", CheckStatus.PASS, "Pass"),
        CheckResult("check8", CheckStatus.PASS, "Pass"),
        CheckResult("check9", CheckStatus.PASS, "Pass"),
        CheckResult("critical_check", CheckStatus.FAIL, "Critical failure"),
    ]

    rating = calculator.calculate_rating(results)
    assert rating == CodebaseRating.problematic


def test_calculate_rating_with_critical_prefix(calculator):
    """Test that checks with 'critical.' prefix are treated as critical."""
    results = [
        CheckResult("check1", CheckStatus.PASS, "Pass"),
        CheckResult("check2", CheckStatus.PASS, "Pass"),
        CheckResult("check3", CheckStatus.PASS, "Pass"),
        CheckResult("check4", CheckStatus.PASS, "Pass"),
        CheckResult("check5", CheckStatus.PASS, "Pass"),
        CheckResult("check6", CheckStatus.PASS, "Pass"),
        CheckResult("check7", CheckStatus.PASS, "Pass"),
        CheckResult("check8", CheckStatus.PASS, "Pass"),
        CheckResult("check9", CheckStatus.PASS, "Pass"),
        CheckResult("critical.security", CheckStatus.FAIL, "Security failure"),
    ]

    rating = calculator.calculate_rating(results)
    assert rating == CodebaseRating.problematic


def test_has_critical_failures_true(calculator):
    """Test detecting critical failures."""
    results = [
        CheckResult("check1", CheckStatus.PASS, "Pass"),
        CheckResult("critical_check", CheckStatus.FAIL, "Critical failure"),
    ]

    assert calculator._has_critical_failures(results) is True


def test_has_critical_failures_false(calculator):
    """Test when there are no critical failures."""
    results = [
        CheckResult("check1", CheckStatus.PASS, "Pass"),
        CheckResult("check2", CheckStatus.FAIL, "Non-critical failure"),
    ]

    assert calculator._has_critical_failures(results) is False


def test_has_critical_failures_with_pass(calculator):
    """Test that passing critical checks don't trigger failure."""
    results = [
        CheckResult("check1", CheckStatus.PASS, "Pass"),
        CheckResult("critical_check", CheckStatus.PASS, "Critical pass"),
    ]

    assert calculator._has_critical_failures(results) is False


def test_calculate_pass_ratio_all_pass(calculator):
    """Test pass ratio calculation with all passing."""
    results = [
        CheckResult("check1", CheckStatus.PASS, "Pass"),
        CheckResult("check2", CheckStatus.PASS, "Pass"),
        CheckResult("check3", CheckStatus.PASS, "Pass"),
    ]

    ratio = calculator._calculate_pass_ratio(results)
    assert ratio == 1.0


def test_calculate_pass_ratio_all_fail(calculator):
    """Test pass ratio calculation with all failing."""
    results = [
        CheckResult("check1", CheckStatus.FAIL, "Fail"),
        CheckResult("check2", CheckStatus.FAIL, "Fail"),
        CheckResult("check3", CheckStatus.FAIL, "Fail"),
    ]

    ratio = calculator._calculate_pass_ratio(results)
    assert ratio == 0.0


def test_calculate_pass_ratio_mixed(calculator):
    """Test pass ratio calculation with mixed results."""
    results = [
        CheckResult("check1", CheckStatus.PASS, "Pass"),
        CheckResult("check2", CheckStatus.PASS, "Pass"),
        CheckResult("check3", CheckStatus.FAIL, "Fail"),
        CheckResult("check4", CheckStatus.FAIL, "Fail"),
    ]

    ratio = calculator._calculate_pass_ratio(results)
    assert ratio == 0.5


def test_calculate_pass_ratio_with_skipped(calculator):
    """Test pass ratio calculation ignores skipped checks."""
    results = [
        CheckResult("check1", CheckStatus.PASS, "Pass"),
        CheckResult("check2", CheckStatus.PASS, "Pass"),
        CheckResult("check3", CheckStatus.SKIP, "Skipped"),
        CheckResult("check4", CheckStatus.SKIP, "Skipped"),
    ]

    ratio = calculator._calculate_pass_ratio(results)
    assert ratio == 1.0  # Only counts pass/fail


def test_calculate_pass_ratio_empty(calculator):
    """Test pass ratio calculation with empty results."""
    results = []

    ratio = calculator._calculate_pass_ratio(results)
    assert ratio == 0.0


def test_calculate_summary_stats(calculator):
    """Test calculating summary statistics."""
    results = [
        CheckResult("check1", CheckStatus.PASS, "Pass"),
        CheckResult("check2", CheckStatus.PASS, "Pass"),
        CheckResult("check3", CheckStatus.FAIL, "Fail"),
        CheckResult("check4", CheckStatus.SKIP, "Skip"),
        CheckResult("check5", CheckStatus.WARNING, "Warning"),
    ]

    stats = calculator.calculate_summary_stats(results)

    assert stats["total_checks"] == 5
    assert stats["pass_count"] == 2
    assert stats["pass_ratio"] == 2 / 3  # 2 pass out of 3 pass/fail
    assert stats["pass_percentage"] == (2 / 3) * 100
    assert stats["status_counts"]["pass"] == 2
    assert stats["status_counts"]["fail"] == 1
    assert stats["status_counts"]["skip"] == 1
    assert stats["status_counts"]["warning"] == 1


def test_calculate_summary_stats_empty(calculator):
    """Test calculating summary statistics with empty results."""
    results = []

    stats = calculator.calculate_summary_stats(results)

    assert stats["total_checks"] == 0
    assert stats["pass_count"] == 0
    assert stats["pass_ratio"] == 0.0
    assert stats["pass_percentage"] == 0.0
    assert stats["status_counts"] == {}


def test_rating_calculator_with_default_config(default_config):
    """Test rating calculator with default config (no rating section)."""
    calc = RatingCalculator(default_config)

    assert calc.critical_checks == set()

    # Should still work with default thresholds
    results = [
        CheckResult("check1", CheckStatus.PASS, "Pass"),
        CheckResult("check2", CheckStatus.PASS, "Pass"),
    ]

    rating = calc.calculate_rating(results)
    assert rating == CodebaseRating.GOLD


def test_rating_with_custom_thresholds():
    """Test rating calculation with custom thresholds."""
    config = Config({
        "rating": {
            "thresholds": {
                "gold": 0.95,
                "silver": 0.85,
                "bronze": 0.75
            }
        }
    })
    calc = RatingCalculator(config)

    # 90% pass rate
    results = [
        CheckResult(f"check{i}", CheckStatus.PASS, "Pass")
        for i in range(9)
    ] + [CheckResult("check10", CheckStatus.FAIL, "Fail")]

    rating = calc.calculate_rating(results)
    assert rating == CodebaseRating.SILVER  # Below gold threshold of 95%
