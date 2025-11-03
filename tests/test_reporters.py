"""Tests for reporter modules."""

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from panoptipy.checks import CheckResult, CheckStatus
from panoptipy.rating import CodebaseRating
from panoptipy.reporters.base_reporter import BaseReporter
from panoptipy.reporters.json import JSONReporter, create_reporter


class ConcreteReporter(BaseReporter):
    """Concrete implementation of BaseReporter for testing."""

    def report(self, results_by_repo, ratings):
        self.results_by_repo = results_by_repo
        self.ratings = ratings

    def report_single(self, results, rating, repo_path):
        self.results = results
        self.rating = rating
        self.repo_path = repo_path


def test_base_reporter_not_implemented():
    """Test that BaseReporter methods raise NotImplementedError."""
    reporter = BaseReporter()

    with pytest.raises(NotImplementedError):
        reporter.report({}, {})

    with pytest.raises(NotImplementedError):
        reporter.report_single([], None, Path("/tmp"))


def test_concrete_reporter():
    """Test that concrete implementation of BaseReporter works."""
    reporter = ConcreteReporter()
    results_by_repo = {Path("/repo1"): [], Path("/repo2"): []}
    ratings = {
        Path("/repo1"): CodebaseRating.GOLD,
        Path("/repo2"): CodebaseRating.SILVER,
    }

    reporter.report(results_by_repo, ratings)

    assert reporter.results_by_repo == results_by_repo
    assert reporter.ratings == ratings


def test_json_reporter_init():
    """Test JSONReporter initialization."""
    reporter = JSONReporter()

    assert reporter.show_details is False
    assert reporter.output_path is None


def test_json_reporter_init_with_options():
    """Test JSONReporter initialization with options."""
    output_path = Path("/tmp/output.json")
    reporter = JSONReporter(show_details=True, output_path=output_path)

    assert reporter.show_details is True
    assert reporter.output_path == output_path


@patch("panoptipy.reporters.json.print_json")
def test_json_reporter_single_repo(mock_print_json):
    """Test JSON reporter with single repository results."""
    reporter = JSONReporter()
    results = [
        CheckResult("check1", CheckStatus.PASS, "Pass message"),
        CheckResult("check2", CheckStatus.FAIL, "Fail message"),
        CheckResult("check3", CheckStatus.SKIP, "Skip message"),
    ]
    rating = CodebaseRating.SILVER
    repo_path = Path("/test/repo")

    reporter.report(results, rating, repo_path)

    # Verify print_json was called
    assert mock_print_json.called
    # Get the JSON string that was passed to print_json
    json_str = mock_print_json.call_args[0][0]
    data = json.loads(json_str)

    assert data["repository"] == str(repo_path)
    assert data["rating"] == "silver"
    assert data["summary"]["total_checks"] == 3
    assert len(data["results"]) == 3


@patch("panoptipy.reporters.json.print_json")
def test_json_reporter_multiple_repos(mock_print_json):
    """Test JSON reporter with multiple repository results."""
    reporter = JSONReporter()
    repo1_path = Path("/repo1")
    repo2_path = Path("/repo2")
    results_by_repo = {
        repo1_path: [CheckResult("check1", CheckStatus.PASS, "Pass")],
        repo2_path: [CheckResult("check2", CheckStatus.FAIL, "Fail")],
    }

    reporter.report(results_by_repo)

    assert mock_print_json.called
    json_str = mock_print_json.call_args[0][0]
    data = json.loads(json_str)

    assert "repositories" in data
    # Use str(Path) for cross-platform compatibility
    assert str(repo1_path) in data["repositories"]
    assert str(repo2_path) in data["repositories"]


def test_json_reporter_write_to_file(tmp_path):
    """Test JSON reporter writing to file."""
    output_path = tmp_path / "output.json"
    reporter = JSONReporter(output_path=output_path)
    results = [CheckResult("check1", CheckStatus.PASS, "Pass message")]
    rating = CodebaseRating.GOLD
    repo_path = Path("/test/repo")

    reporter.report(results, rating, repo_path)

    # Verify file was created and contains valid JSON
    assert output_path.exists()
    with open(output_path) as f:
        data = json.load(f)

    assert data["repository"] == str(repo_path)
    assert data["rating"] == "gold"


@patch("panoptipy.reporters.json.print_json")
def test_json_reporter_with_details(mock_print_json):
    """Test JSON reporter with show_details enabled."""
    reporter = JSONReporter(show_details=True)
    results = [
        CheckResult(
            "check1",
            CheckStatus.FAIL,
            "Fail message",
            details={"file": "test.py", "line": 42},
        )
    ]

    reporter.report(results, None, Path("/repo"))

    json_str = mock_print_json.call_args[0][0]
    data = json.loads(json_str)

    result = data["results"][0]
    assert result["details"] is not None
    assert result["details"]["file"] == "test.py"
    assert result["details"]["line"] == 42


@patch("panoptipy.reporters.json.print_json")
def test_json_reporter_without_details(mock_print_json):
    """Test JSON reporter with show_details disabled."""
    reporter = JSONReporter(show_details=False)
    results = [
        CheckResult(
            "check1",
            CheckStatus.FAIL,
            "Fail message",
            details={"file": "test.py", "line": 42},
        )
    ]

    reporter.report(results, None, Path("/repo"))

    json_str = mock_print_json.call_args[0][0]
    data = json.loads(json_str)

    result = data["results"][0]
    assert result["details"] is None


def test_json_reporter_serialize_results():
    """Test serializing check results."""
    reporter = JSONReporter()
    results = [
        CheckResult("check1", CheckStatus.PASS, "Pass"),
        CheckResult("check2", CheckStatus.FAIL, "Fail", details={"key": "value"}),
    ]

    serialized = reporter._serialize_results(results)

    assert len(serialized) == 2
    assert serialized[0]["check_id"] == "check1"
    assert serialized[0]["status"] == "pass"
    assert serialized[1]["check_id"] == "check2"
    assert serialized[1]["status"] == "fail"


def test_json_reporter_generate_summary():
    """Test generating summary statistics."""
    reporter = JSONReporter()
    results = [
        CheckResult("check1", CheckStatus.PASS, "Pass"),
        CheckResult("check2", CheckStatus.PASS, "Pass"),
        CheckResult("check3", CheckStatus.FAIL, "Fail"),
    ]

    summary = reporter._generate_summary(results)

    assert summary["total_checks"] == 3
    assert "status_counts" in summary
    assert "pass_rate" in summary


def test_json_reporter_get_rating_value():
    """Test getting rating value."""
    reporter = JSONReporter()

    assert reporter._get_rating_value(CodebaseRating.GOLD) == "gold"
    assert reporter._get_rating_value(CodebaseRating.SILVER) == "silver"
    assert reporter._get_rating_value(None) is None


@patch("panoptipy.reporters.json.print_json")
def test_json_reporter_with_none_rating(mock_print_json):
    """Test JSON reporter with None rating."""
    reporter = JSONReporter()
    results = [CheckResult("check1", CheckStatus.PASS, "Pass")]

    reporter.report(results, None, Path("/repo"))

    json_str = mock_print_json.call_args[0][0]
    data = json.loads(json_str)

    assert data["rating"] is None


def test_create_reporter():
    """Test create_reporter factory function."""
    reporter = create_reporter()

    assert isinstance(reporter, JSONReporter)
    assert reporter.show_details is False
    assert reporter.output_path is None


def test_create_reporter_with_options():
    """Test create_reporter with options."""
    output_path = Path("/tmp/output.json")
    reporter = create_reporter(show_details=True, output_path=output_path)

    assert isinstance(reporter, JSONReporter)
    assert reporter.show_details is True
    assert reporter.output_path == output_path


@patch("panoptipy.reporters.json.print_json")
def test_json_reporter_empty_results(mock_print_json):
    """Test JSON reporter with empty results."""
    reporter = JSONReporter()
    results = []

    reporter.report(results, CodebaseRating.problematic, Path("/repo"))

    json_str = mock_print_json.call_args[0][0]
    data = json.loads(json_str)

    assert data["summary"]["total_checks"] == 0
    assert len(data["results"]) == 0


@patch("panoptipy.reporters.json.print_json")
def test_json_reporter_all_status_types(mock_print_json):
    """Test JSON reporter with all status types."""
    reporter = JSONReporter()
    results = [
        CheckResult("check1", CheckStatus.PASS, "Pass"),
        CheckResult("check2", CheckStatus.FAIL, "Fail"),
        CheckResult("check3", CheckStatus.WARNING, "Warning"),
        CheckResult("check4", CheckStatus.SKIP, "Skip"),
        CheckResult("check5", CheckStatus.ERROR, "Error"),
    ]

    reporter.report(results, None, Path("/repo"))

    json_str = mock_print_json.call_args[0][0]
    data = json.loads(json_str)

    statuses = [r["status"] for r in data["results"]]
    assert "pass" in statuses
    assert "fail" in statuses
    assert "warning" in statuses
    assert "skip" in statuses
    assert "error" in statuses
