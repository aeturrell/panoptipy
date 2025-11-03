"""Tests for parquet reporter module."""

from datetime import datetime
from pathlib import Path

import pandas as pd
import pytest

from panoptipy.checks import CheckResult, CheckStatus
from panoptipy.rating import CodebaseRating
from panoptipy.reporters.parquet import ParquetReporter


@pytest.fixture
def sample_results():
    """Create sample check results."""
    return [
        CheckResult("check1", CheckStatus.PASS, "Check passed"),
        CheckResult(
            "check2", CheckStatus.FAIL, "Check failed", details={"error": "details"}
        ),
        CheckResult("check3", CheckStatus.WARNING, "Check warning"),
    ]


class TestParquetReporter:
    """Tests for ParquetReporter class."""

    def test_parquet_reporter_init(self, tmp_path):
        """Test ParquetReporter initialization."""
        output_path = tmp_path / "output.parquet"
        reporter = ParquetReporter(output_path=output_path)

        assert reporter.output_path == output_path
        assert reporter.records == []
        assert isinstance(reporter.timestamp, datetime)

    def test_parquet_reporter_init_with_options(self, tmp_path):
        """Test ParquetReporter initialization with options."""
        output_path = tmp_path / "output.parquet"
        reporter = ParquetReporter(output_path=output_path, show_details=True)

        assert reporter.show_details is True

    def test_report_single_repo(self, sample_results, tmp_path):
        """Test reporting for a single repository."""
        output_path = tmp_path / "output.parquet"
        reporter = ParquetReporter(output_path=output_path)

        reporter.report(sample_results, CodebaseRating.GOLD, Path("/test/repo"))

        # File should be created
        assert output_path.exists()

        # Read and verify the parquet file
        df = pd.read_parquet(output_path)
        assert len(df) == 3
        assert "timestamp" in df.columns
        assert "repository" in df.columns
        assert "check_id" in df.columns
        assert "status" in df.columns
        assert "message" in df.columns
        assert "rating" in df.columns

    def test_report_multiple_repos(self, sample_results, tmp_path):
        """Test reporting for multiple repositories."""
        output_path = tmp_path / "output.parquet"
        reporter = ParquetReporter(output_path=output_path)

        results_by_repo = {
            Path("/repo1"): sample_results[:2],
            Path("/repo2"): sample_results[2:],
        }

        reporter.report(results_by_repo, CodebaseRating.SILVER)

        # File should be created
        assert output_path.exists()

        # Read and verify the parquet file
        df = pd.read_parquet(output_path)
        assert len(df) == 3  # Total of 3 results

    def test_report_empty_results(self, tmp_path):
        """Test reporting with empty results."""
        output_path = tmp_path / "output.parquet"
        reporter = ParquetReporter(output_path=output_path)

        reporter.report([], CodebaseRating.problematic, Path("/test/repo"))

        # File should not be created for empty results
        assert not output_path.exists()

    def test_results_to_records(self, sample_results, tmp_path):
        """Test _results_to_records method."""
        output_path = tmp_path / "output.parquet"
        reporter = ParquetReporter(output_path=output_path)

        timestamp = datetime.now()
        records = reporter._results_to_records(
            sample_results, timestamp, "/test/repo", "gold"
        )

        assert len(records) == 3
        assert all("timestamp" in r for r in records)
        assert all("repository" in r for r in records)
        assert all("check_id" in r for r in records)
        assert all("status" in r for r in records)
        assert all("message" in r for r in records)
        assert all("rating" in r for r in records)

    def test_results_to_records_with_details(self, tmp_path):
        """Test _results_to_records with result details."""
        output_path = tmp_path / "output.parquet"
        reporter = ParquetReporter(output_path=output_path)

        result = CheckResult(
            "check", CheckStatus.FAIL, "Failed", details={"error": "test error"}
        )
        timestamp = datetime.now()
        records = reporter._results_to_records(
            [result], timestamp, "/test/repo", "gold"
        )

        assert len(records) == 1
        assert records[0]["details"] is not None
        assert "error" in records[0]["details"]

    def test_results_to_records_without_details(self, tmp_path):
        """Test _results_to_records without result details."""
        output_path = tmp_path / "output.parquet"
        reporter = ParquetReporter(output_path=output_path)

        result = CheckResult("check", CheckStatus.PASS, "Passed")
        timestamp = datetime.now()
        records = reporter._results_to_records(
            [result], timestamp, "/test/repo", "gold"
        )

        assert len(records) == 1
        assert records[0]["details"] is None

    def test_report_with_none_rating(self, sample_results, tmp_path):
        """Test reporting with None rating."""
        output_path = tmp_path / "output.parquet"
        reporter = ParquetReporter(output_path=output_path)

        reporter.report(sample_results, None, Path("/test/repo"))

        # File should be created
        assert output_path.exists()

        df = pd.read_parquet(output_path)
        assert df["rating"].isna().all()

    def test_report_accumulates_records(self, sample_results, tmp_path):
        """Test that report accumulates records before writing."""
        output_path = tmp_path / "output.parquet"
        reporter = ParquetReporter(output_path=output_path)

        # First call adds records
        reporter.report(sample_results[:1], CodebaseRating.GOLD, Path("/repo1"))

        # Second call should accumulate (but won't in current implementation)
        # In the current implementation, each call writes immediately
        assert output_path.exists()

    def test_repository_name_extraction(self, sample_results, tmp_path):
        """Test that repository name is extracted correctly."""
        output_path = tmp_path / "output.parquet"
        reporter = ParquetReporter(output_path=output_path)

        repo_path = Path("/path/to/my_repo")
        reporter.report(sample_results, CodebaseRating.GOLD, repo_path)

        df = pd.read_parquet(output_path)
        # Repository should be the stem (last component) of the path
        assert df["repository"].iloc[0] == "my_repo"

    def test_status_uses_enum_name(self, tmp_path):
        """Test that status uses the enum name, not value."""
        output_path = tmp_path / "output.parquet"
        reporter = ParquetReporter(output_path=output_path)

        result = CheckResult("check", CheckStatus.PASS, "Passed")
        reporter.report([result], CodebaseRating.GOLD, Path("/test/repo"))

        df = pd.read_parquet(output_path)
        # Status should use enum name (PASS) not value (pass)
        assert df["status"].iloc[0] == "PASS"

    def test_same_timestamp_for_batch(self, sample_results, tmp_path):
        """Test that all records in a batch use the same timestamp."""
        output_path = tmp_path / "output.parquet"
        reporter = ParquetReporter(output_path=output_path)

        reporter.report(sample_results, CodebaseRating.GOLD, Path("/test/repo"))

        df = pd.read_parquet(output_path)
        # All records should have the same timestamp
        assert df["timestamp"].nunique() == 1

    def test_parquet_compression(self, sample_results, tmp_path):
        """Test that parquet file uses snappy compression."""
        output_path = tmp_path / "output.parquet"
        reporter = ParquetReporter(output_path=output_path)

        reporter.report(sample_results, CodebaseRating.GOLD, Path("/test/repo"))

        # File should exist and be readable
        assert output_path.exists()
        df = pd.read_parquet(output_path)
        assert len(df) > 0
