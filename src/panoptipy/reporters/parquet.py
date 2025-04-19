from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Dict, List, Optional, Union

import pandas as pd

from .json import JSONReporter

if TYPE_CHECKING:
    from ..checks import CheckResult
    from ..rating import CodebaseRating


class ParquetReporter(JSONReporter):
    """Reporter that saves check results in a Parquet file with a tidy data structure."""

    def __init__(self, output_path: Path, **kwargs):
        super().__init__(**kwargs)
        self.output_path = output_path
        self.records = []  # Store all records before writing
        self.timestamp = datetime.now()  # Use same timestamp for batch

    def report(
        self,
        results: Union[List["CheckResult"], Dict[Path, List["CheckResult"]]],
        rating: Optional["CodebaseRating"] = None,
        repo_path: Optional[Path] = None,
    ) -> None:
        """Accumulate results and write to parquet file."""
        if isinstance(results, dict):
            # Multiple repositories
            for path, repo_results in results.items():
                self.records.extend(
                    self._results_to_records(
                        repo_results,
                        self.timestamp,
                        str(path),
                        self._get_rating_value(rating),
                    )
                )
        else:
            # Single repository
            self.records.extend(
                self._results_to_records(
                    results,
                    self.timestamp,
                    str(repo_path) if repo_path else None,
                    self._get_rating_value(rating),
                )
            )

        # Write all accumulated records to parquet
        if self.records:  # Only write if we have records
            df = pd.DataFrame(self.records)
            df.to_parquet(self.output_path, compression="snappy", index=False)

    def _results_to_records(
        self,
        results: List["CheckResult"],
        timestamp: datetime,
        repository: Optional[str],
        rating: Optional[str],
    ) -> List[Dict]:
        """Convert check results to tidy record format."""
        return [
            {
                "timestamp": timestamp,
                "repository": Path(repository).stem,
                "check_id": result.check_id,
                "status": result.status.name,
                "message": result.message,
                "rating": rating,
                "details": str(result.details) if result.details else None,
            }
            for result in results
        ]
