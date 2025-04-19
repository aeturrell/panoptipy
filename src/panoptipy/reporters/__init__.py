"""Reporter functionality for panoptipy."""

from pathlib import Path
from typing import Any, Literal, Optional, Union

from ..config import Config
from .console import ConsoleReporter
from .json import JSONReporter
from .parquet import ParquetReporter

ReporterFormat = Literal["console", "json", "parquet"]


def get_reporter(
    format: ReporterFormat = "console",
    output_path: Optional[Path] = None,
    config: Config = None,
    **kwargs: Any,
) -> Union[ConsoleReporter, JSONReporter, ParquetReporter]:
    """Get a reporter instance based on the specified format.

    Args:
        format: Output format ("console", "json", or "parquet")
        output_path: Path for output file (required for parquet format)
        config: Configuration object
        **kwargs: Additional keyword arguments to pass to the reporter

    Returns:
        Reporter instance

    Raises:
        ValueError: If the specified format is not supported
    """
    # Get show_details from config if not explicitly provided
    if "show_details" not in kwargs and config:
        kwargs["show_details"] = config.get("reporters.show_details", True)

    if format == "console":
        return ConsoleReporter(**kwargs)
    elif format == "json":
        return JSONReporter(**kwargs)
    elif format == "parquet":
        if not output_path:
            raise ValueError("output_path is required for parquet format")
        return ParquetReporter(output_path=output_path, **kwargs)
    else:
        raise ValueError(f"Unknown reporter format: {format}")
