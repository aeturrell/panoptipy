"""Reporter functionality for panoptipy."""

from typing import Any

from ..config import Config
from .console import create_reporter as create_console_reporter
from .json import create_reporter as create_json_reporter


def get_reporter(format: str = "console", config: Config = None, **kwargs: Any) -> Any:
    """Get a reporter instance based on the specified format.

    Args:
        format: Output format ("console", "html", or "json")
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
        return create_console_reporter(**kwargs)
    elif format == "html":
        raise NotImplementedError("HTML reporter not yet implemented")
    elif format == "json":
        return create_json_reporter(**kwargs)
    else:
        raise ValueError(f"Unsupported reporter format: {format}")
