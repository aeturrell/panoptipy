"""Reporter functionality for panoptipy."""

from typing import Any

from .console import create_reporter as create_console_reporter


def get_reporter(format: str = "console", **kwargs: Any) -> Any:
    """Get a reporter instance based on the specified format.

    Args:
        format: Output format ("console", "html", or "json")
        **kwargs: Additional keyword arguments to pass to the reporter

    Returns:
        Reporter instance

    Raises:
        ValueError: If the specified format is not supported
    """
    if format == "console":
        return create_console_reporter(**kwargs)
    elif format == "html":
        raise NotImplementedError("HTML reporter not yet implemented")
    elif format == "json":
        raise NotImplementedError("JSON reporter not yet implemented")
    else:
        raise ValueError(f"Unsupported reporter format: {format}")
