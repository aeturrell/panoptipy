# config.py
from pathlib import Path
from typing import Any, Optional  # Added Any for broader type hints if needed

# Use 'tomli' for reading TOML, it's the standard library module in Python 3.11+
# and recommended for earlier versions. Fallback to 'toml' if needed.
try:
    import tomli as tomllib  # Preferred library
except ModuleNotFoundError:
    try:
        import toml as tomllib  # Fallback library
    except ModuleNotFoundError:
        raise ImportError(
            "Please install 'tomli' or 'toml' to read configuration files."
        )


class Config:
    """Configuration for panoptipy."""

    DEFAULT_CONFIG: dict[str, Any] = {
        "checks": {
            "enabled": ["*"],
            "disabled": [],
            "critical": [],
        },
        "reporters": {
            "enabled": ["console"],
            "show_details": True,
        },
        "thresholds": {
            "max_file_size": 500,
        },
    }

    @classmethod
    def load(cls, config_path: Optional[Path] = None) -> "Config":
        """Load configuration from file and merge with defaults.

        Args:
            config_path: Path to configuration file

        Returns:
            Config instance
        """
        config_dict = cls.DEFAULT_CONFIG.copy()

        if config_path and config_path.exists():
            with open(config_path, "r", encoding="utf-8") as f:
                user_config = tomllib.loads(f.read())
                if "tool" in user_config and "panoptipy" in user_config["tool"]:
                    cls._merge_configs(config_dict, user_config["tool"]["panoptipy"])

        return cls(config_dict)

    def __init__(self, config_dict: dict):
        # Consider validating the final config structure here if needed
        self._config = config_dict

    @staticmethod
    def _merge_configs(base: dict, override: dict) -> None:
        """Recursively merge override dictionary into base dictionary."""
        for key, value in override.items():
            # If the key exists in base and both values are dictionaries, recurse
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                Config._merge_configs(base[key], value)
            # Otherwise, overwrite the value in base with the value from override
            else:
                base[key] = value

    def get(self, key: str, default: Any = None) -> Any:  # Added type hints
        """Get a configuration value using dot notation.

        Args:
            key: Configuration key (e.g., "checks.enabled").
            default: Default value if key not found.

        Returns:
            Configuration value or default.
        """
        current = self._config
        try:
            for part in key.split("."):
                if isinstance(current, dict):
                    current = current[part]
                else:
                    # Tried to access a key within a non-dictionary value
                    return default
            return current
        except (
            KeyError,
            TypeError,
        ):  # KeyError if part not found, TypeError might occur if key is not string/hashable (less likely here)
            return default

    def get_check_patterns(self, pattern_type: str) -> list[str]:
        """Get enabled, disabled, or critical check patterns.

        Args:
            pattern_type: Either 'enabled', 'disabled', or 'critical'.

        Returns:
            List of check patterns (defaults to empty list if not found).

        Raises:
            ValueError: If pattern_type is invalid.
        """
        # Include 'critical' as it's in your default config
        if pattern_type not in ("enabled", "disabled", "critical"):
            raise ValueError(
                "pattern_type must be 'enabled', 'disabled', or 'critical'"
            )

        # Ensure we return a list, defaulting to [] if the key doesn't exist
        # or if the retrieved value is not a list.
        value = self.get(f"checks.{pattern_type}", [])
        return value if isinstance(value, list) else []
