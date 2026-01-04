# config.py
from pathlib import Path
from typing import Any, Dict, Optional  # Added Any for broader type hints if needed

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
            "min_readme_length": 100,  # in characters
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

    def to_dict(self) -> Dict[str, Any]:
        """Convert the config to a dictionary for serialization.

        Returns:
            Dictionary representation of the config
        """
        # Based on the provided DEFAULT_CONFIG structure
        config_dict = {
            "checks": {
                "enabled": self.get("checks.enabled", ["*"]),
                "disabled": self.get("checks.disabled", []),
                "critical": self.get("checks.critical", []),
            },
            "reporters": {
                "enabled": self.get("reporters.enabled", ["console"]),
                "show_details": self.get("reporters.show_details", True),
            },
            "thresholds": {
                "max_file_size": self.get("thresholds.max_file_size", 500),
            },
        }

        # Include any custom configs that might have been added
        if hasattr(self, "_config"):
            # Recursively merge any additional config items
            def deep_merge(source, destination):
                for key, value in source.items():
                    if isinstance(value, dict):
                        # get node or create one
                        node = destination.setdefault(key, {})
                        deep_merge(value, node)
                    else:
                        destination[key] = value
                return destination

            # Start with our known structure and merge in any custom items
            custom_config = self._config.copy() if hasattr(self, "_config") else {}
            config_dict = deep_merge(custom_config, config_dict)

        return config_dict

    @classmethod
    def from_dict(cls, config_dict: Dict[str, Any]) -> "Config":
        """Create a Config object from a dictionary.

        Args:
            config_dict: Dictionary representation of the config

        Returns:
            Config object
        """
        config = cls(config_dict)

        # If your Config class stores the config in _config attribute:
        if hasattr(config, "_config"):
            config._config = config_dict.copy()
        else:
            # Alternative approach if Config doesn't use _config:
            # This assumes you have a method to update config values
            for section, values in config_dict.items():
                if isinstance(values, dict):
                    for key, value in values.items():
                        config.set(f"{section}.{key}", value)
                else:
                    config.set(section, values)

        return config
