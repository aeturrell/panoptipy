from pathlib import Path
from typing import Optional

import toml


class Config:
    """Configuration for panoptipy."""

    DEFAULT_CONFIG = {
        "checks": {
            "enabled": ["*"],
            "disabled": [],
            "critical": [],
        },
        "reporters": ["console"],
        "thresholds": {
            "max_file_size": 1000,
            "max_nesting_depth": 5,
        },
    }

    @classmethod
    def load(cls, config_path: Optional[Path] = None) -> "Config":
        """Load configuration from a TOML file or use defaults."""
        config_dict = cls.DEFAULT_CONFIG.copy()

        if config_path and config_path.exists():
            with open(config_path, "rb") as f:
                user_config = toml.load(f)
                if user_config:
                    cls._merge_configs(config_dict, user_config)

        return cls(config_dict)

    def __init__(self, config_dict: dict):
        self._config = config_dict

    @staticmethod
    def _merge_configs(base: dict, override: dict) -> None:
        """Recursively merge override into base."""
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                Config._merge_configs(base[key], value)
            else:
                base[key] = value

    def get(self, key, default=None):
        """Get a configuration value using dot notation.

        Args:
            key: Configuration key
            default: Default value if key not found

        Returns:
            Configuration value or default
        """
        current = self._config
        try:
            for part in key.split("."):
                current = current[part]
            return current
        except (KeyError, TypeError):
            return default

    def get_check_patterns(self, pattern_type: str) -> list[str]:
        """Get enabled or disabled check patterns.

        Args:
            pattern_type: Either 'enabled' or 'disabled'

        Returns:
            List of check patterns

        Raises:
            ValueError: If pattern_type is not 'enabled' or 'disabled'
        """
        if pattern_type not in ("enabled", "disabled"):
            raise ValueError("pattern_type must be 'enabled' or 'disabled'")

        return self.get(f"checks.{pattern_type}", [])
